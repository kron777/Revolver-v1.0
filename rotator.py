"""VPN rotation engine: an asyncio loop on a background thread, driven from
sync Flask handlers via run_coroutine_threadsafe."""
import proton_env  # noqa: F401  -- must come first, sets XDG paths

import asyncio
import random
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime

from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.core.session_holder import ClientTypeMetadata

CLIENT_VERSION = "4.18.0"
IP_ECHOS = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]

KILLSWITCH_LABELS = {0: "Off", 1: "On", 2: "Permanent"}

DISCONNECT_TIMEOUT = 45
CONNECT_TIMEOUT = 60


class Rotator:
    def __init__(self, interval_minutes=30):
        self._loop = None
        self._thread = None
        self._ready = threading.Event()

        self._api = None
        self._connector = None

        # Guards every connection-mutating operation. The API raises
        # ConcurrentConnectionsError if two things drive the tunnel at once, so
        # timer rotation and "rotate now" must never overlap.
        self._conn_lock = None

        self._rotate_task = None
        self.interval_minutes = interval_minutes
        # Jitter: when on, each cycle waits interval +/- JITTER_BAND instead of a
        # fixed period, so the rotation cadence is not trivially fingerprintable.
        self.jitter = False
        self.jitter_band = 0.35   # +/- 35% of the interval
        self.last_wait_seconds = None
        self.rotating = False
        self.next_rotation_at = None
        self.last_rotation_at = None
        self.busy = False
        self.rotation_count = 0

        self.public_ip = None
        self.public_ip_checked_at = None

        self.log = deque(maxlen=300)
        self.init_error = None

    # ---------- lifecycle ----------

    def start(self):
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="vpn-asyncio")
        self._thread.start()
        self._ready.wait(timeout=10)

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._conn_lock = asyncio.Lock()
        self._loop.call_soon(self._ready.set)
        self._loop.run_forever()

    def call(self, coro, timeout=180):
        """Bridge: run a coroutine on the background loop from a sync handler."""
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    def event(self, msg, kind="info"):
        self.log.appendleft({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "msg": msg,
            "kind": kind,
        })

    # ---------- proton api ----------

    async def _ensure(self):
        if self._connector is not None:
            return self._connector
        self._api = ProtonVPNAPI(
            client_type_metadata=ClientTypeMetadata(type="cli", version=CLIENT_VERSION)
        )
        if not self._api.is_user_logged_in():
            raise RuntimeError("not-logged-in")
        self._connector = await self._api.get_vpn_connector()
        return self._connector

    async def _server_name_for(self, server_id):
        if not server_id:
            return None
        try:
            for s in self._api.server_list:
                if s.id == server_id:
                    return s.name
        except Exception:
            pass
        return None

    # ---------- status ----------

    async def _status(self):
        st = {
            "logged_in": False,
            "account": None,
            "tier": None,
            "connected": False,
            "state": "Unknown",
            "server": None,
            "killswitch": None,
            "rotating": self.rotating,
            "interval_minutes": self.interval_minutes,
            # true length of the current cycle (differs from interval when
            # jitter is on) -- the countdown ring scales against this
            "cycle_seconds": self.last_wait_seconds or self.interval_minutes * 60,
            "jitter": self.jitter,
            "jitter_band": self.jitter_band,
            "next_rotation_in": None,
            "last_rotation_at": self.last_rotation_at,
            "rotation_count": self.rotation_count,
            "busy": self.busy,
            "public_ip": self.public_ip,
            "public_ip_checked_at": self.public_ip_checked_at,
            "error": None,
        }
        try:
            c = await self._ensure()
        except RuntimeError as e:
            if str(e) == "not-logged-in":
                st["error"] = "not-logged-in"
                return st
            st["error"] = str(e)
            return st
        except Exception as e:
            st["error"] = f"{type(e).__name__}: {e}"
            return st

        st["logged_in"] = True
        try:
            st["account"] = self._api.account_name
            st["tier"] = self._api.user_tier
        except Exception:
            pass
        st["connected"] = bool(c.is_connected)
        st["state"] = type(c.current_state).__name__
        st["server"] = await self._server_name_for(c.current_server_id)
        try:
            s = await c.get_settings()
            st["killswitch"] = KILLSWITCH_LABELS.get(s.killswitch, str(s.killswitch))
        except Exception:
            pass
        if self.rotating and self.next_rotation_at:
            st["next_rotation_in"] = max(0, int(self.next_rotation_at - time.time()))
        return st

    def status(self):
        try:
            return self.call(self._status(), timeout=30)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}", "logged_in": False,
                    "rotating": self.rotating,
                    "interval_minutes": self.interval_minutes,
                    "public_ip": self.public_ip}

    # ---------- public ip ----------

    @staticmethod
    def _fetch_ip_blocking():
        for url in IP_ECHOS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                return urllib.request.urlopen(req, timeout=8).read().decode().strip()
            except Exception:
                continue
        return None

    async def _check_ip(self, announce=True):
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, self._fetch_ip_blocking)
        if ip:
            self.public_ip = ip
            self.public_ip_checked_at = datetime.now().strftime("%H:%M:%S")
            if announce:
                self.event(f"Public IP: {ip}", "ok")
        else:
            if announce:
                self.event("Public IP lookup failed (no route?)", "err")
        return ip

    def check_ip(self):
        return self.call(self._check_ip(), timeout=60)

    # ---------- rotation ----------

    async def _wait_until(self, pred, timeout, label):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if pred():
                return True
            await asyncio.sleep(0.5)
        self.event(f"Timed out waiting for {label} ({timeout}s)", "err")
        return False

    def _pick_server(self, connector):
        """Lowest-load server the account's tier allows, excluding the current one."""
        tier = self._api.user_tier
        current = connector.current_server_id
        cands = [s for s in self._api.server_list
                 if s.tier <= tier and s.enabled and s.id != current]
        if not cands:
            return None
        pool = sorted(cands, key=lambda s: s.load)[:20]
        return random.choice(pool)

    async def _rotate(self):
        """Disconnect fully, then connect to a fresh server."""
        if self._conn_lock.locked():
            self.event("Rotation already in progress -- skipped", "warn")
            return False
        async with self._conn_lock:
            self.busy = True
            try:
                c = await self._ensure()
                target = self._pick_server(c)
                if target is None:
                    self.event("No eligible servers found", "err")
                    return False

                # Full teardown first: the API raises ConcurrentConnectionsError
                # if a new connection is started while one is still active.
                if c.is_connected or c.is_connection_active:
                    old = await self._server_name_for(c.current_server_id) or "current"
                    self.event(f"Disconnecting from {old}...")
                    await c.disconnect()
                    if not await self._wait_until(
                        lambda: not c.is_connected and not c.is_connection_active,
                        DISCONNECT_TIMEOUT, "disconnect",
                    ):
                        return False
                    self.event("Disconnected", "ok")

                self.event(f"Connecting to {target.name} (load {target.load}%)...")
                vpn_server = c.get_vpn_server(target, self._api.client_config)
                await c.connect(vpn_server, protocol="wireguard")
                if not await self._wait_until(lambda: c.is_connected,
                                              CONNECT_TIMEOUT, "connect"):
                    self.event(f"Connect to {target.name} failed", "err")
                    return False

                self.rotation_count += 1
                self.last_rotation_at = datetime.now().strftime("%H:%M:%S")
                self.event(f"Connected to {target.name}", "ok")
                await asyncio.sleep(2)
                await self._check_ip()
                return True
            except Exception as e:
                self.event(f"Rotation error: {type(e).__name__}: {e}", "err")
                return False
            finally:
                self.busy = False

    def rotate_now(self):
        return self.call(self._rotate(), timeout=200)

    async def _rotate_forever(self):
        try:
            while True:
                base = self.interval_minutes * 60
                if self.jitter:
                    lo, hi = base * (1 - self.jitter_band), base * (1 + self.jitter_band)
                    wait = max(30, random.uniform(lo, hi))
                else:
                    wait = base
                self.last_wait_seconds = int(wait)
                self.next_rotation_at = time.time() + wait
                # Sleep in slices so interval edits and stop take effect promptly.
                while time.time() < self.next_rotation_at:
                    await asyncio.sleep(1)
                await self._rotate()
        except asyncio.CancelledError:
            raise

    async def _start_rotation(self, rotate_immediately):
        if self._rotate_task and not self._rotate_task.done():
            return
        self.rotating = True
        self.event(f"Auto-rotation ON -- every {self.interval_minutes} min", "ok")
        if rotate_immediately:
            await self._rotate()
        self._rotate_task = asyncio.ensure_future(self._rotate_forever())

    def start_rotation(self, rotate_immediately=False):
        self.call(self._start_rotation(rotate_immediately), timeout=200)

    async def _stop_rotation(self):
        if self._rotate_task:
            self._rotate_task.cancel()
            try:
                await self._rotate_task
            except asyncio.CancelledError:
                pass
            self._rotate_task = None
        self.rotating = False
        self.next_rotation_at = None
        self.event("Auto-rotation OFF", "warn")

    def stop_rotation(self):
        self.call(self._stop_rotation(), timeout=30)

    async def _disconnect(self):
        async with self._conn_lock:
            self.busy = True
            try:
                c = await self._ensure()
                if not (c.is_connected or c.is_connection_active):
                    self.event("Already disconnected", "warn")
                    return True
                await c.disconnect()
                ok = await self._wait_until(
                    lambda: not c.is_connected and not c.is_connection_active,
                    DISCONNECT_TIMEOUT, "disconnect")
                self.event("Disconnected" if ok else "Disconnect timed out",
                           "ok" if ok else "err")
                await self._check_ip()
                return ok
            except Exception as e:
                self.event(f"Disconnect error: {type(e).__name__}: {e}", "err")
                return False
            finally:
                self.busy = False

    def disconnect(self):
        return self.call(self._disconnect(), timeout=120)

    async def _set_killswitch(self, mode):
        """Apply Proton's native kill switch (0 off / 1 on / 2 permanent).

        This is a real, root-free control: the privileged part is done by the
        Proton daemon, which already runs as root. The value is read back from
        the connector afterwards so the UI reflects what was actually applied.
        """
        async with self._conn_lock:
            try:
                c = await self._ensure()
                settings = await c.get_settings()
                settings.killswitch = mode
                await c.apply_settings(settings)
                confirmed = (await c.get_settings()).killswitch
                label = KILLSWITCH_LABELS.get(confirmed, str(confirmed))
                if confirmed == mode:
                    self.event(f"Kill switch -> {label}", "ok")
                    return True, label
                self.event(f"Kill switch did not apply (still {label})", "err")
                return False, label
            except Exception as e:
                self.event(f"Kill switch error: {type(e).__name__}: {e}", "err")
                return False, str(e)

    def set_killswitch(self, mode):
        return self.call(self._set_killswitch(mode), timeout=90)

    def set_interval(self, minutes):
        self.interval_minutes = minutes
        if self.rotating:
            self.next_rotation_at = time.time() + minutes * 60
        self.event(f"Interval set to {minutes} min")
