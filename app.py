"""Proton VPN rotator -- local web panel. Binds to 127.0.0.1 only."""
import proton_env  # noqa: F401  -- must be the first import

import argparse
import secrets
import sys

from flask import Flask, jsonify, render_template, request

import defence
from rotator import Rotator

HOST = "127.0.0.1"  # loopback only, never exposed to the network
DEFAULT_PORT = 8737

app = Flask(__name__)
rot = Rotator()


def _rot_state():
    """Cheap, non-blocking view of the engine for the defence watcher.

    Deliberately reads the Rotator's own attributes rather than calling
    rot.status(), which round-trips through the Proton API and would stall the
    watcher thread every poll.
    """
    return {
        "public_ip": rot.public_ip,
        "rotation_count": rot.rotation_count,
        "busy": rot.busy,
        "rotating": rot.rotating,
    }


def _refresh_ip():
    """Silent exit-IP re-check for the watcher (no log spam every cycle)."""
    return rot.call(rot._check_ip(announce=False), timeout=60)


dfn = defence.Defence(
    trigger_cb=lambda: rot.rotate_now(),
    state_cb=_rot_state,
    refresh_ip_cb=_refresh_ip,
)


@app.after_request
def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------
# request guard
# --------------------------------------------------------------------------
# Binding to loopback is not an access control. Any page open in the browser
# can POST to 127.0.0.1, and a DNS-rebinding host can make its own name resolve
# here so the browser treats it as reachable. That was harmless while every
# root action did nothing but return a command string for the user to read.
# It stops being harmless the moment an endpoint executes through passwordless
# sudo -- a drive-by POST would be able to arm or tear down firewall rules.
#
# Three checks, each covering what the others do not:
#   * Host must name loopback -- this is what actually defeats DNS rebinding,
#     since a rebound request still carries the attacker's hostname.
#   * Origin/Referer, when the browser sends one, must name loopback too.
#   * State-changing methods must carry a per-process token. A foreign page
#     cannot read it (same-origin policy blocks reading our HTML), and the
#     custom header forces a CORS preflight that we never answer.
CSRF_TOKEN = secrets.token_urlsafe(32)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _host_ok(value):
    """True when a Host/Origin/Referer authority names loopback (any port)."""
    if not value:
        return False
    authority = value.split("//")[-1].split("/")[0]
    if authority.startswith("["):          # [::1]:8737
        host = authority.split("]")[0] + "]"
    else:
        host = authority.split(":")[0]
    return host in _LOOPBACK_HOSTS


@app.before_request
def _guard():
    if not request.path.startswith("/api/"):
        return None
    if not _host_ok(request.headers.get("Host")):
        return jsonify({"ok": False, "msg": "rejected: non-loopback Host"}), 403
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if origin and not _host_ok(origin):
        return jsonify({"ok": False, "msg": "rejected: cross-origin request"}), 403
    if request.method != "GET":
        token = request.headers.get("X-Revolver-Token", "")
        if not secrets.compare_digest(token, CSRF_TOKEN):
            return jsonify({"ok": False, "msg": "rejected: bad or missing token"}), 403
    return None


@app.route("/")
def index():
    return render_template("index.html", interval=rot.interval_minutes,
                           csrf_token=CSRF_TOKEN)


@app.route("/api/status")
def api_status():
    st = rot.status()
    st["log"] = list(rot.log)[:80]
    return jsonify(st)


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    if rot.busy:
        return jsonify({"ok": False, "msg": "busy"}), 409
    return jsonify({"ok": bool(rot.rotate_now())})


@app.route("/api/rotation", methods=["POST"])
def api_rotation():
    data = request.get_json(silent=True) or {}
    if data.get("on"):
        try:
            mins = int(data.get("interval", rot.interval_minutes))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "msg": "bad interval"}), 400
        if not 1 <= mins <= 1440:
            return jsonify({"ok": False, "msg": "interval must be 1-1440"}), 400
        rot.interval_minutes = mins
        rot.start_rotation(rotate_immediately=bool(data.get("now")))
    else:
        rot.stop_rotation()
    return jsonify({"ok": True})


@app.route("/api/interval", methods=["POST"])
def api_interval():
    data = request.get_json(silent=True) or {}
    try:
        mins = int(data["interval"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"ok": False, "msg": "bad interval"}), 400
    if not 1 <= mins <= 1440:
        return jsonify({"ok": False, "msg": "interval must be 1-1440"}), 400
    rot.set_interval(mins)
    return jsonify({"ok": True})


@app.route("/api/checkip", methods=["POST"])
def api_checkip():
    return jsonify({"ok": True, "ip": rot.check_ip()})


# --------------------------------------------------------------------------
# defence layer
# --------------------------------------------------------------------------

# Root-needing toggles are applied through defence.apply_toggle(), which runs
# only literal argv from defence.SUDO_ALLOWED via `sudo -n` -- no shell, no
# password, nothing interpolated. Anything deliberately left off that allowlist
# (ufw disable, re-enabling IPv6, resolv.conf) comes back with needs_sudo set
# and the exact command for the user to run, exactly as before.
ROOT_TOGGLES = ("lockdown", "ks_enforce_nft", "portscan", "ipv6_os",
                "mac_random", "force_dns")

# Toggles the panel can genuinely apply itself (no root needed).
LOCAL_TOGGLES = ("arp_watch", "capture_detect", "notifications",
                 "auto_rotate_trigger", "auto_lockdown_lock", "jitter")


@app.route("/api/defence")
def api_defence():
    snap = dfn.snapshot()
    snap["toggles"]["jitter"] = rot.jitter
    snap["jitter_band"] = rot.jitter_band
    return jsonify(snap)


@app.route("/api/toggle", methods=["POST"])
def api_toggle():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    want = bool(data.get("on"))

    if name in LOCAL_TOGGLES:
        if name == "jitter":
            rot.jitter = want
            rot.event(f"Rotation jitter {'ON' if want else 'OFF'}"
                      + (f" (+/-{int(rot.jitter_band*100)}%)" if want else ""),
                      "ok" if want else "warn")
        else:
            dfn.toggles[name] = want
            dfn.alert(f"{name.replace('_',' ')} {'ON' if want else 'OFF'}",
                      "ok" if want else "warn")
        return jsonify({"ok": True, "applied": True, "state": want})

    if name in ROOT_TOGGLES:
        res = defence.apply_toggle(name, want)
        if res.get("applied"):
            dfn.alert(res.get("msg", f"{name} applied"), "ok" if want else "warn")
        elif not res.get("ok"):
            dfn.alert(f"{name}: {res.get('msg')} -- {res.get('detail', '')}".strip(),
                      "err")
        return jsonify(res)

    return jsonify({"ok": False, "msg": "unknown toggle"}), 400


@app.route("/api/tripwire")
def api_tripwire():
    """Read-only tripwire view: the startup baseline and the drift from it.

    GET only. It runs no command that changes anything -- /proc/modules, ss and
    /etc/resolv.conf reads -- so there is nothing here to trigger, only to read.
    Like every /api/* route it sits behind _guard(), which requires a loopback
    Host and rejects a cross-origin Origin/Referer.
    """
    return jsonify({
        "ok": True,
        "baseline": dfn.tripwire.baseline,
        "taken_at": dfn.tripwire.taken_at,
        "drift": dfn._drift,
    })


@app.route("/api/audit")
def api_audit():
    """Tail of the append-only root-action feed (read-only)."""
    try:
        n = int(request.args.get("n", 100))
    except (TypeError, ValueError):
        n = 100
    return jsonify({"ok": True, **defence.audit_tail(max(1, min(n, 1000)))})


@app.route("/api/killswitch", methods=["POST"])
def api_killswitch():
    """Proton's own kill switch -- real, applied through the API, no root."""
    data = request.get_json(silent=True) or {}
    try:
        mode = int(data.get("mode", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "msg": "bad mode"}), 400
    if mode not in (0, 1, 2):
        return jsonify({"ok": False, "msg": "mode must be 0, 1 or 2"}), 400
    ok, msg = rot.set_killswitch(mode)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    if rot.busy:
        return jsonify({"ok": False, "msg": "busy"}), 409
    return jsonify({"ok": bool(rot.disconnect())})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    rot.start()
    dfn.start()
    rot.event("Panel started")
    st = rot.status()
    if st.get("error") == "not-logged-in":
        rot.event("Not signed in -- open the Proton VPN app and sign in", "err")
    elif st.get("error"):
        rot.event(f"Startup warning: {st['error']}", "err")
    else:
        rot.event(f"Session: {st.get('account')} (tier {st.get('tier')})")

    print(f"  Proton VPN rotator -> http://{HOST}:{args.port}", file=sys.stderr)
    app.run(host=HOST, port=args.port, threaded=True, debug=False,
            use_reloader=False)


if __name__ == "__main__":
    main()
