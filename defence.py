"""Defence-layer system state readers, watchers and action planning.

Design rules (deliberate, do not "improve" away):

* NOTHING here ever embeds, prompts for, or stores a password. Any action that
  needs root is returned as an exact command string for the user to run.
* Every toggle's reported state is READ BACK FROM THE SYSTEM. Where the truth
  cannot be read without root (ufw, nftables), the state is reported as
  "unknown -- needs sudo" rather than echoing what the UI last clicked. A switch
  must never show "on" while the underlying rule may not be applied.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from collections import deque
from datetime import datetime

# Fallbacks only -- the live values are detected (see primary_iface /
# tunnel_iface). Hard-coding them broke the moment the tunnel came up and the
# default route moved off the physical NIC.
PRIMARY_IFACE = "enp4s0"
TUNNEL_IFACE = "proton0"

# Virtual/managed links that are never the "primary NIC". Proton's kill switch
# adds "pvpnksintrf0" (a dummy with a link/ether and a *better* default-route
# metric than the real NIC) and "ipv6leakintrf0"; without these the route scan
# below picked the dummy and every MAC action aimed at Proton's kill switch
# instead of the physical card.
_VIRTUAL_PREFIXES = ("proton", "pvpn", "ipv6leak", "wg", "tun", "tap", "docker",
                     "virbr", "br-", "veth", "vmnet", "nordlynx", "ipsec", "ppp",
                     "dummy")
# Names a VPN tunnel device plausibly takes, most-specific first.
_TUNNEL_PREFIXES = ("proton", "wg", "nordlynx", "ipsec", "tun")

SCAN_LOG_PREFIX = "REVOLVER-SCAN"

# Loopback / link-local / multicast noise we don't flag as inbound exposure.
_LOCAL_PREFIXES = ("127.", "::1", "0.0.0.0", "*", "[::]", "224.", "239.", "169.254.")


def _run(cmd, timeout=6):
    """Run a command, never raising. Returns (rc, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "not-installed"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:  # pragma: no cover
        return 1, str(e)


def have(tool):
    return shutil.which(tool) is not None


# --------------------------------------------------------------------------
# sudo allowlist
# --------------------------------------------------------------------------
# Every entry below must match /etc/sudoers.d/revolver byte for byte. These are
# literal argv lists: nothing from an HTTP request, the network or the
# filesystem is ever interpolated into them, and they are never handed to a
# shell. That -- not the sudoers file alone -- is what makes argument injection
# impossible, because sudo compares argv element by element.
#
# Deliberately ABSENT, and left manual (see SUDO_MANUAL):
#   * `ufw disable`        -- tearing the firewall down passwordlessly is the
#                             one thing an attacker on this account would want.
#   * re-enabling IPv6     -- same reasoning, un-hardening direction.
#   * anything touching resolv.conf -- NetworkManager owns it now.
#   * `nmcli con modify`   -- needs no root here at all (polkit already grants
#                             settings.modify.system to this user).
SUDO_ALLOWED = {
    "portscan_arm":    ["/usr/sbin/nft", "-f", "/etc/revolver/portscan.nft"],
    "portscan_disarm": ["/usr/sbin/nft", "delete", "table", "inet", "revolver"],
    "portscan_read":   ["/usr/sbin/nft", "list", "table", "inet", "revolver"],
    "ks_arm":          ["/usr/sbin/nft", "-f",
                        "/etc/revolver/killswitch-proton0.nft"],
    "ks_disarm":       ["/usr/sbin/nft", "delete", "table", "inet", "revolver_ks"],
    "ks_read":         ["/usr/sbin/nft", "list", "table", "inet", "revolver_ks"],
    "ufw_read":        ["/usr/sbin/ufw", "status", "verbose"],
    "ufw_deny_in":     ["/usr/sbin/ufw", "default", "deny", "incoming"],
    "ufw_allow_out":   ["/usr/sbin/ufw", "default", "allow", "outgoing"],
    "ufw_enable":      ["/usr/sbin/ufw", "--force", "enable"],
    "ipv6_disable":    ["/usr/sbin/sysctl", "-w",
                        "net.ipv6.conf.all.disable_ipv6=1",
                        "net.ipv6.conf.default.disable_ipv6=1"],
}

# Actions we refuse to allowlist, with the command the UI shows instead.
SUDO_MANUAL = {
    "ufw_disable":  "sudo ufw disable",
    "ipv6_enable":  ("sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 "
                     "net.ipv6.conf.default.disable_ipv6=0"),
}


# --------------------------------------------------------------------------
# append-only audit feed
# --------------------------------------------------------------------------
AUDIT_DIR = os.path.expanduser("~/.local/state/revolver")
AUDIT_LOG = os.path.join(AUDIT_DIR, "actions.log")

# `chattr +a` makes a file append-only for root as well; O_APPEND is what keeps
# writing to it legal under that flag. It is also what makes concurrent writes
# from the Flask worker and the watcher thread atomic per line, so the feed
# cannot interleave into corrupt JSON.
AUDIT_CHATTR_CMD = f"sudo chattr +a {AUDIT_LOG}"


def audit(action, ok=None, argv=None, detail=None, source="panel"):
    """Append one JSON object to the root-action feed. Never raises.

    Called at the moment a privileged command runs, with the argv that actually
    ran -- not with what the UI intended -- so the feed records what happened.
    """
    rec = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "ok": ok,
        "argv": list(argv) if argv else None,
        "detail": (detail or "")[:400] or None,
        "source": source,
    }
    line = json.dumps(rec, sort_keys=True) + "\n"
    try:
        os.makedirs(AUDIT_DIR, exist_ok=True)
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        # A read-only or append-only-locked home must never take the panel down.
        pass
    return rec


def audit_tail(limit=100):
    """Most recent entries, newest first. Unparseable lines are surfaced, not
    silently dropped -- a corrupt line is itself worth seeing."""
    try:
        with open(AUDIT_LOG, "r", errors="replace") as f:
            lines = f.readlines()[-max(1, min(limit, 1000)):]
    except OSError:
        return {"path": AUDIT_LOG, "exists": os.path.exists(AUDIT_LOG),
                "entries": [], "chattr_cmd": AUDIT_CHATTR_CMD,
                "append_only": False}
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except ValueError:
            out.append({"ts": "?", "action": "UNPARSEABLE LINE",
                        "detail": ln[:200], "ok": False})
    out.reverse()
    return {"path": AUDIT_LOG, "exists": True, "entries": out,
            "chattr_cmd": AUDIT_CHATTR_CMD, "append_only": _audit_append_only()}


def _audit_append_only():
    """Is the feed chattr +a? Readable without root via lsattr."""
    rc, out = _run(["lsattr", "-d", AUDIT_LOG], timeout=4)
    if rc != 0:
        return None
    flags = out.split()[0] if out.split() else ""
    return "a" in flags


def sudo_run(key, timeout=15):
    """Run one allowlisted command through sudo. Returns (rc, output).

    `-n` is non-negotiable: it makes sudo fail with a message rather than ever
    blocking a Flask worker on a password prompt. No password is read, stored
    or passed anywhere in this process.

    Every call is audited -- including refusals -- so the feed is a record of
    attempts, not just successes.
    """
    argv = SUDO_ALLOWED.get(key)
    if argv is None:
        audit(key, ok=False, detail="not on the sudo allowlist")
        return 126, f"refused: {key} is not on the sudo allowlist"
    full = ["sudo", "-n"] + list(argv)
    rc, out = _run(full, timeout=timeout)
    # The readiness probe runs on every UI refresh; auditing it would bury the
    # real actions under heartbeat noise.
    if key not in ("portscan_read", "ks_read", "ufw_read"):
        audit(key, ok=(rc == 0), argv=full, detail=out.strip())
    return rc, out


_sudo_probe = {"ts": 0.0, "ok": False}


# sudo's refusals, as it words them. Matched instead of trusting an exit code.
_SUDO_REFUSALS = ("password is required", "a terminal is required",
                  "not allowed to execute", "may not run", "is not in the sudoers")


def sudo_ready(max_age=30):
    """Is /etc/sudoers.d/revolver installed and PASSWORDLESS for this user?

    `sudo -l <cmd>` is not usable here: this account is in the sudo group, so
    every command is "allowed" -- just not without a password. It answered yes
    with no allowlist installed at all. So probe by actually running the
    harmless read (`nft list table`) under `-n` and looking at what sudo says:
    a refusal means not ready, anything else (including nft's own "no such
    table") means sudo let the command through.
    """
    now = time.time()
    if now - _sudo_probe["ts"] < max_age:
        return _sudo_probe["ok"]
    rc, out = _run(["sudo", "-n"] + SUDO_ALLOWED["portscan_read"], timeout=6)
    low = out.lower()
    ok = not any(r in low for r in _SUDO_REFUSALS)
    _sudo_probe.update(ts=now, ok=ok)
    return ok


def tools_state():
    """Which external tools exist. A missing tool is stated plainly in the UI
    rather than letting a control fail silently."""
    return {t: have(t) for t in
            ("nft", "ufw", "ethtool", "macchanger", "notify-send", "nmcli",
             "gdbus", "journalctl", "ip", "ss", "sysctl")}


def _is_physical(name):
    """True only for a link backed by real hardware.

    /sys/class/net/<dev>/device exists for a driver-bound NIC and for nothing
    else -- dummy, wireguard, bridge and veth devices all lack it. This is the
    load-bearing check; the name prefixes above are only a fast pre-filter, and
    a name list alone would keep losing to whatever a VPN client invents next.
    """
    return os.path.exists(f"/sys/class/net/{name}/device")


def _links():
    """[(name, is_ether, is_up)] for every link."""
    rc, out = _run(["ip", "-o", "link", "show"])
    res = []
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r"\d+:\s+([^:@]+)", line)
        if not m:
            continue
        res.append((m.group(1).strip(),
                    "link/ether" in line,
                    "state UP" in line))
    return res


def primary_iface():
    """The physical NIC carrying traffic.

    Taken from the default route, but skipping the tunnel: once the VPN is up
    the default route points at proton0, and that device has no MAC to
    randomize.
    """
    links = _links()
    phys = {n for n, ether, _ in links
            if ether and n != "lo" and not n.startswith(_VIRTUAL_PREFIXES)
            and _is_physical(n)}
    rc, out = _run(["ip", "route", "show", "default"])
    for dev in re.findall(r"dev (\S+)", out):
        if dev in phys:
            return dev
    up = [n for n, ether, is_up in links
          if ether and is_up and n in phys]
    if up:
        return up[0]
    return sorted(phys)[0] if phys else PRIMARY_IFACE


def tunnel_iface():
    """The live tunnel device, or None when no tunnel is up."""
    names = [n for n, _, _ in _links()
             if n.startswith(_TUNNEL_PREFIXES) and n != "lo"]
    for pref in _TUNNEL_PREFIXES:
        for n in names:
            if n.startswith(pref):
                return n
    return None


def nm_connection_for(iface):
    """Active NetworkManager profile name owning an interface (or None)."""
    if not have("nmcli"):
        return None
    rc, out = _run(["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"])
    if rc != 0:
        return None
    for line in out.splitlines():
        # DEVICE is the last field; a profile NAME may itself contain ":"
        name, _, dev = line.rpartition(":")
        if dev == iface and name:
            return name
    return None


# --------------------------------------------------------------------------
# read-only state
# --------------------------------------------------------------------------

def ipv6_state():
    """OS-level IPv6, readable without root; writing needs sudo."""
    rc, out = _run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"])
    disabled = out.strip() == "1" if rc == 0 else None
    return {
        "readable": rc == 0,
        "disabled": disabled,
        "enable_cmd": "sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 "
                      "net.ipv6.conf.default.disable_ipv6=0",
        "disable_cmd": "sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 "
                       "net.ipv6.conf.default.disable_ipv6=1",
    }


def mac_state():
    iface = primary_iface()
    rc, out = _run(["ip", "-o", "link", "show", iface])
    mac = None
    m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    if m:
        mac = m.group(1)
    permanent = None
    rc2, out2 = _run(["ethtool", "-P", iface]) if have("ethtool") else (1, "")
    m2 = re.search(r"([0-9a-f:]{17})", out2)
    if m2:
        permanent = m2.group(1)
    con = nm_connection_for(iface)
    # NetworkManager owns this link, so change it through NM rather than
    # `ip link` (NM would revert that on the next activation). The profile name
    # is read live -- it is not always "Wired connection 1".
    argv = None
    if con:
        kind = ("802-11-wireless" if iface.startswith(("wl", "wlan"))
                else "802-3-ethernet")
        # No sudo and no sudoers entry: polkit already grants this user
        # settings.modify.system + network-control, so nmcli does this
        # unprivileged. Allowlisting `nmcli con modify` would have been the
        # single widest entry in the file for no gain -- it can set any
        # property on any profile.
        argv = {
            "random": [["nmcli", "con", "modify", con,
                        f"{kind}.cloned-mac-address", "random"],
                       ["nmcli", "con", "up", con]],
            "permanent": [["nmcli", "con", "modify", con,
                           f"{kind}.cloned-mac-address", "permanent"],
                          ["nmcli", "con", "up", con]],
        }
        rnd = (f"nmcli con modify {shlex.quote(con)} {kind}.cloned-mac-address random "
               f"&& nmcli con up {shlex.quote(con)}")
        rst = (f"nmcli con modify {shlex.quote(con)} {kind}.cloned-mac-address permanent "
               f"&& nmcli con up {shlex.quote(con)}")
    else:
        rnd = rst = None
    return {
        "iface": iface,
        "nm_connection": con,
        "mac": mac,
        "permanent": permanent,
        "randomized": bool(permanent and mac and permanent != mac),
        "randomize_cmd": rnd or (
            f"# no active NetworkManager profile found for {iface}"),
        "restore_cmd": rst or (
            f"# no active NetworkManager profile found for {iface}"),
        "argv": argv,
        "needs_sudo": False,
        "macchanger": have("macchanger"),
        "nmcli": have("nmcli"),
        "ethtool": have("ethtool"),
    }


NM_BIN = "/usr/sbin/NetworkManager"

# The durable fix for this box. Ubuntu ships dns=systemd-resolved in
# /usr/lib/NetworkManager/conf.d/10-dns-resolved.conf, but systemd-resolved is
# disabled here -- so NetworkManager hands DNS to a daemon that never answers
# and deliberately never writes /etc/resolv.conf, leaving whatever static file
# is on disk. The 90- prefix matters: conf.d snippets merge in filename order
# and 00- would sort *before* the file it needs to override.
NM_DNS_FIX = (
    "sudo cp -a /etc/resolv.conf \"/etc/resolv.conf.revolver-backup-$(date "
    "+%Y%m%d-%H%M%S)\" && "
    "printf '[main]\\ndns=default\\nrc-manager=file\\n' | "
    "sudo tee /etc/NetworkManager/conf.d/90-revolver-dns.conf >/dev/null && "
    "NetworkManager --print-config | head -20   "
    "# confirm dns=default, THEN: "
    "sudo systemctl reload NetworkManager && sudo nmcli general reload dns-rc")


def _nm_dns_config():
    """NetworkManager's effective dns= and rc-manager= (no root needed).

    A commented line in --print-config means "left at the default", so only
    uncommented keys are read back.
    """
    if not os.path.exists(NM_BIN):
        return None, None
    rc, out = _run([NM_BIN, "--print-config"], timeout=8)
    if rc != 0:
        return None, None
    dns = rc_manager = None
    for line in out.splitlines():
        t = line.strip()
        if dns is None and t.startswith("dns="):
            dns = t.split("=", 1)[1].strip()
        elif rc_manager is None and t.startswith("rc-manager="):
            rc_manager = t.split("=", 1)[1].strip()
    return dns, rc_manager


def _resolv_manager():
    """Who owns /etc/resolv.conf, read off the file itself."""
    try:
        head = open("/etc/resolv.conf").readline()
    except OSError:
        return "unreadable"
    if "NetworkManager" in head:
        return "NetworkManager"
    if "resolvconf" in head:
        return "resolvconf"
    if "systemd-resolved" in head or "stub-resolv" in head:
        return "systemd-resolved"
    return "static"


def dns_state():
    """Detect DNS leak: is the system resolver the tunnel's DNS or not?"""
    resolvers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        resolvers.append(parts[1])
    except Exception:
        pass

    tun = tunnel_iface()
    rc, out = _run(["nmcli", "dev", "show", tun]) if tun else (1, "")
    tunnel_dns = re.findall(r"IP4\.DNS\[\d+\]:\s+(\S+)", out) if rc == 0 else []

    resolved_running = _run(
        ["systemctl", "is-active", "systemd-resolved"])[1].strip() == "active"
    nm_dns, nm_rc = _nm_dns_config()
    manager = _resolv_manager()
    symlink = os.path.islink("/etc/resolv.conf")
    static = manager == "static" and not symlink

    # 0.0.0.0 is what Proton's kill-switch profile advertises on purpose: a
    # black-hole resolver, so a tunnel drop fails closed instead of falling
    # back to the LAN in cleartext. That is the desired state, not a leak.
    blackholed = bool(resolvers) and all(r == "0.0.0.0" for r in resolvers)

    # With no tunnel up there is nothing to leak *out of* -- report unknown
    # rather than a reassuring "not leaking".
    if blackholed:
        leaking = False
    elif not tun or not tunnel_dns:
        leaking = None
    else:
        leaking = bool(resolvers) and not any(r in tunnel_dns for r in resolvers)

    # The fix depends on WHY it leaks, so it is derived rather than canned.
    if static and nm_dns == "systemd-resolved" and not resolved_running:
        fix = NM_DNS_FIX
        note = ("NetworkManager is set to dns=systemd-resolved but that service is "
                "disabled here, so nothing writes /etc/resolv.conf and the static "
                "file wins. Give NetworkManager the file and DNS follows the tunnel.")
    elif static:
        fix = NM_DNS_FIX
        note = ("/etc/resolv.conf is a static root-owned file, so NetworkManager's "
                "tunnel DNS is being ignored.")
    elif manager == "NetworkManager":
        fix = "sudo nmcli general reload dns-rc"
        note = ("NetworkManager owns /etc/resolv.conf; it rewrites it on every "
                "connection change, so DNS follows the tunnel.")
    else:
        fix = "sudo nmcli general reload dns-rc"
        note = f"/etc/resolv.conf is managed by {manager}."

    return {
        "tunnel_iface": tun,
        "resolvers": resolvers,
        "tunnel_dns": tunnel_dns,
        "leaking": leaking,
        "blackholed": blackholed,
        "resolved_running": resolved_running,
        "nm_dns_mode": nm_dns,
        "nm_rc_manager": nm_rc or "default",
        "managed_by": manager,
        "symlink": symlink,
        "static_resolv": static,
        # No sudo entry backs this: resolv.conf belongs to NetworkManager, and
        # a `tee` into it would be reverted on the next connection change.
        "needs_sudo": True,
        "fix_cmd": fix,
        "note": note,
    }


def gateway_state():
    rc, out = _run(["ip", "route", "show", "default"])
    gw = None
    m = re.search(r"default via (\S+)", out)
    if m:
        gw = m.group(1)
    mac = None
    if gw:
        rc2, out2 = _run(["ip", "neigh", "show", gw])
        m2 = re.search(r"lladdr ([0-9a-f:]{17})", out2)
        if m2:
            mac = m2.group(1)
    return {"gateway": gw, "mac": mac}


def firewall_state():
    """ufw/nft cannot be read at all without root -- report that honestly."""
    st = {
        "ufw_installed": have("ufw"),
        "nft_installed": have("nft"),
        "readable": False,
        "active": None,          # None == genuinely unknown, never assumed
        "default_incoming": None,
        "reason": None,
        "status_cmd": "sudo ufw status verbose",
    }
    if not st["ufw_installed"]:
        st["reason"] = "ufw is not installed"
        return st
    # Unprivileged `ufw status` always fails ("You need to be root"), which is
    # why this card read "unknown" forever. Read it through the allowlist.
    rc, out = _run(["ufw", "status"])
    if rc != 0 or "need to be root" in out.lower():
        rc, out = sudo_run("ufw_read")
    if rc != 0 or "need to be root" in out.lower():
        st["reason"] = ("ufw status requires root; install /etc/sudoers.d/revolver "
                        "to let the panel read it")
        return st
    st["readable"] = True
    st["active"] = "Status: active" in out
    m = re.search(r"Default:\s+(\w+)\s+\(incoming\)", out)
    if m:
        st["default_incoming"] = m.group(1)
    return st


# ss prints a leading Netid column only when several protocols are listed
# (-tulnp); with -tnp the first column is the state instead. Parsing by fixed
# index gets this wrong one way or the other -- which silently emptied the
# connection monitor and printed Send-Q values as port numbers.
_SS_NETIDS = {"tcp", "udp", "raw", "icmp", "sctp", "dccp", "unix",
              "nl", "vsock", "xdp", "tipc", "p_raw", "p_dgr"}


def _parse_ss(args):
    rc, out = _run(["ss", "-H"] + args)
    rows = []
    if rc != 0:
        # -H (no header) is not in ancient iproute2; fall back to trimming it.
        rc, out = _run(["ss"] + args)
        if rc != 0:
            return rows
        out = "\n".join(out.splitlines()[1:])
    for line in out.splitlines():
        toks = line.split()
        if len(toks) < 4:
            continue
        proc = ""
        if toks[-1].startswith("users:("):
            pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', toks[-1])
            if pm:
                proc = f"{pm.group(1)}/{pm.group(2)}"
            toks = toks[:-1]
        if len(toks) < 4:
            continue
        if toks[0].lower() in _SS_NETIDS:
            netid, state = toks[0], toks[1]
        else:
            netid, state = "tcp", toks[0]
        # Address columns are the last two, whichever shape the row has.
        local, peer = toks[-2], toks[-1]
        rows.append({"netid": netid, "state": state,
                     "local": local, "peer": peer, "proc": proc})
    return rows


def _addr_of(hostport):
    """Split 'ip:port' handling IPv6 brackets and iface%suffixes."""
    hp = hostport
    if hp.startswith("["):
        addr, _, port = hp.rpartition("]:")
        return addr.lstrip("["), port
    addr, _, port = hp.rpartition(":")
    return addr.split("%")[0], port


def listening_ports():
    """Listening sockets, flagged public vs localhost."""
    out = []
    for r in _parse_ss(["-tulnp"]):
        addr, port = _addr_of(r["local"])
        public = not (addr.startswith("127.") or addr in ("::1",)
                      or addr.startswith("169.254."))
        # 0.0.0.0 / :: mean "all interfaces" -- that is the exposed case.
        wildcard = addr in ("0.0.0.0", "::", "*", "")
        out.append({"proto": r["netid"], "addr": addr, "port": port,
                    "proc": r["proc"], "public": public, "wildcard": wildcard})
    out.sort(key=lambda x: (not x["wildcard"], x["proto"], x["port"]))
    return out


def connections(listen_ports=None):
    """Established TCP connections, flagging non-loopback remotes.

    `inbound` marks a connection someone else opened TO us -- our local port is
    one we listen on, or the socket is still half-open (SYN-RECV). Outbound
    sockets use an ephemeral local port and are ordinary browsing traffic; the
    auto-rotate trigger must not fire on those or every visited website would
    rotate the tunnel.
    """
    if listen_ports is None:
        listen_ports = {p["port"] for p in listening_ports()}
    out = []
    for r in _parse_ss(["-tnp"]):
        if r["state"] not in ("ESTAB", "SYN-SENT", "SYN-RECV", "CLOSE-WAIT"):
            continue
        raddr, rport = _addr_of(r["peer"])
        laddr, lport = _addr_of(r["local"])
        local = raddr.startswith(_LOCAL_PREFIXES) or raddr.startswith("192.168.")
        inbound = r["state"] == "SYN-RECV" or lport in listen_ports
        # laddr is the load-bearing field for the tripwire: a socket's source
        # address tells you which interface it leaves by, with no per-packet
        # route lookup.
        out.append({"remote": raddr, "rport": rport, "laddr": laddr,
                    "lport": lport, "proc": r["proc"], "state": r["state"],
                    "local": local, "inbound": inbound})
    out.sort(key=lambda x: (x["local"], not x["inbound"]))
    return out


def syn_backlog():
    """Half-open (SYN-RECV) sockets -- a root-free SYN-flood signal."""
    rc, out = _run(["ss", "-tan", "state", "syn-recv"])
    if rc != 0:
        return None
    return max(0, len(out.strip().splitlines()) - 1)


def scan_events(since="-30 min", limit=40):
    """Scan hits logged by the nft rule, read from the kernel journal.

    The ruleset itself needs root to list, but journald exposes the kernel log
    to members of the `adm`/`systemd-journal` group -- so when the rule IS armed
    and firing, this is real evidence, readable without sudo. The reverse does
    not hold: no lines means "no hits seen", not "not armed".
    """
    if not have("journalctl"):
        return {"readable": False, "reason": "journalctl is not installed",
                "events": [], "count": 0}
    rc, out = _run(["journalctl", "-k", "--since", since, "-o", "short-iso",
                    "--no-pager"], timeout=8)
    if rc != 0:
        return {"readable": False,
                "reason": "kernel log not readable by this user "
                          "(needs the adm or systemd-journal group)",
                "events": [], "count": 0}
    evs = []
    for line in out.splitlines():
        if SCAN_LOG_PREFIX not in line:
            continue
        src = re.search(r"SRC=(\S+)", line)
        dpt = re.search(r"DPT=(\S+)", line)
        proto = re.search(r"PROTO=(\S+)", line)
        stamp = line.split(" ", 1)[0]
        evs.append({
            "ts": stamp[11:19] if len(stamp) >= 19 else stamp,
            "src": src.group(1) if src else "?",
            "dport": dpt.group(1) if dpt else "?",
            "proto": proto.group(1) if proto else "TCP",
        })
    return {"readable": True, "reason": None,
            "events": evs[-limit:], "count": len(evs)}


def portscan_state(scan=None):
    """State of the scan-detection rule.

    The ruleset cannot be listed without root, so `armed` is normally unknown.
    The one case it can be answered honestly is when the rule has logged a hit:
    that proves it is loaded. Absence of hits proves nothing either way.
    """
    # The watcher already polls the journal on its own cadence; reuse that
    # rather than shelling out to journalctl on every UI refresh.
    if scan is None:
        scan = scan_events()

    # Preferred: ask the kernel directly through the allowlisted read. That is
    # the only answer that can say "not armed" truthfully.
    armed, readable, reason = None, False, None
    if sudo_ready():
        rc, out = sudo_run("portscan_read")
        if rc == 0:
            armed, readable = True, True
            reason = "read from the live ruleset"
        elif "No such file or directory" in out or "does not exist" in out:
            armed, readable = False, True
            reason = "read from the live ruleset: table is not loaded"
        else:
            reason = f"nft read failed: {out.strip()[:120]}"
    if not readable:
        # Fallback: a logged hit proves the rule is loaded. Absence proves
        # nothing either way, so that stays None rather than False.
        armed = True if scan.get("count") else None
        reason = reason or (
            "rule confirmed armed: hits present in the kernel log" if armed else
            "nftables ruleset requires root to read; install "
            "/etc/sudoers.d/revolver, or wait for the rule's first logged hit")
    return {
        "nft_installed": have("nft"),
        "readable": readable or scan["count"] > 0,
        "armed": armed,
        "reason": reason,
        "scan": scan,
        "syn_backlog": syn_backlog(),
        "sudo_ready": sudo_ready(),
        "status_cmd": "sudo nft list table inet revolver",
        # Fallback text only, for a box without the allowlist installed. The
        # panel itself loads /etc/revolver/portscan.nft instead: the rule body
        # lives in a root-owned file so no quoting survives a shell, and there
        # is nothing for the panel to interpolate into it.
        "arm_cmd": (
            "sudo nft add table inet revolver && "
            "sudo nft add chain inet revolver input '{ type filter hook input priority -10 ; }' && "
            "sudo nft add rule inet revolver input tcp flags syn "
            "limit rate over 20/second burst 40 packets "
            "log prefix '\"REVOLVER-SCAN \"' drop"),
        "disarm_cmd": "sudo nft delete table inet revolver",
    }


def lockdown_cmds():
    return {
        "on": "sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable",
        "off": "sudo ufw disable",
    }


def killswitch_enforce_cmds():
    """Interface-bound egress lock: drop anything not leaving the tunnel.

    The rule is bound to the tunnel device that is actually up. Handing out a
    command naming a device that does not exist would produce a policy-drop
    chain with no accept rule -- i.e. it would cut the machine off the network.
    """
    tun = tunnel_iface()
    if not tun:
        return {
            "tunnel": None,
            "on": ("# no tunnel interface is up -- connect the VPN first.\n"
                   "# Arming an output policy-drop chain with no tunnel to "
                   "accept on would cut off all networking."),
            "off": "sudo nft delete table inet revolver_ks",
        }
    return {
        "tunnel": tun,
        "on": ("sudo nft add table inet revolver_ks && "
               "sudo nft add chain inet revolver_ks out '{ type filter hook output priority 0 ; policy drop ; }' && "
               f"sudo nft add rule inet revolver_ks out oifname {tun} accept && "
               "sudo nft add rule inet revolver_ks out oifname lo accept && "
               "sudo nft add rule inet revolver_ks out ip daddr 192.168.0.0/16 accept"),
        "off": "sudo nft delete table inet revolver_ks",
    }


# --------------------------------------------------------------------------
# applying root actions
# --------------------------------------------------------------------------
# The shipped kill-switch ruleset is pinned to this device. The chain is
# `policy drop` on output and accepts only this oifname, so loading it while a
# different device carries the tunnel would cut the machine off the network.
# There is deliberately no wildcard variant: a wildcard in the sudoers entry
# would let any interface name be substituted.
KS_PINNED_IFACE = "proton0"


def _applied(msg, detail=""):
    return {"ok": True, "applied": True, "needs_sudo": False,
            "msg": msg, "detail": detail}


def _manual(msg, command):
    """No allowlist entry covers this -- hand the exact command to the user."""
    return {"ok": True, "applied": False, "needs_sudo": True,
            "msg": msg, "command": command}


def _failed(msg, detail=""):
    return {"ok": False, "applied": False, "needs_sudo": False,
            "msg": msg, "detail": detail}


_NO_SUDOERS = ("The sudo allowlist is not installed "
               "(/etc/sudoers.d/revolver). Run this yourself:")


def killswitch_enforce_state():
    """Is the nft egress lock actually loaded? None when it cannot be read."""
    if not sudo_ready():
        return None
    rc, out = sudo_run("ks_read")
    if rc == 0:
        return True
    if "No such file or directory" in out or "does not exist" in out:
        return False
    return None


def apply_toggle(name, want):
    """Apply a root-needing toggle, or hand back the command to run by hand.

    `applied` is True only when the underlying command actually returned
    success -- never because the UI asked for it. Anything not covered by the
    allowlist falls through to the surfaced-command path unchanged.
    """
    # -------- ufw lockdown --------
    if name == "lockdown":
        if not want:
            return _manual(
                "Turning the firewall off is deliberately NOT passwordless. "
                "Run this yourself:", SUDO_MANUAL["ufw_disable"])
        if not sudo_ready():
            return _manual(_NO_SUDOERS, lockdown_cmds()["on"])
        for key in ("ufw_deny_in", "ufw_allow_out", "ufw_enable"):
            rc, out = sudo_run(key, timeout=30)
            if rc != 0:
                return _failed(f"ufw step '{key}' failed", out.strip()[:300])
        return _applied("Lockdown applied: deny incoming, allow outgoing, ufw enabled")

    # -------- nft egress lock --------
    if name == "ks_enforce_nft":
        cmds = killswitch_enforce_cmds()
        if not want:
            if not sudo_ready():
                return _manual(_NO_SUDOERS, cmds["off"])
            rc, out = sudo_run("ks_disarm")
            if rc != 0 and "No such file" not in out and "does not exist" not in out:
                return _failed("could not remove the egress lock", out.strip()[:300])
            return _applied("Kill-switch egress lock removed")
        tun = cmds["tunnel"]
        if tun != KS_PINNED_IFACE:
            return _manual(
                f"Refusing to arm automatically: the shipped ruleset is pinned to "
                f"{KS_PINNED_IFACE} but the live tunnel is "
                f"{tun or 'not up'}. Arming a policy-drop output chain that does "
                f"not accept the real tunnel would cut off all networking.",
                cmds["on"])
        if not sudo_ready():
            return _manual(_NO_SUDOERS, cmds["on"])
        rc, out = sudo_run("ks_arm")
        if rc != 0:
            return _failed("could not arm the egress lock", out.strip()[:300])
        return _applied(f"Egress lock armed on {tun}")

    # -------- port-scan rule --------
    if name == "portscan":
        st = portscan_state()
        if not sudo_ready():
            return _manual(_NO_SUDOERS, st["arm_cmd"] if want else st["disarm_cmd"])
        if want:
            rc, out = sudo_run("portscan_arm")
            if rc != 0:
                return _failed("could not arm the scan rule", out.strip()[:300])
            return _applied("Port-scan rule armed")
        rc, out = sudo_run("portscan_disarm")
        if rc != 0 and "No such file" not in out and "does not exist" not in out:
            return _failed("could not remove the scan rule", out.strip()[:300])
        return _applied("Port-scan rule removed")

    # -------- IPv6 --------
    if name == "ipv6_os":
        if not want:
            return _manual(
                "Re-enabling IPv6 is the un-hardening direction and is "
                "deliberately NOT passwordless. Run this yourself:",
                SUDO_MANUAL["ipv6_enable"])
        if not sudo_ready():
            return _manual(_NO_SUDOERS, ipv6_state()["disable_cmd"])
        rc, out = sudo_run("ipv6_disable")
        if rc != 0:
            return _failed("could not disable IPv6", out.strip()[:300])
        return _applied("IPv6 disabled at the OS")

    # -------- MAC randomize (no root involved) --------
    if name == "mac_random":
        st = mac_state()
        argv = st.get("argv")
        if not argv:
            return _failed("no active NetworkManager profile found for "
                           f"{st.get('iface')}")
        for cmd in argv["random" if want else "permanent"]:
            rc, out = _run(cmd, timeout=45)
            if rc != 0:
                return _failed(f"nmcli failed: {' '.join(cmd[:4])}",
                               out.strip()[:300])
        return _applied(
            f"MAC {'randomized' if want else 'restored'} on {st.get('iface')} "
            f"via {st.get('nm_connection')}")

    # -------- DNS (reporting only) --------
    if name == "force_dns":
        d = dns_state()
        if d["managed_by"] == "NetworkManager":
            return _manual(
                "NetworkManager already owns /etc/resolv.conf, so DNS follows "
                "the tunnel on its own. Nothing to force. To re-apply now:",
                d["fix_cmd"])
        return _manual(
            "This is a system DNS change, not a panel action -- and a write to "
            "resolv.conf would be reverted on the next connection change. "
            "Back up first, then run:", d["fix_cmd"])

    return _failed(f"unknown toggle: {name}")


def screen_locked():
    """GNOME/Zorin screensaver state over the session bus (no root needed)."""
    rc, out = _run(["gdbus", "call", "--session", "--dest", "org.gnome.ScreenSaver",
                    "--object-path", "/org/gnome/ScreenSaver",
                    "--method", "org.gnome.ScreenSaver.GetActive"])
    if rc != 0:
        return None
    return "true" in out.lower()


# --------------------------------------------------------------------------
# capture detection (DETECTOR ONLY -- see note in notify text)
# --------------------------------------------------------------------------

CAPTURE_HINTS = ("obs", "ffmpeg", "wf-recorder", "simplescreenrecorder", "vokoscreen",
                 "kazam", "peek", "gnome-screenshot", "spectacle", "flameshot",
                 "shutter", "recordmydesktop", "byzanz", "maim", "scrot", "import",
                 "x11grab", "xwd", "gpu-screen-recorder")


def capture_processes():
    """Processes whose executable indicates screen capture.

    This DETECTS capture; it cannot prevent it. On an X11 session any client can
    read the root window, so a userspace "blocker" would be theatre. The real
    mitigation is a Wayland session.

    Matching is on the executable name with word boundaries, plus the explicit
    x11grab/kmsgrab flags. Substring matching over the whole command line gives
    false positives (qemu's "sandbox on,obsolete=deny" contains "obs").
    """
    rc, out = _run(["ps", "-eo", "pid,comm,args", "--no-headers"])
    hits = []
    if rc != 0:
        return hits
    me = str(os.getpid())
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid, comm, args = parts
        if pid == me:
            continue
        low_args = args.lower()
        if "revolver" in low_args or "defence.py" in low_args:
            continue
        # a shell that merely spawned the grabber is noise; the grabber itself
        # is reported on its own line
        if os.path.basename(comm.lower()) in ("bash", "sh", "zsh", "dash", "fish"):
            continue

        hit = None
        # 1. explicit X11/KMS grab flags are unambiguous evidence
        if "x11grab" in low_args or "kmsgrab" in low_args:
            hit = "x11grab"
        else:
            # 2. executable name matches a known capture tool (whole word only)
            base = os.path.basename(comm.lower())
            for h in CAPTURE_HINTS:
                if h in ("ffmpeg", "x11grab"):
                    continue  # ffmpeg alone is not evidence of capture
                if re.fullmatch(re.escape(h) + r"[-_.0-9]*", base):
                    hit = h
                    break
        if hit:
            hits.append({"pid": pid, "comm": comm, "hint": hit, "args": args[:120]})
    return hits


# --------------------------------------------------------------------------
# tripwire: startup baseline + drift
# --------------------------------------------------------------------------
# Everything here is read-only. Modules come from /proc/modules, sockets from
# ss, resolvers from /etc/resolv.conf -- no root, and nothing is ever written
# back to the system.

# Module families that load and unload during ordinary desktop use. Additions
# matching these are RECORDED but do not raise an alert; everything else does.
# Prefix match, so "usb" covers usbhid/usb_storage/usbcore.
_MODULE_IGNORE_PREFIXES = (
    # hot-plug / input
    "usb", "uas", "cdc_", "hid", "joydev", "xpad", "ff_memless", "ftdi",
    "ch341", "cp210x", "pl2303", "mtp",
    # bluetooth + audio, which come and go with devices
    "bt", "bluetooth", "rfcomm", "bnep", "snd", "uvcvideo", "videodev",
    "videobuf", "media", "mc",
    # filesystems mounted on demand (USB sticks, ISOs, snaps, containers)
    "fuse", "exfat", "vfat", "fat", "ntfs", "nls_", "isofs", "udf", "loop",
    "squashfs", "overlay", "dm_", "md_", "raid", "cifs", "nfs", "autofs",
    "jbd2", "ext4", "btrfs", "xfs", "crc",
    # virtualisation + containers: libvirt and docker are both running here
    "kvm", "vhost", "vfio", "tun", "tap", "veth", "bridge", "br_netfilter",
    "macvlan", "ipvlan", "vboxdrv", "vmw",
    # netfilter, which reloads whenever a firewall rule changes -- including
    # REVOLVER's own nft tables, so leaving these out would self-trigger
    "nf_", "nft_", "xt_", "x_tables", "ip_tables", "iptable_", "ip6_",
    "ip6table_", "ebtable", "arptable", "nfnetlink",
    # crypto algorithms demand-loaded by anything using the crypto API
    "algif_", "af_alg", "ccm", "cmac", "gcm", "ctr", "cbc", "ecb", "hmac",
    "sha", "aes", "des", "chacha", "poly1305", "curve25519", "hkdf", "ghash",
    "blake2", "crypto", "essiv", "cts",
)

# Source addresses that mean "this socket never leaves the box".
_LOOPBACK_SRC = ("127.", "::1")


def _norm_addr(a):
    """Strip the IPv4-mapped IPv6 prefix.

    The kernel reports a dual-stack socket's source as ::ffff:10.2.0.2. Without
    this, that socket compares unequal to the tunnel address and every
    dual-stack app looks like an off-tunnel leak.
    """
    a = (a or "").split("%")[0]
    if a.lower().startswith("::ffff:"):
        return a[7:]
    return a


def _is_private(addr):
    """RFC1918 / link-local / CGNAT / unique-local -- i.e. not the Internet."""
    a = _norm_addr(addr)
    if a.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fe80:",
                     "fc", "fd")):
        return True
    if a.startswith("172."):
        try:
            return 16 <= int(a.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    if a.startswith("100."):                      # 100.64.0.0/10 CGNAT
        try:
            return 64 <= int(a.split(".")[1]) <= 127
        except (IndexError, ValueError):
            return False
    return False


# Coarse CDN ranges. These only ever SUPPRESS the quiet "unknown process"
# alert; they can never suppress the loud off-tunnel one, so a wrong entry
# costs a missed nudge, not a missed leak. Ordered most-specific first.
_CDN_PREFIXES = (
    ("Google", ("173.194.", "142.250.", "142.251.", "172.217.", "216.58.",
                "216.239.", "209.85.", "74.125.", "64.233.")),
    ("Cloudflare", ("104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                    "104.26.", "104.27.", "104.28.", "172.64.", "172.65.",
                    "172.66.", "172.67.", "162.158.", "162.159.", "188.114.",
                    "190.93.", "197.234.", "198.41.", "1.1.1.", "1.0.0.")),
    ("GCP", ("34.", "35.")),
    ("AWS", ("3.", "13.", "15.", "18.", "44.", "52.", "54.", "99.", "107.20.",
             "184.72.", "23.20.", "50.16.", "50.17.")),
)

CDN_PORTS = ("443", "80")


def cdn_label(addr, port):
    """Which CDN a remote belongs to, or None. Advisory only."""
    if port not in CDN_PORTS:
        return None
    a = _norm_addr(addr)
    for name, prefixes in _CDN_PREFIXES:
        if a.startswith(prefixes):
            return name
    return None


def loaded_modules():
    """Module names from /proc/modules -- readable by anyone, no lsmod fork."""
    mods = set()
    try:
        with open("/proc/modules") as f:
            for line in f:
                name = line.split(None, 1)[0] if line.strip() else ""
                if name:
                    mods.add(name)
    except OSError:
        pass
    return mods


def module_ignored(name):
    return name.startswith(_MODULE_IGNORE_PREFIXES)


def resolv_fingerprint():
    """Nameservers plus the significant option lines from /etc/resolv.conf."""
    ns, opts = [], []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        ns.append(parts[1])
                elif line.startswith(("search", "domain", "options")):
                    opts.append(line)
    except OSError:
        pass
    return {"nameservers": ns, "options": opts}


def tunnel_addrs():
    """Local addresses belonging to the tunnel device (empty when it is down)."""
    tun = tunnel_iface()
    if not tun:
        return set()
    rc, out = _run(["ip", "-o", "addr", "show", tun])
    if rc != 0:
        return set()
    return {_norm_addr(m) for m in
            re.findall(r"inet6?\s+([0-9a-fA-F:.]+)/", out)}


def classify_connections(conns=None, tun_addrs=None):
    """Split live connections into on-tunnel / off-tunnel / loopback.

    The decision is made on the socket's SOURCE address, which is the interface
    the kernel already chose for it -- no per-connection route lookup, and it
    stays correct while routes are being rewritten mid-rotation.
    """
    if conns is None:
        conns = connections()
    if tun_addrs is None:
        tun_addrs = tunnel_addrs()
    out = {"on_tunnel": [], "off_tunnel": [], "off_tunnel_lan": [],
           "loopback": [], "tunnel_addrs": sorted(tun_addrs)}
    for c in conns:
        laddr = _norm_addr(c.get("laddr"))
        raddr = _norm_addr(c.get("remote"))
        row = dict(c, laddr=laddr, remote=raddr,
                   cdn=cdn_label(raddr, c.get("rport", "")))
        if laddr.startswith(_LOOPBACK_SRC):
            out["loopback"].append(row)
        elif tun_addrs and laddr in tun_addrs:
            out["on_tunnel"].append(row)
        elif _is_private(raddr):
            # Leaving by the physical NIC to the LAN: the router, a printer, a
            # NAS. Off-tunnel by design, so it is reported but not shouted at.
            out["off_tunnel_lan"].append(row)
        else:
            # Leaving the box by something other than the tunnel, to a public
            # address, while a tunnel exists. This is the leak case.
            out["off_tunnel"].append(row)
    return out


class Tripwire:
    """Baseline taken once at startup; every later poll is compared to it.

    The baseline is deliberately NOT re-taken on drift: if it were, an attacker
    who opened a port would have it silently absorbed on the next tick. It only
    moves when the operator asks for it.
    """

    def __init__(self):
        self.baseline = None
        self.taken_at = None
        self._seen = set()          # drift already alerted on, so it fires once

    def take(self):
        listen = listening_ports()
        conns = connections()
        self.baseline = {
            "listening": sorted({f"{p['proto']}/{p['addr']}:{p['port']}"
                                 for p in listen}),
            "modules": sorted(loaded_modules()),
            "net_procs": sorted({c["proc"].split("/")[0]
                                 for c in conns if c.get("proc")}),
            "resolv": resolv_fingerprint(),
        }
        self.taken_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._seen.clear()
        return self.baseline

    def check(self):
        """Compare now against the baseline. Returns (drift, alerts).

        alerts is a list of (message, kind) that has not been reported before,
        so a persistent change is announced once rather than every 5 seconds.
        """
        if self.baseline is None:
            self.take()
            return {"baselined": False}, []

        base = self.baseline
        alerts = []

        listen = listening_ports()
        now_listen = {f"{p['proto']}/{p['addr']}:{p['port']}" for p in listen}
        new_listen = sorted(now_listen - set(base["listening"]))
        gone_listen = sorted(set(base["listening"]) - now_listen)

        now_mods = loaded_modules()
        new_mods = sorted(now_mods - set(base["modules"]))
        # Every addition is recorded; only non-ignored ones are alerted.
        notable_mods = [m for m in new_mods if not module_ignored(m)]
        ignored_mods = [m for m in new_mods if module_ignored(m)]

        conns = connections()
        now_procs = {c["proc"].split("/")[0] for c in conns if c.get("proc")}
        new_procs = sorted(now_procs - set(base["net_procs"]))

        resolv = resolv_fingerprint()
        resolv_changed = resolv != base["resolv"]

        cls = classify_connections(conns)

        # ---- alerts, each fired once ----
        for p in new_listen:
            if self._fire(("listen", p)):
                alerts.append((f"NEW LISTENING PORT {p} "
                               f"(not present at baseline)", "err"))
        for m in notable_mods:
            if self._fire(("mod", m)):
                alerts.append((f"KERNEL MODULE LOADED: {m} "
                               f"(not in the startup baseline)", "err"))
        for pr in new_procs:
            if self._fire(("proc", pr)):
                alerts.append((f"NEW PROCESS WITH NETWORK CONNECTIONS: {pr}",
                               "warn"))
        if resolv_changed and self._fire(("resolv", json.dumps(resolv,
                                                              sort_keys=True))):
            alerts.append((f"/etc/resolv.conf CHANGED -> "
                           f"{' '.join(resolv['nameservers']) or '(none)'}",
                           "err"))

        # The loud one: a socket leaving the box off-tunnel to a public address.
        # Never suppressed by the CDN list -- normal browsing is on-tunnel, so
        # a CDN hit that is OFF-tunnel is exactly the leak worth shouting about.
        for c in cls["off_tunnel"]:
            key = ("offtun", c["remote"], c["rport"], c["proc"])
            if self._fire(key):
                alerts.append((f"OFF-TUNNEL CONNECTION {c['proc'] or '?'} -> "
                               f"{c['remote']}:{c['rport']} via {c['laddr']} "
                               f"(NOT through the tunnel)", "err"))

        # The quiet one: on-tunnel, but a process that was not running at
        # baseline talking somewhere that is not a known CDN.
        for c in cls["on_tunnel"]:
            proc = (c.get("proc") or "").split("/")[0]
            if not proc or proc in base["net_procs"] or c.get("cdn"):
                continue
            key = ("unknown", proc, c["remote"], c["rport"])
            if self._fire(key):
                alerts.append((f"UNKNOWN PROCESS ON TUNNEL: {proc} -> "
                               f"{c['remote']}:{c['rport']}", "warn"))

        drift = {
            "baselined": True,
            "taken_at": self.taken_at,
            "listening": {"new": new_listen, "gone": gone_listen},
            "modules": {"new": new_mods, "notable": notable_mods,
                        "ignored": ignored_mods,
                        "baseline_count": len(base["modules"]),
                        "now_count": len(now_mods)},
            "net_procs": {"new": new_procs},
            "resolv": {"changed": resolv_changed, "baseline": base["resolv"],
                       "now": resolv},
            "connections": {
                "on_tunnel": len(cls["on_tunnel"]),
                "off_tunnel": cls["off_tunnel"],
                "off_tunnel_lan": len(cls["off_tunnel_lan"]),
                "loopback": len(cls["loopback"]),
                "tunnel_addrs": cls["tunnel_addrs"],
            },
            "clean": not (new_listen or notable_mods or resolv_changed
                          or cls["off_tunnel"]),
        }
        return drift, alerts

    def _fire(self, key):
        """True the first time a given drift item is seen."""
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


# --------------------------------------------------------------------------
# watcher
# --------------------------------------------------------------------------

class Defence:
    """Background poller: ARP watch, connection monitor, capture detector, lock."""

    POLL = 5
    IP_POLL = 90        # seconds between exit-IP re-checks (network call)
    SCAN_POLL = 15      # seconds between kernel-log scans

    def __init__(self, notify_cb=None, trigger_cb=None,
                 state_cb=None, refresh_ip_cb=None):
        self.alerts = deque(maxlen=120)
        self.toggles = {
            "arp_watch": False,
            "capture_detect": False,
            "notifications": False,
            "auto_rotate_trigger": False,
            "auto_lockdown_lock": False,
        }
        self._notify_cb = notify_cb
        self._trigger_cb = trigger_cb
        # state_cb -> {"public_ip", "rotation_count", "busy", "rotating"}
        self._state_cb = state_cb
        # refresh_ip_cb forces a fresh exit-IP lookup (blocking, network)
        self._refresh_ip_cb = refresh_ip_cb

        self._gw_mac = None
        self._seen_conns = set()
        self._seen_capture = set()
        self._was_locked = None
        self._exit_ip = None
        self._exit_rot = None
        self._last_ip_check = 0.0
        self._last_scan_check = 0.0
        self._seen_scans = set()
        self._seeded = False
        self._scan = {"readable": False, "events": [], "count": 0,
                      "reason": "not polled yet"}
        # Baseline is taken on the first poll, not here: at __init__ time the
        # tunnel may not be up yet, and a baseline without tunnel addresses
        # would mark every later connection as off-tunnel drift.
        self.tripwire = Tripwire()
        self._drift = {"baselined": False}

        self._lock = threading.Lock()
        self._cache = {}
        self._stop = threading.Event()
        self._thread = None

    # ---- alerts ----

    def alert(self, msg, kind="warn", notify=False):
        with self._lock:
            self.alerts.appendleft({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "msg": msg, "kind": kind})
        if notify and self.toggles.get("notifications") and have("notify-send"):
            urgency = "critical" if kind == "err" else "normal"
            subprocess.Popen(
                ["notify-send", "-u", urgency, "-a", "REVOLVER", "REVOLVER", msg],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ---- lifecycle ----

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="defence-watch")
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as e:
                self.alert(f"watcher error: {type(e).__name__}: {e}", "err")
            self._stop.wait(self.POLL)

    def _poll(self):
        # ARP / gateway MAC
        gw = gateway_state()
        if self.toggles["arp_watch"] and gw.get("mac"):
            if self._gw_mac is None:
                self._gw_mac = gw["mac"]
            elif gw["mac"] != self._gw_mac:
                self.alert(
                    f"GATEWAY MAC CHANGED {self._gw_mac} -> {gw['mac']} "
                    f"(possible ARP spoof / MITM)", "err", notify=True)
                self._gw_mac = gw["mac"]

        # connection monitor
        listen = listening_ports()
        conns = connections({p["port"] for p in listen})
        new_inbound = []
        for c in conns:
            if c["local"] or not c["inbound"]:
                continue
            key = (c["remote"], c["rport"], c["lport"])
            if key not in self._seen_conns:
                self._seen_conns.add(key)
                new_inbound.append(c)
        if not self._seeded:
            # First pass only establishes the baseline -- everything already
            # open at startup is pre-existing, not an event to rotate on.
            self._seeded = True
            new_inbound = []
        if new_inbound and self.toggles["auto_rotate_trigger"] and self._trigger_cb:
            c = new_inbound[0]
            self.alert(f"New INBOUND connection {c['remote']}:{c['rport']} "
                       f"-> local port {c['lport']} -- firing rotation",
                       "warn", notify=True)
            self._fire_rotation()

        # exit-IP watch: an exit IP that changes without a rotation of ours is
        # the tunnel having moved underneath us (drop / reconnect / leak).
        self._check_exit_ip()

        # port-scan hits logged by the nft rule (kernel journal, no root)
        now = time.time()
        if now - self._last_scan_check >= self.SCAN_POLL:
            self._last_scan_check = now
            self._scan = scan_events()
            for e in self._scan.get("events", []):
                key = (e["ts"], e["src"], e["dport"])
                if key in self._seen_scans:
                    continue
                self._seen_scans.add(key)
                self.alert(f"PORT SCAN {e['src']} -> port {e['dport']} "
                           f"({e['proto']}) dropped at host", "err", notify=True)

        # tripwire: baseline on the first pass, drift comparison after that
        try:
            self._drift, drift_alerts = self.tripwire.check()
            for msg, kind in drift_alerts:
                self.alert(msg, kind, notify=(kind == "err"))
        except Exception as e:
            self.alert(f"tripwire error: {type(e).__name__}: {e}", "err")

        # capture detector
        caps = capture_processes() if self.toggles["capture_detect"] else []
        for c in caps:
            key = c["pid"] + c["comm"]
            if key not in self._seen_capture:
                self._seen_capture.add(key)
                self.alert(f"SCREEN CAPTURE DETECTED: {c['comm']} (pid {c['pid']}) "
                           f"[{c['hint']}]", "err", notify=True)

        # screen lock
        locked = screen_locked()
        if self.toggles["auto_lockdown_lock"] and locked is not None:
            if self._was_locked is None:
                self._was_locked = locked
            elif locked and not self._was_locked:
                self.alert("Screen locked -- lockdown needs root, run: "
                           + lockdown_cmds()["on"], "warn", notify=True)
            self._was_locked = locked

        with self._lock:
            self._cache = {
                "listening": listen,
                "connections": conns,
                "capture": caps,
                "gateway": gw,
                "locked": locked,
            }

    def _fire_rotation(self):
        try:
            self._trigger_cb()
        except Exception as e:
            self.alert(f"trigger rotation failed: {e}", "err")
        # Our own rotation changes the exit IP; re-seat the baseline so the
        # IP watch does not immediately re-trigger on the change we caused.
        self._exit_ip = None

    def _check_exit_ip(self):
        """Detect an exit IP that changed without us rotating."""
        if not (self.toggles["auto_rotate_trigger"] and self._state_cb):
            return
        st = self._state_cb() or {}
        if st.get("busy") or st.get("error"):
            return

        now = time.time()
        if self._refresh_ip_cb and now - self._last_ip_check >= self.IP_POLL:
            self._last_ip_check = now
            try:
                self._refresh_ip_cb()
            except Exception as e:
                self.alert(f"exit-IP check failed: {type(e).__name__}: {e}", "warn")
                return
            st = self._state_cb() or {}

        ip, rot = st.get("public_ip"), st.get("rotation_count")
        if not ip:
            return
        if self._exit_ip is None:
            self._exit_ip, self._exit_rot = ip, rot
            return
        if ip == self._exit_ip:
            self._exit_rot = rot
            return

        # A change we caused (rotation_count moved) is expected; anything else
        # is the tunnel shifting on its own.
        ours = rot is not None and self._exit_rot is not None and rot != self._exit_rot
        old = self._exit_ip
        self._exit_ip, self._exit_rot = ip, rot
        if ours:
            return
        self.alert(f"UNEXPECTED EXIT IP CHANGE {old} -> {ip} "
                   f"(no rotation of ours) -> firing rotation", "err", notify=True)
        self._fire_rotation()

    # ---- snapshot for the UI ----

    def snapshot(self):
        with self._lock:
            cache = dict(self._cache)
            alerts = list(self.alerts)[:40]
        return {
            "toggles": dict(self.toggles),
            "alerts": alerts,
            "listening": cache.get("listening", []),
            "connections": cache.get("connections", []),
            "capture": cache.get("capture", []),
            "locked": cache.get("locked"),
            "ipv6": ipv6_state(),
            "mac": mac_state(),
            "dns": dns_state(),
            "gateway": cache.get("gateway", gateway_state()),
            "firewall": firewall_state(),
            "portscan": portscan_state(self._scan),
            "lockdown_cmds": lockdown_cmds(),
            "ks_enforce_cmds": killswitch_enforce_cmds(),
            "ks_enforce_armed": killswitch_enforce_state(),
            "sudo_ready": sudo_ready(),
            "session_type": os.environ.get("XDG_SESSION_TYPE", "unknown"),
            "notify_available": have("notify-send"),
            "tools": tools_state(),
            "ifaces": {"primary": primary_iface(), "tunnel": tunnel_iface()},
            "scan": self._scan,
            "exit_ip_seen": self._exit_ip,
            "tripwire": self._drift,
            "audit": audit_tail(40),
        }
