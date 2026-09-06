"""
MUST be imported before any `proton.*` module.

Two Proton VPN installs can coexist on this machine, and they keep their
connection state in different places:

    Flatpak (com.protonvpn.www):
        ~/.var/app/com.protonvpn.www/cache/Proton/VPN/connection/...
    Native (python3-proton-vpn-api-core):
        ~/.cache/Proton/VPN/connection/...

The system-wide API reads $XDG_CACHE_HOME/Proton/VPN. If we point it at the
wrong one, `is_connected` reports False while a tunnel is actually up -- and
then _rotate() skips its teardown and calls connect() into a live connection,
which is the ConcurrentConnectionsError collision.

This originally hard-redirected to the Flatpak paths whenever that directory
merely EXISTED. That is wrong: the directory outlives its last use, so a stale
Flatpak cache silently shadowed the live native one. Observed 2026-09-06: the
Flatpak file named JP-FREE#20 (a connection NetworkManager no longer knew)
while the live tunnel was US-FREE#121 recorded in the native file.

So choose by evidence instead: whichever persistence file was written most
recently describes the current connection. Both absent -> leave the host
defaults alone.

proton.utils.environment.ExecutionEnvironment is a Singleton that resolves
these paths in __init__, so this has to run before the first proton import.
"""
import os

FLATPAK_BASE = os.path.expanduser("~/.var/app/com.protonvpn.www")
HOST_CACHE = os.path.expanduser("~/.cache")
HOST_CONFIG = os.path.expanduser("~/.config")

_PERSIST = "Proton/VPN/connection/connection_persistence.json"


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _pick():
    """(cache, config, label) for whichever install last wrote connection state."""
    flatpak_cache = os.path.join(FLATPAK_BASE, "cache")
    flatpak = _mtime(os.path.join(flatpak_cache, _PERSIST))
    host = _mtime(os.path.join(HOST_CACHE, _PERSIST))

    if flatpak is not None and (host is None or flatpak > host):
        return (flatpak_cache, os.path.join(FLATPAK_BASE, "config"), "flatpak")
    if host is not None:
        return (HOST_CACHE, HOST_CONFIG, "native")
    # Nothing has ever connected; fall back to the Flatpak dirs if that install
    # is present, otherwise leave the host defaults untouched.
    if os.path.isdir(FLATPAK_BASE):
        return (flatpak_cache, os.path.join(FLATPAK_BASE, "config"), "flatpak")
    return (None, None, "host-default")


_cache, _config, ACTIVE_INSTALL = _pick()
if _cache:
    os.environ["XDG_CACHE_HOME"] = _cache
    os.environ["XDG_CONFIG_HOME"] = _config

# kept for backwards compatibility with anything that imported this flag
USING_FLATPAK_PATHS = ACTIVE_INSTALL == "flatpak"
