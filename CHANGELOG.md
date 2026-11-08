# Changelog

## 2026-11-08

- **Fix:** `rotator.py` — the teardown-and-reconnect sequence inside `_rotate()`
  (`await c.disconnect()` / `await c.connect()`) could hang indefinitely with no
  error when the official ProtonVPN desktop app was also running and already
  holding the tunnel. Observed: stuck for 16+ minutes with zero log output;
  `/api/status` and the dashboard showed "NO SESSION" / "API FAULT —
  TimeoutError" the whole time. Root cause confirmed by closing the desktop
  app mid-hang and watching the stuck call complete in under 2 seconds.
  Fixed by bounding that specific sequence with `asyncio.wait_for(...,
  timeout=TEARDOWN_RECONNECT_TIMEOUT)` (25s) in a new `_teardown_and_reconnect`
  helper. On timeout, the event log now reports "Timed out taking over the VPN
  connection -- is the ProtonVPN desktop app still open? Close it and try
  again." instead of a bare `TimeoutError`.
  - Decision: Jon will run Revolver and the ProtonVPN desktop app as mutually
    exclusive going forward (desktop app stays closed). No coexistence mode
    was found in the installed `proton-vpn-api-core` library.
  - Verified: normal rotation (desktop app closed) completes in ~6s with the
    patch in place, no spurious timeout triggered.
