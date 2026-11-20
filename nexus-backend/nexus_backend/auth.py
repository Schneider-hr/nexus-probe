"""Authentication for the Nexus API and dashboard.

Write endpoints (a probe reporting in) require that probe's own key, sent as
the `X-Nexus-Probe-Key` header. Keys are configured on the server with
`NEXUS_PROBE_KEYS="nano-1:<key>,nano-2:<key>"`, so one stolen probe key only
lets an attacker speak as that one probe. Generate a key with:

    python -c "import secrets; print(secrets.token_urlsafe(32))"

Each probe key is also rate-limited (see check_probe_rate_limit): a leaked or
malfunctioning probe can't be used to flood the backend.

Read endpoints and the dashboard itself require HTTP Basic auth, configured
with `NEXUS_DASHBOARD_USER` (default "nexus") and `NEXUS_DASHBOARD_PASSWORD`.
This is enforced by api.py's middleware, not per-route, so it also covers the
static dashboard files - unlike a token baked into the dashboard's own built
JavaScript (anyone who loads the page can read that out of the bundle), a
real Basic Auth challenge is checked server-side before anything is sent, and
the browser handles prompting for and caching the credentials.

Secure by default: with no probe keys / no dashboard password configured,
access is refused (503) unless `NEXUS_AUTH_DISABLED=1` is set explicitly,
which is for local development only. All secrets are compared in constant
time to avoid timing side channels.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import time
from typing import Literal

from fastapi import HTTPException


def auth_disabled() -> bool:
    return os.environ.get("NEXUS_AUTH_DISABLED") == "1"


def probe_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in os.environ.get("NEXUS_PROBE_KEYS", "").split(","):
        item = item.strip()
        if ":" not in item:
            continue
        probe_id, key = item.split(":", 1)
        if probe_id.strip() and key.strip():
            keys[probe_id.strip()] = key.strip()
    return keys


# --- per-probe rate limiting ---
# A fixed 60s window per probe_id. Generous enough for normal operation (one
# heartbeat + a couple of alerts every few seconds) while capping how much
# damage a single leaked probe key can do to this free-tier backend.
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 60

_rate_limit_state: dict[str, tuple[float, int]] = {}


def check_probe_rate_limit(probe_id: str) -> None:
    """Raise 429 if this probe_id has made too many requests this window."""
    now = time.monotonic()
    window_start, count = _rate_limit_state.get(probe_id, (now, 0))
    if now - window_start >= RATE_LIMIT_WINDOW_SECONDS:
        window_start, count = now, 0
    count += 1
    _rate_limit_state[probe_id] = (window_start, count)
    if count > RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many requests for this probe - slow down")


def authenticate_probe(probe_id: str, presented: str | None) -> None:
    """Raise unless `presented` is the configured key for exactly this probe."""
    if auth_disabled():
        return
    keys = probe_keys()
    if not keys:
        raise HTTPException(
            status_code=503,
            detail="No probe keys configured. Set NEXUS_PROBE_KEYS (or NEXUS_AUTH_DISABLED=1 for local development only).",
        )
    expected = keys.get(probe_id)
    # One generic message for "unknown probe" and "wrong key" so the API does
    # not reveal which probe IDs exist.
    if expected is None or presented is None or not hmac.compare_digest(expected.encode(), presented.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing probe key")
    check_probe_rate_limit(probe_id)


# --- dashboard HTTP Basic auth ---

DashboardAuthResult = Literal["ok", "unconfigured", "invalid"]


def dashboard_credentials() -> tuple[str, str] | None:
    password = os.environ.get("NEXUS_DASHBOARD_PASSWORD")
    if not password:
        return None
    username = os.environ.get("NEXUS_DASHBOARD_USER", "nexus")
    return username, password


def check_dashboard_auth(authorization: str | None) -> DashboardAuthResult:
    if auth_disabled():
        return "ok"
    creds = dashboard_credentials()
    if creds is None:
        return "unconfigured"
    if not authorization or not authorization.startswith("Basic "):
        return "invalid"
    try:
        decoded = base64.b64decode(authorization[len("Basic "):], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return "invalid"
    username, sep, password = decoded.partition(":")
    if not sep:
        return "invalid"
    expected_user, expected_pass = creds
    user_ok = hmac.compare_digest(username, expected_user)
    pass_ok = hmac.compare_digest(password, expected_pass)
    return "ok" if (user_ok and pass_ok) else "invalid"
