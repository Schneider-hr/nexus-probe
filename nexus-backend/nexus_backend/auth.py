"""Authentication for the Nexus API.

Write endpoints (a probe reporting in) require that probe's own key, sent as
the `X-Nexus-Probe-Key` header. Keys are configured on the server with
`NEXUS_PROBE_KEYS="nano-1:<key>,nano-2:<key>"`, so one stolen probe key only
lets an attacker speak as that one probe. Generate a key with:

    python -c "import secrets; print(secrets.token_urlsafe(32))"

Read endpoints (the dashboard) are open unless `NEXUS_READ_TOKEN` is set, in
which case they need `Authorization: Bearer <token>`.

Secure by default: with no probe keys configured, writes are refused (503)
unless `NEXUS_AUTH_DISABLED=1` is set explicitly, which is for local
development only. Keys are compared in constant time.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException


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


def require_read_access(authorization: str | None = Header(default=None)) -> None:
    token = os.environ.get("NEXUS_READ_TOKEN")
    if not token:
        return
    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail="Missing read token")
    if not hmac.compare_digest(token.encode(), authorization[len(prefix):].encode()):
        raise HTTPException(status_code=401, detail="Invalid read token")
