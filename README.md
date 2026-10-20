# Nexus — Physical / RF Security Assessment Platform

Nexus is a small fleet of ESP32-S3 probes that perform physical and RF
security checks (BLE, WiFi, RFID/NFC, Sub-GHz, IR, Zigbee — see below for
what's actually implemented today vs. designed for later), reporting back
to a FastAPI backend that scores what they find into a GRC-style risk
register, surfaced on a live React dashboard.

It's the hardware-side companion to
[AD Risk Auditor](https://github.com/Schneider-hr/ad-risk-auditor): that
project's LDAP collector proves software/directory weaknesses and scores
them the same way this project's probes prove physical/RF weaknesses —
one scoring model, two different collectors.

## Architecture

```
firmware/          ESP32-S3 probe firmware (ESP-IDF v5.2.2)
nexus-backend/      FastAPI backend — scoring, risk register, alert feed
nexus-dashboard/    React/Vite live dashboard
```

- **Audit modules** (planned) prove a weakness exists and produce a scored
  **Finding** in the risk register (likelihood × impact, MITRE ATT&CK where
  it honestly maps, NIST 800-53/CIS Controls reference, a recommendation).
- **Detection modules** report live observations into a separate, simpler
  **Alert** feed instead — they're not proving a weakness, just flagging
  something worth a human's attention (e.g. "a BLE tracker is following
  this probe"). Alerts are deliberately not merged into the risk-scoring
  model.
- Where a finding type doesn't map cleanly onto a MITRE ATT&CK Enterprise
  technique (e.g. a garage remote being replayable), `mitre_attack` is left
  `None` rather than forced into the nearest-sounding ID.

## Module status

| Module | Type | Status |
|---|---|---|
| `ble_tracker_detect` | Detection | **Implemented** — passive BLE scanning for Apple Find My accessories and persistence-based generic tracker detection. Built and compiles clean against ESP-IDF v5.2.2 for ESP32-S3; not yet flashed to real hardware. |
| `wifi_rogue_ap_detect` | Detection | **Implemented** — one *passive* Wi-Fi scan per pass (it listens to beacons, sends no probe requests) and flags a network name broadcast by both a protected and an OPEN access point, the classic evil-twin signature. Mesh networks with matching security are not flagged. The detection logic has 9 host-side unit tests (`firmware/tests/`) that pass; the firmware builds against ESP-IDF v5.2.2; not yet run on a real board. |
| `rfid_nfc_clone` | Audit | Risk profile only — scoring logic exists in the backend; firmware not yet written. |
| `subghz_replay` | Audit | Risk profile only. |
| `ir_replay` | Audit | Risk profile only. |
| `wifi_handshake_capture` | Audit | Risk profile only. |
| `wifi_evil_twin` | Audit | Risk profile only. |
| `zigbee_discovery` | Audit | Risk profile only. |
| `gpio_debug_interface` | Audit | Risk profile only. |

"Risk profile only" means the backend already knows how to score a finding
from that module (title, likelihood/impact, MITRE mapping, recommendation)
so a firmware module can be dropped in later without backend changes —
same "collector proves it, backend scores it" split as AD Risk Auditor.

### Why there's no HID injection (BadUSB) module

An earlier draft of this project's module list included HID injection
(a probe posing as a USB keyboard to run an unauthenticated payload). It
was dropped entirely and is not coming back — no firmware code, no backend
risk profile. The rest of the module list stayed scoped to passive
detection and read-only/replay-only RF checks against hardware the
operator owns or is authorized to test.

## Running it

**Backend**
```
cd nexus-backend
pip install -r requirements.txt -r requirements-dev.txt

# one key per probe (generate with: python -c "import secrets; print(secrets.token_urlsafe(32))")
export NEXUS_PROBE_KEYS="nano-1:<key-for-nano-1>,nano-2:<key-for-nano-2>"
export NEXUS_DB_PATH=nexus.db          # persist data; leave unset for in-memory only
python -m uvicorn nexus_backend.api:app --host 127.0.0.1 --port 8000
```
`pytest` runs the test suite (50 tests, including real FastAPI `TestClient`
end-to-end passes for auth, persistence and input validation).

Configuration (all environment variables):

| Variable | Purpose |
|---|---|
| `NEXUS_PROBE_KEYS` | `probe_id:key` pairs. A probe must send its own key as `X-Nexus-Probe-Key` to register, heartbeat, or report. Without any keys configured, writes are refused (503), not silently allowed. |
| `NEXUS_AUTH_DISABLED=1` | Turns probe authentication off. Local development only. |
| `NEXUS_READ_TOKEN` | If set, every read endpoint needs `Authorization: Bearer <token>`. |
| `NEXUS_DB_PATH` | SQLite file for persistence. Unset/empty = in-memory only. |
| `NEXUS_CORS_ORIGINS` | Comma-separated dashboard origins allowed to call the API from a browser (default: local dev servers only). |

**Dashboard**
```
cd nexus-dashboard
npm install
echo VITE_NEXUS_API_BASE=http://127.0.0.1:8000 > .env.local
# only if the backend sets NEXUS_READ_TOKEN: echo VITE_NEXUS_READ_TOKEN=<token> >> .env.local
npm run dev
```

**Firmware**
```
cd firmware
cp components/nexus_core/include/nexus_config.example.h components/nexus_core/include/nexus_config.h
# edit nexus_config.h: WiFi, backend URL, and this probe's NEXUS_PROBE_KEY
idf.py build
idf.py -p PORT flash
```

Host-side unit tests for the Wi-Fi detection logic (no board needed):
```
cd firmware
gcc -Wall -Wextra -I components/nexus_core/modules/wifi_rogue_ap_detect \
    tests/test_rogue_ap_logic.c components/nexus_core/modules/wifi_rogue_ap_detect/rogue_ap_logic.c -o test && ./test
```

## Honest current limitations

- **Probe-to-backend traffic is only as safe as its transport.** Per-probe API
  keys stop an unauthenticated device from writing, but over plain HTTP the
  key and data cross the network in the clear. Use HTTPS
  (`NEXUS_BACKEND_USE_TLS 1`) outside a trusted lab; the TLS path in the
  firmware has not been tested on hardware.
- **The dashboard has no user login.** `NEXUS_READ_TOKEN` is a shared token
  that ends up in the built JavaScript, so it deters casual visitors but is
  not a secret. For anything real, put the dashboard behind an authenticating
  reverse proxy.
- Persistence is a single SQLite file written on every change. That is fine for
  a small fleet; there is no backup, migration, or data-retention policy.
- Neither firmware module has been run on physical hardware. Both are verified
  by building against the real ESP-IDF toolchain; the Wi-Fi detection logic
  is additionally covered by host-side unit tests, but real-world scan
  behaviour (including how a scan interacts with the probe's own Wi-Fi link)
  is untested.
- Battery reporting is a placeholder: with no fuel gauge on this hardware the
  firmware omits the field, and the dashboard shows nothing rather than a fake
  percentage.
