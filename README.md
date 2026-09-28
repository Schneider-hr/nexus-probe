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
python -m uvicorn nexus_backend.api:app --host 127.0.0.1 --port 8000
```
`pytest` runs the test suite (26 tests, including a real FastAPI
`TestClient` end-to-end pass).

**Dashboard**
```
cd nexus-dashboard
npm install
echo VITE_NEXUS_API_BASE=http://127.0.0.1:8000 > .env.local
npm run dev
```

**Firmware**
```
cd firmware
cp components/nexus_core/include/nexus_config.example.h components/nexus_core/include/nexus_config.h
# edit nexus_config.h with real WiFi + backend details
idf.py build
idf.py -p PORT flash
```

## Honest current limitations

- The backend's store is in-memory only — restarting it drops all probes,
  findings, and alerts. There's no database yet.
- No authentication anywhere (probe→backend or dashboard→backend). CORS is
  wide open (`allow_origins=["*"]`). This is a local/lab tool as it stands,
  not something to expose to the open internet.
- `ble_tracker_detect` has been verified by compiling against the real
  ESP-IDF toolchain, not by running on physical hardware yet.
- Battery reporting is a placeholder (`-1` = no fuel gauge on this hardware
  yet); the dashboard hides it rather than showing a fake percentage.
