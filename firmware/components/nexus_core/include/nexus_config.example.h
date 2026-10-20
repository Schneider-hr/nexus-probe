// Template. Copy to nexus_config.h (git-ignored) in this same directory
// and fill in your WiFi and Nexus backend details.
#pragma once

#define NEXUS_WIFI_SSID "your-wifi-ssid"
#define NEXUS_WIFI_PASSWORD "your-wifi-password"

// Point this at your Nexus backend, e.g. "http://192.168.1.50:8000"
// while developing (NEXUS_BACKEND_USE_TLS 0), or an https:// URL in
// production (NEXUS_BACKEND_USE_TLS 1, uses the ESP-IDF certificate
// bundle to validate the backend's TLS certificate).
#define NEXUS_BACKEND_URL "http://192.168.1.50:8000"
#define NEXUS_BACKEND_USE_TLS 0

#define NEXUS_PROBE_ID "nano-1"
#define NEXUS_PROBE_NAME "Nano Alpha"

// This probe's own API key. Must match the entry for NEXUS_PROBE_ID in the
// backend's NEXUS_PROBE_KEYS (e.g. "nano-1:<key>"). Generate one with:
//   python -c "import secrets; print(secrets.token_urlsafe(32))"
// Never commit the real key: nexus_config.h is git-ignored.
#define NEXUS_PROBE_KEY "replace-with-a-long-random-key"
