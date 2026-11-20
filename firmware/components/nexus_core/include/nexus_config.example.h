// Template. Copy to nexus_config.h (git-ignored) in this same directory
// and fill in your WiFi and Nexus backend details.
#pragma once

// These two are no longer used to connect directly — WiFi is now set up
// through the on-device setup AP (see nexus_wifi.h) and the result is
// stored in NVS, not compile-time constants. Left here only as a reminder
// of the overall flow; delete once that's familiar.
#define NEXUS_WIFI_SSID "your-wifi-ssid"
#define NEXUS_WIFI_PASSWORD "your-wifi-password"

// WPA2 passphrase for this probe's own temporary setup AP ("Nexus-Setup-<id>"),
// used only while it has no working WiFi credentials yet. Hand this to
// whoever is deploying the probe out of band (e.g. printed in the handoff
// docs) — never send it over the air, and change it per deployment if you
// want a different group of people able to (re)configure the probe.
// Must be 8-63 characters (WPA2 requirement).
#define NEXUS_SETUP_AP_PASSWORD "change-me-per-deployment"

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
