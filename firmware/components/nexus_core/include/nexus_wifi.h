#pragma once

/**
 * WiFi connection with self-service provisioning.
 *
 * On every boot: if a WiFi SSID/password is already stored in NVS, this
 * tries to connect with it. If that succeeds, it returns immediately — the
 * normal case on every boot after the first.
 *
 * If there's nothing stored yet, or the stored credentials fail to
 * connect, this starts a temporary WPA2-protected setup access point
 * instead (SSID "Nexus-Setup-<probe id>", passphrase
 * NEXUS_SETUP_AP_PASSWORD) with a small web form at its own IP. Whoever
 * is deploying the probe connects to that AP, opens any web page (a
 * built-in DNS responder redirects every lookup to the form, the same
 * trick commercial IoT setup flows use so the page "just pops up"), and
 * enters the real WiFi network's name and password. The probe saves that
 * to NVS, restarts, and connects normally from then on.
 *
 * The setup AP only runs for NEXUS_PROVISION_WINDOW_MS per boot, not
 * indefinitely — see nexus_wifi.c's module docstring for why that matters.
 */

void nexus_wifi_connect_blocking(void);
