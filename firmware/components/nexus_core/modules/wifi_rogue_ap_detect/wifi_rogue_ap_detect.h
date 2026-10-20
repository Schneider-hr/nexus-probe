#pragma once

#include "nexus_module.h"

/**
 * Passive rogue access point / evil-twin detection: a defensive Wi-Fi
 * monitor. Each pass does one PASSIVE channel scan (it listens for the
 * beacon frames access points broadcast on their own; it does not send
 * probe requests), then flags any network name (SSID) broadcast by one
 * protected access point and one OPEN access point at the same time, which
 * is the classic signature of an evil-twin impersonation. Mesh networks
 * and multi-access-point offices (same name, same security) are not flagged.
 *
 * The module never connects to, authenticates with, deauthenticates,
 * or transmits to any network other than the one the probe itself is
 * already joined to for reporting.
 */
extern const nexus_module_t wifi_rogue_ap_detect_module;
