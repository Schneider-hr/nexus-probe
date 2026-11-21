#pragma once

#include "nexus_module.h"

/**
 * WiFi deauthentication/disassociation flood detection — purely passive.
 *
 * Complements wifi_rogue_ap_detect: that module spots a fake AP sitting
 * there; this one spots the attack that usually *drives victims onto it* -
 * an attacker sending forged 802.11 deauth/disassoc management frames to
 * knock devices off their real network so they reconnect to an
 * attacker-controlled one (or just as a standalone denial-of-service).
 *
 * Uses the WiFi driver's promiscuous-mode receive callback to count
 * deauth/disassoc frames seen on the probe's current channel while it stays
 * normally connected as a station - this never transmits anything itself
 * (no deauth frames are sent, only counted), and only ever reads the fixed
 * header fields it needs (frame-control byte, address fields), never
 * trusting anything attacker-controlled beyond that.
 *
 * A handful of deauth/disassoc frames during normal operation is routine
 * (a device roaming, an AP cycling a stale association) - only a burst well
 * above that gets reported, to avoid flagging ordinary WiFi housekeeping as
 * an attack.
 */
extern const nexus_module_t wifi_deauth_detect_module;
