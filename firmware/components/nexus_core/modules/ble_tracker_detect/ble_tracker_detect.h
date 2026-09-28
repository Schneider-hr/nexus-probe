#pragma once

#include "nexus_module.h"

/**
 * Passive BLE tracker detection — purely defensive, no transmission beyond
 * standard BLE scan requests (and passive scanning here doesn't even send
 * those). This module never connects to, pairs with, or transmits anything
 * to another device; it only listens to public BLE advertisements, the same
 * category of behavior as Apple's own "Item Safety Alerts" / the AirGuard
 * app.
 *
 * Two independent checks run each scan window:
 *   1. Apple "Find My" network accessory advertisements (a documented,
 *      public format: manufacturer id 0x004C, type byte 0x12) — flags an
 *      AirTag or other Find My accessory advertising nearby.
 *   2. Persistence-based generic tracker detection: any other BLE MAC seen
 *      across enough consecutive scan windows is flagged as "following"
 *      the probe, regardless of vendor — this is how the module also
 *      surfaces non-Apple trackers (Tile, SmartTag, etc.) that don't use a
 *      documented advertisement format we can identify by content alone.
 */
extern const nexus_module_t ble_tracker_detect_module;
