#pragma once

#include <stddef.h>
#include "esp_err.h"

/**
 * HTTP client for reporting to the Nexus backend. One JSON POST per call —
 * deliberately simple (no batching, no retry queue) for v1, matching the
 * rest of this project's "ship narrow and correct" approach.
 */

esp_err_t nexus_client_register(const char *probe_id, const char *name,
                                 const char *const *modules, size_t module_count);

esp_err_t nexus_client_heartbeat(const char *probe_id, int battery_pct);

esp_err_t nexus_client_report_finding(const char *probe_id, const char *module,
                                       const char *location, const char *detail);

// For detection modules (live observations, e.g. an unwanted BLE tracker
// seen nearby) — a separate, simpler feed from the scored risk-register
// findings above. severity is a free-form string ("info"/"warning"/"critical").
esp_err_t nexus_client_report_alert(const char *probe_id, const char *module,
                                     const char *message, const char *severity);
