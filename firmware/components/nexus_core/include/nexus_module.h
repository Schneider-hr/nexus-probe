#pragma once

#include <stddef.h>
#include "esp_err.h"

/**
 * The module interface every probe capability implements.
 *
 * init() does one-time hardware setup (e.g. bringing up a radio stack).
 * run() performs the module's action and reports the result:
 *   - ESP_OK           : the finding was proven; out_detail holds a short,
 *                         human-readable detail string (may be empty)
 *   - ESP_ERR_NOT_FOUND : ran cleanly, nothing to report this pass
 *   - anything else     : a real failure (main.c logs it, does not report
 *                         a finding for it)
 */
typedef struct {
    const char *name; // matches a key in the backend's module_profiles.py — must stay in sync
    esp_err_t (*init)(void);
    esp_err_t (*run)(char *out_detail, size_t out_detail_len);
} nexus_module_t;
