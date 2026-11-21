#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "nexus_module.h"
#include "nexus_client.h"
#include "nexus_config.h"
#include "nexus_wifi.h"
#include "ble_tracker_detect.h"
#include "wifi_rogue_ap_detect.h"
#include "wifi_deauth_detect.h"

static const char *TAG = "nexus_main";

#define MODULE_RUN_PAUSE_MS 5000

// The backend is a free-tier Render service: it spins down after idle time
// and takes 30-60s to wake on the next request, and its disk (and so the
// registered-probe list) is wiped on every redeploy or spin-down/wake cycle.
// So registration is not a one-shot "do it once at boot" thing - it has to
// survive both a cold backend at boot and the backend forgetting about us
// later. Retry with a capped backoff, and whenever a heartbeat gets rejected
// (the backend no longer knows this probe_id), re-register before the next
// heartbeat rather than looping on failed requests forever.
#define REGISTER_RETRY_INITIAL_DELAY_MS 5000
#define REGISTER_RETRY_MAX_DELAY_MS 30000

// Every module this probe runs. Add a module's `_module` symbol here to
// enroll it — main.c loops over this array generically rather than
// special-casing each one.
static const nexus_module_t *s_modules[] = {
    &ble_tracker_detect_module,
    &wifi_rogue_ap_detect_module,
    &wifi_deauth_detect_module,
};
#define MODULE_COUNT (sizeof(s_modules) / sizeof(s_modules[0]))

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    nexus_wifi_connect_blocking();

    for (size_t i = 0; i < MODULE_COUNT; i++) {
        esp_err_t err = s_modules[i]->init();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "module '%s' init failed: %s", s_modules[i]->name, esp_err_to_name(err));
        }
    }

    const char *module_names[MODULE_COUNT];
    for (size_t i = 0; i < MODULE_COUNT; i++) {
        module_names[i] = s_modules[i]->name;
    }

    uint32_t retry_delay_ms = REGISTER_RETRY_INITIAL_DELAY_MS;
    while (nexus_client_register(NEXUS_PROBE_ID, NEXUS_PROBE_NAME, module_names, MODULE_COUNT) != ESP_OK) {
        ESP_LOGW(TAG, "registration failed (backend unreachable/cold?); retrying in %ums", (unsigned)retry_delay_ms);
        vTaskDelay(pdMS_TO_TICKS(retry_delay_ms));
        retry_delay_ms = retry_delay_ms * 2 < REGISTER_RETRY_MAX_DELAY_MS ? retry_delay_ms * 2 : REGISTER_RETRY_MAX_DELAY_MS;
    }

    char detail[160];
    while (1) {
        // battery_pct=-1: no fuel gauge on this hardware yet.
        esp_err_t hb_err = nexus_client_heartbeat(NEXUS_PROBE_ID, -1);
        if (hb_err != ESP_OK) {
            // Either a transient blip, or the backend's state was wiped (free-
            // tier redeploy/restart) and it no longer knows this probe_id -
            // re-registering is harmless either way (the backend upserts) and
            // self-heals both without needing to tell the two cases apart.
            ESP_LOGW(TAG, "heartbeat failed, re-registering");
            nexus_client_register(NEXUS_PROBE_ID, NEXUS_PROBE_NAME, module_names, MODULE_COUNT);
        }

        for (size_t i = 0; i < MODULE_COUNT; i++) {
            esp_err_t err = s_modules[i]->run(detail, sizeof(detail));
            if (err == ESP_OK) {
                // All current modules are detection modules (live
                // observations -> the Alert feed). Once an audit module
                // is added here, branch on module type and call
                // nexus_client_report_finding() for those instead.
                nexus_client_report_alert(NEXUS_PROBE_ID, s_modules[i]->name, detail, s_modules[i]->severity);
            } else if (err != ESP_ERR_NOT_FOUND) {
                ESP_LOGW(TAG, "module '%s' run failed: %s", s_modules[i]->name, esp_err_to_name(err));
            }
        }

        vTaskDelay(pdMS_TO_TICKS(MODULE_RUN_PAUSE_MS));
    }
}
