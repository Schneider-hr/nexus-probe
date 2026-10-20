#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "wifi_rogue_ap_detect.h"
#include "rogue_ap_logic.h"

static const char *TAG = "wifi_rogue_ap";

#define MAX_APS 40

// Static, not stack: the main task's stack is small and a full scan result
// plus the converted list would be several kilobytes.
static wifi_ap_record_t s_records[MAX_APS];
static ap_observation_t s_observations[MAX_APS];

static esp_err_t wifi_rogue_ap_detect_init(void)
{
    // Wi-Fi is already initialised and started in station mode by main.c
    // (the probe needs it to report to the backend), so nothing to set up.
    return ESP_OK;
}

static ap_security_t classify(wifi_auth_mode_t mode)
{
    // WEP is treated as open: it provides no real protection, so an "open or
    // WEP" twin of a WPA network is exactly what an impersonator would use.
    return (mode == WIFI_AUTH_OPEN || mode == WIFI_AUTH_WEP) ? AP_SECURITY_OPEN : AP_SECURITY_PROTECTED;
}

static esp_err_t wifi_rogue_ap_detect_run(char *out_detail, size_t out_detail_len)
{
    if (out_detail != NULL && out_detail_len > 0) {
        out_detail[0] = '\0';
    }

    wifi_scan_config_t scan_cfg = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_PASSIVE,
        .scan_time.passive = 360, // ms listening per channel
    };
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true /* block until done */);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan failed: %s", esp_err_to_name(err));
        return err;
    }

    uint16_t count = MAX_APS;
    err = esp_wifi_scan_get_ap_records(&count, s_records);
    if (err != ESP_OK) {
        return err;
    }

    for (uint16_t i = 0; i < count; i++) {
        memset(&s_observations[i], 0, sizeof(s_observations[i]));
        strncpy(s_observations[i].ssid, (const char *)s_records[i].ssid, sizeof(s_observations[i].ssid) - 1);
        memcpy(s_observations[i].bssid, s_records[i].bssid, 6);
        s_observations[i].security = classify(s_records[i].authmode);
    }

    int flagged = rogue_ap_find_security_mismatch(s_observations, count, out_detail, out_detail_len);
    ESP_LOGI(TAG, "scan saw %u access points, %d suspicious", (unsigned)count, flagged);
    return flagged > 0 ? ESP_OK : ESP_ERR_NOT_FOUND;
}

const nexus_module_t wifi_rogue_ap_detect_module = {
    .name = "wifi_rogue_ap_detect",
    .init = wifi_rogue_ap_detect_init,
    .run = wifi_rogue_ap_detect_run,
};
