#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"

#include "wifi_deauth_detect.h"

static const char *TAG = "wifi_deauth_detect";

#define SCAN_WINDOW_MS 10000
// A handful of deauth/disassoc frames during normal operation is routine
// (a device roaming off, an AP cleaning up a stale association). A real
// attack floods many per second, so only a burst at or above this count
// within one window is reported - keeps ordinary WiFi housekeeping from
// being flagged as an attack.
#define DEAUTH_BURST_THRESHOLD 15

// Top 6 bits of the first frame-control byte = subtype(4 bits) + type(2
// bits), ignoring the low 2 protocol-version bits (always 0 in practice).
#define FRAME_TYPE_SUBTYPE_MASK 0xFC
#define DEAUTH_TYPE_SUBTYPE 0xC0    // type=management(00), subtype=deauth(1100)
#define DISASSOC_TYPE_SUBTYPE 0xA0  // type=management(00), subtype=disassoc(1010)

static portMUX_TYPE s_counter_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_deauth_count;
static uint32_t s_disassoc_count;
static uint8_t s_last_bssid[6];
static bool s_have_bssid;

// Runs in the WiFi driver's own task context (not a true ISR) - kept short,
// and never reads past what the driver itself reports as received (sig_len
// comes from the radio, not from attacker-controlled frame content).
static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) {
        return;
    }
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    // Need frame-control(2) + duration(2) + addr1(6) + addr2(6) + addr3(6) = 22 bytes.
    if (pkt->rx_ctrl.sig_len < 22) {
        return;
    }
    const uint8_t *payload = pkt->payload;
    uint8_t type_subtype = payload[0] & FRAME_TYPE_SUBTYPE_MASK;

    if (type_subtype != DEAUTH_TYPE_SUBTYPE && type_subtype != DISASSOC_TYPE_SUBTYPE) {
        return;
    }

    portENTER_CRITICAL(&s_counter_mux);
    if (type_subtype == DEAUTH_TYPE_SUBTYPE) {
        s_deauth_count++;
    } else {
        s_disassoc_count++;
    }
    memcpy(s_last_bssid, payload + 16, 6); // addr3 = BSSID
    s_have_bssid = true;
    portEXIT_CRITICAL(&s_counter_mux);
}

static esp_err_t wifi_deauth_detect_init(void)
{
    // WiFi is already initialized and connected in station mode by main.c
    // (via nexus_wifi_connect_blocking) - this just layers a promiscuous-mode
    // receive callback on top. Receiving extra frames alongside an active
    // STA association is normal, supported behavior; nothing is transmitted.
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_err_t err = esp_wifi_set_promiscuous_filter(&filter);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous_filter failed: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_promiscuous_rx_cb failed: %s", esp_err_to_name(err));
        return err;
    }
    return esp_wifi_set_promiscuous(true);
}

static esp_err_t wifi_deauth_detect_run(char *out_detail, size_t out_detail_len)
{
    vTaskDelay(pdMS_TO_TICKS(SCAN_WINDOW_MS));

    uint32_t deauth, disassoc;
    uint8_t bssid[6];
    bool have_bssid;
    portENTER_CRITICAL(&s_counter_mux);
    deauth = s_deauth_count;
    disassoc = s_disassoc_count;
    have_bssid = s_have_bssid;
    memcpy(bssid, s_last_bssid, sizeof(bssid));
    s_deauth_count = 0;
    s_disassoc_count = 0;
    s_have_bssid = false;
    portEXIT_CRITICAL(&s_counter_mux);

    uint32_t total = deauth + disassoc;
    if (total < DEAUTH_BURST_THRESHOLD) {
        return ESP_ERR_NOT_FOUND;
    }

    if (out_detail != NULL && out_detail_len > 0) {
        if (have_bssid) {
            snprintf(out_detail, out_detail_len,
                     "%" PRIu32 " deauth/disassoc frames in %ds targeting BSSID "
                     "%02X:%02X:%02X:%02X:%02X:%02X - possible deauthentication attack",
                     total, SCAN_WINDOW_MS / 1000,
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        } else {
            snprintf(out_detail, out_detail_len,
                     "%" PRIu32 " deauth/disassoc frames in %ds - possible deauthentication attack",
                     total, SCAN_WINDOW_MS / 1000);
        }
    }
    return ESP_OK;
}

const nexus_module_t wifi_deauth_detect_module = {
    .name = "wifi_deauth_detect",
    .severity = "critical", // an active attack in progress, not just a passive observation
    .init = wifi_deauth_detect_init,
    .run = wifi_deauth_detect_run,
};
