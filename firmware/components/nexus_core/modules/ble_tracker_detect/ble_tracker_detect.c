#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_hs_adv.h"
#include "host/util/util.h"

#include "ble_tracker_detect.h"

static const char *TAG = "ble_tracker_detect";

// How many consecutive scan windows an unknown device must be seen in
// before it's flagged as "following" the probe (persistence-based generic
// tracker detection — catches non-Apple trackers we can't identify by
// advertisement content alone).
#define PERSISTENCE_THRESHOLD 3
#define MAX_TRACKED_DEVICES 32
#define SCAN_WINDOW_MS 10000

typedef struct {
    ble_addr_t addr;
    uint8_t seen_count;
    bool in_use;
    bool reported;
} tracked_device_t;

static tracked_device_t s_devices[MAX_TRACKED_DEVICES];
static SemaphoreHandle_t s_sync_sem;

// Set by the GAP event handler during a scan window, read by run() once the
// window closes.
static bool s_findmy_seen;
static ble_addr_t s_findmy_addr;
static char *s_persistent_hit_detail;
static size_t s_persistent_hit_detail_len;

static void addr_to_str(const ble_addr_t *addr, char *out, size_t out_len)
{
    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
              addr->val[5], addr->val[4], addr->val[3],
              addr->val[2], addr->val[1], addr->val[0]);
}

// Apple's Find My network accessory format (public, documented spec):
// manufacturer id 0x004C (little-endian bytes 0x4C, 0x00), type byte 0x12.
static bool is_apple_findmy(const struct ble_hs_adv_fields *fields)
{
    return fields->mfg_data != NULL && fields->mfg_data_len >= 3 &&
           fields->mfg_data[0] == 0x4C && fields->mfg_data[1] == 0x00 &&
           fields->mfg_data[2] == 0x12;
}

static tracked_device_t *find_or_add_device(const ble_addr_t *addr)
{
    tracked_device_t *free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED_DEVICES; i++) {
        if (s_devices[i].in_use && memcmp(&s_devices[i].addr, addr, sizeof(*addr)) == 0) {
            return &s_devices[i];
        }
        if (!s_devices[i].in_use && free_slot == NULL) {
            free_slot = &s_devices[i];
        }
    }
    if (free_slot != NULL) {
        free_slot->in_use = true;
        free_slot->addr = *addr;
        free_slot->seen_count = 0;
        free_slot->reported = false;
    }
    return free_slot;
}

static int gap_event_handler(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        struct ble_hs_adv_fields fields;
        if (ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data) != 0) {
            return 0;
        }

        if (is_apple_findmy(&fields) && !s_findmy_seen) {
            s_findmy_seen = true;
            s_findmy_addr = event->disc.addr;
        }

        tracked_device_t *dev = find_or_add_device(&event->disc.addr);
        if (dev != NULL) {
            if (dev->seen_count < UINT8_MAX) {
                dev->seen_count++;
            }
            if (dev->seen_count >= PERSISTENCE_THRESHOLD && !dev->reported &&
                s_persistent_hit_detail != NULL) {
                dev->reported = true;
                char mac[18];
                addr_to_str(&dev->addr, mac, sizeof(mac));
                snprintf(s_persistent_hit_detail, s_persistent_hit_detail_len,
                         "Unknown BLE device %s seen in %u consecutive scan windows",
                         mac, dev->seen_count);
            }
        }
        return 0;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE:
        return 0;
    default:
        return 0;
    }
}

static void start_scan(void)
{
    uint8_t own_addr_type;
    if (ble_hs_id_infer_auto(0, &own_addr_type) != 0) {
        ESP_LOGW(TAG, "could not infer own address type");
        return;
    }

    struct ble_gap_disc_params disc_params = {
        .filter_duplicates = 0, // we need every report to count persistence correctly
        .passive = 1,           // never send scan requests — listen only
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    int rc = ble_gap_disc(own_addr_type, SCAN_WINDOW_MS, &disc_params, gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_gap_disc failed; rc=%d", rc);
    }
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE stack reset; reason=%d", reason);
}

static void on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    xSemaphoreGive(s_sync_sem);
}

static void host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static esp_err_t ble_tracker_detect_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        return err;
    }

    memset(s_devices, 0, sizeof(s_devices));
    s_sync_sem = xSemaphoreCreateBinary();
    if (s_sync_sem == NULL) {
        return ESP_ERR_NO_MEM;
    }

    err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(err));
        return err;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;

    nimble_port_freertos_init(host_task);

    // on_sync() runs once the NimBLE host finishes starting up; block here
    // so run() is never called before the stack is ready to scan.
    if (xSemaphoreTake(s_sync_sem, pdMS_TO_TICKS(10000)) != pdTRUE) {
        ESP_LOGE(TAG, "timed out waiting for NimBLE sync");
        return ESP_ERR_TIMEOUT;
    }

    return ESP_OK;
}

static esp_err_t ble_tracker_detect_run(char *out_detail, size_t out_detail_len)
{
    s_findmy_seen = false;
    s_persistent_hit_detail = out_detail;
    s_persistent_hit_detail_len = out_detail_len;
    if (out_detail != NULL && out_detail_len > 0) {
        out_detail[0] = '\0';
    }

    start_scan();
    vTaskDelay(pdMS_TO_TICKS(SCAN_WINDOW_MS + 500));

    if (s_findmy_seen) {
        char mac[18];
        addr_to_str(&s_findmy_addr, mac, sizeof(mac));
        if (out_detail != NULL && out_detail_len > 0) {
            snprintf(out_detail, out_detail_len,
                     "Apple Find My accessory advertising nearby (%s)", mac);
        }
        return ESP_OK;
    }

    if (out_detail != NULL && out_detail[0] != '\0') {
        // A persistence-based hit was already written into out_detail by
        // the GAP event handler during this scan window.
        return ESP_OK;
    }

    return ESP_ERR_NOT_FOUND;
}

const nexus_module_t ble_tracker_detect_module = {
    .name = "ble_tracker_detect",
    .init = ble_tracker_detect_init,
    .run = ble_tracker_detect_run,
};
