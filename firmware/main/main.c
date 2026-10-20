#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#include "nexus_module.h"
#include "nexus_client.h"
#include "nexus_config.h"
#include "ble_tracker_detect.h"
#include "wifi_rogue_ap_detect.h"

static const char *TAG = "nexus_main";

#define WIFI_CONNECT_TIMEOUT_MS 15000
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define MODULE_RUN_PAUSE_MS 5000

// Every module this probe runs. Add a module's `_module` symbol here to
// enroll it — main.c loops over this array generically rather than
// special-casing each one.
static const nexus_module_t *s_modules[] = {
    &ble_tracker_detect_module,
    &wifi_rogue_ap_detect_module,
};
#define MODULE_COUNT (sizeof(s_modules) / sizeof(s_modules[0]))

static EventGroupHandle_t s_wifi_event_group;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta_and_wait(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = NEXUS_WIFI_SSID,
            .password = NEXUS_WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connected");
    } else {
        ESP_LOGW(TAG, "WiFi connect timed out after %dms; continuing anyway "
                       "(backend reports will just fail until it connects)",
                 WIFI_CONNECT_TIMEOUT_MS);
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta_and_wait();

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
    nexus_client_register(NEXUS_PROBE_ID, NEXUS_PROBE_NAME, module_names, MODULE_COUNT);

    char detail[160];
    while (1) {
        // battery_pct=-1: no fuel gauge on this hardware yet.
        nexus_client_heartbeat(NEXUS_PROBE_ID, -1);

        for (size_t i = 0; i < MODULE_COUNT; i++) {
            esp_err_t err = s_modules[i]->run(detail, sizeof(detail));
            if (err == ESP_OK) {
                // All current modules are detection modules (live
                // observations -> the Alert feed). Once an audit module
                // is added here, branch on module type and call
                // nexus_client_report_finding() for those instead.
                nexus_client_report_alert(NEXUS_PROBE_ID, s_modules[i]->name, detail, "warning");
            } else if (err != ESP_ERR_NOT_FOUND) {
                ESP_LOGW(TAG, "module '%s' run failed: %s", s_modules[i]->name, esp_err_to_name(err));
            }
        }

        vTaskDelay(pdMS_TO_TICKS(MODULE_RUN_PAUSE_MS));
    }
}
