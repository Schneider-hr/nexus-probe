#include <string.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include "nexus_client.h"
#include "nexus_config.h"

static const char *TAG = "nexus_client";

// Buffers big enough for a real device-registration reply; the backend's
// responses are small JSON objects, not a data stream, so a fixed buffer
// read in one shot is fine here (no chunked reassembly needed).
#define HTTP_RESP_BUF_LEN 512

static esp_err_t post_json(const char *path, cJSON *body)
{
    char *payload = cJSON_PrintUnformatted(body);
    if (payload == NULL) {
        ESP_LOGE(TAG, "cJSON_PrintUnformatted failed");
        return ESP_FAIL;
    }

    char url[256];
    snprintf(url, sizeof(url), "%s%s", NEXUS_BACKEND_URL, path);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 8000,
#if NEXUS_BACKEND_USE_TLS
        .crt_bundle_attach = esp_crt_bundle_attach,
#endif
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        free(payload);
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-Nexus-Probe-Key", NEXUS_PROBE_KEY);
    esp_http_client_set_post_field(client, payload, strlen(payload));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        if (status < 200 || status >= 300) {
            ESP_LOGW(TAG, "POST %s -> HTTP %d", path, status);
            err = ESP_FAIL;
        } else {
            ESP_LOGI(TAG, "POST %s -> HTTP %d", path, status);
        }
    } else {
        ESP_LOGE(TAG, "POST %s failed: %s", path, esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    free(payload);
    return err;
}

esp_err_t nexus_client_register(const char *probe_id, const char *name,
                                 const char *const *modules, size_t module_count)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "probe_id", probe_id);
    cJSON_AddStringToObject(body, "name", name);
    cJSON *mods = cJSON_AddArrayToObject(body, "modules");
    for (size_t i = 0; i < module_count; i++) {
        cJSON_AddItemToArray(mods, cJSON_CreateString(modules[i]));
    }

    esp_err_t err = post_json("/api/v1/probes/register", body);
    cJSON_Delete(body);
    return err;
}

esp_err_t nexus_client_heartbeat(const char *probe_id, int battery_pct)
{
    cJSON *body = cJSON_CreateObject();
    // A negative value means "no fuel gauge": leave the field out (the
    // backend only accepts 0-100) rather than sending a made-up number.
    if (battery_pct >= 0 && battery_pct <= 100) {
        cJSON_AddNumberToObject(body, "battery_pct", battery_pct);
    }
    cJSON_AddStringToObject(body, "status", "online");

    char path[96];
    snprintf(path, sizeof(path), "/api/v1/probes/%s/heartbeat", probe_id);

    esp_err_t err = post_json(path, body);
    cJSON_Delete(body);
    return err;
}

esp_err_t nexus_client_report_finding(const char *probe_id, const char *module,
                                       const char *location, const char *detail)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "probe_id", probe_id);
    cJSON_AddStringToObject(body, "module", module);
    if (location != NULL && location[0] != '\0') {
        cJSON_AddStringToObject(body, "location", location);
    }
    if (detail != NULL && detail[0] != '\0') {
        cJSON_AddStringToObject(body, "detail", detail);
    }

    esp_err_t err = post_json("/api/v1/findings", body);
    cJSON_Delete(body);
    return err;
}

esp_err_t nexus_client_report_alert(const char *probe_id, const char *module,
                                     const char *message, const char *severity)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "probe_id", probe_id);
    cJSON_AddStringToObject(body, "module", module);
    cJSON_AddStringToObject(body, "message", message);
    cJSON_AddStringToObject(body, "severity", severity);

    esp_err_t err = post_json("/api/v1/alerts", body);
    cJSON_Delete(body);
    return err;
}
