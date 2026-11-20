/**
 * WiFi connection with self-service provisioning — see nexus_wifi.h.
 *
 * Security notes (read this before changing the defaults):
 *
 *   - The setup AP is WPA2, not open. An open setup AP would let anyone
 *     within range during provisioning both read the real WiFi password
 *     off the air as it's submitted, and race to submit a *rogue* network
 *     first — on a probe whose whole job is catching rogue APs, shipping
 *     with an open one would be an embarrassing contradiction. The setup
 *     passphrase (NEXUS_SETUP_AP_PASSWORD) is meant to be handed to
 *     whoever is deploying the probe out of band (e.g. printed in the
 *     handoff docs), never sent over the air itself.
 *   - The setup AP only runs for NEXUS_PROVISION_WINDOW_MS per boot, then
 *     the device restarts rather than leaving it open indefinitely. This
 *     bounds how long the device is ever in its lower-security setup mode
 *     to a short, observable window instead of a standing target.
 *   - The DNS responder below exists purely so a phone/laptop's captive-
 *     portal detection opens the setup page automatically, the same trick
 *     real consumer IoT devices use. It deliberately does NOT parse the
 *     incoming question beyond checking the packet is long enough to hold
 *     one — every query gets the same canned "go to 192.168.4.1" answer,
 *     so there is nothing here that inspects or trusts attacker-controlled
 *     content beyond a minimum-length check.
 *   - Credentials are stored in NVS, which is NOT flash-encrypted by
 *     default on this project yet — see the firmware README for why that
 *     tradeoff was made deliberately for now, and how to enable it later.
 */

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_http_server.h"
#include "lwip/sockets.h"

#include "nexus_wifi.h"
#include "nexus_config.h"

static const char *TAG = "nexus_wifi";

#define NVS_NAMESPACE "nexus_wifi"
#define NVS_KEY_SSID "ssid"
#define NVS_KEY_PASS "pass"

#define STA_CONNECT_TIMEOUT_MS 15000
#define STA_CONNECT_RETRIES 2
#define PROVISION_WINDOW_MS (10 * 60 * 1000) // 10 minutes per boot, then restart — see file docstring
#define DNS_PORT 53
#define SOFTAP_IP "192.168.4.1" // ESP-IDF's default SoftAP address; not queried, just documented

#define WIFI_CONNECTED_BIT BIT0
#define CREDENTIALS_SAVED_BIT BIT0

static EventGroupHandle_t s_sta_event_group;
static EventGroupHandle_t s_provision_event_group;
static httpd_handle_t s_httpd = NULL;
static TaskHandle_t s_dns_task = NULL;
static volatile bool s_dns_task_should_stop = false;

// --- NVS ---

static bool load_credentials(char *ssid, size_t ssid_len, char *pass, size_t pass_len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t s_len = ssid_len, p_len = pass_len;
    esp_err_t s_err = nvs_get_str(h, NVS_KEY_SSID, ssid, &s_len);
    esp_err_t p_err = nvs_get_str(h, NVS_KEY_PASS, pass, &p_len);
    nvs_close(h);
    return s_err == ESP_OK && p_err == ESP_OK && ssid[0] != '\0';
}

static esp_err_t save_credentials(const char *ssid, const char *pass)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_str(h, NVS_KEY_SSID, ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(h, NVS_KEY_PASS, pass);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

// --- station mode ---

static void sta_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_sta_event_group, WIFI_CONNECTED_BIT);
    }
}

// Tries once to connect with whatever's in NVS. Returns true if it got an IP
// before the timeout.
static bool try_connect_sta(const char *ssid, const char *pass)
{
    s_sta_event_group = xEventGroupCreate();

    esp_event_handler_instance_t wifi_handler, ip_handler;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &sta_event_handler, NULL, &wifi_handler));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &sta_event_handler, NULL, &ip_handler));

    wifi_config_t wifi_config = {0};
    strlcpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_sta_event_group, WIFI_CONNECTED_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(STA_CONNECT_TIMEOUT_MS));
    bool connected = (bits & WIFI_CONNECTED_BIT) != 0;

    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_handler);
    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, ip_handler);
    vEventGroupDelete(s_sta_event_group);

    if (!connected) {
        esp_wifi_stop();
    }
    return connected;
}

// --- captive-portal DNS responder ---
//
// Answers every query with an A record for SOFTAP_IP, so a phone/laptop's
// "is this network captive?" probe gets a real-looking answer and opens
// the setup page automatically. Only ever reads the fixed-size header
// fields it needs and the minimum length to locate the question's end —
// never indexes past what recvfrom() actually returned.
static void dns_responder_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "dns socket() failed");
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "dns bind() failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t req[512];
    uint8_t resp[512 + 16];
    while (!s_dns_task_should_stop) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, req, sizeof(req), 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            continue; // timeout (so the stop flag gets checked) or a benign recv error
        }
        // Need at least a 12-byte header and a question with a non-empty
        // name and 4 bytes of QTYPE/QCLASS, i.e. 12 + 1 + 4 at minimum.
        if (n < 17) {
            continue;
        }
        // Find the question name's terminating zero byte, bounded by what
        // we actually received — never trust a length claimed inside the
        // packet itself.
        int qend = 12;
        while (qend < n && req[qend] != 0) {
            qend++;
        }
        if (qend >= n || qend + 5 > n) {
            continue; // malformed or truncated; drop it silently
        }
        int qlen = qend + 5 - 12; // name + null + QTYPE(2) + QCLASS(2)

        int rlen = 0;
        memcpy(resp, req, 12);
        resp[2] = 0x81; // QR=1 (response), RD copied below
        resp[3] = 0x80; // RA=1, rcode=0
        resp[2] |= (req[2] & 0x01); // preserve RD bit from the query
        resp[6] = 0x00; resp[7] = 0x01; // ANCOUNT=1
        resp[8] = 0x00; resp[9] = 0x00; // NSCOUNT=0
        resp[10] = 0x00; resp[11] = 0x00; // ARCOUNT=0
        rlen = 12;
        memcpy(resp + rlen, req + 12, qlen - 12); // echo the question back as-is
        rlen += qlen - 12;

        // Answer: name = pointer to offset 12, TYPE A, CLASS IN, TTL 60, 4-byte RDATA.
        uint8_t answer[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
                               0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                               192, 168, 4, 1};
        if ((size_t)(rlen + sizeof(answer)) > sizeof(resp)) {
            continue; // would not fit; drop rather than overflow
        }
        memcpy(resp + rlen, answer, sizeof(answer));
        rlen += sizeof(answer);

        sendto(sock, resp, rlen, 0, (struct sockaddr *)&from, from_len);
    }
    close(sock);
    vTaskDelete(NULL);
}

// --- setup HTTP server ---

static const char SETUP_PAGE[] =
    "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Nexus probe setup</title></head><body style='font-family:sans-serif;max-width:420px;margin:40px auto;padding:0 16px'>"
    "<h2>Connect this Nexus probe to WiFi</h2>"
    "<p>Enter the WiFi network this probe should join and report over. "
    "This page is only served to devices connected to the probe's own setup network.</p>"
    "<form method='POST' action='/save'>"
    "<label>Network name (SSID)<br><input name='ssid' maxlength='32' required style='width:100%;padding:8px;margin:6px 0'></label><br>"
    "<label>Password<br><input name='password' type='password' maxlength='64' style='width:100%;padding:8px;margin:6px 0'></label><br>"
    "<button type='submit' style='padding:10px 20px;margin-top:10px'>Save and connect</button>"
    "</form></body></html>";

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, SETUP_PAGE, HTTPD_RESP_USE_STRLEN);
}

// Decodes a application/x-www-form-urlencoded value in place; '+' -> space,
// '%XX' -> byte. Stops safely at the input's own NUL; never writes past
// out_len.
static void urldecode(const char *in, char *out, size_t out_len)
{
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0' && o + 1 < out_len; i++) {
        if (in[i] == '+') {
            out[o++] = ' ';
        } else if (in[i] == '%' && isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
            char hex[3] = {in[i + 1], in[i + 2], 0};
            out[o++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
}

// Finds "key=value" within a urlencoded body and url-decodes the value into out.
static bool form_get(const char *body, const char *key, char *out, size_t out_len)
{
    size_t key_len = strlen(key);
    const char *p = body;
    while (p != NULL) {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            const char *val_start = p + key_len + 1;
            const char *amp = strchr(val_start, '&');
            char raw[160];
            size_t raw_len = amp ? (size_t)(amp - val_start) : strlen(val_start);
            if (raw_len >= sizeof(raw)) {
                raw_len = sizeof(raw) - 1;
            }
            memcpy(raw, val_start, raw_len);
            raw[raw_len] = '\0';
            urldecode(raw, out, out_len);
            return true;
        }
        p = strchr(p, '&');
        if (p != NULL) {
            p++;
        }
    }
    return false;
}

static esp_err_t save_post_handler(httpd_req_t *req)
{
    char body[256];
    size_t len = req->content_len < sizeof(body) - 1 ? req->content_len : sizeof(body) - 1;
    int received = httpd_req_recv(req, body, len);
    if (received <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    body[received] = '\0';

    char ssid[33] = {0};
    char pass[65] = {0};
    if (!form_get(body, "ssid", ssid, sizeof(ssid)) || ssid[0] == '\0') {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_send(req, "Missing network name", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    form_get(body, "password", pass, sizeof(pass)); // open networks: empty password is valid

    esp_err_t err = save_credentials(ssid, pass);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_credentials failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, "<html><body style='font-family:sans-serif'>"
                          "<h3>Saved. The probe is restarting and will join that network.</h3>"
                          "</body></html>", HTTPD_RESP_USE_STRLEN);

    ESP_LOGI(TAG, "credentials saved for SSID '%s'; restarting", ssid);
    xEventGroupSetBits(s_provision_event_group, CREDENTIALS_SAVED_BIT);
    return ESP_OK;
}

static httpd_handle_t start_setup_httpd(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 4;
    config.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return NULL;
    }

    httpd_uri_t save_uri = {.uri = "/save", .method = HTTP_POST, .handler = save_post_handler};
    httpd_register_uri_handler(server, &save_uri);

    // Everything else (the setup page itself, and every OS's captive-portal
    // probe path — /generate_204, /hotspot-detect.html, /ncsi.txt, ...) gets
    // the same setup page, which is what makes it auto-open on most devices.
    httpd_uri_t root_uri = {.uri = "/*", .method = HTTP_GET, .handler = root_get_handler};
    httpd_register_uri_handler(server, &root_uri);

    return server;
}

// --- provisioning mode ---

static void run_provisioning_ap(void)
{
    char ap_ssid[48];
    snprintf(ap_ssid, sizeof(ap_ssid), "Nexus-Setup-%s", NEXUS_PROBE_ID);

    wifi_config_t ap_config = {0};
    strlcpy((char *)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(ap_ssid);
    strlcpy((char *)ap_config.ap.password, NEXUS_SETUP_AP_PASSWORD, sizeof(ap_config.ap.password));
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.max_connection = 4;
    ap_config.ap.channel = 1;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGW(TAG, "No working WiFi credentials — started setup AP '%s' (WPA2, see "
                  "NEXUS_SETUP_AP_PASSWORD) for up to %d minutes. Connect to it and "
                  "open any web page to configure this probe's real network.",
             ap_ssid, PROVISION_WINDOW_MS / 60000);

    s_provision_event_group = xEventGroupCreate();
    s_dns_task_should_stop = false;
    xTaskCreate(dns_responder_task, "nexus_dns", 4096, NULL, 5, &s_dns_task);
    s_httpd = start_setup_httpd();

    xEventGroupWaitBits(s_provision_event_group, CREDENTIALS_SAVED_BIT, pdFALSE, pdFALSE,
                         pdMS_TO_TICKS(PROVISION_WINDOW_MS));

    // Either credentials were just saved, or the window timed out with
    // nothing configured — in both cases, restart. Bounding the AP to one
    // boot's window rather than looping in place is deliberate (see this
    // file's top docstring): it turns "open for setup" into a short,
    // observable state instead of a standing one.
    ESP_LOGI(TAG, "leaving provisioning mode; restarting");
    vTaskDelay(pdMS_TO_TICKS(500)); // give the HTTP response time to actually flush
    esp_restart();
}

// --- entry point ---

void nexus_wifi_connect_blocking(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    char ssid[33] = {0};
    char pass[65] = {0};
    bool have_saved = load_credentials(ssid, sizeof(ssid), pass, sizeof(pass));

    if (have_saved) {
        for (int attempt = 1; attempt <= STA_CONNECT_RETRIES; attempt++) {
            ESP_LOGI(TAG, "connecting to saved network '%s' (attempt %d/%d)", ssid, attempt, STA_CONNECT_RETRIES);
            if (try_connect_sta(ssid, pass)) {
                ESP_LOGI(TAG, "WiFi connected");
                return;
            }
        }
        ESP_LOGW(TAG, "could not connect with the saved credentials after %d attempts", STA_CONNECT_RETRIES);
    } else {
        ESP_LOGI(TAG, "no WiFi credentials stored yet");
    }

    run_provisioning_ap(); // does not return — ends in esp_restart()
}
