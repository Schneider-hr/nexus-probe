idf_component_register(
    SRCS "src/nexus_client.c"
         "src/nexus_wifi.c"
         "modules/ble_tracker_detect/ble_tracker_detect.c"
         "modules/wifi_rogue_ap_detect/wifi_rogue_ap_detect.c"
         "modules/wifi_rogue_ap_detect/rogue_ap_logic.c"
         "modules/wifi_deauth_detect/wifi_deauth_detect.c"
    INCLUDE_DIRS "include" "modules/ble_tracker_detect" "modules/wifi_rogue_ap_detect" "modules/wifi_deauth_detect"
    REQUIRES esp_http_client esp_http_server json mbedtls bt nvs_flash esp_wifi esp_netif lwip
)
