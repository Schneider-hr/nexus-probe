idf_component_register(
    SRCS "src/nexus_client.c"
         "modules/ble_tracker_detect/ble_tracker_detect.c"
         "modules/wifi_rogue_ap_detect/wifi_rogue_ap_detect.c"
         "modules/wifi_rogue_ap_detect/rogue_ap_logic.c"
    INCLUDE_DIRS "include" "modules/ble_tracker_detect" "modules/wifi_rogue_ap_detect"
    REQUIRES esp_http_client json mbedtls bt nvs_flash esp_wifi
)
