idf_component_register(
    SRCS "src/nexus_client.c" "modules/ble_tracker_detect/ble_tracker_detect.c"
    INCLUDE_DIRS "include" "modules/ble_tracker_detect"
    REQUIRES esp_http_client json mbedtls bt nvs_flash esp_wifi
)
