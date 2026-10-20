// Host-side unit tests for the rogue-AP detection logic (no ESP-IDF needed).
// Build and run on a normal PC, e.g.:
//   gcc -Wall -Wextra -I components/nexus_core/modules/wifi_rogue_ap_detect \
//       tests/test_rogue_ap_logic.c components/nexus_core/modules/wifi_rogue_ap_detect/rogue_ap_logic.c -o test && ./test
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "rogue_ap_logic.h"

static ap_observation_t ap(const char *ssid, uint8_t last_octet, ap_security_t sec)
{
    ap_observation_t a;
    memset(&a, 0, sizeof(a));
    strncpy(a.ssid, ssid, sizeof(a.ssid) - 1);
    a.bssid[0] = 0xAA; a.bssid[5] = last_octet;
    a.security = sec;
    return a;
}

static void test_open_twin_of_protected_network_is_flagged(void)
{
    ap_observation_t aps[] = { ap("CorpWiFi", 1, AP_SECURITY_PROTECTED), ap("CorpWiFi", 2, AP_SECURITY_OPEN) };
    char detail[160];
    assert(rogue_ap_find_security_mismatch(aps, 2, detail, sizeof(detail)) == 1);
    assert(strstr(detail, "CorpWiFi") != NULL);
    assert(strstr(detail, "AA:00:00:00:00:02") != NULL); // the OPEN one is named
    assert(strstr(detail, "AA:00:00:00:00:01") != NULL);
}

static void test_order_does_not_matter(void)
{
    ap_observation_t aps[] = { ap("CorpWiFi", 2, AP_SECURITY_OPEN), ap("Other", 9, AP_SECURITY_PROTECTED), ap("CorpWiFi", 1, AP_SECURITY_PROTECTED) };
    assert(rogue_ap_find_security_mismatch(aps, 3, NULL, 0) == 1);
}

static void test_mesh_with_same_security_is_not_flagged(void)
{
    ap_observation_t aps[] = { ap("HomeMesh", 1, AP_SECURITY_PROTECTED), ap("HomeMesh", 2, AP_SECURITY_PROTECTED), ap("HomeMesh", 3, AP_SECURITY_PROTECTED) };
    assert(rogue_ap_find_security_mismatch(aps, 3, NULL, 0) == 0);
}

static void test_open_guest_network_alone_is_not_flagged(void)
{
    ap_observation_t aps[] = { ap("CafeGuest", 1, AP_SECURITY_OPEN), ap("CafeGuest", 2, AP_SECURITY_OPEN) };
    assert(rogue_ap_find_security_mismatch(aps, 2, NULL, 0) == 0);
}

static void test_different_ssids_are_not_compared(void)
{
    ap_observation_t aps[] = { ap("Office", 1, AP_SECURITY_PROTECTED), ap("OfficeGuest", 2, AP_SECURITY_OPEN) };
    assert(rogue_ap_find_security_mismatch(aps, 2, NULL, 0) == 0);
}

static void test_hidden_ssids_are_ignored(void)
{
    ap_observation_t aps[] = { ap("", 1, AP_SECURITY_PROTECTED), ap("", 2, AP_SECURITY_OPEN) };
    assert(rogue_ap_find_security_mismatch(aps, 2, NULL, 0) == 0);
}

static void test_each_ssid_counted_once_even_with_many_aps(void)
{
    ap_observation_t aps[] = {
        ap("A", 1, AP_SECURITY_PROTECTED), ap("A", 2, AP_SECURITY_OPEN), ap("A", 3, AP_SECURITY_OPEN), ap("A", 4, AP_SECURITY_PROTECTED),
        ap("B", 5, AP_SECURITY_PROTECTED), ap("B", 6, AP_SECURITY_OPEN),
    };
    assert(rogue_ap_find_security_mismatch(aps, 6, NULL, 0) == 2);
}

static void test_ssid_is_sanitised_and_output_is_bounded(void)
{
    ap_observation_t aps[] = { ap("Evil\"\\\x01net", 1, AP_SECURITY_PROTECTED), ap("Evil\"\\\x01net", 2, AP_SECURITY_OPEN) };
    char small[40];
    memset(small, 'X', sizeof(small));
    assert(rogue_ap_find_security_mismatch(aps, 2, small, sizeof(small)) == 1);
    assert(small[sizeof(small) - 1] == '\0' || strlen(small) < sizeof(small)); // never overruns
    char big[160];
    rogue_ap_find_security_mismatch(aps, 2, big, sizeof(big));
    assert(strchr(big, '\x01') == NULL);
    assert(strstr(big, "Evil???net") != NULL);
}

static void test_empty_input(void)
{
    assert(rogue_ap_find_security_mismatch(NULL, 0, NULL, 0) == 0);
}

int main(void)
{
    test_open_twin_of_protected_network_is_flagged();
    test_order_does_not_matter();
    test_mesh_with_same_security_is_not_flagged();
    test_open_guest_network_alone_is_not_flagged();
    test_different_ssids_are_not_compared();
    test_hidden_ssids_are_ignored();
    test_each_ssid_counted_once_even_with_many_aps();
    test_ssid_is_sanitised_and_output_is_bounded();
    test_empty_input();
    printf("all rogue-AP logic tests passed\n");
    return 0;
}
