#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Pure detection logic for the rogue-AP / evil-twin check. Deliberately free
 * of any ESP-IDF dependency so it can be unit-tested on a normal PC.
 */

typedef enum {
    AP_SECURITY_OPEN = 0,   // no encryption (also WEP, which offers none worth the name)
    AP_SECURITY_PROTECTED,  // WPA / WPA2 / WPA3 (personal or enterprise)
} ap_security_t;

typedef struct {
    char ssid[33];          // NUL-terminated; empty for hidden networks
    uint8_t bssid[6];
    ap_security_t security;
} ap_observation_t;

/**
 * Look for the classic evil-twin signature: the same SSID being broadcast by
 * different access points where one is protected and another is OPEN. Many
 * access points sharing an SSID with the SAME security is normal (mesh,
 * multi-AP office) and is NOT flagged. Hidden SSIDs are ignored.
 *
 * Returns the number of distinct SSIDs flagged. If at least one is flagged
 * and out_detail is non-NULL, a short human-readable description of the
 * first one is written to it (SSID text is sanitised to printable ASCII).
 */
int rogue_ap_find_security_mismatch(const ap_observation_t *aps, size_t count,
                                    char *out_detail, size_t out_detail_len);
