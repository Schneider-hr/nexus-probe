#include <stdio.h>
#include <string.h>
#include "rogue_ap_logic.h"

static void format_mac(const uint8_t *m, char *out, size_t out_len)
{
    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// SSIDs are attacker-controlled bytes; never print them raw into a report.
static void sanitise(const char *in, char *out, size_t out_len)
{
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0' && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c >= 0x20 && c < 0x7F && c != '"' && c != '\\') ? (char)c : '?';
    }
    out[o] = '\0';
}

int rogue_ap_find_security_mismatch(const ap_observation_t *aps, size_t count,
                                    char *out_detail, size_t out_detail_len)
{
    int flagged = 0;
    int first_written = 0;

    for (size_t i = 0; i < count; i++) {
        if (aps[i].ssid[0] == '\0') {
            continue; // hidden network: nothing to compare by name
        }

        // Only act on the first observation of each SSID, so an SSID is
        // counted once however many access points broadcast it.
        int seen_before = 0;
        for (size_t k = 0; k < i; k++) {
            if (strcmp(aps[k].ssid, aps[i].ssid) == 0) {
                seen_before = 1;
                break;
            }
        }
        if (seen_before) {
            continue;
        }

        const ap_observation_t *open_ap = NULL;
        const ap_observation_t *protected_ap = NULL;
        for (size_t j = i; j < count; j++) {
            if (strcmp(aps[j].ssid, aps[i].ssid) != 0) {
                continue;
            }
            if (aps[j].security == AP_SECURITY_OPEN && open_ap == NULL) {
                open_ap = &aps[j];
            } else if (aps[j].security == AP_SECURITY_PROTECTED && protected_ap == NULL) {
                protected_ap = &aps[j];
            }
        }

        if (open_ap != NULL && protected_ap != NULL) {
            flagged++;
            if (!first_written && out_detail != NULL && out_detail_len > 0) {
                char ssid[33], open_mac[18], prot_mac[18];
                sanitise(aps[i].ssid, ssid, sizeof(ssid));
                format_mac(open_ap->bssid, open_mac, sizeof(open_mac));
                format_mac(protected_ap->bssid, prot_mac, sizeof(prot_mac));
                snprintf(out_detail, out_detail_len,
                         "Possible evil twin: \"%s\" is broadcast both protected (%s) and OPEN (%s)",
                         ssid, prot_mac, open_mac);
                first_written = 1;
            }
        }
    }
    return flagged;
}
