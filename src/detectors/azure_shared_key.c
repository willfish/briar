/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared Azure key bytes, HMAC and date mechanics, not provider policy.
 * Decoded-prefix behavior follows Go 1.26.7 encoding/base64 (BSD-3-Clause);
 * reimplemented in C. See NOTICE and LICENSES/BSD-3-Clause-Go.txt. */
#include "azure_shared_key.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int sextet(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool newline(unsigned char c) { return c == '\r' || c == '\n'; }

int br_azure_base64_std_decode(br_slice input, br_bytes *prefix, size_t *bad_offset)
{
    if (prefix) *prefix = (br_bytes){0};
    if (bad_offset) *bad_offset = SIZE_MAX;
    if (!prefix || !bad_offset || (!input.data && input.len)) return -1;
    size_t capacity = input.len / 4 * 3;
    prefix->data = malloc(capacity ? capacity : 1);
    if (!prefix->data) return -1;
    size_t at = 0;
    while (at < input.len) {
        unsigned char values[4] = {0};
        size_t count = 0;
        bool padded = false;
        while (count < 4) {
            if (at == input.len) {
                if (!count) return 0;
                *bad_offset = at - count;
                return 1;
            }
            unsigned char c = input.data[at++];
            int value = sextet(c);
            if (value >= 0) { values[count++] = (unsigned char)value; continue; }
            if (newline(c)) continue;
            if (c != '=' || count < 2) { *bad_offset = at - 1; return 1; }
            if (count == 2) {
                while (at < input.len && newline(input.data[at])) ++at;
                if (at == input.len) { *bad_offset = at; return 1; }
                if (input.data[at] != '=') { *bad_offset = at - 1; return 1; }
                ++at;
            }
            while (at < input.len && newline(input.data[at])) ++at;
            padded = true;
            break;
        }
        uint32_t bits = (uint32_t)values[0] << 18 | (uint32_t)values[1] << 12 |
                        (uint32_t)values[2] << 6 | values[3];
        prefix->data[prefix->len++] = (unsigned char)(bits >> 16);
        if (count >= 3) prefix->data[prefix->len++] = (unsigned char)(bits >> 8);
        if (count == 4) prefix->data[prefix->len++] = (unsigned char)bits;
        if (padded) {
            if (at < input.len) { *bad_offset = at; return 1; }
            return 0;
        }
    }
    return 0;
}

int br_azure_hmac_sha256_base64(br_slice key, br_slice message, char out[45])
{
    if (!out || (!key.data && key.len) || (!message.data && message.len)) return -1;
    static const unsigned char empty[] = "";
    unsigned char digest[32];
    size_t len = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key.data ? key.data : empty, key.len,
                   message.data ? message.data : empty, message.len, digest, sizeof(digest), &len) || len != 32)
        return -1;
    return EVP_EncodeBlock((unsigned char *)out, digest, 32) == 44 ? 0 : -1;
}

int br_azure_http_date_utc(int64_t epoch_seconds, char out[30])
{
    if (!out) return -1;
    time_t when = (time_t)epoch_seconds;
    struct tm utc;
    if ((int64_t)when != epoch_seconds || !gmtime_r(&when, &utc)) return -1;
    int64_t year = (int64_t)utc.tm_year + 1900;
    if (year < 0 || year > 9999 || utc.tm_mon < 0 || utc.tm_mon > 11 || utc.tm_wday < 0 || utc.tm_wday > 6)
        return -1;
    static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int len = snprintf(out, 30, "%s, %02d %s %04" PRId64 " %02d:%02d:%02d GMT",
        days[utc.tm_wday], utc.tm_mday, months[utc.tm_mon], year, utc.tm_hour, utc.tm_min, utc.tm_sec);
    return len == 29 ? 0 : -1;
}
