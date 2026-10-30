/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/timezoneapi/timezoneapi.go.
 * A ResponseContainsSubstring error aborts FromData, unlike a Do error. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* 1 found, 0 absent. A too-long token or a non-EOF read error is fatal text. */
static int contains_date(br_slice body, const char *read_error, const char **cause)
{
    static const char needle[] = "date";
    size_t at = 0;
    bool eof = !read_error;
    while (at < body.len) {
        size_t remaining = body.len - at, lf = SIZE_MAX;
        size_t window = remaining < 65537 ? remaining : 65537;
        for (size_t i = 0; i < window; ++i) if (body.data[at + i] == '\n') { lf = i; break; }
        if (lf == SIZE_MAX && remaining > 65536) {
            *cause = "bufio.Scanner: token too long";
            return -1;
        }
        if (lf == SIZE_MAX && !eof) break;
        size_t len = lf == SIZE_MAX ? remaining : lf;
        if (len && body.data[at + len - 1] == '\r') --len;
        if (len >= sizeof(needle) - 1) {
            for (size_t i = 0; i + sizeof(needle) - 1 <= len; ++i)
                if (!memcmp(body.data + at + i, needle, sizeof(needle) - 1)) return 1;
        }
        if (lf == SIZE_MAX) break;
        at += lf + 1;
    }
    if (read_error) { *cause = read_error; return -1; }
    return 0;
}

static int verify_timezoneapi(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[64];
    int n = snprintf(url, sizeof(url), "https://timezoneapi.io/api/ip/?token=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot construct Timezoneapi URL");
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        const char *cause = NULL;
        int found = contains_date(response.body, response.body_error, &cause);
        if (found < 0) rc = fail(error, cause ? cause : "Timezoneapi response scan failed");
        else if (found == 1 && response.status >= 200 && response.status < 300) result->verified = true;
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_timezoneapi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Timezoneapi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned, "out of memory creating Timezoneapi result");
        else if (verify) {
            int checked = verify_timezoneapi(ctx, keys.items[i], &result, &owned);
            if (checked < 0) rc = -1;
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "out of memory appending Timezoneapi result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"timezoneapi"};
static br_detector timezoneapi = {
    .type = 289, .version = 0, .name = "Timezoneapi", .custom_name = "",
    .description = "Timezoneapi is a service that provides time zone information. Timezoneapi keys can be used to access and retrieve time zone data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_timezoneapi,
};

int br_timezoneapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Timezoneapi detector output");
    *out = NULL;
    if (br_key_pattern_init(&timezoneapi, "\\b([a-zA-Z]{20})\\b", error) != 0) return -1;
    *out = &timezoneapi;
    return 0;
}
