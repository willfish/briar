/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/holidayapi/holidayapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int holidayapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False represents the source's constructor-error continue, not rejection. */
static bool holidayapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://holidayapi.com/v1/holidays?key=";
    static const char suffix[] = "&country=PH&year=2020";
    /* The fixed capture alphabet needs neither trimming nor URL encoding.
     * Assemble the complete literal URL before the nil-context constructor. */
    char url[sizeof(base) - 1 + 36 + sizeof(suffix)];
    _Static_assert(sizeof(url) == 97, "HolidayAPI URL is 96 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 36);
    memcpy(url + sizeof(base) - 1 + 36, suffix, sizeof(suffix));
    if (!ctx) return false;
    unsigned char dedup_key[41];
    memcpy(dedup_key, "361:", 4);
    memcpy(dedup_key + 4, key.data, 36);
    dedup_key[40] = '\0';
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key) - 1},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Preserve the entire key, including the borrowed transport's guard. The
     * owned source client promotes buffering errors before Do succeeds; the
     * detector itself ignores replay bodies. Suppress the whole shared setup/Do
     * error domain without a verification-error setter or text classification. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original capture, URL and full key survive every ordinary release;
     * synthesized headers/UA retain only the shared adapter's own lifetime. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int holidayapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return holidayapi_fail(error, "invalid or uninitialized HolidayAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Preserve occurrences/duplicates and construct
         * the finding before any request-constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = holidayapi_fail(&owned_error, "cannot create HolidayAPI result");
        if (rc == 0 && verify) keep = holidayapi_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = holidayapi_fail(&owned_error, "cannot append HolidayAPI result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const holidayapi_keywords[] = {"holidayapi"};
static br_detector holidayapi_detector = {
    .type = 361, .version = 0, .name = "HolidayAPI", .custom_name = "",
    .description = "HolidayAPI keys are used to access holiday data for various countries and years. These keys can be used to query and retrieve holiday information programmatically.",
    .keywords = holidayapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = holidayapi_scan,
};

int br_holidayapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return holidayapi_fail(error, "invalid HolidayAPI detector output");
    *out = NULL;
    if (!holidayapi_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(holidayapi_keywords, 1, "\\b([a-z0-9-]{36})\\b", &regex, error) != 0)
            return -1;
        holidayapi_detector.state = regex;
    }
    *out = &holidayapi_detector;
    return 0;
}
