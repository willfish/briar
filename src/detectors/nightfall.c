/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nightfall/nightfall.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int nightfall_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Bearer value and body are borrowed through synchronous send and release.
 * Source adds no Content-Type. Timeout 0 selects the SANE default. */
static void nightfall_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[43];
    unsigned char body[] = "{\"fileSizeBytes\":256}";
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 35);
    authorization[42] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "POST",
        .url = "https://api.nightfall.ai/v3/upload",
        .headers = headers,
        .nheaders = 1,
        .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    /* A reached send stays unverified for every cause, including NULL.
     * Do not invent or publish transport text, and do not call a setter. */
    free(transport_error);
    if (send_rc == 0 && response.status >= 200 && response.status < 300)
        result->verified = true; /* body_error does not change a successful send. */
    br_http_release(ctx, &response); /* One release for this attempted send. */
}

static int nightfall_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nightfall_fail(error, "invalid or uninitialized Nightfall scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match, including duplicates. Any nonzero,
     * including +1, is fatal before skip or success. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0 && !owned_error) owned_error = strdup("cannot scan Nightfall matches");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure, including
         * +1, is fatal before the constructor skip, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nightfall_fail(&owned_error, "cannot create Nightfall result");
        else if (verify && !ctx) {
            /* Nil context drops after finding allocation, before prepare,
             * send, and release. A constructor skip is not an attempt. */
        } else {
            if (verify) nightfall_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = nightfall_fail(&owned_error, "cannot append Nightfall result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const nightfall_keywords[] = {"nightfall"};
static br_detector nightfall_detector = {
    .type = 847,
    .version = 0,
    .name = "Nightfall",
    .custom_name = "",
    .description = "Nightfall is a data security platform providing sensitive data detection and protection. The detected key can be used to interact with Nightfall's API.",
    .keywords = nightfall_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = nightfall_scan,
};

int br_nightfall_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nightfall_fail(error, "invalid Nightfall detector output");
    *out = NULL;
    if (!nightfall_detector.state) {
        br_regex *regex = NULL;
        /* Keyword is an engine hint only. This grammar is not prefixed. */
        if (br_regex_compile("\\b(NF-[a-zA-Z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        nightfall_detector.state = regex;
    }
    *out = &nightfall_detector;
    return 0;
}
