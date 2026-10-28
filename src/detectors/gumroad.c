/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gumroad/gumroad.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int gumroad_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void gumroad_verify(const br_scan_ctx *ctx, br_slice payload, br_result *result)
{
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.gumroad.com/v2/products",
        .headers = headers, .nheaders = 1, .body = payload,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The source ignores every setup/Do error and never reads the body. Keep
     * the nonempty GET, including the native adapter's existing guard. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
}

static int gumroad_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gumroad_fail(error, "invalid or uninitialized Gumroad scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet; retain original occurrences. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = gumroad_fail(&owned_error, "cannot create Gumroad result");
        if (rc == 0) {
            /* Upstream prepares all 56 literal bytes even in NoV, before the
             * nil-context constructor skip. No encoding or formatting step. */
            unsigned char payload[13 + 43];
            memcpy(payload, "access_token=", 13);
            memcpy(payload + 13, key.data, 43);
            if (verify && ctx)
                gumroad_verify(ctx, (br_slice){payload, sizeof(payload)}, &result);
            if ((!verify || ctx) && br_results_push(out, &result) != 0)
                rc = gumroad_fail(&owned_error, "cannot append Gumroad result");
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

static const char *const gumroad_keywords[] = {"gumroad"};
static br_detector gumroad_detector = {
    .type = 792, .version = 0, .name = "Gumroad", .custom_name = "",
    .description = "Gumroad is an online platform that facilitates the sale of products by creators. Gumroad API keys can be used to access and manage these products.",
    .keywords = gumroad_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = gumroad_scan,
};

int br_gumroad_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gumroad_fail(error, "invalid Gumroad detector output");
    *out = NULL;
    if (!gumroad_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(gumroad_keywords, 1, "\\b([a-z0-9A-Z-]{43})\\b", &regex, error) != 0)
            return -1;
        gumroad_detector.state = regex;
    }
    *out = &gumroad_detector;
    return 0;
}
