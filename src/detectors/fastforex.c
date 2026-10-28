/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fastforex/fastforex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fastforex_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void fastforex_verify(const br_scan_ctx *ctx, const char url[72], br_result *result)
{
    /* Constructor's known nil-context skip has passed. Borrow the entire stack
     * URL through synchronous send AND release; only common UA is added. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding without setter/classifier. Successful-send 2xx verifies
     * regardless of body contents or read errors. Tests must inject transport. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only. Eager Reader/release timing, native/private
     * client, regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int fastforex_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fastforex_fail(error, "invalid or uninitialized FastForex scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates and
         * actual hyphen-boundary fragments, not validated UUIDs/full tokens. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fastforex_fail(&owned_error, "cannot create FastForex result");
        char url[72];
        if (rc == 0 && verify) {
            /* Finding THEN complete URL BEFORE constructor skip. KEY28 permits
             * bounded literal assembly with no encoder/formatter/heap copy. */
            memcpy(url, "https://api.fastforex.io/fetch-all?api_key=", 43);
            memcpy(url + 43, keys.items[i], 29); /* Original key28 plus NUL. */
        }
        if (rc == 0 && (!verify || ctx)) {
            if (verify) fastforex_verify(ctx, url, &result);
            if (br_results_push(out, &result) != 0)
                rc = fastforex_fail(&owned_error, "cannot append FastForex result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fastforex_keywords[] = {"fastforex"};
static br_detector fastforex_detector = {
    .type = 636, .version = 0, .name = "FastForex", .custom_name = "",
    .description = "FastForex provides foreign exchange rate data. FastForex API keys can be used to access and retrieve this data.",
    .keywords = fastforex_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fastforex_scan,
};

int br_fastforex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fastforex_fail(error, "invalid FastForex detector output");
    *out = NULL;
    if (br_key_pattern_init(&fastforex_detector, "\\b([a-z0-9-]{28})\\b", error) != 0) return -1;
    *out = &fastforex_detector;
    return 0;
}
