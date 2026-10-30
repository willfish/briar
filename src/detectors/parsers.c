/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/parsers/parsers.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.parsers.dev/api/v1/parse/postgresql/";
static const char body[] = "{\"sql\": \"CREATE TABLE t();SELECT 1; SELECT 1 FROM ; SELECT 2\"}";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_parsers(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Parsers scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* No detector-level dedupe. A repeated key under one keyword is prefix
     * consumption. Capture runs even when verify is set and ctx is NULL. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating Parsers result");
        /* Finding precedes a nil-context drop. The URL and body are constants
         * and are not allocated. A nil context drops only this candidate. */
        if (rc == 0 && verify) {
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            /* Source adds x-api-key. Go canonicalizes that to X-Api-Key before
             * send. Shared HTTP does not, so the canonical name is set here. */
            const br_header headers[] = {
                {"Content-Type", "application/json"},
                {"X-Api-Key", keys.items[i]},
            };
            const br_http_request request = {
                .method = "POST", .url = url, .headers = headers, .nheaders = 2,
                .body = {(const unsigned char *)body, sizeof(body) - 1},
                .profile = BR_HTTP_SANE, .detector_type = 765,
            };
            br_http_response response = {0};
            char *transport_error = NULL;
            /* Any 2xx verifies. The body is not read. A transport error stays
             * unverified and is not published. No setter. */
            if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(transport_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending Parsers result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"parsers"};
static br_detector parsers = {
    .type = 765, .version = 0, .name = "Parsers", .custom_name = "",
    .description = "Parsers is a service used for parsing SQL queries. Parsers API keys can be used to access and modify this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_parsers,
};

int br_parsers_init(const br_detector **out, char **error)
{
    _Static_assert(sizeof(body) - 1 == 62, "Parsers body must be 62 bytes");
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Parsers detector output");
    *out = NULL;
    if (br_key_pattern_init(&parsers, "\\b([0-9a-z]{64})\\b", error) != 0)
        return -1;
    *out = &parsers;
    return 0;
}
