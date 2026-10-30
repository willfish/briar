/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zipcodebase/zipcodebase.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_zipcodebase(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Source returns the constructor error. SetVerificationError gets no secrets,
     * so unwrap stores "net/http: nil Context" without redaction of the key. */
    const char *cause = NULL;
    char status_error[80];
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (!ctx) cause = "net/http: nil Context";
    else {
        const br_header headers[] = {
            {"Accept", "application/vnd.zipcodebase+json; version=3"},
            {"apikey", key},
        };
        const br_http_request request = {
            .method = "GET", .url = "https://app.zipcodebase.com/api/v1/search?codes=10005,10006",
            .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        if (br_http_send(ctx, &request, &response, &error) != 0)
            cause = error;
        else if (response.status == 200) result->verified = true;
        else if (response.status != 401 && response.status != 403) {
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
        }
    }
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0) rc = -1;
    if (ctx) br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_zipcodebase(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Zipcodebase scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0 ||
            (verify && verify_zipcodebase(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory creating Zipcodebase result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"zipcodebase"};
static br_detector zipcodebase = {
    .type = 825, .version = 0, .name = "Zipcodebase", .custom_name = "",
    .description = "Zipcodebase is a service that provides access to a database of postal codes. The API keys can be used to query this database for information related to postal codes.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_zipcodebase,
};

int br_zipcodebase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Zipcodebase detector output");
    *out = NULL;
    if (br_key_pattern_init(&zipcodebase,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &zipcodebase;
    return 0;
}
