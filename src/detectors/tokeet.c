/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tokeet/tokeet.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } tokeet_patterns;

static int tokeet_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void tokeet_verify(const br_scan_ctx *ctx, const char *url, const char *key, br_result *result)
{
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int tokeet_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tokeet_fail(error, "invalid or uninitialized Tokeet scan");
    const tokeet_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Nested match order, including duplicates. The id is not a secret part. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            bool keep = true;
            char url[96];
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = tokeet_fail(&owned_error, "cannot create Tokeet result");
            else if (verify) {
                int n = snprintf(url, sizeof(url), "https://capi.tokeet.com/v1/user?account=%s", ids.items[i]);
                if (n < 0 || (size_t)n >= sizeof(url))
                    rc = tokeet_fail(&owned_error, "cannot create Tokeet URL");
                else if (!ctx) keep = false;
                else tokeet_verify(ctx, url, keys.items[k], &result);
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = tokeet_fail(&owned_error, "cannot append Tokeet result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tokeet_keywords[] = {"tokeet"};
static tokeet_patterns tokeet_state;
static br_detector tokeet_detector = {
    .type = 864, .version = 0, .name = "Tokeet", .custom_name = "",
    .description = "Tokeet is a property management software used for managing rental properties. Tokeet API keys can be used to access and modify property data and manage bookings.",
    .keywords = tokeet_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &tokeet_state, .scan = tokeet_scan,
};

int br_tokeet_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tokeet_fail(error, "invalid Tokeet detector output");
    *out = NULL;
    if (!tokeet_state.key &&
        br_regex_compile_prefixed(tokeet_keywords, 1,
                                  "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                                  &tokeet_state.key, error) != 0)
        return -1;
    /* The source dot is any character, not a literal separator. */
    if (!tokeet_state.id &&
        br_regex_compile_prefixed(tokeet_keywords, 1, "\\b([0-9]{10}.[0-9]{4})\\b",
                                  &tokeet_state.id, error) != 0)
        return -1;
    *out = &tokeet_detector;
    return 0;
}
