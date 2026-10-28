/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/guardianapi/guardianapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int guardianapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's nil-context skip. */
static bool guardianapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://content.guardianapis.com/search?api-key=";
    static const char suffix[] = "";
    char url[sizeof(prefix) - 1 + 36 + sizeof(suffix)];
    /* The capture is exactly 36 ASCII bytes. Construct the complete literal
     * URL before the context-bound constructor, without UUID normalization. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 36);
    memcpy(url + sizeof(prefix) - 1 + 36, suffix, sizeof(suffix));
    if (!ctx) return false;

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/allocation/Do failure domain is false-kept;
     * status alone matters and response bodies/read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Only the original URL is retained through release, not the ordinary
     * shared adapter's effective request, headers or synthesized User-Agent. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int guardianapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return guardianapi_fail(error, "invalid or uninitialized Guardianapi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace cannot change this grammar. Preserve every original
         * occurrence, including duplicates and the unusual first-block A. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = guardianapi_fail(&owned_error, "cannot create Guardianapi result");
        if (rc == 0 && verify) keep = guardianapi_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = guardianapi_fail(&owned_error, "cannot append Guardianapi result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const guardianapi_keywords[] = {"guardianapi"};
static br_detector guardianapi_detector = {
    .type = 259, .version = 0, .name = "Guardianapi", .custom_name = "",
    .description = "Guardian API keys are used to access content and data from The Guardian's API. These keys can be used to retrieve articles, search content, and interact with The Guardian's content platform.",
    .keywords = guardianapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = guardianapi_scan,
};

int br_guardianapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return guardianapi_fail(error, "invalid Guardianapi detector output");
    *out = NULL;
    if (!guardianapi_detector.state) {
        /* Extraction's prefix differs from the engine dispatch keyword. */
        static const char *const prefixes[] = {"guardian"};
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(prefixes, 1,
                "\\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
                &regex, error) != 0)
            return -1;
        guardianapi_detector.state = regex;
    }
    *out = &guardianapi_detector;
    return 0;
}
