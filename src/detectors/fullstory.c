/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fullstory/v1/fullstory.go
 * and pkg/detectors/fullstory/v2/fullstory_v2.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static int fullstory_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int fullstory_version_data(br_result *result, const char *version)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *value = json_object_new_string(version);
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "version", value) != 0) { json_object_put(value); return -1; }
    return 0;
}

/* Same policy for genuine provider versions, explicit version-specific URL.
 * Caller supplies its exact fixed-size stack buffer AFTER constructor success. */
static void fullstory_request(const br_scan_ctx *ctx, const char *url, br_slice key,
                               char *authorization, br_result *result)
{
    /* LITERAL Basic TOKEN, NOT Basic encoding of credentials or TOKEN:. */
    memcpy(authorization, "Basic ", 6); memcpy(authorization + 6, key.data, key.len); authorization[6 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain, without
     * setter/classifier. All 2xx verify; body and read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete borrowed auth remains live THROUGH synchronous send AND release.
     * Safe single release, not source scan-deferred Close. Full Reader/deferred-
     * close, native client/regexp and global source/engine/output parity remain
     * partial. No copied header/codec/heap staging or shared guard bypass. */
    br_http_release(ctx, &response);
    free(send_error);
}

static bool fullstory_verify(const br_detector *detector, const br_scan_ctx *ctx,
                              br_slice key, br_result *result)
{
    if (!ctx) return false;
    if (detector->version == 1) {
        char authorization[95]; /* Basic + 88 + NUL. */
        fullstory_request(ctx, "https://api.fullstory.com/operations/v1", key, authorization, result);
    } else {
        char authorization[111]; /* Basic + 104 + NUL. */
        fullstory_request(ctx, "https://api.fullstory.com/v2/users", key, authorization, result);
    }
    return true;
}

static int fullstory_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fullstory_fail(error, "invalid or uninitialized Fullstory scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0}; bool keep = true;
        /* Original occurrences/duplicates. TrimSpace is a no-op; no decoding,
         * full-token validation, capture folding, entropy/filter/cache policy.
         * Both finding AND owned string version metadata precede verification. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fullstory_fail(&owned_error, "cannot create Fullstory result");
        if (rc == 0 && fullstory_version_data(&result, detector->version == 1 ? "1" : "2") != 0)
            rc = fullstory_fail(&owned_error, "cannot create Fullstory version metadata");
        if (rc == 0 && verify) keep = fullstory_verify(detector, ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = fullstory_fail(&owned_error, "cannot append Fullstory result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fullstory_keywords[] = {"fullstory"};
static br_detector fullstory_v1_detector = {
    .type = 394, .version = 1, .name = "Fullstory", .custom_name = "",
    .description = "Fullstory is a digital experience analytics platform that captures and analyzes customer interactions on websites and mobile apps. Fullstory API keys can be used to access and analyze this data.",
    .keywords = fullstory_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = fullstory_scan,
};
static br_detector fullstory_v2_detector = {
    .type = 394, .version = 2, .name = "Fullstory", .custom_name = "",
    .description = "Fullstory is a digital experience analytics platform. Fullstory keys can be used to access user session data and analytics.",
    .keywords = fullstory_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = fullstory_scan,
};

static int fullstory_init(br_detector *detector, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fullstory_fail(error, "invalid Fullstory detector output");
    *out = NULL;
    if (!detector->state) {
        br_regex *pattern = NULL;
        int rc = detector->version == 1
            ? br_regex_compile_prefixed(fullstory_keywords, 1, "\\b([a-zA-Z-0-9/+]{88})\\b", &pattern, error)
            : br_regex_compile("\\b(na1\\.[A-Za-z0-9\\+\\/]{100})\\b", &pattern, error);
        if (rc != 0) return -1;
        detector->state = pattern;
    }
    *out = detector;
    return 0;
}

int br_fullstory_v1_init(const br_detector **out, char **error) { return fullstory_init(&fullstory_v1_detector, out, error); }
int br_fullstory_v2_init(const br_detector **out, char **error) { return fullstory_init(&fullstory_v2_detector, out, error); }
