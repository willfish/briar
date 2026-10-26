/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bulksms. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *key; } bulksms_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    /* Source supplies ZERO secrets, including for ID/key/Basic-auth echoes. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_bulksms(const br_scan_ctx *ctx, br_slice id, br_slice key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char *authorization = NULL;
    if (br_http_basic_auth(id, key, &authorization, NULL)) {
        free(authorization);
        return -1; /* Normalize helper +1 before handling provider outcomes. */
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.bulksms.com/v1/messages",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Ignore all body/read/drain/close errors. Eager ABI1 release does not
     * establish native Go streaming/drain/close timing parity. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return rc ? -1 : 0;
}

static int scan_bulksms(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Bulksms scan");
    const bulksms_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->key) return fail(error, "uninitialized Bulksms patterns");
    br_captures ids = {0}, keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->id, input, &ids, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, &owned_error);
    /* Independent unique sets, including key captures from ID fragments. Keep
     * every ID-major/key-minor pair; there is no UUID validation, consumption,
     * equality exclusion or successful-verification break. */
    for (size_t id = 0; !rc && id < ids.len; ++id) {
        for (size_t key = 0; !rc && key < keys.len; ++key) {
            br_slice id_bytes = br_captures_at(&ids, id), key_bytes = br_captures_at(&keys, key);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key_bytes, "key", id_bytes, "id", (br_slice){0}))
                rc = fail(&owned_error, "cannot create Bulksms result");
            if (!rc && verify && verify_bulksms(ctx, id_bytes, key_bytes, &result))
                rc = fail(&owned_error, "cannot verify Bulksms candidate");
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Bulksms result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static bulksms_patterns patterns;
static const char *const keywords[] = {"bulksms"};
static const br_detector bulksms = {
    .type = 833, .version = 0, .name = "Bulksms", .custom_name = "",
    .description = "BulkSMS is a service used for sending SMS messages in bulk. BulkSMS credentials can be used to access and send messages through the BulkSMS API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_bulksms,
};

int br_bulksms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bulksms detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1, "\\b([A-F0-9-]{37})\\b", &patterns.id, error)) return -1;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9!@#$%^&*()]{29})\\b", &patterns.key, error)) return -1;
    *out = &bulksms;
    return 0;
}
