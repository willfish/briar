/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/brandfetch/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* V1 explicitly delegates to V2.VerifyMatch upstream. This function does not
 * replace or enrich ExtraData: each caller keeps its original version map. */
static int verify_brandfetch(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1))
            return fail(error, "cannot store Brandfetch verification error");
        return 0;
    }
    char auth[sizeof("Bearer ") + 44];
    int n = snprintf(auth, sizeof(auth), "Bearer %.*s", (int)token.len, (const char *)token.data);
    if (n < 0 || (size_t)n >= sizeof(auth)) return fail(error, "cannot construct Brandfetch Authorization header");
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.brandfetch.io/v2/brands/google.com",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = br_result_set_verification_error(result, cause, &token, 1);
    /* Source closes ONLY; it does not drain. ABI1 eagerly releases each response
     * and does not establish native Go close-only/streaming timing parity. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? fail(error, "cannot store Brandfetch verification error") : 0;
}

static int scan_brandfetch(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const bool is_v1 = detector && detector->version == 1;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, is_v1 ? "invalid or uninitialized Brandfetch v1 scan" : "invalid or uninitialized Brandfetch v2 scan");
    const char *version_text = is_v1 ? "1" : "2";
    br_captures tokens = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        /* Both captures exclude whitespace; V2's source TrimSpace is a no-op. */
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key"))
            rc = fail(&owned_error, is_v1 ? "cannot create Brandfetch v1 result" : "cannot create Brandfetch v2 result");
        if (!rc) {
            result.extra_data = json_object_new_object();
            br_json *version = json_object_new_string(version_text);
            if (!result.extra_data || !version) {
                json_object_put(version);
                rc = fail(&owned_error, is_v1 ? "cannot allocate Brandfetch v1 metadata" : "cannot allocate Brandfetch v2 metadata");
            } else if (json_object_object_add(result.extra_data, "version", version)) {
                json_object_put(version);
                rc = fail(&owned_error, is_v1 ? "cannot store Brandfetch v1 metadata" : "cannot store Brandfetch v2 metadata");
            }
        }
        if (!rc && verify) rc = verify_brandfetch(ctx, token, &result, &owned_error);
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, is_v1 ? "cannot append Brandfetch v1 result" : "cannot append Brandfetch v2 result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char description[] = "Brandfetch is a service that provides brand data, including logos, colors, fonts, and more. Brandfetch API keys can be used to access this data.";
static const char *const keywords[] = {"brandfetch"};
static br_detector v1 = {
    .type = 333, .version = 1, .name = "Brandfetch", .custom_name = "", .description = description,
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_brandfetch,
};
static br_detector v2 = {
    .type = 333, .version = 2, .name = "Brandfetch", .custom_name = "", .description = description,
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_brandfetch,
};

int br_brandfetch_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Brandfetch v1 detector output");
    *out = NULL;
    if (br_key_pattern_init(&v1, "\\b([0-9A-Za-z]{40})\\b", error)) return -1;
    *out = &v1;
    return 0;
}

int br_brandfetch_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Brandfetch v2 detector output");
    *out = NULL;
    /* No added word boundaries, decoding, padding or entropy validation. */
    if (br_key_pattern_init(&v2, "([a-zA-Z0-9=+/\\-_!@#$%^&*()]{43}=)", error)) return -1;
    *out = &v2;
    return 0;
}
