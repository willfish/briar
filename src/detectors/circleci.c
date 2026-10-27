/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/circleci/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int circle_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* V2 explicitly delegates to V1.VerifyCircleCIToken upstream. Neither version
 * replaces its original Version metadata, including on constructor/Do errors. */
static int circle_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    const br_slice token = {result->raw.data, result->raw.len};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return circle_fail(error, "cannot store Circle verification error");
        return 0;
    }
    const br_header headers[] = {{"Accept", "application/json;"}, {"Circle-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://circleci.com/api/v2/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 4,
    };
    /* ABI1's empty body cannot express Go http.NoBody reader identity. Context
     * transport injection models the optional override, not full http.Client
     * timeout/redirect/cookie configuration. */
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
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
    /* Copy/redact the full token before releasing any owner of a cause. */
    int rc = br_result_set_verification_error(result, cause, &token, 1);
    /* Source verifier defers drain+Close and ignores their errors. ABI1 eagerly
     * releases and may have buffered the body; streaming/timing parity is not
     * established. Body/read/drain/close errors never determine this result. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc != 0 ? circle_fail(error, "cannot store Circle verification error") : 0;
}

static int circle_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return circle_fail(error, "invalid or uninitialized Circle scan");
    br_captures tokens = {0};
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &tokens, true, error);
    /* First-seen byte-identical uniqueness is one permitted traversal of the
     * upstream map. No case folding, trimming, decoding or entropy filtering. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&tokens, i), "key") != 0)
            rc = circle_fail(error, "cannot create Circle result");
        if (rc == 0) {
            result.extra_data = json_object_new_object();
            br_json *version = json_object_new_string(detector->version == 1 ? "1" : "2");
            if (!result.extra_data || !version) {
                json_object_put(version);
                rc = circle_fail(error, "cannot allocate Circle metadata");
            } else if (json_object_object_add(result.extra_data, "Version", version) != 0) {
                json_object_put(version);
                rc = circle_fail(error, "cannot store Circle metadata");
            }
        }
        if (rc == 0 && verify) rc = circle_verify(ctx, tokens.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = circle_fail(error, "cannot append Circle result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    return rc == 0 ? 0 : -1;
}

static const char description[] = "CircleCI is a continuous integration and delivery platform used to build, test, and deploy software. CircleCI tokens can be used to interact with the CircleCI API and access various resources and functionalities.";
static const char *const v1_keywords[] = {"circle"};
static const char *const v2_keywords[] = {"CCIPAT_"};
static br_detector v1 = {
    .type = 4, .version = 1, .name = "Circle", .custom_name = "", .description = description,
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = circle_scan,
};
static br_detector v2 = {
    .type = 4, .version = 2, .name = "Circle", .custom_name = "", .description = description,
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = circle_scan,
};

int br_circleci_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return circle_fail(error, "invalid Circle v1 detector output");
    *out = NULL;
    if (br_key_pattern_init(&v1, "([a-fA-F0-9]{40})", error) != 0) return -1;
    *out = &v1;
    return 0;
}

int br_circleci_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return circle_fail(error, "invalid Circle v2 detector output");
    *out = NULL;
    if (!v2.state) {
        br_regex *pattern = NULL;
        /* Direct source pattern: exact CCIPAT_ literal, no PrefixRegex or added
         * word boundaries; both payload and hex tail preserve original case. */
        if (br_regex_compile("(CCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40})", &pattern, error) != 0) return -1;
        v2.state = pattern;
    }
    *out = &v2;
    return 0;
}
