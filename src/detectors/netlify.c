/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/netlify/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key; } netlify_state;

static const char rotation_guide[] = "https://howtorotate.com/docs/tutorials/netlify/";
static const char *const netlify_keywords[] = {"netlify"};

static int netlify_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int add_extra(br_result *result, const char *version)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *guide = json_object_new_string(rotation_guide);
    if (!guide || json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return -1;
    }
    br_json *text = json_object_new_string(version);
    if (!text || json_object_object_add(result->extra_data, "version", text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

/* Always invoke the setter, including a nil cause. NULL is a checked no-op.
 * +1 is fatal. Release already happened when a send was attempted. */
static int set_cause(br_result *result, const char *cause, br_slice token, char **error)
{
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return netlify_fail(error, "cannot store Netlify verification error");
    return 0;
}

static int netlify_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    /* Nil context is a constructor failure that still publishes. No send, no release. */
    if (!ctx) return set_cause(result, "net/http: nil Context", token, error);
    char authorization[64];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.netlify.com/api/v1/sites",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    /* Source discards the body and ignores that copy error. body_error cannot
     * change the status decision. Only 200 verifies. 401 is a nil error. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status == 200) {
        result->verified = true;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* One release before the setter, including a later setter failure. The
     * Bearer value remains through this release. */
    br_http_release(ctx, &response);
    int rc = set_cause(result, cause, token, error);
    free(send_error);
    return rc;
}

static int netlify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return netlify_fail(error, "invalid or uninitialized Netlify scan");
    const netlify_state *state = detector->state;
    if (!state->key) return netlify_fail(error, "uninitialized Netlify pattern");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source map dedup is unordered. Keep first-seen uniqueness only. Do not
     * TrimSpace. ExtraData is present even when verification is off. */
    int rc = br_captures_find(state->key, input, &keys, true, &owned_error);
    const char *version = detector->version == 2 ? "2" : "1";
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&keys, i);
        bool bad = detector->version == 2 ? token.len != 40 : token.len < 43 || token.len > 45;
        if (bad)
            rc = netlify_fail(&owned_error, "invalid Netlify capture");
        else if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = netlify_fail(&owned_error, "cannot create Netlify result");
        else if (add_extra(&result, version) != 0)
            rc = netlify_fail(&owned_error, "cannot create Netlify metadata");
        else if (verify)
            rc = netlify_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = netlify_fail(&owned_error, "cannot append Netlify result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static netlify_state v1_compiled, v2_compiled;
static const char description[] =
    "Netlify is a cloud platform for web developers that provides hosting and serverless backend services for web applications and static websites. Netlify API keys can be used to manage sites, deploy applications, and access various services offered by the platform.";
static const br_detector v1_detector = {
    .type = 74, .version = 1, .name = "Netlify", .custom_name = "", .description = description,
    .keywords = netlify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &v1_compiled, .scan = netlify_scan,
};
static const br_detector v2_detector = {
    .type = 74, .version = 2, .name = "Netlify", .custom_name = "", .description = description,
    .keywords = netlify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &v2_compiled, .scan = netlify_scan,
};

static int init_one(const br_detector *detector, netlify_state *state, const char *capture,
                    const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return netlify_fail(error, "invalid Netlify detector output");
    *out = NULL;
    if (!state->key && br_regex_compile_prefixed(netlify_keywords, 1, capture, &state->key, error) != 0)
        return -1;
    *out = detector;
    return 0;
}

int br_netlify_v1_init(const br_detector **out, char **error)
{
    return init_one(&v1_detector, &v1_compiled, "\\b([A-Za-z0-9_-]{43,45})\\b", out, error);
}

int br_netlify_v2_init(const br_detector **out, char **error)
{
    return init_one(&v2_detector, &v2_compiled, "\\b(nfp_[a-zA-Z0-9_]{36})\\b", out, error);
}
