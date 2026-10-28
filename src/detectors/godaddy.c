/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/godaddy/{v1,v2}/godaddy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *keys, *secrets;
    const char *url, *environment;
} godaddy_state;

static int godaddy_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* V2 explicitly delegates its verifier and auth construction to V1. This does
 * not merge their distinct source defaultClient/custom getClient identities.
 * Neither source client coalesces requests; no type-based client is invented. */
static int godaddy_verify(const godaddy_state *state, const br_scan_ctx *ctx,
                          const char *authorization, br_slice secret,
                          br_result *result, char **error)
{
    const char *cause = NULL;
    char *send_error = NULL;
    char status_error[64];
    int rc = 0;
    bool verified = false;
    if (!ctx) {
        cause = "net/http: nil Context";
        if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
            return godaddy_fail(error, "cannot store GoDaddy verification error");
        return 0;
    }
    /* Header.Set follows successful request construction. */
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = state->url, .headers = &header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    /* Retain the whole mixed shared setup/Do domain. Never classify diagnostic
     * text, and redact ONLY the hidden secret, not the key or complete auth. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: case 403: verified = true; break;
        case 401: break;
        default: {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = godaddy_fail(error, "cannot format GoDaddy status error");
            else cause = status_error;
            break;
        }
        }
    }
    /* Source verifier-defers drain/Close before FromData publishes Verified
     * and calls its setter. Bodies/read errors do not change the decision.
     * Original auth survives release, not the adapter's temporary headers/UA;
     * owned send_error and local status_error remain valid through the setter. */
    br_http_release(ctx, &response);
    result->verified = verified;
    if (rc == 0 && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = godaddy_fail(error, "cannot store GoDaddy verification error");
    free(send_error);
    return rc;
}

static int godaddy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return godaddy_fail(error, "invalid or uninitialized GoDaddy scan");
    const godaddy_state *state = detector->state;
    br_captures keys = {0}, secrets = {0};
    size_t original_len = out->len;
    char *owned_error = NULL;
    int rc = br_captures_find(state->keys, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(state->secrets, input, &secrets, true, &owned_error);
    /* Source maps are unique by ORIGINAL bytes. First-seen key-major traversal
     * is one allowed map order; emit the full product, with a required hidden
     * secret even in NoV. Do not trim, normalize, filter or clean here. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < secrets.len; ++j) {
            br_slice secret = br_captures_at(&secrets, j);
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = godaddy_fail(&owned_error, "cannot create GoDaddy result");
            if (rc == 0 && !(result.extra_data = json_object_new_object()))
                rc = godaddy_fail(&owned_error, "cannot create GoDaddy extra data");
            if (rc == 0 && verify) {
                /* MakeAuthHeaderValue is evaluated BEFORE the verifier's
                 * constructor/nil-context branch. Maximum: 68 bytes plus NUL. */
                char authorization[69];
                _Static_assert(sizeof(authorization) == 8 + 37 + 1 + 22 + 1, "GoDaddy auth bound");
                memcpy(authorization, "sso-key ", 8);
                memcpy(authorization + 8, key.data, key.len);
                authorization[8 + key.len] = ':';
                memcpy(authorization + 9 + key.len, secret.data, secret.len);
                authorization[9 + key.len + secret.len] = '\0';
                rc = godaddy_verify(state, ctx, authorization, secret, &result, &owned_error);
                /* Environment follows the checked setter, including NULL cause. */
                if (rc == 0) {
                    br_json *environment = json_object_new_string(state->environment);
                    if (!environment) rc = godaddy_fail(&owned_error, "cannot create GoDaddy environment");
                    else if (json_object_object_add(result.extra_data, "Environment", environment) != 0) {
                        json_object_put(environment);
                        rc = godaddy_fail(&owned_error, "cannot store GoDaddy environment");
                    }
                }
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = godaddy_fail(&owned_error, "cannot append GoDaddy result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const godaddy_keywords[] = {"godaddy"};
static godaddy_state godaddy_v1_state = {
    .url = "https://api.ote-godaddy.com/v1/domains/available?domain=example.com", .environment = "OTE",
};
static godaddy_state godaddy_v2_state = {
    .url = "https://api.godaddy.com/v1/domains/available?domain=example.com", .environment = "Prod",
};
#define GODADDY_DESCRIPTOR(V) { \
    .type = 1008, .version = V, .name = "GoDaddy", .custom_name = "", \
    .description = "GoDaddy offers website building, hosting and security tools and services to construct, expand and protect the online presence." \
                   "GoDaddy provides applications and access to relevant third-party products and platforms to connect their customers", \
    .keywords = godaddy_keywords, .nkeywords = 1, \
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = godaddy_scan, \
}
static br_detector godaddy_v1 = GODADDY_DESCRIPTOR(1);
static br_detector godaddy_v2 = GODADDY_DESCRIPTOR(2);
#undef GODADDY_DESCRIPTOR

static int godaddy_init(br_detector *detector, godaddy_state *state, const char *capture,
                        const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return godaddy_fail(error, "invalid GoDaddy detector output");
    *out = NULL;
    if (!detector->state) {
        br_regex *keys = NULL, *secrets = NULL;
        if (br_regex_compile_prefixed(godaddy_keywords, 1, capture, &keys, error) != 0) return -1;
        if (br_regex_compile_prefixed(godaddy_keywords, 1, "\\b([a-zA-Z0-9]{22})\\b", &secrets, error) != 0) {
            br_regex_free(keys);
            return -1;
        }
        state->keys = keys; state->secrets = secrets;
        detector->state = state;
    }
    *out = detector;
    return 0;
}

int br_godaddy_v1_init(const br_detector **out, char **error)
{
    return godaddy_init(&godaddy_v1, &godaddy_v1_state, "\\b([a-zA-Z0-9_]{37})\\b", out, error);
}

int br_godaddy_v2_init(const br_detector **out, char **error)
{
    return godaddy_init(&godaddy_v2, &godaddy_v2_state, "\\b([a-zA-Z0-9_]{35})\\b", out, error);
}
