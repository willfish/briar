/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/digitaloceanv2/digitaloceanv2.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int digitalocean_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int digitalocean_borrowed_error(br_result *result, const char *leaf, char **error)
{
    /* Source unwrapToLast removes known %w envelopes. Injected diagnostics are
     * already leaves: never strip arbitrary text or supply secret arguments. */
    if (br_result_set_verification_error(result, leaf, NULL, 0) != 0)
        return digitalocean_fail(error, "cannot copy DigitalOceanV2 verification error");
    return 0;
}

static int digitalocean_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    br_json **selected = user;
    /* Map keys are exact byte strings, not folded struct tags or json-c C-string
     * keys. In particular access_token\u0000x cannot collide with access_token. */
    if (name.len != 12 || memcmp(name.data, "access_token", 12)) return 0;
    json_object_put(*selected);
    *selected = value && json_object_is_type(value, json_type_string) ? json_object_get(value) : NULL;
    /* Every exact duplicate replaces: null/wrong type resets, later string
     * restores eligibility. An empty JSON string is still a successful string. */
    return 0;
}

/* 0: owned issued string; +1: ordinary owned leaf cause; -1: fatal scan failure. */
static int digitalocean_refresh_json(br_slice body, br_json **issued, char **cause, char **error)
{
    *issued = NULL;
    *cause = NULL;
    /* Only the consumed 200 JSON after successful ReadAll reaches this boundary.
     * Go invalid-UTF-8 replacement/unquoting is not full json-c parity. Valid
     * Unicode and escaped-NUL strings remain supported, without broad rewriting. */
    if (!br_utf8_valid(body))
        return digitalocean_fail(error, "unsupported: DigitalOceanV2 invalid UTF-8 refresh JSON semantics");
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause); /* WHOLE-body syntax first. */
    if (rc != 0) {
        json_object_put(root);
        return rc < 0 ? digitalocean_fail(error, "cannot decode DigitalOceanV2 refresh response") : 1;
    }
    if (root && !json_object_is_type(root, json_type_object)) {
        /* A root array/number mismatch wins over conversion of nested numbers. */
        rc = br_json_type_cause(root, NULL, "map[string]interface {}", cause);
        json_object_put(root);
        return rc == 0 ? 1 : digitalocean_fail(error, "cannot create DigitalOceanV2 root type cause");
    }
    if (root) {
        /* Unlike typed structs, map interface values convert ALL numbers,
         * including nested/unknown/overwritten members, before field access. */
        rc = br_json_check_float64_numbers(body, cause);
        if (rc == 0) rc = br_json_each_member(body, digitalocean_member, issued);
    }
    json_object_put(root);
    if (rc != 0) {
        json_object_put(*issued);
        *issued = NULL;
        return rc < 0 ? digitalocean_fail(error, "cannot project DigitalOceanV2 refresh response") : 1;
    }
    if (*issued) return 0;

    static const char prefix[] = "access_token not found in response: ";
    if (body.len > SIZE_MAX - sizeof(prefix))
        return digitalocean_fail(error, "DigitalOceanV2 response cause too large");
    *cause = malloc(sizeof(prefix) + body.len);
    if (!*cause) return digitalocean_fail(error, "cannot create DigitalOceanV2 response cause");
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    if (body.len) memcpy(*cause + sizeof(prefix) - 1, body.data, body.len);
    (*cause)[sizeof(prefix) - 1 + body.len] = '\0';
    /* Valid whole JSON cannot contain raw NUL. Escaped \u0000 stays ASCII in
     * this exact unredacted body echo, and decoded NUL in issued strings survives. */
    return 1;
}

static int digitalocean_refresh(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    static const char prefix[] = "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token=";
    char url[157];
    _Static_assert(sizeof(prefix) - 1 + 71 + 1 == sizeof(url), "DigitalOceanV2 refresh URL must be 156 bytes plus NUL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, token.data, token.len);
    url[sizeof(url) - 1] = '\0';
    /* Source concatenates the query before request construction. Nil context
     * retains false and the bare leaf cause, never a skip or panic. */
    if (!ctx) {
        int rc = digitalocean_borrowed_error(result, "net/http: nil Context", error);
        if (rc == 0) result->verified = false; /* Refresh setter precedes Verified. */
        return rc;
    }
    const br_http_request request = {
        .method = "POST", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *owned_cause = NULL;
    const char *borrowed_leaf = NULL;
    char status_cause[64];
    br_json *issued = NULL;
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        borrowed_leaf = transport_error ? transport_error : "HTTP transport failed";
    else if (response.body_error != NULL)
        borrowed_leaf = response.body_error; /* ReadAll error, even empty, dominates EVERY status. */
    else if (response.status == 200) {
        int decoded = digitalocean_refresh_json(response.body, &issued, &owned_cause, error);
        if (decoded < 0) rc = -1;
        else verified = decoded == 0;
    } else if (response.status != 401) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = digitalocean_fail(error, "cannot format DigitalOceanV2 status cause");
        else borrowed_leaf = status_cause;
    }
    if (rc == 0) {
        if (owned_cause) {
            /* Private JSON/echo causes already have independent ownership.
             * Moving them is exactly the zero-secret setter's non-NULL replace
             * operation, without a redundant strdup. NULL remains a no-op. */
            free(result->verification_error);
            result->verification_error = owned_cause;
            owned_cause = NULL;
        } else rc = digitalocean_borrowed_error(result, borrowed_leaf, error);
        if (rc == 0) {
            result->verified = verified;
            if (verified) {
                /* Transfer the retained complete string, including empty/Unicode/
                 * NUL bytes. No revalidation or request using the issued token.
                 * Raw remains the original refresh token. */
                if (json_object_object_add(result->secret_parts, "key", issued) != 0)
                    rc = digitalocean_fail(error, "cannot replace DigitalOceanV2 secret key");
                else issued = NULL;
            }
        }
    }
    /* Borrowed causes are copied before release. Source registers deferred Close
     * only AFTER ReadAll success; always release ABI responses, even read errors.
     * Eager buffering, POST redirects/body, Reader/full private-client/error-chain
     * semantics and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    json_object_put(issued);
    free(owned_cause);
    free(transport_error);
    return rc;
}

static int digitalocean_access(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx) {
        result->verified = false; /* Access assigns Verified BEFORE the setter. */
        return digitalocean_borrowed_error(result, "net/http: nil Context", error);
    }
    char authorization[7 + 71 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.digitalocean.com/v2/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *leaf = NULL;
    char status_cause[64];
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        leaf = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status == 200) verified = true; /* Bodies/read errors are ignored here. */
    else if (response.status != 401) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = digitalocean_fail(error, "cannot format DigitalOceanV2 status cause");
        else leaf = status_cause;
    }
    if (rc == 0) {
        result->verified = verified;
        rc = digitalocean_borrowed_error(result, leaf, error);
    }
    /* The complete stack auth and borrowed diagnostics remain valid through
     * send, setter and release; shared mixed send stages are not text-classified. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int digitalocean_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return digitalocean_fail(error, "invalid or uninitialized DigitalOceanV2 scan");
    size_t original_len = out->len;
    br_captures tokens = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* The upstream unique-token map has unspecified order. First-source order
     * is only a native iteration choice, not map-order/global-output parity. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0}; br_slice token = br_captures_at(&tokens, i);
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = digitalocean_fail(&owned_error, "cannot create DigitalOceanV2 result");
        if (rc == 0 && verify)
            rc = !memcmp(token.data, "dor_v1_", 7) ? digitalocean_refresh(ctx, token, &result, &owned_error) :
                                                     digitalocean_access(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = digitalocean_fail(&owned_error, "cannot append DigitalOceanV2 result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const digitalocean_keywords[] = {"dop_v1_", "doo_v1_", "dor_v1_"};
static br_detector digitalocean_detector = {
    .type = 897, .version = 0, .name = "DigitalOceanV2", .custom_name = "",
    .description = "DigitalOcean is a cloud service provider offering scalable compute and storage solutions. DigitalOcean API keys can be used to access and manage these resources.",
    .keywords = digitalocean_keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = digitalocean_scan,
};

int br_digitaloceanv2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return digitalocean_fail(error, "invalid DigitalOceanV2 detector output");
    *out = NULL;
    if (!digitalocean_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\\b", &pattern, error) != 0) return -1;
        digitalocean_detector.state = pattern;
    }
    *out = &digitalocean_detector;
    return 0;
}
