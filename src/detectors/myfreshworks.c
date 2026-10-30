/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/myfreshworks/myfreshworks.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } myfreshworks_patterns;

static int myfreshworks_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Always invoke the setter, including a NULL cause. NULL is a checked no-op.
 * +1 is fatal. The secret passed upstream is the token, never the domain ID. */
static int myfreshworks_set(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return myfreshworks_fail(error, "cannot sanitize Myfreshworks verification error");
    return 0;
}

/* The zero constructor has a nil client. Verification uses the scan transport.
 * A nil context is a constructor error that still publishes: no send, no release. */
static int myfreshworks_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                               br_result *result, char **error)
{
    static const char suffix[] = ".myfreshworks.com/crm/sales/api/sales_accounts/filters";
    _Static_assert(sizeof(suffix) == 55, "Freshworks URL suffix");
    if (key.len != 22 || id.len < 2 || id.len > 20)
        return myfreshworks_fail(error, "invalid Myfreshworks capture");
    if (!ctx) return myfreshworks_set(result, "net/http: nil Context", key, error);

    char url[8 + 20 + 54 + 1];
    memcpy(url, "https://", 8);
    memcpy(url + 8, id.data, id.len);
    memcpy(url + 8 + id.len, suffix, sizeof(suffix));
    char authorization[12 + 22 + 1];
    memcpy(authorization, "Token token=", 12);
    memcpy(authorization + 12, key.data, key.len);
    authorization[12 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    const char *read_error = response.body_error;
    br_slice body = response.body;
    char *owned_cause = NULL;
    char status_cause[64];
    const char *cause = NULL;
    int rc = 0;
    bool verified = false;
    if (send_rc != 0) {
        /* Setup and Do share this domain, including a reached NULL. */
        cause = transport_error;
    } else if (status == 200) {
        if (read_error) {
            /* Copy before release. Native release frees body_error. */
            owned_cause = strdup(read_error);
            if (!owned_cause) rc = myfreshworks_fail(error, "cannot copy Myfreshworks read error");
            else cause = owned_cause;
        } else {
            br_json *document = NULL;
            char *json_cause = NULL;
            /* Whole-document json.Valid. Null and scalars count. Do not pass
             * a syntax cause to the setter. Decide this before release. */
            int valid = br_json_document(body, &document, &json_cause);
            json_object_put(document);
            free(json_cause);
            if (valid < 0) rc = myfreshworks_fail(error, "cannot validate Myfreshworks response JSON");
            else verified = valid == 0;
        }
    } else if (status != 401 && status != 403) {
        int n = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_cause))
            rc = myfreshworks_fail(error, "cannot format Myfreshworks status cause");
        else cause = status_cause;
    }
    /* One release for every attempted send, before the setter, including a
     * later setter or formatter failure. Stack header and URL stay alive. */
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        rc = myfreshworks_set(result, cause, key, error);
    }
    free(owned_cause);
    free(transport_error);
    return rc ? -1 : 0;
}

static int myfreshworks_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return myfreshworks_fail(error, "invalid or uninitialized Myfreshworks scan");
    const myfreshworks_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id)
        return myfreshworks_fail(error, "uninitialized Myfreshworks patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, &owned_error);
    /* br_scan_key cannot express a missing side. Either side alone yields
     * nothing and no error. Keep every pair, including duplicates, key-major
     * and ID-minor. TrimSpace is a no-op for both grammars. The ID is not stored. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = myfreshworks_fail(&owned_error, "cannot create Myfreshworks finding");
            if (!rc && verify)
                rc = myfreshworks_verify(ctx, key, br_captures_at(&ids, i), &result, &owned_error);
            if (!rc && br_results_push(out, &result) != 0)
                rc = myfreshworks_fail(&owned_error, "cannot append Myfreshworks finding");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const myfreshworks_keywords[] = {"freshworks"};
static myfreshworks_patterns myfreshworks_compiled;
static br_detector myfreshworks_detector = {
    .type = 216, .version = 0, .name = "Myfreshworks", .custom_name = "",
    .description = "Freshworks is a customer engagement platform offering various services like CRM, IT service management, and more. Freshworks API keys can be used to access and manage these services.",
    .keywords = myfreshworks_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &myfreshworks_compiled, .scan = myfreshworks_scan,
};

int br_myfreshworks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return myfreshworks_fail(error, "invalid Myfreshworks detector output");
    *out = NULL;
    if (!myfreshworks_compiled.key &&
        br_regex_compile_prefixed(myfreshworks_keywords, 1,
            "\\b([a-z0-9A-Z-_]{22})\\b", &myfreshworks_compiled.key, error) != 0)
        return -1;
    if (!myfreshworks_compiled.id &&
        br_regex_compile_prefixed(myfreshworks_keywords, 1,
            "\\b([a-zA-Z0-9-_]{2,20})\\b", &myfreshworks_compiled.id, error) != 0)
        return -1;
    *out = &myfreshworks_detector;
    return 0;
}
