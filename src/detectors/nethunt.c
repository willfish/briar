/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nethunt/nethunt.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } nethunt_patterns;

static int nethunt_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int nethunt_verify(const br_scan_ctx *ctx, br_slice token, br_slice user,
                          br_result *result, char **error)
{
    /* Caller passed the nil-context constructor skip. SetBasicAuth(user, token):
     * the helper already includes Basic. The ID is not a finding field. */
    char *authorization = NULL;
    if (br_http_basic_auth(user, token, &authorization, error) != 0) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://nethunt.com/api/v1/zapier/triggers/readable-folder",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source never reads the body, so body_error cannot suppress a 2xx or drop
     * the finding. Setup/Do failure stays unverified. Never set a verification
     * error. The Basic value remains through send and this one release. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return 0;
}

static int nethunt_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nethunt_fail(error, "invalid or uninitialized Nethunt scan");
    const nethunt_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return nethunt_fail(error, "uninitialized Nethunt patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Full key-major, ID-minor product, duplicates included. Neither side
     * alone yields a result. The 1024 span is an engine hint, not a scan cap.
     * TrimSpace is a no-op. The ID is hidden from Raw, RawV2, secret parts,
     * and extra data. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice token = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            br_slice user = br_captures_at(&ids, i);
            bool attempt = !verify || ctx;
            if (token.len != 36 || user.len < 25 || user.len > 30)
                rc = nethunt_fail(&owned_error, "invalid Nethunt capture");
            else if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                rc = nethunt_fail(&owned_error, "cannot create Nethunt result");
            if (rc == 0 && attempt) {
                if (verify) rc = nethunt_verify(ctx, token, user, &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = nethunt_fail(&owned_error, "cannot append Nethunt result");
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static nethunt_patterns nethunt_compiled;
static const char *const nethunt_keywords[] = {"nethunt"};
static const br_detector nethunt_detector = {
    .type = 268, .version = 0, .name = "Nethunt", .custom_name = "",
    .description = "Nethunt is a CRM tool. Credentials found can be used to access and manage CRM data.",
    .keywords = nethunt_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &nethunt_compiled, .scan = nethunt_scan,
};

int br_nethunt_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nethunt_fail(error, "invalid Nethunt detector output");
    *out = NULL;
    /* Source [a-z0-9-\S] is RE2 non-whitespace, including VT. PCRE2 \S also
     * excludes VT, so the class is written out. The ID class is copied exactly
     * and is not widened. */
    if (!nethunt_compiled.key && br_regex_compile_prefixed(nethunt_keywords, 1,
            "\\b([^\\t\\n\\f\\r ]{36})\\b", &nethunt_compiled.key, error) != 0)
        return -1;
    if (!nethunt_compiled.id && br_regex_compile_prefixed(nethunt_keywords, 1,
            "\\b([a-zA-Z0-9.-@]{25,30})\\b", &nethunt_compiled.id, error) != 0)
        return -1;
    *out = &nethunt_detector;
    return 0;
}
