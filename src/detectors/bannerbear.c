/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bannerbear/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int put_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value)) { json_object_put(value); return -1; }
    return 0;
}

static int version_data(br_result *result, int version)
{
    br_json *data = json_object_new_object();
    if (!data) return -1;
    if (put_text(data, "version", version == 1 ? "1" : "2")) { json_object_put(data); return -1; }
    json_object_put(result->extra_data);
    result->extra_data = data;
    return 0;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    /* The core setter returns positive 1 on allocation failure, not a source
     * verification outcome. Keep every resource failure negative locally. */
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static bool master_marker(br_slice body)
{
    static const unsigned char full[] = "When using a Master API Key";
    static const unsigned char limited[] = "Master Key is Limited Access";
    return br_slice_find(body, (br_slice){full, sizeof(full) - 1}, 0) != SIZE_MAX ||
           br_slice_find(body, (br_slice){limited, sizeof(limited) - 1}, 0) != SIZE_MAX;
}

static int verify_bannerbear(const br_scan_ctx *ctx, int version, const char *key, br_result *result)
{
    /* V2 assigns the verifier's returned map wholesale. Constructor and Do
     * failures return nil; V1 keeps its original version map on every branch. */
    if (version == 2) { json_object_put(result->extra_data); result->extra_data = NULL; }
    if (!ctx) return set_cause(result, "net/http: nil Context");

    /* Both source captures are bounded: V1 is 24 bytes and V2 is 36. */
    char auth[sizeof("Bearer ") + 36];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.bannerbear.com/v2/auth",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Successful Do restores V2 metadata before any status/read decision. */
        if (version == 2) rc = version_data(result, 2);
        if (!rc) {
            if (response.status == 200) {
                result->verified = true;
                if (version == 2) rc = put_text(result->extra_data, "key_type", "Project API Key");
            } else if (version == 2 && response.status == 400) {
                /* ReadAll's error wins even if its partial body has a marker. */
                if (response.body_error) cause = response.body_error;
                else if (master_marker(response.body)) {
                    result->verified = true;
                    rc = put_text(result->extra_data, "key_type", "Master API Key");
                } else {
                    /* ABI1 has no arbitrary resp.Status reason text and its
                     * error strings cannot preserve NUL in the complete body.
                     * Keep the candidate, not a fabricated/truncated diagnostic. */
                    cause = "unsupported: Bannerbear v2 non-marker 400 diagnostic";
                }
            } else if (response.status != 401) {
                snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
                cause = status_error;
            }
        }
    }
    if (!rc) rc = set_cause(result, cause);
    /* The injected ABI releases eagerly per request. Source drain/close errors
     * are ignored; native streaming/drain timing parity is not established. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_bannerbear(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Bannerbear scan");
    br_captures keys = {0};
    size_t original_len = out->len;
    /* V1 preserves occurrences; only V2 builds a unique key set. */
    int rc = br_captures_find(detector->state, input, &keys, detector->version == 2, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") ||
            version_data(&result, detector->version))
            rc = fail(error, "cannot create Bannerbear result");
        if (!rc && verify && verify_bannerbear(ctx, detector->version, keys.items[i], &result))
            rc = fail(error, "cannot verify Bannerbear candidate");
        if (!rc && br_results_push(out, &result)) rc = fail(error, "cannot append Bannerbear result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char description[] = "Bannerbear is an API for generating dynamic images, videos, and GIFs. Bannerbear API keys can be used to access and manipulate these resources.";
static const char *const v1_keywords[] = {"bannerbear"};
static const char *const v2_keywords[] = {"bb_pr_", "bb_ma_"};
static br_detector v1 = {
    .type = 430, .version = 1, .name = "Bannerbear", .custom_name = "", .description = description,
    .keywords = v1_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = scan_bannerbear,
};
static br_detector v2 = {
    .type = 430, .version = 2, .name = "Bannerbear", .custom_name = "", .description = description,
    .keywords = v2_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = scan_bannerbear,
};

int br_bannerbear_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bannerbear v1 detector output");
    *out = NULL;
    if (!v1.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(v1_keywords, 1, "\\b([0-9a-zA-Z]{22}tt)\\b", &pattern, error)) return -1;
        v1.state = pattern;
    }
    *out = &v1;
    return 0;
}

int br_bannerbear_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bannerbear v2 detector output");
    *out = NULL;
    if (!v2.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(bb_(?:pr|ma)_[a-f0-9]{30})\\b", &pattern, error)) return -1;
        v2.state = pattern;
    }
    *out = &v2;
    return 0;
}
