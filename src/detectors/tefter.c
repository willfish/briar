/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tefter/tefter.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>

typedef enum { TEF_ABORT = -1, TEF_KEEP = 0, TEF_SKIP = 1 } tef_outcome;

static int tef_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

__attribute__((weak)) int br_tefter_json_document(br_slice body, br_json **out, char **cause)
{
    return br_json_document(body, out, cause);
}

static tef_outcome tef_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return TEF_SKIP;
    char token[20 + 1];
    memcpy(token, key.data, key.len);
    token[key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-User-Token", token},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://www.tefter.io/api/bookmarks?url=google.com",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* A client.Do error still appends an unverified finding. Only a missing
     * context or a body-read error drops the occurrence. No setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        free(transport_error);
        br_http_release(ctx, &response);
        return TEF_KEEP;
    }
    if (response.body_error) {
        br_http_release(ctx, &response);
        return TEF_SKIP;
    }
    br_json *document = NULL;
    char *json_error = NULL;
    int valid = br_tefter_json_document(response.body, &document, &json_error);
    json_object_put(document);
    if (valid != 0 && valid != 1) {
        tef_fail(error, "cannot inspect Tefter body");
        free(json_error);
        br_http_release(ctx, &response);
        return TEF_ABORT;
    }
    free(json_error);
    result->verified = response.status >= 200 && response.status < 300 && valid == 0;
    br_http_release(ctx, &response);
    return TEF_KEEP;
}

static int tef_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tef_fail(error, "invalid or uninitialized Tefter scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        tef_outcome outcome = TEF_KEEP;
        if (key.len != 20) {
            tef_fail(&owned_error, "invalid Tefter capture");
            outcome = TEF_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            tef_fail(&owned_error, "cannot create Tefter result");
            outcome = TEF_ABORT;
        } else if (verify) {
            outcome = tef_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == TEF_KEEP && br_results_push(out, &result) != 0) {
            tef_fail(&owned_error, "cannot append Tefter result");
            outcome = TEF_ABORT;
        }
        br_result_clear(&result);
        if (outcome == TEF_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tef_keywords[] = {"tefter"};
static br_detector tef_detector = {
    .type = 826, .version = 0, .name = "Tefter", .custom_name = "",
    .description = "Tefter is a bookmarking service. Tefter API keys can be used to access and manage bookmarks.",
    .keywords = tef_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tef_scan,
};

int br_tefter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tef_fail(error, "invalid Tefter detector output");
    *out = NULL;
    if (br_key_pattern_init(&tef_detector, "\\b([0-9a-zA-Z]{20})\\b", error) != 0)
        return -1;
    *out = &tef_detector;
    return 0;
}
