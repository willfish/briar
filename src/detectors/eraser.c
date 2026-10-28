/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/eraser/eraser.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char eraser_guide[] = "https://howtorotate.com/docs/tutorials/eraser/";

static int eraser_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int eraser_rotation(br_result *result)
{
    /* This owned map exists even when verification will replace it with nil.
     * Do not elide its resource failures or retain it as verification metadata. */
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *value = json_object_new_string(eraser_guide);
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "rotation_guide", value) == 0) return 0;
    json_object_put(value); return -1;
}

static int eraser_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Source constructs this exact strings.Reader BEFORE the request ctor.
     * Static complete bytes need no serializer, heap copy or failure seam. */
    static const unsigned char body[] = "{\"elements\":[{\"type\":\"diagram\"}]}";
    _Static_assert(sizeof(body) == 34, "Eraser render payload must be 33 bytes plus NUL");
    const br_slice payload = {body, sizeof(body) - 1};
    char authorization[28], status_cause[80];
    _Static_assert(7 + 20 + 1 == sizeof(authorization), "Eraser Bearer must be 27 bytes plus NUL");
    br_http_response response = {0}; char *transport_error = NULL;
    const char *cause = NULL; bool sent = false, verified = false; int rc = 0;
    if (!ctx) cause = "net/http: nil Context"; /* Retain false, not a constructor skip. */
    else {
        /* Header construction follows the successful ctor. Captures are exactly
         * 20 ASCII bytes: complete stack assembly cannot fail or truncate. */
        memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, key.data, key.len);
        authorization[7 + key.len] = '\0';
        const br_header headers[] = {{"Authorization", authorization}, {"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "POST", .url = "https://app.eraser.io/api/render/elements",
            .headers = headers, .nheaders = 2, .body = payload,
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        sent = true;
        /* Retain ALL mixed shared setup/allocation/Do causes; never classify or
         * strip diagnostic text. Every response body/read error is ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error ? transport_error : "HTTP transport failed";
        else if (response.status == 200) verified = true;
        else if (response.status != 401) {
            int len = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", response.status);
            if (len < 0 || (size_t)len >= sizeof(status_cause)) rc = eraser_fail(error, "cannot format Eraser status cause");
            else cause = status_cause;
        }
    }
    if (!rc) {
        result->verified = verified;
        /* verifyMatch ALWAYS returns nil ExtraData, including constructor and
         * Do errors. Assignment precedes SetVerificationError in the source. */
        json_object_put(result->extra_data); result->extra_data = NULL;
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = eraser_fail(error, "cannot sanitize Eraser verification error");
    }
    /* Copy/sanitize causes BEFORE release. Complete static payload and stack
     * Bearer live through send AND release, even on failed sends. Source drains
     * and closes per verifyMatch; buffered Reader/drain/private-client/native
     * POST redirect/error-chain and global engine/output parity remain partial. */
    if (sent) br_http_release(ctx, &response);
    free(transport_error);
    return rc ? -1 : 0;
}

static int eraser_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return eraser_fail(error, "invalid or uninitialized Eraser scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    /* Deduplicate original bytes without TrimSpace or case normalization.
     * First-source order is one native traversal, not randomized Go map parity. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) rc = eraser_fail(&owned_error, "cannot create Eraser finding");
        if (!rc && eraser_rotation(&result) != 0) rc = eraser_fail(&owned_error, "cannot create Eraser rotation metadata");
        if (!rc && verify) rc = eraser_verify(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result) != 0) rc = eraser_fail(&owned_error, "cannot append Eraser finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const eraser_keywords[] = {"eraser"};
static br_detector eraser_detector = {
    .type = 990, .version = 0, .name = "Eraser", .custom_name = "",
    .description = "Eraser is a tool used for generating diagrams from DSL. Eraser API tokens can be used to authenticate and interact with the Eraser API.",
    .keywords = eraser_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = eraser_scan,
};

int br_eraser_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return eraser_fail(error, "invalid Eraser detector output");
    *out = NULL;
    if (br_key_pattern_init(&eraser_detector, "\\b([0-9a-zA-Z]{20})\\b", error) != 0) return -1;
    *out = &eraser_detector;
    return 0;
}
