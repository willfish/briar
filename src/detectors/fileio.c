/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fileio/fileio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static int fileio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int fileio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                         bool *keep, char **error)
{
    if (!ctx) { *keep = false; return 0; } /* Constructor failure SKIPS. */
    static const char prefix[] = "Bearer ";
    char authorization[sizeof(prefix) + 39];
    _Static_assert(sizeof(authorization) == 47, "Bearer value must be 46 bytes plus NUL");
    /* Complete Authorization is prepared AFTER construction. Private captures
     * are 39 ASCII bytes, including source's dot/hyphen boundary quirks. */
    memcpy(authorization, prefix, sizeof(prefix) - 1);
    memcpy(authorization + sizeof(prefix) - 1, key.data, key.len);
    authorization[sizeof(prefix) - 1 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://file.io/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. After
     * successful Do, ANY non-NULL ReadAll error retains false, without JSON. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && !response.body_error) {
        br_json *document = NULL;
        char *cause = NULL;
        /* Whole-body json.Valid runs BEFORE EVERY status decision. Null and
         * all scalar types count; do NOT apply generic float64 conversion. */
        int valid = br_json_document(response.body, &document, &cause);
        if (valid < 0) rc = fileio_fail(error, "cannot validate FileIO response JSON");
        else if (valid == 0) result->verified = response.status >= 200 && response.status < 300;
        json_object_put(document);
        free(cause); /* Ordinary invalid JSON is deliberately suppressed. */
    }
    /* Stack Authorization stays live through BOTH synchronous send and release.
     * Source scan-defers Close only after successful ReadAll/json.Valid. ABI1
     * eager buffering/release and Reader/close timing differ. Shared Go JSON/
     * invalid-UTF8/native limits, private clients, full SANE/RE2 and global
     * engine/output behavior remain partial. No setter or classifier. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int fileio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fileio_fail(error, "invalid or uninitialized FileIO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Original occurrences/duplicates and the EXACT regex's word boundaries,
     * not full-token validation. TrimSpace is a no-op; findings precede skips. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fileio_fail(&owned_error, "cannot create FileIO result");
        if (rc == 0 && verify)
            rc = fileio_verify(ctx, br_captures_at(&keys, i), &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = fileio_fail(&owned_error, "cannot append FileIO result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fileio_keywords[] = {"fileio"};
static br_detector fileio_detector = {
    .type = 527, .version = 0, .name = "FileIO", .custom_name = "",
    .description = "FileIO is a service for temporary file sharing. The detected key can be used to access and manage shared files.",
    .keywords = fileio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fileio_scan,
};

int br_fileio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fileio_fail(error, "invalid FileIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&fileio_detector, "\\b([A-Z0-9.-]{39})\\b", error) != 0)
        return -1;
    *out = &fileio_detector;
    return 0;
}
