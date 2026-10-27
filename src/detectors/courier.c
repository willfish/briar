/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/courier/courier.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int courier_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int courier_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, char **error)
{
    /* Fixed method/URL: nil ctx is the known NewRequestWithContext failure.
     * Source skips this candidate BEFORE preparing its Authorization value. */
    if (!ctx) {
        *keep = false;
        return 0;
    }
    static const char bearer[] = "Bearer ";
    /* The middle key segment is unbounded. Keep the full original key in one
     * necessary owned header buffer; neither truncate nor impose a new cap. */
    if (key.len > SIZE_MAX - sizeof(bearer))
        return courier_fail(error, "Courier Authorization header size overflow");
    char *auth = malloc(sizeof(bearer) + key.len);
    if (!auth) return courier_fail(error, "cannot allocate Courier Authorization header");
    memcpy(auth, bearer, sizeof(bearer) - 1);
    memcpy(auth + sizeof(bearer) - 1, key.data, key.len);
    auth[sizeof(bearer) - 1 + key.len] = '\0';
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.courier.com/preferences",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1 also combines setup and
     * allocation failures in this domain; suppress it whole, without a setter
     * or error-text classification. Own finding/auth failures remain fatal. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close ONLY until scan return; body/read errors are ignored.
     * ABI1 releases per request and may buffer eagerly. Deferred lifetime,
     * full native-client and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return 0;
}

static int courier_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return courier_fail(error, "invalid or uninitialized Courier scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace cannot change this ASCII grammar. Preserve occurrences,
         * including duplicates, and prepare findings BEFORE constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = courier_fail(&owned_error, "cannot create Courier result");
        if (rc == 0 && verify && courier_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = courier_fail(&owned_error, "cannot append Courier result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const courier_keywords[] = {"courier"};
static br_detector courier_detector = {
    .type = 665, .version = 0, .name = "Courier", .custom_name = "",
    .description = "Courier is a notification service that allows developers to send notifications through multiple channels. Courier API keys can be used to manage and send notifications.",
    .keywords = courier_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = courier_scan,
};

int br_courier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return courier_fail(error, "invalid Courier detector output");
    *out = NULL;
    /* Only PrefixRegex's keyword is case-insensitive. Literal pk_ is lowercase;
     * the arbitrary alphanumeric middle segment has no upper length bound. */
    if (br_key_pattern_init(&courier_detector,
            "\\b(pk\\_[a-zA-Z0-9]{1,}\\_[a-zA-Z0-9]{28})\\b", error) != 0) return -1;
    *out = &courier_detector;
    return 0;
}
