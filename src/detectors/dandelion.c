/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dandelion/dandelion.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DANDELION_ABORT = -1, DANDELION_KEEP = 0, DANDELION_SKIP = 1
} dandelion_outcome;

static int dandelion_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static dandelion_outcome dandelion_verify(const br_scan_ctx *ctx, br_slice key,
                                         br_result *result, char **error)
{
    /* This exact 32-byte ASCII alphanumeric capture needs no escaping. Borrow
     * the complete bounded URL, including its NUL, through send AND release. */
    char url[sizeof("https://api.dandelion.eu/datatxt/li/v1/?text=Smart&token=") + 32];
    int n = snprintf(url, sizeof(url), "https://api.dandelion.eu/datatxt/li/v1/?text=Smart&token=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        dandelion_fail(error, "cannot format Dandelion URL");
        return DANDELION_ABORT;
    }
    /* Source formats the complete URL before the known nil-context skip. */
    if (!ctx) return DANDELION_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines setup/allocation and Do failures. Suppress that whole
     * domain, without a verification-error setter or diagnostic classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * never affect status. Eager buffering/release, full native SANE behavior
     * and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DANDELION_KEEP;
}

static int dandelion_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dandelion_fail(error, "invalid or uninitialized Dandelion scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        dandelion_outcome outcome = DANDELION_KEEP;
        /* TrimSpace is a no-op. Retain every occurrence, including duplicates.
         * Finding resources must precede URL preparation and constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            dandelion_fail(&owned_error, "cannot create Dandelion result");
            outcome = DANDELION_ABORT;
        }
        if (outcome == DANDELION_KEEP && verify)
            outcome = dandelion_verify(ctx, key, &result, &owned_error);
        if (outcome == DANDELION_KEEP && br_results_push(out, &result) != 0) {
            dandelion_fail(&owned_error, "cannot append Dandelion result");
            outcome = DANDELION_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DANDELION_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dandelion_keywords[] = {"dandelion"};
static br_detector dandelion_detector = {
    .type = 619, .version = 0, .name = "Dandelion", .custom_name = "",
    .description = "Dandelion is a text analysis service. Dandelion tokens can be used to access and analyze text data using their APIs.",
    .keywords = dandelion_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dandelion_scan,
};

int br_dandelion_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dandelion_fail(error, "invalid Dandelion detector output");
    *out = NULL;
    if (br_key_pattern_init(&dandelion_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &dandelion_detector;
    return 0;
}
