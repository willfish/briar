/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/formbucket/formbucket.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int formbucket_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int formbucket_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                              bool *keep, char **error)
{
    if (!ctx) { *keep = false; return 0; } /* Constructor skip: NO auth allocation. */
    br_header headers[2] = {{"Accept", "application/json"}};
    /* Source authorization is UNBOUNDED: exactly ONE necessary complete
     * allocation, after constructor/Accept, without cap/VLA/formatter/copy seam. */
    if (key.len > SIZE_MAX - 8) return formbucket_fail(error, "FormBucket authorization size overflow");
    char *authorization = malloc(key.len + 8);
    if (!authorization) return formbucket_fail(error, "cannot allocate FormBucket authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[key.len + 7] = '\0';
    /* ABI1 header C strings cannot carry NUL. Only AFTER the necessary complete
     * allocation, retain false with zero IO rather than send a truncated key.
     * Other Unicode/control bytes use existing WHOLE-domain header policies. */
    if (memchr(key.data, '\0', key.len)) { free(authorization); return 0; }
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://www.formbucket.com/v1/profile", .profile = BR_HTTP_SANE,
        .headers = headers, .nheaders = 2, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding even with populated body_error, without setter/classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        /* Source ReadAll precedes EVERY status. ANY non-NULL read error, even
         * empty, DROPS this occurrence rather than retaining a false finding. */
        if (response.body_error != NULL) *keep = false;
        else {
            static const unsigned char marker[] = "created_on";
            bool valid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && valid;
        }
    }
    /* Full owned authorization lives through send AND release, freed afterwards.
     * Source scan-defers Close twice after a successful read; ABI1 releases each
     * owned response ONCE, eagerly, even failure. Reader/native/private client,
     * regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return 0;
}

static int formbucket_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return formbucket_fail(error, "invalid or uninitialized FormBucket scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        /* TrimSpace is a no-op for first/last alphabets. Preserve ORIGINAL
         * occurrences/duplicates and byte lengths, including wildcard NUL.
         * Own finding resources precede skip, header guard, DROP or suppression. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = formbucket_fail(&owned_error, "cannot create FormBucket result");
        if (rc == 0 && verify) rc = formbucket_verify(ctx, br_captures_at(&keys, i), &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = formbucket_fail(&owned_error, "cannot append FormBucket result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const formbucket_keywords[] = {"formbucket"};
static br_detector formbucket_detector = {
    .type = 713, .version = 0, .name = "FormBucket", .custom_name = "",
    .description = "FormBucket is a service used to collect and manage form submissions. The detected credential can be used to access and modify form data.",
    .keywords = formbucket_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = formbucket_scan,
};

int br_formbucket_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return formbucket_fail(error, "invalid FormBucket detector output");
    *out = NULL;
    /* The FIRST separator is a wildcard RUNE (not LF), NOT a literal dot.
     * Keep unbounded groups, source class spelling and NO ending boundary. */
    if (br_key_pattern_init(&formbucket_detector,
            "\\b([0-9A-Za-z]{1,}.[0-9A-Za-z]{1,}\\.[0-9A-Z-a-z\\-_]{1,})", error) != 0) return -1;
    *out = &formbucket_detector;
    return 0;
}
