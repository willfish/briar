/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dronahq/dronahq.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { DRONAHQ_KEEP, DRONAHQ_SKIP } dronahq_outcome;

static int dronahq_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static dronahq_outcome dronahq_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The capture is exactly 50 unreserved ASCII bytes. Prepare the complete
     * literal URL, including NUL, BEFORE the known nil-context constructor skip.
     * No formatter, heap duplicate or artificial URL-allocation seam is needed. */
    static const char prefix[] = "https://plugin.api.dronahq.com/users/?tokenkey=";
    char url[sizeof(prefix) + 50];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key, 51);
    if (!ctx) return DRONAHQ_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * setter or diagnostic classifier. Retain failed-send findings as false. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrow the whole stack URL through synchronous send AND release. Body
     * contents/read errors are ignored. Source scan-defers Close only; eager
     * buffering/release, native client, regexp and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DRONAHQ_KEEP;
}

static int dronahq_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dronahq_fail(error, "invalid or uninitialized DronaHQ scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Keep every original occurrence and duplicate;
         * finding resources precede URL preparation and any constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = dronahq_fail(&owned_error, "cannot create DronaHQ result");
        if (rc == 0 && (!verify || dronahq_verify(ctx, keys.items[i], &result) == DRONAHQ_KEEP)) {
            if (br_results_push(out, &result) != 0)
                rc = dronahq_fail(&owned_error, "cannot append DronaHQ result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dronahq_keywords[] = {"dronahq"};
static br_detector dronahq_detector = {
    .type = 651, .version = 0, .name = "DronaHQ", .custom_name = "",
    .description = "DronaHQ is a platform for building internal tools and applications. DronaHQ keys can be used to access and manage these tools and applications.",
    .keywords = dronahq_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dronahq_scan,
};

int br_dronahq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dronahq_fail(error, "invalid DronaHQ detector output");
    *out = NULL;
    if (br_key_pattern_init(&dronahq_detector, "\\b([a-z0-9]{50})\\b", error) != 0) return -1;
    *out = &dronahq_detector;
    return 0;
}
