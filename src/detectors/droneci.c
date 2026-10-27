/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/droneci/droneci.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int droneci_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor-failure continue, not a false finding. */
static bool droneci_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* Finding resources precede the nil-context skip. */
    /* Authorization follows successful request construction. The compiled
     * capture is exactly 32 ASCII bytes: complete stack assembly cannot fail,
     * truncate or require a heap copy/formatting/allocation seam. */
    char authorization[40];
    _Static_assert(7 + 32 + 1 == sizeof(authorization), "DroneCI auth must be 39 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://cloud.drone.io/api/user", .profile = BR_HTTP_SANE,
        .headers = headers, .nheaders = 1, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. Never
     * classify diagnostics, skip these findings or call a verification setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored at every status. Keep the stack auth alive
     * through BOTH synchronous send and release, including failed sends.
     * Source scan-deferred Close-only timing, buffered Reader/native/private
     * clients, regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int droneci_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return droneci_fail(error, "invalid or uninitialized DroneCI scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* The shared key scanner cannot express the constructor skip. Keep that
     * decision private and separate from nonzero owned resource failures. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates and
         * create each finding before a possible nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = droneci_fail(&owned_error, "cannot create DroneCI finding");
        if (!rc && verify) keep = droneci_verify(ctx, key, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = droneci_fail(&owned_error, "cannot append DroneCI finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const droneci_keywords[] = {"droneci"};
static br_detector droneci_detector = {
    .type = 135, .version = 0, .name = "DroneCI", .custom_name = "",
    .description = "DroneCI is a continuous integration service that automates the testing and deployment of applications. DroneCI tokens can be used to access and control CI/CD pipelines.",
    .keywords = droneci_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = droneci_scan,
};

int br_droneci_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return droneci_fail(error, "invalid DroneCI detector output");
    *out = NULL;
    if (br_key_pattern_init(&droneci_detector, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &droneci_detector;
    return 0;
}
