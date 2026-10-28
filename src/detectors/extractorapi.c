/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/extractorapi/extractorapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int extractorapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source constructor-error continue, not a false finding. */
static bool extractorapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://extractorapi.com/api/v1/extractor?apikey=";
    static const char suffix[] = "&url=example.com";
    char url[106];
    _Static_assert(sizeof(prefix) - 1 + 40 + sizeof(suffix) == sizeof(url),
                   "ExtractorAPI URL must be 105 bytes plus NUL");
    /* Source concatenates the COMPLETE bounded URL before its constructor.
     * The captured alphabet is unreserved: preserve literal query order/bytes,
     * without an encoder, heap copy, formatter, cap or artificial failure seam. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
    if (!ctx) return false; /* Finding and URL preparation precede nil-context skip. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain. Retain false
     * findings; never classify diagnostics or call a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore every body/read error and keep the complete stack URL live through
     * BOTH synchronous send and release, even for failed sends. Source scan-
     * deferred Close-only timing, buffered Reader/native/private-client/regexp
     * behavior and global engine/output parity remain partial. Guards unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int extractorapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return extractorapi_fail(error, "invalid or uninitialized ExtractorAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* TrimSpace is a no-op even for hyphen edges. Keep all original captures
     * and duplicates; no invented full-token boundary/hex/entropy validation. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = extractorapi_fail(&owned_error, "cannot create ExtractorAPI finding");
        /* Owned resource errors are fatal BEFORE constructor skips or shared
         * send suppression. The shared key verifier cannot express this skip. */
        if (!rc && verify) keep = extractorapi_verify(ctx, key, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = extractorapi_fail(&owned_error, "cannot append ExtractorAPI finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const extractorapi_keywords[] = {"extractorapi"};
static br_detector extractorapi_detector = {
    .type = 784, .version = 0, .name = "ExtractorAPI", .custom_name = "",
    .description = "ExtractorAPI is a service for extracting data from various sources. ExtractorAPI keys can be used to access and extract data from these sources.",
    .keywords = extractorapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = extractorapi_scan,
};

int br_extractorapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return extractorapi_fail(error, "invalid ExtractorAPI detector output");
    *out = NULL;
    /* Exact source class: hyphen is legal; the two word boundaries are NOT
     * equivalent to excluding every member of the whole token alphabet. */
    if (br_key_pattern_init(&extractorapi_detector, "\\b([a-zA-Z-0-9]{40})\\b", error) != 0) return -1;
    *out = &extractorapi_detector;
    return 0;
}
