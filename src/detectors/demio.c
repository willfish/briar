/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/demio/demio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } demio_patterns;
typedef enum { DEMIO_ABORT = -1, DEMIO_KEEP = 0, DEMIO_SKIP = 1 } demio_outcome;

static int demio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static demio_outcome demio_verify(const br_scan_ctx *ctx, br_slice key, br_slice secret,
                                  br_result *result, char **error)
{
    /* Both captures are unreserved ASCII. Own the complete bounded URL on the
     * stack through synchronous send AND release, with key first in the query. */
    char url[sizeof("https://my.demio.com/api/v1/ping/query?api_key=&api_secret=") + 32 + 20];
    int n = snprintf(url, sizeof(url), "https://my.demio.com/api/v1/ping/query?api_key=%.*s&api_secret=%.*s",
                     (int)key.len, (const char *)key.data, (int)secret.len, (const char *)secret.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        demio_fail(error, "cannot format Demio URL");
        return DEMIO_ABORT;
    }
    /* Formatting precedes NewRequestWithContext's known nil-context skip. */
    if (!ctx) return DEMIO_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the whole shared setup/allocation/Do domain, without a setter
     * or diagnostic-stage classifier. Body/read errors never alter status. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Eager ABI
     * buffering/release, full native client and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DEMIO_KEEP;
}

static int demio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return demio_fail(error, "invalid or uninitialized Demio scan");
    const demio_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->secret)
        return demio_fail(error, "uninitialized Demio patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    /* Independent occurrence lists, key-major Cartesian products, duplicates
     * included. TrimSpace is a no-op; no detector-local span or equality filter. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            demio_outcome outcome = DEMIO_KEEP;
            /* The secret is required for the product but intentionally hidden
             * from Raw, RawV2 and SecretParts, even after verification. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                demio_fail(&owned_error, "cannot create Demio result");
                outcome = DEMIO_ABORT;
            }
            if (outcome == DEMIO_KEEP && verify)
                outcome = demio_verify(ctx, key, br_captures_at(&secrets, s), &result, &owned_error);
            if (outcome == DEMIO_KEEP && br_results_push(out, &result) != 0) {
                demio_fail(&owned_error, "cannot append Demio result");
                outcome = DEMIO_ABORT;
            }
            br_result_clear(&result);
            if (outcome == DEMIO_ABORT) rc = -1;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static demio_patterns demio_compiled;
static const char *const demio_keywords[] = {"demio"};
static const br_detector demio_detector = {
    .type = 863, .version = 0, .name = "Demio", .custom_name = "",
    .description = "Demio is a webinar platform that allows users to host, promote, and analyze webinars. Demio API keys can be used to access and manage webinar data.",
    .keywords = demio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &demio_compiled, .scan = demio_scan,
};

int br_demio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return demio_fail(error, "invalid Demio detector output");
    *out = NULL;
    if (!demio_compiled.key && br_regex_compile_prefixed(demio_keywords, 1,
            "\\b([a-z0-9A-Z]{32})\\b", &demio_compiled.key, error) != 0) return -1;
    if (!demio_compiled.secret && br_regex_compile_prefixed(demio_keywords, 1,
            "\\b([a-z0-9A-Z]{10,20})\\b", &demio_compiled.secret, error) != 0) return -1;
    *out = &demio_detector;
    return 0;
}
