/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/customerguru/customerguru.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } customerguru_patterns;
typedef enum {
    CUSTOMERGURU_ABORT = -1, CUSTOMERGURU_KEEP = 0, CUSTOMERGURU_SKIP = 1
} customerguru_outcome;

static int customerguru_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static customerguru_outcome customerguru_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                                               br_result *result, char **error)
{
    /* Both captures are bounded ASCII alphanumeric. Keep the complete ID-first
     * query, including its NUL, borrowed through synchronous send AND release. */
    char url[sizeof("https://customer.guru/export/customers?api_secret=&api_token=") + 50 + 30];
    int n = snprintf(url, sizeof(url), "https://customer.guru/export/customers?api_secret=%.*s&api_token=%.*s",
                     (int)id.len, (const char *)id.data, (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        customerguru_fail(error, "cannot format CustomerGuru URL");
        return CUSTOMERGURU_ABORT;
    }
    /* Source evaluates the complete URL before the known nil-context skip. */
    if (!ctx) return CUSTOMERGURU_SKIP;
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
    return CUSTOMERGURU_KEEP;
}

static int customerguru_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return customerguru_fail(error, "invalid or uninitialized CustomerGuru scan");
    const customerguru_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return customerguru_fail(error, "uninitialized CustomerGuru patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k), id = br_captures_at(&ids, i);
            customerguru_outcome outcome = CUSTOMERGURU_KEEP;
            /* Independent occurrence lists: every key-major/ID-minor product,
             * including duplicates. TrimSpace changes neither alphabet. Finding
             * resources precede URL preparation and any constructor skip. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0) {
                customerguru_fail(&owned_error, "cannot create CustomerGuru result");
                outcome = CUSTOMERGURU_ABORT;
            }
            if (outcome == CUSTOMERGURU_KEEP && verify)
                outcome = customerguru_verify(ctx, key, id, &result, &owned_error);
            if (outcome == CUSTOMERGURU_KEEP && br_results_push(out, &result) != 0) {
                customerguru_fail(&owned_error, "cannot append CustomerGuru result");
                outcome = CUSTOMERGURU_ABORT;
            }
            br_result_clear(&result);
            if (outcome == CUSTOMERGURU_ABORT) rc = -1;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static customerguru_patterns customerguru_compiled;
static const char *const customerguru_keywords[] = {"customerguru"};
static const char *const customerguru_prefixes[] = {"guru"};
static const br_detector customerguru_detector = {
    .type = 226, .version = 0, .name = "CustomerGuru", .custom_name = "",
    .description = "CustomerGuru is a feedback platform used to collect and analyze customer feedback. API keys and secrets can be used to access and manage this feedback data.",
    .keywords = customerguru_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &customerguru_compiled, .scan = customerguru_scan,
};

int br_customerguru_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return customerguru_fail(error, "invalid CustomerGuru detector output");
    *out = NULL;
    /* Dispatch uses customerguru; BOTH extraction patterns instead use guru,
     * including its trailing occurrence within customerguru at the full gap. */
    if (!customerguru_compiled.key && br_regex_compile_prefixed(customerguru_prefixes, 1,
        "\\b([a-z0-9A-Z]{30})\\b", &customerguru_compiled.key, error) != 0) return -1;
    if (!customerguru_compiled.id && br_regex_compile_prefixed(customerguru_prefixes, 1,
        "\\b([a-z0-9A-Z]{50})\\b", &customerguru_compiled.id, error) != 0) return -1;
    *out = &customerguru_detector;
    return 0;
}
