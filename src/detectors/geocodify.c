/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/geocodify/geocodify.go. */
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    char *error;
} geocodify_matches;

static bool verify_geocodify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The capture fixes the URL size; no escaping or query reordering. Keep
     * the complete value alive through BOTH synchronous send and release. */
    static const char prefix[] = "https://api.geocodify.com/v2/geocode?api_key=";
    char url[sizeof(prefix) + 40];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 40);
    url[sizeof(url) - 1] = '\0';
    /* NewRequestWithContext rejects nil only after finding/URL construction. */
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* ABI1 combines shared setup errors and Do errors: retain every such
     * failure as false, without a setter. This provider never reads the body. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int emit(void *user, const br_span *groups, size_t count)
{
    geocodify_matches *matches = user;
    if (count < 2 || groups[1].begin == SIZE_MAX || groups[1].end > matches->input.len ||
        groups[1].end < groups[1].begin || groups[1].end - groups[1].begin != 40)
        return fail(&matches->error, "invalid Geocodify capture");
    br_slice key = {matches->input.data + groups[1].begin, 40};
    /* TrimSpace is a no-op for this grammar. Preserve original occurrences,
     * including duplicates, without staging copies or applying local filters. */
    br_result result = {0};
    int rc = br_finding_key_bytes(&result, matches->detector->type, key, "key");
    if (rc != 0) rc = fail(&matches->error, "cannot create Geocodify result");
    else {
        bool keep = !matches->verify || verify_geocodify(matches->ctx, key, &result);
        if (keep && br_results_push(matches->out, &result) != 0)
            rc = fail(&matches->error, "cannot append Geocodify result");
    }
    br_result_clear(&result);
    return rc;
}

static int scan_geocodify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Geocodify scan");
    size_t original_len = out->len;
    geocodify_matches matches = {detector, ctx, input, out, verify, NULL};
    char *owned_error = NULL;
    int rc = br_regex_each(detector->state, input, emit, &matches, &owned_error);
    if (matches.error) { free(owned_error); owned_error = matches.error; }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"geocodify"};
static br_detector geocodify = {
    .type = 542, .version = 0, .name = "Geocodify", .custom_name = "",
    .description = "Geocodify is a service that provides geocoding and reverse geocoding capabilities. Geocodify API keys can be used to access these geocoding services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_geocodify,
};

int br_geocodify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Geocodify detector output");
    *out = NULL;
    if (br_key_pattern_init(&geocodify, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &geocodify;
    return 0;
}
