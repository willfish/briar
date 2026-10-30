/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nasdaqdatalink/nasdaqdatalink.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int nasdaqdatalink_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET. */
static int nasdaqdatalink_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                 bool *keep, char **error)
{
    static const char prefix[] =
        "https://data.nasdaq.com/api/v3/datasets/FRED/GDP.csv?api_key=";
    static const char suffix[] = "&collapse=annual&rows=6&order=asc&column_index=1";
    *keep = false;
    if (key.len != 20) return nasdaqdatalink_fail(error, "invalid NasdaqDataLink capture");
    if (!ctx) return 0;
    /* Source assigns the package client timeout. Keep the 10 seconds on this
     * request only. Do not mutate a shared client, add headers, or encode. */
    size_t n = sizeof(prefix) - 1 + key.len + sizeof(suffix) - 1;
    char *url = malloc(n + 1);
    if (!url) return nasdaqdatalink_fail(error, "out of memory constructing NasdaqDataLink URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Preparation and Do stay unverified, with no setter. Source never reads
     * the body, so a body_error cannot suppress a 2xx or drop the finding.
     * Release once for every attempted send. The URL stays alive through it. */
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    free(url);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int nasdaqdatalink_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nasdaqdatalink_fail(error, "invalid or uninitialized NasdaqDataLink scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 20)
            rc = nasdaqdatalink_fail(&owned_error, "invalid NasdaqDataLink capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nasdaqdatalink_fail(&owned_error, "cannot create NasdaqDataLink finding");
        if (!rc && verify)
            rc = nasdaqdatalink_verify(ctx, key, &result, &keep, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = nasdaqdatalink_fail(&owned_error, "cannot append NasdaqDataLink finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const nasdaqdatalink_keywords[] = {"nasdaq"};
static br_detector nasdaqdatalink_detector = {
    .type = 532, .version = 0, .name = "NasdaqDataLink", .custom_name = "",
    .description = "Nasdaq Data Link provides financial, economic and alternative datasets. The API key can be used to access and retrieve this data.",
    .keywords = nasdaqdatalink_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = nasdaqdatalink_scan,
};

int br_nasdaqdatalink_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nasdaqdatalink_fail(error, "invalid NasdaqDataLink detector output");
    *out = NULL;
    if (br_key_pattern_init(&nasdaqdatalink_detector, "\\b([a-zA-Z0-9_-]{20})\\b", error) != 0)
        return -1;
    *out = &nasdaqdatalink_detector;
    return 0;
}
