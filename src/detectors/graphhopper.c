/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/graphhopper/graphhopper.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int graphhopper_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes the source constructor's nil-context skip. */
static bool graphhopper_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://graphhopper.com/api/1/geocode?q=Philippines&key=";
    static const char suffix[] = "&type=json";
    char url[sizeof(prefix) - 1 + 36 + sizeof(suffix)];
    /* The grammar bounds the original key to exactly 36 ASCII bytes. Assemble
     * the complete literal URL before the context-bound constructor. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 36);
    memcpy(url + sizeof(prefix) - 1 + 36, suffix, sizeof(suffix));
    if (!ctx) return false;

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/allocation/Do error domain. Body reads
     * are ignored, and every successful-send 2xx verifies. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original URL storage survives release, including failed/empty attempts;
     * ordinary ABI1 prepared headers and synthesized UA do not. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int graphhopper_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return graphhopper_fail(error, "invalid or uninitialized Graphhopper scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Preserve occurrences, duplicates and the
         * regex's context-dependent leading/trailing hyphens, not UUIDs. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = graphhopper_fail(&owned_error, "cannot create Graphhopper result");
        if (rc == 0 && verify) keep = graphhopper_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = graphhopper_fail(&owned_error, "cannot append Graphhopper result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const graphhopper_keywords[] = {"graphhopper"};
static br_detector graphhopper_detector = {
    .type = 436, .version = 0, .name = "Graphhopper", .custom_name = "",
    .description = "Graphhopper provides a routing engine for route planning and navigation. The API keys can be used to access and utilize the Graphhopper routing services.",
    .keywords = graphhopper_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = graphhopper_scan,
};

int br_graphhopper_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return graphhopper_fail(error, "invalid Graphhopper detector output");
    *out = NULL;
    if (!graphhopper_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(graphhopper_keywords, 1, "\\b([a-z0-9-]{36})\\b", &regex, error) != 0)
            return -1;
        graphhopper_detector.state = regex;
    }
    *out = &graphhopper_detector;
    return 0;
}
