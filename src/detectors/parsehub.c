/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/parsehub/parsehub.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char parsehub_prefix[] = "https://www.parsehub.com/api/v2/projects?api_key=";
static const char parsehub_suffix[] = "&limit=1";

static int parsehub_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Fixed 12-byte key. Stack is enough; do not allocate the URL just to fail it. */
static int assemble_url(char *url, size_t cap, br_slice key)
{
    size_t prefix = sizeof(parsehub_prefix) - 1, suffix = sizeof(parsehub_suffix) - 1;
    if (key.len != 12 || !key.data || prefix + 12 + suffix + 1 > cap) return -1;
    memcpy(url, parsehub_prefix, prefix);
    memcpy(url + prefix, key.data, 12);
    memcpy(url + prefix + 12, parsehub_suffix, suffix + 1);
    return 0;
}

static int send_parsehub(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    /* No provider headers. The URL was assembled before the constructor. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies. Do not read the body or publish a cause. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_parsehub(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return parsehub_fail(error, "invalid or uninitialized Parsehub scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* FindAll runs before URL assembly and before a nil drop, including verify set and ctx NULL.
     * Any nonzero, including +1, is fatal before that drop. */
    int capture_rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    int rc = capture_rc == 0 ? 0 : -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        char url[sizeof(parsehub_prefix) + 12 + sizeof(parsehub_suffix) - 1];
        int finding_rc = br_finding_key_bytes(&result, detector->type, key, "key");
        int url_rc = 0;
        /* Finding exists before the raw query is assembled. Do not percent-encode. */
        if (finding_rc == 0 && verify) url_rc = assemble_url(url, sizeof(url), key);
        if (finding_rc != 0)
            rc = parsehub_fail(&owned_error, "out of memory creating detector result");
        else if (url_rc != 0)
            rc = parsehub_fail(&owned_error, "invalid Parsehub capture");
        else if (verify && !ctx) {
            /* NewRequestWithContext(nil) drops only this candidate after the URL exists.
             * No headers, send, release, or append. */
            br_result_clear(&result);
            continue;
        } else if (verify && send_parsehub(ctx, url, &result) != 0)
            rc = parsehub_fail(&owned_error, "cannot verify Parsehub candidate");
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = parsehub_fail(&owned_error, "out of memory appending detector result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const parsehub_keywords[] = {"parsehub"};
static br_detector parsehub_detector = {
    .type = 803, .version = 0, .name = "Parsehub", .custom_name = "",
    .description = "Parsehub is a web scraping service that allows users to extract data from websites. Parsehub API keys can be used to access and manage scraping projects.",
    .keywords = parsehub_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_parsehub,
};

int br_parsehub_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return parsehub_fail(error, "invalid Parsehub detector output");
    *out = NULL;
    if (br_key_pattern_init(&parsehub_detector, "\\b([0-9a-zA-Z]{12})\\b", error) != 0)
        return -1;
    *out = &parsehub_detector;
    return 0;
}
