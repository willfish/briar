/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/docparser/docparser.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int docparser_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool docparser_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Literal concatenation of the fixed hex capture has no formatting error
     * domain. Prepare the complete URL before the constructor skip and borrow
     * it through both send and release. */
    static const char prefix[] = "https://api.docparser.com/v1/parsers?api_key=";
    char url[sizeof(prefix) + 40];
    _Static_assert(sizeof(url) == 86, "Docparser URL must be 85 bytes plus NUL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    if (!ctx) return false; /* Known NewRequestWithContext constructor failure. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain,
     * without a verification-error setter or diagnostic-text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Every body/read
     * error is ignored. Eager buffering/release, full SANE/RE2 behavior and
     * global engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int docparser_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return docparser_fail(error, "invalid or uninitialized Docparser scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Keep original occurrences, including duplicates.
         * Finding resources precede URL preparation and constructor skipping;
         * br_scan_key's verifier cannot express that candidate-only skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = docparser_fail(&owned_error, "cannot create Docparser result");
        if (rc == 0 && verify) keep = docparser_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = docparser_fail(&owned_error, "cannot append Docparser result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const docparser_keywords[] = {"docparser"};
static br_detector docparser_detector = {
    .type = 838, .version = 0, .name = "Docparser", .custom_name = "",
    .description = "Docparser is a document processing service that extracts data from PDFs and scanned documents. Docparser API keys can be used to access and manipulate this data.",
    .keywords = docparser_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = docparser_scan,
};

int br_docparser_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return docparser_fail(error, "invalid Docparser detector output");
    *out = NULL;
    if (br_key_pattern_init(&docparser_detector, "\\b([a-f0-9]{40})\\b", error) != 0)
        return -1;
    *out = &docparser_detector;
    return 0;
}
