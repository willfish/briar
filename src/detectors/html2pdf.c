/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/html2pdf/html2pdf.go. */
#include "detectors.h"
#include "key_scan.h"
#include "captures.h"
#include "findings.h"
#include "../http_internal.h"

#include <stdlib.h>
#include <string.h>

static int html2pdf_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void html2pdf_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "{\"html\":\"Helloworld\",\"apiKey\":\"";
    static const char suffix[] = "\"}";
    unsigned char body[sizeof(prefix) - 1 + 64 + sizeof(suffix) - 1];
    /* The complete ASCII struct JSON, in declaration order, precedes http.Post.
     * The checked 64-byte alphanumeric capture needs no JSON escaping. */
    memcpy(body, prefix, sizeof(prefix) - 1);
    memcpy(body + sizeof(prefix) - 1, key.data, key.len);
    memcpy(body + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix) - 1);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.html2pdf.app/v1/generate",
        .headers = headers, .nheaders = 1, .body = {body, sizeof(body)},
        .profile = BR_HTTP_PRIVATE_DEFAULT_CLIENT, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Package http.Post ignores FromData's context. The private boundary keeps
     * only its explicit byte transport; it is not SANE or native DefaultClient. */
    if (br_http_default_client_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Every setup/Do error keeps a false finding without a setter. Status alone
     * matters; body/read errors are ignored. Provider storage survives release,
     * but the helper's projected background context ends at send return. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int html2pdf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return html2pdf_fail(error, "invalid or uninitialized Html2Pdf scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        /* Source TrimSpace is a no-op for the capture alphabet. Preserve every
         * non-overlapping occurrence, including duplicates, without cleaning. */
        if (key.len != 64) rc = html2pdf_fail(&owned_error, "invalid Html2Pdf capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = html2pdf_fail(&owned_error, "cannot create Html2Pdf result");
        if (rc == 0 && verify) html2pdf_verify(ctx, key, &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = html2pdf_fail(&owned_error, "cannot append Html2Pdf result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const html2pdf_keywords[] = {"html2pdf"};
static br_detector html2pdf_detector = {
    .type = 355, .version = 0, .name = "Html2Pdf", .custom_name = "",
    .description = "Html2Pdf is a service that converts HTML content into PDF documents. API keys for Html2Pdf can be used to authenticate and authorize access to this service.",
    .keywords = html2pdf_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = html2pdf_scan,
};

int br_html2pdf_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return html2pdf_fail(error, "invalid Html2Pdf detector output");
    *out = NULL;
    if (br_key_pattern_init(&html2pdf_detector, "\\b([a-zA-Z0-9]{64})\\b", error) != 0) return -1;
    *out = &html2pdf_detector;
    return 0;
}
