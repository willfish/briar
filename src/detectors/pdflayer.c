/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pdflayer/pdflayer.go. */
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int pdflayer_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* Complete response bytes only. A read error defeats every byte, so the marker
 * is searched only after a successful full read. */
static bool contains_contents(br_slice body)
{
    static const char marker[] = "Contents";
    if (!body.data || body.len < sizeof(marker) - 1) return false;
    for (size_t i = 0; i + sizeof(marker) - 1 <= body.len; ++i)
        if (!memcmp(body.data + i, marker, sizeof(marker) - 1)) return true;
    return false;
}

static int pdflayer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pdflayer_fail(error, "invalid or uninitialized PdfLayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pdflayer_fail(&owned_error, "cannot create PdfLayer result");
        if (rc == 0 && verify) {
            static const char prefix[] = "https://api.pdflayer.com/api/convert?access_key=";
            static const char suffix[] = "&document_url=https://pdflayer.com/downloads/invoice.html";
            char url[sizeof(prefix) - 1 + 32 + sizeof(suffix)];
            memcpy(url, prefix, sizeof(prefix) - 1);
            memcpy(url + sizeof(prefix) - 1, key.data, 32);
            memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                response.body_error == NULL) {
                if (!response.body.data && response.body.len)
                    rc = pdflayer_fail(&owned_error, "invalid PdfLayer response body");
                else
                    result.verified = response.status >= 200 && response.status < 300 &&
                                      contains_contents(response.body);
            }
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pdflayer_fail(&owned_error, "cannot append PdfLayer result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pdflayer_keywords[] = {"pdflayer"};
static br_detector pdflayer_detector = {
    .type = 493, .version = 0, .name = "PdfLayer", .custom_name = "",
    .description = "PdfLayer is a service for converting HTML documents to PDF. PdfLayer API keys can be used to access and utilize the PDF conversion service.",
    .keywords = pdflayer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pdflayer_scan,
};

int br_pdflayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pdflayer_fail(error, "invalid PdfLayer detector output");
    *out = NULL;
    if (br_key_pattern_init(&pdflayer_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &pdflayer_detector;
    return 0;
}
