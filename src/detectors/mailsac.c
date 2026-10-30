/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailsac/mailsac.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char url[] = "https://mailsac.com/api/addresses";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int scan_mailsac(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Mailsac scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Capture runs even when verify is set and ctx is NULL. Any nonzero,
     * including +1, is fatal before a nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating Mailsac result");
        if (rc == 0 && verify) {
            /* The URL is the constant above. It is not allocated. A nil
             * context is NewRequestWithContext's "net/http: nil Context". */
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            /* Mailsac-Key is already canonical. The {36,} capture is unbounded,
             * so the header borrows the complete key through send and release. */
            const br_header headers[] = {
                {"Content-Type", "application/json"},
                {"Mailsac-Key", keys.items[i]},
            };
            const br_http_request request = {
                .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                .profile = BR_HTTP_SANE, .detector_type = 481,
            };
            br_http_response response = {0};
            char *transport_error = NULL;
            /* Any 2xx verifies. The body and its read error are not inspected.
             * Other statuses and send failures stay unverified with no setter. */
            if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                result.verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(transport_error);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending Mailsac result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"mailsac"};
static br_detector mailsac = {
    .type = 481, .version = 0, .name = "Mailsac", .custom_name = "",
    .description = "Mailsac is a disposable email service used for testing and temporary email purposes. "
                   "Mailsac API keys can be used to access and manage email addresses and messages.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_mailsac,
};

int br_mailsac_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Mailsac detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&mailsac, "\\b(k_[0-9A-Za-z]{36,})\\b", error) != 0)
        return -1;
    *out = &mailsac;
    return 0;
}
