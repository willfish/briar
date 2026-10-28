/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gocardless/gocardless.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int gocardless_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void gocardless_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The pattern bounds the complete, possibly quote-terminated key at 46 bytes. */
    static const char prefix[] = "Bearer ";
    char auth[sizeof(prefix) + 46];
    memcpy(auth, prefix, sizeof(prefix) - 1);
    memcpy(auth + sizeof(prefix) - 1, key.data, key.len);
    auth[sizeof(prefix) - 1 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", auth},
        /* net/http Header.Add canonicalizes the source's GoCardless-Version. */
        {"Gocardless-Version", "2015-07-06"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.gocardless.com/customers/",
        .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* The whole shared setup/Do error domain is ignored; the body is not read. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider auth/capture storage survives release, not shared synthesized UA. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int gocardless_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gocardless_fail(error, "invalid or uninitialized GoCardless scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 46) {
            rc = gocardless_fail(&owned_error, "invalid GoCardless capture");
            break;
        }
        /* TrimSpace only removes the consumed space/CR/LF in this alphabet.
         * Quotes remain part of Raw, secret parts and Authorization. */
        unsigned char last = key.data[key.len - 1];
        if (last == ' ' || last == '\r' || last == '\n') --key.len;
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = gocardless_fail(&owned_error, "cannot create GoCardless result");
        else if (!(verify && !ctx)) {
            /* The nil-context request constructor fails after finding creation. */
            if (verify) gocardless_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = gocardless_fail(&owned_error, "cannot append GoCardless result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const gocardless_keywords[] = {"gocardless"};
static br_detector gocardless_detector = {
    .type = 184, .version = 0, .name = "GoCardless", .custom_name = "",
    .description = "GoCardless is an online payments service that makes collecting payments by direct debit easy for everyone. GoCardless API keys can be used to access and manage payment transactions.",
    .keywords = gocardless_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = gocardless_scan,
};

int br_gocardless_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gocardless_fail(error, "invalid GoCardless detector output");
    *out = NULL;
    if (!gocardless_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(live_[0-9A-Za-z_\\-]{40}[ \"'\\r\\n]{1})", &regex, error) != 0)
            return -1;
        gocardless_detector.state = regex;
    }
    *out = &gocardless_detector;
    return 0;
}
