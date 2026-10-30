/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mandrill/mandrill.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* 0 keep, 1 skip this candidate, -1 resource failure. */
static int verify_mandrill(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Source interpolates the capture before NewRequestWithContext. This
     * alphabet cannot contain quotes, so the object stays one JSON string. */
    char body[40];
    int n = snprintf(body, sizeof(body), "{\"key\": \"%s\"}", key);
    if (n < 0 || (size_t)n >= sizeof(body)) return -1;
    if (!ctx) return 1;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://mandrillapp.com/api/1.0/users/info",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, (size_t)n},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    /* Every constructor-success Do error is swallowed. Non-2xx is unverified
     * with no setter. Body and close errors are ignored. */
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_mandrill(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Mandrill scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace cannot change this bounded ASCII alphabet. Duplicates stay. */
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(error, "out of memory creating Mandrill result");
        else if (verify) {
            int checked = verify_mandrill(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct Mandrill request body");
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Mandrill result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"mandrill"};
static br_detector mandrill = {
    .type = 172, .version = 0, .name = "Mandrill", .custom_name = "",
    .description = "Mandrill is a transactional email API for Mailchimp users. Mandrill API keys can be used to send and track email messages.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_mandrill,
};

int br_mandrill_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Mandrill detector output");
    *out = NULL;
    if (br_key_pattern_init(&mandrill, "\\b([A-Za-z0-9_-]{22})\\b", error) != 0) return -1;
    *out = &mandrill;
    return 0;
}
