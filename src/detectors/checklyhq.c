/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/checklyhq/checklyhq.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int checklyhq_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void checklyhq_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[40] = "Bearer ";
    memcpy(auth + 7, key, 33); /* Exactly 32 captured ASCII bytes plus NUL. */
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.checklyhq.com/v1/checks",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 649,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1's unified nonzero send
     * domain also conflates adapter allocation/setup failures, an explicit
     * partial gap. No error-text classification or verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without draining. ABI1 eagerly releases
     * each request and may already have buffered the body. Body errors ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int checklyhq_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return checklyhq_fail(error, "invalid or uninitialized ChecklyHQ scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII captures leave nil context as the known
         * constructor failure: source skips rather than appends the finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op for the captured lowercase ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = checklyhq_fail(error, "out of memory creating ChecklyHQ result");
        else if (verify) checklyhq_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = checklyhq_fail(error, "out of memory appending ChecklyHQ result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const checklyhq_keywords[] = {"checklyhq"};
static br_detector checklyhq_detector = {
    .type = 649, .version = 0, .name = "ChecklyHQ", .custom_name = "",
    .description = "ChecklyHQ is a monitoring service for API and browser checks. "
                   "ChecklyHQ API keys can be used to access and manage these checks.",
    .keywords = checklyhq_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = checklyhq_scan,
};

int br_checklyhq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return checklyhq_fail(error, "invalid ChecklyHQ detector output");
    *out = NULL;
    if (br_key_pattern_init(&checklyhq_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &checklyhq_detector;
    return 0;
}
