/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/campayn/campayn.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int campayn_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void campayn_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const char prefix[] = "TRUEREST apikey=";
    char auth[sizeof(prefix) + 64];
    memcpy(auth, prefix, sizeof(prefix) - 1);
    memcpy(auth + sizeof(prefix) - 1, key, 65); /* Exactly 64 captured ASCII bytes plus NUL. */
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://campayn.com/api/v1/lists",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 254,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1's one nonzero send domain
     * also includes adapter allocation/setup failures: those remain suppressed
     * here, an explicit partial gap, never inferred from error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only (no drain). ABI1 releases each request
     * eagerly and may already have buffered the body. All body errors ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int campayn_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return campayn_fail(error, "invalid or uninitialized Campayn scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the reachable
         * NewRequestWithContext failure: source continues, skipping finding. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace is a no-op for the captured lowercase ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = campayn_fail(error, "out of memory creating Campayn result");
        else if (verify) campayn_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = campayn_fail(error, "out of memory appending Campayn result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const campayn_keywords[] = {"campayn"};
static br_detector campayn_detector = {
    .type = 254, .version = 0, .name = "Campayn", .custom_name = "",
    .description = "Campayn is an email marketing service that allows users to create, send, and track email campaigns. "
                   "Campayn API keys can be used to manage email lists, send emails, and track campaign performance.",
    .keywords = campayn_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = campayn_scan,
};

int br_campayn_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return campayn_fail(error, "invalid Campayn detector output");
    *out = NULL;
    if (br_key_pattern_init(&campayn_detector, "\\b([a-z0-9]{64})\\b", error) != 0) return -1;
    *out = &campayn_detector;
    return 0;
}
