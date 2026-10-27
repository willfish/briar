/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/companyhub/companyhub.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } companyhub_patterns;

static int companyhub_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void companyhub_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result)
{
    /* Source constructs the request before auth preparation. The caller has
     * already skipped known nil-context constructor failure. Captures guarantee
     * key=20, id=4..32; keep complete ID + SPACE + KEY + NUL live through release. */
    char authorization[54];
    memcpy(authorization, id.data, id.len);
    authorization[id.len] = ' ';
    memcpy(authorization + id.len + 1, key.data, key.len);
    authorization[id.len + 1 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.companyhub.com/v1/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 256,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines adapter setup/allocation and Do failures. Suppress the whole
     * domain, without error-text classification or a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only without reading/draining. Eager buffering,
     * per-request release and full native client behavior remain partial.
     * Body/read errors never change the source status-only decision. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int companyhub_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return companyhub_fail(error, "invalid CompanyHub scan arguments");
    const companyhub_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return companyhub_fail(error, "uninitialized CompanyHub detector");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            /* TrimSpace is a no-op. Preserve key-major/ID-minor occurrences,
             * including duplicates, self-pairs and source-captured context words. */
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                      br_captures_at(&ids, i), "id", (br_slice){0}) != 0)
                rc = companyhub_fail(error, "out of memory creating CompanyHub result");
            else if (verify && !ctx) {
                /* Finding/pair resources precede constructor failure handling.
                 * Fixed URL/method and ASCII leave nil context as the known skip. */
                br_result_clear(&result);
                continue;
            } else if (verify) companyhub_verify(ctx, br_captures_at(&keys, k), br_captures_at(&ids, i), &result);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = companyhub_fail(error, "out of memory appending CompanyHub result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc == 0 ? 0 : -1;
}

static companyhub_patterns companyhub_compiled;
static const char *const companyhub_keywords[] = {"companyhub"};
static const br_detector companyhub_detector = {
    .type = 256, .version = 0, .name = "CompanyHub", .custom_name = "",
    .description = "CompanyHub is a CRM tool used to manage customer relationships. "
                   "CompanyHub keys can be used to access and manipulate CRM data.",
    .keywords = companyhub_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &companyhub_compiled, .scan = companyhub_scan,
};

int br_companyhub_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return companyhub_fail(error, "invalid CompanyHub detector output");
    *out = NULL;
    if (!companyhub_compiled.key && br_regex_compile_prefixed(companyhub_keywords, 1,
        "\\b([0-9a-zA-Z]{20})\\b", &companyhub_compiled.key, error) != 0) return -1;
    if (!companyhub_compiled.id && br_regex_compile_prefixed(companyhub_keywords, 1,
        "\\b([a-zA-Z0-9$%^=-]{4,32})\\b", &companyhub_compiled.id, error) != 0) return -1;
    *out = &companyhub_detector;
    return 0;
}
