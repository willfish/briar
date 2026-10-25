/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aha/aha.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } aha_patterns;
static aha_patterns patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_aha(const br_scan_ctx *ctx, const char *key,
                      const char *host, br_result *result)
{
    /* Captures bound the token to 64 bytes and the host to at most 70 bytes. */
    char url[128], auth[72];
    snprintf(url, sizeof(url), "https://%s/api/v1/me", host);
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.aha+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 802,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream checks only status and ignores response-body errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 404:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Only the token is supplied for redaction, not the captured hostname. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_aha(const br_detector *detector, const br_scan_ctx *ctx,
                    bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Aha scan arguments");
    const aha_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->host)
        return fail(error, "uninitialized Aha patterns");

    br_captures keys = {0}, hosts = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->host, input, &hosts, true, error);
    if (!rc && hosts.len == 0)
        rc = br_captures_push(&hosts, (br_slice){(const unsigned char *)"aha.io", 6}, false, error);

    /* Keep token occurrences in source order, paired with each unique host.
     * The capture alphabet excludes whitespace, so TrimSpace is a no-op. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t h = 0; !rc && h < hosts.len; ++h) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                hosts.items[h], "url") != 0 ||
                (verify && verify_aha(ctx, keys.items[k], hosts.items[h], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Aha result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&hosts);
    return rc;
}

static const char *const keywords[] = {"aha.io"};
static const char *const key_prefix[] = {"aha"};
static const br_detector aha = {
    .type = 802, .version = 0, .name = "Aha", .custom_name = "",
    .description = "Aha is a product management software suite. Aha API keys can be used "
                   "to access and modify product data and workflows.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_aha,
};

int br_aha_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Aha detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(key_prefix, 1, "\\b([0-9a-f]{64})\\b", &patterns.key, error) != 0)
        return -1;
    /* Preserve the mandatory second label character and the missing end boundary. */
    if (!patterns.host &&
        br_regex_compile("\\b([A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])\\.aha\\.io)",
                          &patterns.host, error) != 0)
        return -1;
    *out = &aha;
    return 0;
}
