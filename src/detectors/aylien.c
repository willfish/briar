/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aylien/aylien.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } aylien_patterns;

static int aylien_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int aylien_verify(const br_scan_ctx *ctx, const char *key,
                          const char *id, br_result *result)
{
    const br_header headers[] = {
        {"X-AYLIEN-NewsAPI-Application-ID", id},
        {"X-AYLIEN-NewsAPI-Application-Key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.aylien.com/news/stories",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 485,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains the body but ignores its contents and read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* SetVerificationError receives only the key, not the application ID. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int aylien_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return aylien_fail(error, "invalid Aylien scan arguments");
    const aylien_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return aylien_fail(error, "uninitialized Aylien detector");

    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, error);
    /* The capture alphabets make TrimSpace a no-op. Preserve occurrences and
     * the upstream key-major, ID-minor Cartesian product, including duplicates. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                ids.items[i], "id") != 0 ||
                (verify && aylien_verify(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = aylien_fail(error, "out of memory creating Aylien result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static aylien_patterns aylien_compiled;
static const char *const aylien_keywords[] = {"aylien"};
static const br_detector aylien_detector = {
    .type = 485, .version = 0, .name = "Aylien", .custom_name = "",
    .description = "Aylien is a text analysis platform that provides natural language processing "
                   "and machine learning APIs. Aylien API keys can be used to access and analyze text data.",
    .keywords = aylien_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &aylien_compiled, .scan = aylien_scan,
};

int br_aylien_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return aylien_fail(error, "invalid Aylien detector output");
    *out = NULL;
    if (!aylien_compiled.key &&
        br_regex_compile_prefixed(aylien_keywords, 1, "\\b([a-z0-9]{32})\\b",
                                  &aylien_compiled.key, error) != 0)
        return -1;
    if (!aylien_compiled.id &&
        br_regex_compile_prefixed(aylien_keywords, 1, "\\b([a-z0-9]{8})\\b",
                                  &aylien_compiled.id, error) != 0)
        return -1;
    *out = &aylien_detector;
    return 0;
}
