/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/adobeio/adobeio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } adobeio_patterns;
static adobeio_patterns patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_adobeio(const br_scan_ctx *ctx, const char *key,
                          const char *id, br_result *result)
{
    const br_header headers[] = {{"x-api-key", key}, {"x-product", id}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://stock.adobe.io/Rest/Media/1/Search/Files?locale=en_US%2526search_parameters%255Bwords%255D=kittens",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 136,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* The transport buffers the body. Upstream ignores drain/close errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies neither key nor ID to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_adobeio(const br_detector *detector, const br_scan_ctx *ctx,
                        bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AdobeIO scan arguments");
    const adobeio_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id)
        return fail(error, "uninitialized AdobeIO patterns");

    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, true, error);
    /* Independent unique sets form a Cartesian product, regardless of position. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                ids.items[i], "id") != 0 ||
                (verify && verify_adobeio(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating AdobeIO result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static const char *const keywords[] = {"adobe"};
/* Commented out in the pinned defaults; retain this unversioned direct factory. */
static const br_detector adobeio = {
    .type = 136, .version = 0, .name = "AdobeIO", .custom_name = "",
    .description = "AdobeIO provides APIs for integrating with Adobe services. "
                   "These credentials can be used to access Adobe services and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_adobeio,
};

int br_adobeio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AdobeIO detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9.]{12})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &adobeio;
    return 0;
}
