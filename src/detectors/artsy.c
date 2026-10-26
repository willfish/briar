/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/artsy/artsy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } artsy_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_artsy(const br_scan_ctx *ctx, const char *key,
                         const char *id, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.artsy.net/api/tokens/xapp_token?client_id=%s&client_secret=%s", id, key);
    const br_http_request request = {
        .method = "POST", .url = url, .profile = BR_HTTP_SANE, .detector_type = 278,
    };
    /* Upstream uses http.NoBody and supplies no headers. */
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Deferred body-drain and close errors do not affect verification. */
        switch (response.status) {
        case 201: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream redacts the key only, not the client ID. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_artsy(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Artsy scan arguments");
    const artsy_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return fail(error, "uninitialized Artsy patterns");
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, error);
    /* Both alphabets exclude whitespace, making TrimSpace a no-op. Keep every
     * occurrence, with keys outermost and IDs innermost in source order. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0 ||
                (verify && verify_artsy(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating Artsy result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static artsy_patterns patterns;
static const char *const keywords[] = {"artsy"};
static const br_detector artsy = {
    .type = 278, .version = 0, .name = "Artsy", .custom_name = "",
    .description = "Artsy is an online platform for discovering, buying, and selling art. "
                   "Artsy API keys can be used to access Artsy's services and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_artsy,
};

int br_artsy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Artsy detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-zA-Z]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-zA-Z]{20})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &artsy;
    return 0;
}
