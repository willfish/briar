/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/stytch/stytch.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } stytch_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_stytch(const br_scan_ctx *ctx, const char *id, const char *token, br_result *result, char **error)
{
    if (!ctx) return 1;
    char *auth = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                           (br_slice){(const unsigned char *)token, strlen(token)}, &auth, error) != 0)
        return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.stytch.com/v1/users/pending",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(auth);
    return 0;
}

static int scan_stytch(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Stytch scan");
    const stytch_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(patterns->id, input, &ids, false, &owned);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            /* The project ID authenticates but is not stored. Raw is the token. */
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = fail(&owned, "out of memory creating Stytch result");
            else if (verify && verify_stytch(ctx, ids.items[i], keys.items[k], &result, &owned) > 0) {
                br_result_clear(&result);
                continue;
            } else if (verify && owned) rc = -1;
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "out of memory appending Stytch result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"stytch"};
static stytch_patterns patterns;
static br_detector stytch = {
    .type = 538, .version = 0, .name = "Stytch", .custom_name = "",
    .description = "Stytch is a platform for passwordless authentication. Stytch API keys can be used to access and manage authentication services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_stytch,
};

int br_stytch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Stytch detector output");
    *out = NULL;
    const char *const prefix[] = {"stytch"};
    if (!patterns.key && br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9-_]{47}=)", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id && br_regex_compile_prefixed(prefix, 1, "\\b([a-z0-9-]{49})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &stytch;
    return 0;
}
