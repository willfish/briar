/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shutterstock/shutterstock.go.
 * Raw is the 16-character secret. The 32-character value is only the Basic user. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static br_regex *key_re, *secret_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_shutterstock(const br_scan_ctx *ctx, const char *user, const char *secret,
                               br_result *result, char **error)
{
    if (!ctx) return 1;
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)user, strlen(user)},
                           (br_slice){(const unsigned char *)secret, strlen(secret)},
                           &authorization, error) != 0)
        return -1;
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.shutterstock.com/v2/images/search",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int scan_shutterstock(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !secret_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shutterstock scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(secret_re, input, &secrets, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        for (size_t j = 0; !rc && j < secrets.len; ++j) {
            br_result result = {0};
            int outcome = 0;
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&secrets, j), "key") != 0) {
                fail(&owned_error, "cannot create Shutterstock result");
                outcome = -1;
            } else if (verify)
                outcome = verify_shutterstock(ctx, keys.items[i], secrets.items[j], &result, &owned_error);
            if (outcome == 0 && br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append Shutterstock result");
                outcome = -1;
            }
            br_result_clear(&result);
            if (outcome < 0) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"shutterstock"};
static br_detector shutterstock = {
    .type = 462, .version = 0, .name = "Shutterstock", .custom_name = "",
    .description = "Shutterstock is a global provider of stock photography, footage, music, and editing tools. Shutterstock API keys can be used to access and modify this content.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_shutterstock,
};

int br_shutterstock_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"shutterstock"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shutterstock detector output");
    *out = NULL;
    if (!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-zA-Z]{32})\\b", &key_re, error) != 0)
        return -1;
    if (!secret_re && br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-zA-Z]{16})\\b", &secret_re, error) != 0)
        return -1;
    shutterstock.state = key_re;
    *out = &shutterstock;
    return 0;
}
