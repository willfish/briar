/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sigopt/sigopt.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_sigopt(const br_scan_ctx *ctx, const char *authorization, br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.sigopt.com/v1/experiments",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 704,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_sigopt(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Sigopt scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len != 48) rc = fail(&owned, "invalid Sigopt capture");
        else if (br_finding_key_bytes(&result, 704, key, "key") != 0)
            rc = fail(&owned, "cannot create Sigopt result");
        else if (verify) {
            char *authorization = NULL, *auth_error = NULL;
            br_slice password = {(const unsigned char *)"", 0};
            /* key: is encoded before NewRequestWithContext's nil-context skip. */
            if (br_http_basic_auth(key, password, &authorization, &auth_error) != 0)
                rc = fail(&owned, auth_error ? auth_error : "cannot encode Sigopt credentials");
            else if (!ctx) skip = true;
            else verify_sigopt(ctx, authorization, &result);
            free(authorization);
            free(auth_error);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Sigopt result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sigopt"};
static br_detector sigopt = {
    .type = 704, .version = 0, .name = "Sigopt", .custom_name = "",
    .description = "Sigopt is a platform for optimizing machine learning models. Sigopt API keys "
                   "can be used to access and manage experiments on the Sigopt platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_sigopt,
};

int br_sigopt_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Sigopt detector output");
    *out = NULL;
    if (!sigopt.state) {
        static const char *const prefixes[] = {"sigopt"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([A-Z0-9]{48})\\b", &compiled, error) != 0)
            return -1;
        sigopt.state = compiled;
    }
    *out = &sigopt;
    return 0;
}
