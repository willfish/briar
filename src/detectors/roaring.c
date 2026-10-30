/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/roaring/roaring.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_roaring(const br_scan_ctx *ctx, const char *authorization, br_result *result)
{
    static const unsigned char body[] = "grant_type=client_credentials";
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.roaring.io/token",
        .headers = headers, .nheaders = 1, .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 480,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_roaring(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Roaring scan");
    br_captures parts = {0};
    char *owned = NULL;
    size_t original = out->len;
    /* Client and secret patterns are identical, so one capture list is both axes. */
    int rc = br_captures_find(detector->state, input, &parts, false, &owned);
    for (size_t c = 0; !rc && c < parts.len; ++c) {
        for (size_t s = 0; !rc && s < parts.len; ++s) {
            br_slice client = br_captures_at(&parts, c), secret = br_captures_at(&parts, s);
            br_result result = {0};
            bool skip = false;
            if (client.len != 28 || secret.len != 28)
                rc = fail(&owned, "invalid Roaring capture");
            else if (br_finding_pair_bytes(&result, 480, client, "client_id", secret, "client_secret",
                                           (br_slice){0}) != 0)
                rc = fail(&owned, "cannot create Roaring result");
            else if (verify) {
                char *authorization = NULL, *auth_error = NULL;
                /* Basic credential and the form body exist before the nil-context skip. */
                if (br_http_basic_auth(client, secret, &authorization, &auth_error) != 0)
                    rc = fail(&owned, auth_error ? auth_error : "cannot encode Roaring credentials");
                else if (!ctx) skip = true;
                else verify_roaring(ctx, authorization, &result);
                free(authorization);
                free(auth_error);
            }
            if (!rc && !skip && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Roaring result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&parts);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"roaring"};
static br_detector roaring = {
    .type = 480, .version = 0, .name = "Roaring", .custom_name = "",
    .description = "Roaring credentials can be used to access the Roaring API, which provides "
                   "services for high-performance, compressed bitmaps.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_roaring,
};

int br_roaring_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Roaring detector output");
    *out = NULL;
    if (!roaring.state) {
        static const char *const prefixes[] = {"roaring"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([0-9A-Za-z_-]{28})\\b", &compiled, error) != 0)
            return -1;
        roaring.state = compiled;
    }
    *out = &roaring;
    return 0;
}
