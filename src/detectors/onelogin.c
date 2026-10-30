/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/onelogin/onelogin.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../http_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } onelogin_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_onelogin(const br_scan_ctx *ctx, const char *id, const char *secret,
                             br_result *result)
{
    static const char *const urls[] = {
        "https://api.us.onelogin.com/auth/oauth2/v2/token",
        "https://api.eu.onelogin.com/auth/oauth2/v2/token",
    };
    static const unsigned char body[] = "{\"grant_type\":\"client_credentials\"}";
    char authorization[155];
    /* Both literal URLs and this JSON body exist before a nil-context drop.
     * Header.Add runs only after NewRequestWithContext succeeds. */
    int n = snprintf(authorization, sizeof(authorization),
                     "client_id:%s, client_secret:%s", id, secret);
    if (n != 154) return;
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i) {
        if (!ctx) continue;
        const br_header headers[] = {
            {"Authorization", authorization},
            {"Content-Type", "application/json; charset=utf-8"},
        };
        const br_http_request request = {
            .method = "POST", .url = urls[i], .headers = headers, .nheaders = 2,
            .body = {body, sizeof(body) - 1}, .profile = BR_HTTP_SANE,
            .timeout_ms = 5000, .detector_type = 22,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Plain http.Client{Timeout: 5s} uses DefaultTransport, not SaneHttpClient.
         * Do errors and non-2xx statuses are suppressed; either domain can verify. */
        if (br_http_default_transport_5s_send(ctx, &request, &response, &transport_error) == 0 &&
            response.status >= 200 && response.status < 300)
            result->verified = true;
        br_http_release(ctx, &response);
        free(transport_error);
    }
}

static int scan_onelogin(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid OneLogin scan");
    const onelogin_patterns *compiled = detector->state;
    br_captures ids = {0}, secrets = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(compiled->id, input, &ids, false, &owned);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, false, &owned);
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice id = br_captures_at(&ids, i), secret = br_captures_at(&secrets, s);
            br_result result = {0};
            if (id.len != 64 || secret.len != 64 || memchr(id.data, 0, id.len) ||
                memchr(secret.data, 0, secret.len))
                rc = fail(&owned, "invalid OneLogin capture");
            else if (br_finding_pair_bytes(&result, 22, id, "client_id", secret, "client_secret",
                                           (br_slice){(const unsigned char *)":", 1}) != 0 ||
                     !(result.redacted = strndup((const char *)id.data, id.len)))
                rc = fail(&owned, "cannot create OneLogin result");
            else if (verify)
                verify_onelogin(ctx, ids.items[i], secrets.items[s], &result);
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append OneLogin result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static onelogin_patterns patterns;
static const char *const keywords[] = {"onelogin"};
static br_detector onelogin = {
    .type = 22, .version = 0, .name = "OneLogin", .custom_name = "",
    .description = "OneLogin is an identity and access management provider. OneLogin OAuth "
                   "client IDs and secrets can be used to authenticate and authorize API requests.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_onelogin,
};

int br_onelogin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid OneLogin detector output");
    *out = NULL;
    if (!patterns.id &&
        br_regex_compile("(?i)id[a-zA-Z0-9_' \"=]{0,20}([a-z0-9]{64})", &patterns.id, error) != 0)
        return -1;
    if (!patterns.secret &&
        br_regex_compile("(?i)secret[a-zA-Z0-9_' \"=]{0,20}([a-z0-9]{64})", &patterns.secret, error) != 0)
        return -1;
    *out = &onelogin;
    return 0;
}
