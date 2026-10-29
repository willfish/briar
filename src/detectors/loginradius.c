/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/loginradius/loginradius.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char loginradius_url[] = "https://api.loginradius.com/identity/v2/serverinfo?apikey=";

typedef struct loginradius_attempt {
    br_http_request request;
    br_http_response response;
    struct loginradius_attempt *previous;
    char url[];
} loginradius_attempt;

static int loginradius_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static loginradius_attempt *loginradius_request(br_slice key)
{
    if (key.len > SIZE_MAX - sizeof(loginradius_attempt) - sizeof(loginradius_url)) return NULL;
    loginradius_attempt *attempt = malloc(sizeof(*attempt) + sizeof(loginradius_url) + key.len);
    if (!attempt) return NULL;
    *attempt = (loginradius_attempt){0};
    memcpy(attempt->url, loginradius_url, sizeof(loginradius_url) - 1);
    memcpy(attempt->url + sizeof(loginradius_url) - 1, key.data, key.len);
    attempt->url[sizeof(loginradius_url) - 1 + key.len] = '\0';
    attempt->request = (br_http_request){
        .method = "GET", .url = attempt->url, .profile = BR_HTTP_SANE, .detector_type = 510,
    };
    return attempt;
}

static void loginradius_release(const br_scan_ctx *ctx, loginradius_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int loginradius_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return loginradius_fail(error, "invalid or uninitialized Loginradius scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    loginradius_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this lowercase-hex UUID grammar. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = loginradius_fail(error, "out of memory creating Loginradius result");
        if (rc == 0 && verify) {
            loginradius_attempt *attempt = loginradius_request(key);
            if (!attempt) rc = loginradius_fail(error, "out of memory creating Loginradius request");
            else if (!ctx) {
                /* Source constructs the finding and URL before the nil-context
                 * constructor failure drops this occurrence, without a send. */
                free(attempt);
                br_result_clear(&result);
                continue;
            } else {
                char *transport_error = NULL;
                /* The entire mixed preparation/Do error domain is suppressed,
                 * irrespective of error text or sign; there is no setter. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    result.verified = attempt->response.status >= 200 && attempt->response.status < 300;
                    attempt->previous = deferred;
                    deferred = attempt;
                } else loginradius_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = loginradius_fail(error, "out of memory appending Loginradius result");
        br_result_clear(&result);
    }
    /* Source closes successful responses in reverse order after publication.
     * Retain only provider storage here, not synthesized shared HTTP headers. */
    while (deferred) {
        loginradius_attempt *previous = deferred->previous;
        loginradius_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const loginradius_keywords[] = {"loginradius"};
static br_detector loginradius_detector = {
    .type = 510, .version = 0, .name = "Loginradius", .custom_name = "",
    .description = "Loginradius is a customer identity and access management (CIAM) platform. The API keys can be used "
                   "to manage user identities, authentication, and access control.",
    .keywords = loginradius_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = loginradius_scan,
};

int br_loginradius_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return loginradius_fail(error, "invalid Loginradius detector output");
    *out = NULL;
    if (br_key_pattern_init(&loginradius_detector,
        "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0) return -1;
    *out = &loginradius_detector;
    return 0;
}
