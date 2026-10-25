/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/amadeus/amadeus.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } amadeus_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_amadeus(const br_scan_ctx *ctx, const char *key,
                           const char *secret, br_result *result)
{
    char payload[128];
    snprintf(payload, sizeof(payload),
             "grant_type=client_credentials&client_id=%s&client_secret=%s", key, secret);
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://test.api.amadeus.com/v1/security/oauth2/token",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)payload, strlen(payload)},
        .profile = BR_HTTP_SANE, .detector_type = 453,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: {
            static const unsigned char marker[] = "access_token";
            if (response.body_error) cause = response.body_error;
            else result->verified = br_slice_find(response.body,
                (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            break;
        }
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies neither part to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_amadeus(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Amadeus scan arguments");
    const amadeus_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->secret) return fail(error, "uninitialized Amadeus patterns");
    br_captures keys = {0}, secrets = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, true, error);
    /* Independent maps form a Cartesian product; their iteration order is unspecified. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", secrets.items[s], "secret") != 0 ||
                (verify && verify_amadeus(ctx, keys.items[k], secrets.items[s], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating Amadeus result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    return rc;
}

static amadeus_patterns patterns;
static const char *const keywords[] = {"amadeus"};
static const br_detector amadeus = {
    .type = 453, .version = 0, .name = "Amadeus", .custom_name = "",
    .description = "Amadeus provides travel technology solutions. "
                   "Amadeus API keys can be used to access and modify travel-related data and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_amadeus,
};

int br_amadeus_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Amadeus detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Za-z]{32})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.secret && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Za-z]{16})\\b", &patterns.secret, error) != 0)
        return -1;
    *out = &amadeus;
    return 0;
}
