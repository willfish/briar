/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/autodesk/autodesk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *secret; } autodesk_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_autodesk(const br_scan_ctx *ctx, const char *key,
                            const char *secret, br_result *result)
{
    char payload[128];
    snprintf(payload, sizeof(payload),
             "grant_type=client_credentials&client_id=%s&client_secret=%s", key, secret);
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://developer.api.autodesk.com/authentication/v1/authenticate",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)payload, strlen(payload)},
        .profile = BR_HTTP_SANE, .detector_type = 604,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = br_http_send(ctx, &request, &response, &error);
    result->verified = !rc && response.status >= 200 && response.status < 300;
    /* All transport/status/body errors are suppressed. Release immediately,
     * rather than retaining upstream's deferred closes until the scan ends. */
    br_http_release(ctx, &response);
    free(error);
}

static int scan_autodesk(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Autodesk scan arguments");
    const autodesk_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->secret) return fail(error, "uninitialized Autodesk patterns");
    br_captures keys = {0}, secrets = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, false, error);
    /* Upstream retains every occurrence and pairs key-major, secret-minor. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                 secrets.items[s], "secret") != 0) {
                rc = fail(error, "out of memory creating Autodesk result");
            } else {
                if (verify) verify_autodesk(ctx, keys.items[k], secrets.items[s], &result);
                if (br_results_push(out, &result) != 0)
                    rc = fail(error, "out of memory appending Autodesk result");
            }
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    return rc;
}

static autodesk_patterns patterns;
static const char *const keywords[] = {"autodesk"};
static const br_detector autodesk = {
    .type = 604, .version = 0, .name = "Autodesk", .custom_name = "",
    .description = "Autodesk provides software services for design and engineering. "
                   "Autodesk API keys can be used to access and modify data within Autodesk services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_autodesk,
};

int br_autodesk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Autodesk detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Za-z]{32})\\b",
                                                   &patterns.key, error) != 0)
        return -1;
    if (!patterns.secret && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Za-z]{16})\\b",
                                                      &patterns.secret, error) != 0)
        return -1;
    *out = &autodesk;
    return 0;
}
