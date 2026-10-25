/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apideck/apideck.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } apideck_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_apideck(const br_scan_ctx *ctx, const char *key,
                           const char *id, br_result *result)
{
    char auth[sizeof("Bearer ") + 101];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {{"x-apideck-app-id", id}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://unify.apideck.com/vault/consumers",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 212,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores deferred body-drain and close errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
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

static int scan_apideck(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ApiDeck scan arguments");
    const apideck_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return fail(error, "uninitialized ApiDeck patterns");
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, true, error);
    /* Independent unique maps form a Cartesian product, in unspecified order. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0 ||
                (verify && verify_apideck(ctx, keys.items[k], ids.items[i], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating ApiDeck result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static apideck_patterns patterns;
static const char *const keywords[] = {"apideck"};
static const br_detector apideck = {
    .type = 212, .version = 0, .name = "ApiDeck", .custom_name = "",
    .description = "ApiDeck is a platform that provides a unified API to connect multiple services. "
                   "ApiDeck keys can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_apideck,
};

int br_apideck_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ApiDeck detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile("\\b(sk_live_[a-z0-9A-Z-]{93})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9A-Z]{40})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &apideck;
    return 0;
}
