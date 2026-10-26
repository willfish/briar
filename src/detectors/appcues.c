/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/appcues/appcues.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *username, *id; } appcues_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_appcues(const br_scan_ctx *ctx, const char *key,
                           const char *username, const char *id, br_result *result)
{
    char url[sizeof("https://api.appcues.com/v2/accounts//flows") + 5];
    snprintf(url, sizeof(url), "https://api.appcues.com/v2/accounts/%s/flows", id);
    br_slice secrets[] = {
        {(const unsigned char *)username, strlen(username)},
        {(const unsigned char *)key, strlen(key)},
        {(const unsigned char *)id, strlen(id)},
    };
    char *auth = NULL;
    if (br_http_basic_auth(secrets[0], secrets[1], &auth, NULL) != 0) return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 322,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the response body but ignores both errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 400:
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* The account ID is hidden from findings but still participates in redaction.
     * Keep the source order: username, key, then ID. */
    int rc = br_result_set_verification_error(result, cause, secrets, 3);
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_appcues(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Appcues scan arguments");
    const appcues_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->username || !compiled->id)
        return fail(error, "uninitialized Appcues detector");
    br_captures keys = {0}, usernames = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, false, error);
    if (!rc) rc = br_captures_find(compiled->username, input, &usernames, false, error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, error);
    /* Capture alphabets exclude whitespace, so TrimSpace is a no-op. All three
     * occurrence lists are required, even without verification; do not deduplicate. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t u = 0; !rc && u < usernames.len; ++u) {
            for (size_t i = 0; !rc && i < ids.len; ++i) {
                br_result result = {0};
                /* Account IDs affect requests, not RawV2 or SecretParts. */
                if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                    usernames.items[u], "username") != 0 ||
                    (verify && verify_appcues(ctx, keys.items[k], usernames.items[u], ids.items[i], &result) != 0) ||
                    br_results_push(out, &result) != 0)
                    rc = fail(error, "out of memory creating Appcues result");
                br_result_clear(&result);
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&usernames);
    br_captures_clear(&ids);
    return rc;
}

static appcues_patterns patterns;
static const char *const keywords[] = {"appcues"};
static const br_detector appcues = {
    .type = 322, .version = 0, .name = "Appcues", .custom_name = "",
    .description = "Appcues is a user engagement platform that helps create personalized user "
                   "experiences. The detected credentials can be used to access and manage "
                   "user engagement flows and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_appcues,
};

int br_appcues_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Appcues detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9-]{36})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.username &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9-]{39})\\b", &patterns.username, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9]{5})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &appcues;
    return 0;
}
