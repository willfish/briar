/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/anypointoauth2/anypointoauth2.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } anypoint_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_anypoint(const br_scan_ctx *ctx, const char *id,
                            const char *secret, br_result *result)
{
    /* Both captures are hexadecimal, so neither needs JSON string escaping. */
    char payload[sizeof("{\"grant_type\":\"client_credentials\",\"client_id\":\"\",\"client_secret\":\"\"}") + 64];
    snprintf(payload, sizeof(payload),
             "{\"grant_type\":\"client_credentials\",\"client_id\":\"%s\",\"client_secret\":\"%s\"}", id, secret);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://anypoint.mulesoft.com/accounts/oauth2/token",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)payload, strlen(payload)},
        .profile = BR_HTTP_SANE, .detector_type = 1032,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains the body but ignores its contents and read errors. */
        switch (response.status) {
        case 200:
        case 422: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Neither credential is supplied to SetVerificationError upstream. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int make_result(br_result *result, int32_t type, br_slice id, br_slice secret)
{
    if (br_finding_pair_bytes(result, type, id, "client_id", secret, "client_secret",
                              (br_slice){(const unsigned char *)":", 1}) != 0)
        return -1;
    /* RawV2 is ID:secret, but Raw is the secret. Both captures are exactly 32
     * bytes, so the shared finding's owned Raw allocation can be reused. */
    memcpy(result->raw.data, secret.data, secret.len);
    result->raw.len = secret.len;
    return 0;
}

static int scan_anypoint(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AnypointOAuth2 scan arguments");
    const anypoint_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->secret)
        return fail(error, "uninitialized AnypointOAuth2 detector");
    br_captures ids = {0}, secrets = {0};
    int rc = br_captures_find(compiled->id, input, &ids, true, error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, true, error);
    bool *removed = !rc && ids.len && secrets.len ? calloc(secrets.len, sizeof(*removed)) : NULL;
    if (!rc && ids.len && secrets.len && !removed)
        rc = fail(error, "out of memory tracking AnypointOAuth2 secrets");
    /* Go map order is unspecified; shared captures retain first occurrences. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            if (removed[s] || !strcmp(ids.items[i], secrets.items[s])) continue;
            br_result result = {0};
            if (make_result(&result, detector->type, br_captures_at(&ids, i), br_captures_at(&secrets, s)) != 0 ||
                (verify && verify_anypoint(ctx, ids.items[i], secrets.items[s], &result) != 0)) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AnypointOAuth2 result");
                break;
            }
            bool verified = result.verified;
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending AnypointOAuth2 result");
                break;
            }
            if (verified) {
                /* A successful pair consumes this secret for every later ID and
                 * stops this ID's search, including source-accepted status 422. */
                removed[s] = true;
                break;
            }
        }
    }
    free(removed);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    return rc;
}

static anypoint_patterns patterns;
static const char *const keywords[] = {"anypoint"};
static const char *const id_prefixes[] = {"anypoint", "id"};
static const char *const secret_prefixes[] = {"anypoint", "secret"};
static const br_detector anypoint = {
    .type = 1032, .version = 0, .name = "AnypointOAuth2", .custom_name = "",
    .description = "Anypoint is a unified platform that allows organizations to build and manage "
                   "APIs and integrations. Anypoint credentials can be used to access and "
                   "manipulate these integrations and API data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_anypoint,
};

int br_anypointoauth2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AnypointOAuth2 detector output");
    *out = NULL;
    if (!patterns.id &&
        br_regex_compile_prefixed(id_prefixes, 2, "\\b([0-9a-f]{32})\\b", &patterns.id, error) != 0)
        return -1;
    if (!patterns.secret &&
        br_regex_compile_prefixed(secret_prefixes, 2, "\\b([0-9a-fA-F]{32})\\b", &patterns.secret, error) != 0)
        return -1;
    *out = &anypoint;
    return 0;
}
