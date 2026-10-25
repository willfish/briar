/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/anypoint/anypoint.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *organization; } anypoint_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_anypoint(const br_scan_ctx *ctx, const char *key,
                            const char *organization, br_result *result)
{
    char url[192], auth[sizeof("Bearer ") + 36];
    snprintf(url, sizeof(url),
             "https://anypoint.mulesoft.com/apiplatform/repository/v2/organizations/%s/apis/by-name?apiName=",
             organization);
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 179,
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
    /* Upstream supplies neither key nor organization to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_anypoint(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Anypoint scan arguments");
    const anypoint_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->organization) return fail(error, "uninitialized Anypoint patterns");
    br_captures keys = {0}, organizations = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->organization, input, &organizations, true, error);
    /* Organization captures also match the key regex. Only equal pairs are
     * excluded; both independent unique maps have unspecified iteration order. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t o = 0; !rc && o < organizations.len; ++o) {
            if (!strcmp(keys.items[k], organizations.items[o])) continue;
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                organizations.items[o], "organization") != 0 ||
                (verify && verify_anypoint(ctx, keys.items[k], organizations.items[o], &result) != 0) ||
                br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating Anypoint result");
            }
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&organizations);
    return rc;
}

static anypoint_patterns patterns;
static const char *const keywords[] = {"anypoint"};
static const char *const organization_prefix[] = {"org"};
static const char uuid_capture[] = "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b";
static const br_detector anypoint = {
    .type = 179, .version = 0, .name = "Anypoint", .custom_name = "",
    .description = "Anypoint is a unified platform that allows organizations to build and manage APIs and integrations. "
                   "Anypoint credentials can be used to access and manipulate these integrations and API data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_anypoint,
};

int br_anypoint_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Anypoint detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile(uuid_capture, &patterns.key, error) != 0) return -1;
    if (!patterns.organization &&
        br_regex_compile_prefixed(organization_prefix, 1, uuid_capture, &patterns.organization, error) != 0)
        return -1;
    *out = &anypoint;
    return 0;
}
