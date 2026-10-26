/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/atlassiandatacenter/jiradatacenterpat. */
#include "detectors.h"
#include "datacenter.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *url; } jira_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int jira_result(br_result *result, int32_t type, br_slice token, const char *endpoint)
{
    static const unsigned char colon[] = ":";
    int rc = endpoint ? br_finding_pair_bytes(result, type, token, "token",
        (br_slice){(const unsigned char *)endpoint, strlen(endpoint)}, "url",
        (br_slice){colon, 1}) : br_finding_key_bytes(result, type, token, "token");
    if (rc) return -1;
    char redacted[10];
    memcpy(redacted, token.data, 3);
    memcpy(redacted + 3, "...", 3);
    memcpy(redacted + 6, token.data + token.len - 3, 3);
    redacted[9] = '\0';
    result->redacted = strdup(redacted);
    if (!result->redacted) return -1;
    if (!endpoint) {
        result->extra_data = json_object_new_object();
        if (!result->extra_data) return -1;
        br_json *message = json_object_new_string(
            "No Jira Data Center URL was found or configured. To verify this token, "
            "set the Jira instance base URL as a custom endpoint.");
        if (!message) return -1;
        if (json_object_object_add(result->extra_data, "message", message) != 0) {
            json_object_put(message);
            return -1;
        }
    }
    return 0;
}

static int enrich_jira(br_result *result, const char *endpoint, br_json *body)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *url = json_object_new_string(endpoint);
    if (!url) return -1;
    if (json_object_object_add(result->extra_data, "endpoint", url) != 0) {
        json_object_put(url);
        return -1;
    }
    static const struct { const char *source, *output; } fields[] = {
        {"displayName", "display_name"}, {"emailAddress", "email_address"},
    };
    /* The helper returns the first document's generic map: exact field names,
     * last duplicate wins, and a final null must not revive an earlier string. */
    for (size_t i = 0; body && i < sizeof(fields) / sizeof(fields[0]); ++i) {
        br_json *value = NULL;
        if (!json_object_object_get_ex(body, fields[i].source, &value) ||
            !json_object_is_type(value, json_type_string)) continue;
        br_json *copy = json_object_get(value);
        if (json_object_object_add(result->extra_data, fields[i].output, copy) != 0) {
            json_object_put(copy);
            return -1;
        }
    }
    return 0;
}

static int verify_jira(const br_scan_ctx *ctx, const char *endpoint, const char *token,
                       br_result *result)
{
    char *url = NULL, *cause = NULL;
    br_json *body = NULL;
    int rc = br_dc_request_url(endpoint, "/rest/api/2/myself", "", &url, &cause);
    if (!rc)
        rc = br_dc_verify(ctx, BR_HTTP_DETECTOR_PUBLIC, 1046, url, token,
                          &result->verified, &body, &cause);
    if (rc >= 0) {
        if (result->verified && !cause) rc = enrich_jira(result, endpoint, body);
        else rc = 0; /* Unsupported URL forms are candidate causes, not scan failures. */
        if (!rc) {
            br_slice secret = {result->raw.data, result->raw.len};
            rc = br_result_set_verification_error(result, cause, &secret, 1);
        }
    }
    json_object_put(body);
    free(url);
    free(cause);
    return rc;
}

static int scan_jira(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid JiraDataCenterPAT scan arguments");
    const jira_patterns *compiled = detector->state;
    if (!compiled->token || !compiled->url)
        return fail(error, "uninitialized JiraDataCenterPAT patterns");
    br_captures tokens = {0};
    br_endpoint_list endpoints = {0};
    int rc = br_captures_find(compiled->token, input, &tokens, true, error);
    if (!rc) rc = br_dc_find_endpoints(input, compiled->url, ctx ? ctx->endpoints : NULL,
                                      &endpoints, error);
    for (size_t t = 0; !rc && t < tokens.len; ++t) {
        br_slice token = br_captures_at(&tokens, t);
        if (!br_dc_is_structural_pat44(token)) continue;
        for (size_t e = 0; !rc && e < (endpoints.len ? endpoints.len : 1); ++e) {
            const char *endpoint = endpoints.len ? endpoints.items[e] : NULL;
            br_result result = {0};
            if (jira_result(&result, detector->type, token, endpoint) != 0 ||
                (endpoint && verify && verify_jira(ctx, endpoint, tokens.items[t], &result) != 0)) {
                rc = fail(error, "out of memory creating JiraDataCenterPAT result");
            }
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending JiraDataCenterPAT result");
            br_result_clear(&result);
            if (verified) break;
        }
    }
    br_captures_clear(&tokens);
    br_endpoint_list_clear(&endpoints);
    return rc;
}

static jira_patterns patterns;
static const char *const keywords[] = {"jira", "atlassian"};
static const br_detector jira = {
    .type = 1046, .version = 0, .name = "JiraDataCenterPAT", .custom_name = "",
    .description = "Jira Data Center is a self-hosted version of Jira. Personal Access Tokens "
                   "(PATs) are used to authenticate API requests to Jira Data Center instances.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_jira,
    .validate_endpoints = br_endpoints_validate_configured,
};

int br_jiradatacenterpat_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid JiraDataCenterPAT detector output");
    *out = NULL;
    if (!patterns.token && br_dc_token_pattern(keywords, 2, &patterns.token, error) != 0)
        return -1;
    if (!patterns.url && br_dc_url_pattern(keywords, 2, &patterns.url, error) != 0)
        return -1;
    *out = &jira;
    return 0;
}
