/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hubspot_apikey/{v1,v2}/apikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hubspot_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int hubspot_status_cause(int status, char **cause, char **error)
{
    int needed = snprintf(NULL, 0, "unexpected HTTP response status %d", status);
    if (needed < 0) return hubspot_fail(error, "cannot format HubSpot status cause");
    *cause = malloc((size_t)needed + 1);
    if (!*cause) return hubspot_fail(error, "cannot allocate HubSpot status cause");
    if (snprintf(*cause, (size_t)needed + 1, "unexpected HTTP response status %d", status) != needed)
        return hubspot_fail(error, "cannot format HubSpot status cause");
    return 0;
}

/* Each source version selects its own optional client or package default.
 * ABI1 consumes the explicitly selected context transport without autodetection,
 * coalescing or a new shared source-client namespace. */
static int hubspot_v1_verify(const br_scan_ctx *ctx, br_slice token, bool *verified,
                              char **cause, char **error)
{
    static const char endpoint[] = "https://api.hubapi.com/contacts/v1/lists?hapikey=";
    *verified = false;
    *cause = NULL;
    /* The complete query is assembled before NewRequestWithContext. The v1
     * grammar bounds this original ASCII token to 36 bytes. */
    size_t url_size = sizeof(endpoint) + token.len;
    char *url = malloc(url_size);
    if (!url) return hubspot_fail(error, "cannot allocate HubSpot v1 URL");
    int n = snprintf(url, url_size, "%s%.*s", endpoint, (int)token.len, (const char *)token.data);
    if (n < 0 || (size_t)n != url_size - 1) {
        free(url);
        return hubspot_fail(error, "cannot format HubSpot v1 URL");
    }
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        free(url);
        return *cause ? 0 : hubspot_fail(error, "cannot create HubSpot constructor cause");
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 107,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* Setup and Do failures are one retained domain, regardless of sign or
         * diagnostic text. Only our own fallback allocation is classified. */
        *cause = send_error;
        send_error = NULL;
        if (!*cause) {
            *cause = strdup("HTTP transport failed");
            if (!*cause) rc = hubspot_fail(error, "cannot create HubSpot transport cause");
        }
    } else if (response.status == 200 || response.status == 403) {
        *verified = true;
    } else if (response.status != 401) {
        rc = hubspot_status_cause(response.status, cause, error);
    }
    /* Source drains/closes before returning its verdict. Ignore body/read
     * errors at every status; release each ABI1 attempt, including setup errors.
     * Original URL/capture storage survives release, prepared headers/UA do not. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc;
}

static int hubspot_v2_verify(const br_scan_ctx *ctx, br_slice token, bool *verified,
                              char **cause, char **error)
{
    *verified = false;
    *cause = NULL;
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        return *cause ? 0 : hubspot_fail(error, "cannot create HubSpot constructor cause");
    }
    /* Unlike v1's query, v2's Bearer value is assembled after construction.
     * The direct, case-sensitive grammar bounds this token to 44 bytes. */
    size_t auth_size = sizeof("Bearer ") + token.len;
    char *authorization = malloc(auth_size);
    if (!authorization) return hubspot_fail(error, "cannot allocate HubSpot v2 authorization");
    int n = snprintf(authorization, auth_size, "Bearer %.*s", (int)token.len, (const char *)token.data);
    if (n < 0 || (size_t)n != auth_size - 1) {
        free(authorization);
        return hubspot_fail(error, "cannot format HubSpot v2 authorization");
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.hubapi.com/account-info/v3/api-usage/daily/private-apps",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 107,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        *cause = send_error;
        send_error = NULL;
        if (!*cause) {
            *cause = strdup("HTTP transport failed");
            if (!*cause) rc = hubspot_fail(error, "cannot create HubSpot transport cause");
        }
    } else if (response.status == 200 || response.status == 403) {
        *verified = true;
    } else if (response.status != 401) {
        rc = hubspot_status_cause(response.status, cause, error);
    }
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return rc;
}

static int hubspot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len) ||
        (detector->version != 1 && detector->version != 2))
        return hubspot_fail(error, "invalid or uninitialized HubSpot scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* Upstream iterates a Go map: uniqueness is exact original-token identity.
     * This native collection uses discovery order, not Go's unspecified order. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = hubspot_fail(&owned_error, "cannot create HubSpot finding");
        if (rc == 0 && detector->version == 2) {
            size_t tail = token.len - 8;
            result.redacted = malloc(tail + sizeof("..."));
            if (!result.redacted) rc = hubspot_fail(&owned_error, "cannot allocate HubSpot v2 redaction");
            else {
                /* Source keeps the ENTIRE UUID tail, then appends an ellipsis. */
                memcpy(result.redacted, token.data + 8, tail);
                memcpy(result.redacted + tail, "...", sizeof("..."));
            }
        }
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            rc = detector->version == 1 ? hubspot_v1_verify(ctx, token, &verified, &cause, &owned_error) :
                                         hubspot_v2_verify(ctx, token, &verified, &cause, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                /* Both versions pass ZERO secrets. Keep the whole supplied
                 * cause, and check even the NULL no-op-not-clear setter. */
                if (br_result_set_verification_error(&result, cause, NULL, 0) != 0)
                    rc = hubspot_fail(&owned_error, "cannot set HubSpot verification error");
            }
            free(cause);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = hubspot_fail(&owned_error, "cannot append HubSpot finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const hubspot_v1_prefixes[] = {"hubapi", "hapi_?key", "hubspot"};
static const char *const hubspot_v1_keywords[] = {"hubapi", "hapikey", "hapi_key", "hubspot"};
static br_detector hubspot_v1 = {
    .type = 107, .version = 1, .name = "HubSpotApiKey", .custom_name = "",
    .description = "HubSpot is a CRM platform that provides tools for marketing, sales, and customer service. HubSpot API keys can be used to access and modify data within the HubSpot platform.",
    .keywords = hubspot_v1_keywords, .nkeywords = 4,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hubspot_scan,
};
static const char *const hubspot_v2_keywords[] = {"pat-na1-", "pat-eu1-"};
static br_detector hubspot_v2 = {
    .type = 107, .version = 2, .name = "HubSpotApiKey", .custom_name = "",
    .description = "HubSpot is a CRM platform that provides tools for marketing, sales, and customer service. HubSpot API keys can be used to access and modify data within the HubSpot platform.",
    .keywords = hubspot_v2_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hubspot_scan,
};

int br_hubspot_apikey_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hubspot_fail(error, "invalid HubSpot v1 detector output");
    *out = NULL;
    if (!hubspot_v1.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(hubspot_v1_prefixes, 3,
                "\\b([a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})\\b",
                &regex, error) != 0) return -1;
        hubspot_v1.state = regex;
    }
    *out = &hubspot_v1;
    return 0;
}

int br_hubspot_apikey_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hubspot_fail(error, "invalid HubSpot v2 detector output");
    *out = NULL;
    if (!hubspot_v2.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(pat-(?:eu|na)1-[A-Za-z0-9]{8}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{12})\\b",
                             &regex, error) != 0) return -1;
        hubspot_v2.state = regex;
    }
    *out = &hubspot_v2;
    return 0;
}
