/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/okta/okta.go. */
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int okta_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *token, *domain; } okta_patterns;
typedef struct {
    br_http_request request;
    br_header headers[3];
    char authorization[5 + 42 + 1];
} okta_request;

static int okta_cause(const char *text, char **cause, char **error)
{
    *cause = strdup(text);
    return *cause ? 0 : okta_fail(error, "cannot retain Okta verification cause");
}

static int okta_verify(const br_scan_ctx *ctx, br_slice domain, br_slice token,
                        bool *verified, char **cause, char **error)
{
    static const char prefix[] = "https://", suffix[] = "/api/v1/users/me";
    *verified = false; *cause = NULL;
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (domain.len > SIZE_MAX - overhead) return okta_fail(error, "Okta URL too large");
    char *url = malloc(domain.len + overhead);
    if (!url) return okta_fail(error, "cannot construct Okta URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain.data, domain.len);
    memcpy(url + sizeof(prefix) - 1 + domain.len, suffix, sizeof(suffix));
    /* Source formats the complete URL before nil-context construction. A nil
     * constructor retains a false/error finding, without reaching headers. */
    if (!ctx) {
        int rc = okta_cause("net/http: nil Context", cause, error);
        free(url); return rc;
    }
    okta_request *attempt = malloc(sizeof(*attempt));
    if (!attempt) { free(url); return okta_fail(error, "cannot construct Okta request"); }
    *attempt = (okta_request){0};
    memcpy(attempt->authorization, "SSWS ", 5);
    memcpy(attempt->authorization + 5, token.data, token.len);
    attempt->authorization[5 + token.len] = 0;
    attempt->headers[0] = (br_header){"Accept", "application/json"};
    attempt->headers[1] = (br_header){"Content-Type", "application/json"};
    attempt->headers[2] = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = url, .headers = attempt->headers, .nheaders = 3,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 21,
    };
    br_http_response response = {0}; char *send_error = NULL;
    int send_rc = br_http_send(ctx, &attempt->request, &response, &send_error);
    int rc = 0; bool matched = false;
    if (send_rc != 0) {
        /* The whole mixed shared preparation/Do domain returns its original
         * owned cause, without diagnostic-text classification or redaction. */
        *cause = send_error; send_error = NULL;
    } else if (response.status == 200) {
        static const unsigned char marker[] = "\"activated\":";
        matched = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        /* ReadAll's error is discarded: search the original partial bytes. */
    } else if (response.status != 401) {
        char text[64]; int n = snprintf(text, sizeof(text), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(text)) rc = okta_fail(error, "cannot format Okta status cause");
        else rc = okta_cause(text, cause, error);
    }
    /* Helper-local close precedes caller Verified/setter/publication. Original
     * URL/auth/headers/captures live through this release; prepared storage does
     * not. Search borrowed bytes first, and keep owned diagnostics afterward. */
    br_http_release(ctx, &response);
    free(send_error); free(attempt); free(url);
    if (rc == 0) *verified = matched;
    return rc;
}

static int okta_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return okta_fail(error, "invalid or uninitialized Okta scan");
    const okta_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures tokens = {0}, domains = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    /* Domain collection is reached even when the independent token set is empty.
     * First-occurrence unique lists are a permitted, not promised Go-map order. */
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        for (size_t j = 0; rc == 0 && j < domains.len; ++j) {
            br_slice domain = br_captures_at(&domains, j);
            br_result result = {0};
            if (token.len != 42 || br_finding_pair_bytes(&result, detector->type, token, "token",
                domain, "domain", (br_slice){(const unsigned char *)":", 1}) != 0)
                rc = okta_fail(&owned_error, "cannot create Okta result");
            if (rc == 0) {
                /* The common factory owns the right-sized RawV2 allocation;
                 * source has domain first there, while Raw remains the token. */
                memcpy(result.raw_v2.data, domain.data, domain.len);
                result.raw_v2.data[domain.len] = ':';
                memcpy(result.raw_v2.data + domain.len + 1, token.data, token.len);
            }
            if (rc == 0 && verify) {
                bool verified = false; char *cause = NULL;
                rc = okta_verify(ctx, domain, token, &verified, &cause, &owned_error);
                if (rc == 0) {
                    result.verified = verified;
                    /* Mandatory, including NULL cause; source passes NO secrets. */
                    if (br_result_set_verification_error(&result, cause, NULL, 0) != 0)
                        rc = okta_fail(&owned_error, "cannot set Okta verification error");
                }
                free(cause);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = okta_fail(&owned_error, "cannot append Okta result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&domains); br_captures_clear(&tokens);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const okta_keywords[] = {".okta"};
static okta_patterns okta_compiled;
static br_detector okta_detector = {
    .type = 21, .version = 0, .name = "Okta", .custom_name = "",
    .description = "Okta is an identity and access management service. Okta tokens can be used to authenticate and access various resources and APIs within an organization.",
    .keywords = okta_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = okta_scan,
};

int br_okta_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return okta_fail(error, "invalid Okta detector output");
    *out = NULL;
    if (!okta_detector.state) {
        okta_patterns patterns = {0};
        /* One bounded outer capture preserves source matches[0] for the shared
         * group1 capture helper, including the terminal-hyphen word boundary. */
        if (br_regex_compile("\\b(00[a-zA-Z0-9_-]{40})\\b", &patterns.token, error) != 0) return -1;
        if (br_regex_compile("\\b([a-z0-9-]{1,40}\\.okta(?:preview|-emea){0,1}\\.com)\\b", &patterns.domain, error) != 0) {
            br_regex_free(patterns.token); return -1;
        }
        okta_compiled = patterns; okta_detector.state = &okta_compiled;
    }
    *out = &okta_detector;
    return 0;
}
