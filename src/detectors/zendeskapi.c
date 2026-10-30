/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zendeskapi/zendeskapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zendesk_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zendesk_cause(br_result *result, const char *cause, br_slice token, char **error)
{
    if (br_result_set_verification_error(result, cause, &token, 1) != 0)
        return zendesk_fail(error, "cannot store ZendeskApi verification error");
    return 0;
}

static int zendesk_verify(const br_scan_ctx *ctx, br_slice email, br_slice token, br_slice domain,
                          br_result *result, char **error)
{
    static const char prefix[] = "https://";
    static const char suffix[] = "/api/v2/users.json";
    if (domain.len > SIZE_MAX - (sizeof(prefix) - 1 + sizeof(suffix) - 1))
        return zendesk_fail(error, "ZendeskApi URL size overflow");
    size_t size = sizeof(prefix) - 1 + domain.len + sizeof(suffix) - 1;
    char *url = malloc(size + 1);
    if (!url) return zendesk_fail(error, "cannot allocate ZendeskApi URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain.data, domain.len);
    memcpy(url + sizeof(prefix) - 1 + domain.len, suffix, sizeof(suffix));
    int rc = 0;
    if (!ctx || memchr(url, '\0', size)) {
        rc = zendesk_cause(result, "net/http: nil Context", token, error);
        free(url);
        return rc;
    }
    if (email.len > SIZE_MAX - 7 || token.len > SIZE_MAX - email.len - 7)
        rc = zendesk_fail(error, "ZendeskApi identity too large");
    char *user = NULL;
    if (rc == 0) {
        user = malloc(email.len + 6 + 1);
        if (!user) rc = zendesk_fail(error, "cannot allocate ZendeskApi user");
        else {
            memcpy(user, email.data, email.len);
            memcpy(user + email.len, "/token", 7);
        }
    }
    char *authorization = NULL;
    if (rc == 0 && br_http_basic_auth((br_slice){(const unsigned char *)user, email.len + 6},
                                      token, &authorization, error) != 0)
        rc = -1;
    if (rc == 0) {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        char status[64];
        const char *cause = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0)
            cause = send_error;
        else if (response.status == 200) result->verified = true;
        else if (response.status != 401 && response.status != 404) {
            snprintf(status, sizeof(status), "unexpected status code: %d", response.status);
            cause = status;
        }
        rc = zendesk_cause(result, cause, token, error);
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(authorization);
    free(user);
    free(url);
    return rc;
}

static int zendesk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !patterns[2] || !out ||
        (!input.data && input.len))
        return zendesk_fail(error, "invalid or uninitialized ZendeskApi scan");
    size_t original_len = out->len;
    br_captures tokens = {0}, emails = {0}, domains = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &emails, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &tokens, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[2], input, &domains, true, &owned_error);
    for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
        for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
            for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
                br_result result = {0};
                br_slice token = br_captures_at(&tokens, t);
                if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                    rc = zendesk_fail(&owned_error, "cannot create ZendeskApi result");
                else if (verify)
                    rc = zendesk_verify(ctx, br_captures_at(&emails, e), token,
                                        br_captures_at(&domains, d), &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = zendesk_fail(&owned_error, "cannot append ZendeskApi result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&emails);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const zendesk_keywords[] = {"zendesk"};
static const char *const zendesk_prefix[] = {"zendesk"};
static br_regex *zendesk_patterns[3];
static br_detector zendesk_detector = {
    .type = 95, .version = 0, .name = "ZendeskApi", .custom_name = "",
    .description = "Zendesk is a customer service platform. Zendesk API tokens can be used to access and modify customer service data.",
    .keywords = zendesk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = zendesk_scan,
};

int br_zendeskapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zendesk_fail(error, "invalid ZendeskApi detector output");
    *out = NULL;
    if (!zendesk_patterns[0] &&
        br_regex_compile("\\b([a-zA-Z-0-9-]{5,16}\\@[a-zA-Z-0-9]{4,16}\\.[a-zA-Z-0-9]{3,6})\\b",
                         &zendesk_patterns[0], error) != 0)
        return -1;
    /* Unanchored 40-character token. The prefix is zendesk, not a word boundary. */
    if (!zendesk_patterns[1] &&
        br_regex_compile_prefixed(zendesk_prefix, 1, "([A-Za-z0-9_-]{40})",
                                  &zendesk_patterns[1], error) != 0)
        return -1;
    if (!zendesk_patterns[2] &&
        br_regex_compile("\\b([a-zA-Z-0-9]{3,25}\\.zendesk\\.com)\\b",
                         &zendesk_patterns[2], error) != 0)
        return -1;
    zendesk_detector.state = zendesk_patterns;
    *out = &zendesk_detector;
    return 0;
}
