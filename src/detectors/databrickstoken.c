/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/databrickstoken/databrickstoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *domain, *token; } databrickstoken_patterns;

static int databrickstoken_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int databrickstoken_verify(const br_scan_ctx *ctx, br_slice token, br_slice domain,
                                  br_result *result, char **error)
{
    static const char prefix[] = "https://", path[] = "/api/2.0/preview/scim/v2/Me";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(path); /* Includes URL NUL. */
    if (domain.len > SIZE_MAX - fixed)
        return databrickstoken_fail(error, "DatabricksToken request URL size overflow");
    /* One necessary owned URL, preserving the complete unbounded ASCII domain.
     * Do not impose DNS label limits, normalize it or copy a temporary URL. */
    char *url = malloc(fixed + domain.len);
    if (!url) return databrickstoken_fail(error, "cannot allocate DatabricksToken request URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain.data, domain.len);
    memcpy(url + sizeof(prefix) - 1 + domain.len, path, sizeof(path));
    /* Source tokens are exactly 36 or 38 bytes. Complete bounded Bearer auth
     * needs at most 45 bytes + NUL and stays on the stack through release. */
    char authorization[46];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    /* http.NewRequest, NOT NewRequestWithContext: ignore the scan's deadline
     * and cancellation, even when already expired/cancelled. Preserve the
     * injected transport/UA configuration; a NULL scan context is not a skip. */
    br_scan_ctx background = ctx ? *ctx : (br_scan_ctx){0};
    background.deadline_monotonic_ms = 0;
    background.cancelled = NULL;
    background.cancel_user = NULL;
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    if (br_http_send(&background, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = databrickstoken_fail(error, "cannot format DatabricksToken verification status");
        else cause = status_error;
    }
    /* Source passes ZERO redaction arguments: preserve token/domain echoes.
     * Copy causes BEFORE response release; a positive setter error is fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = databrickstoken_fail(error, "cannot set DatabricksToken verification error");
    /* URL and stack auth remain live through release. Source verifier defers
     * drain+close, ignoring body errors; eager buffering/lifetime, private client
     * overrides, Go URL parsing and full/global parity remain partial. PUBLIC
     * must stay fail-closed natively before I/O, never aliased to SANE. */
    br_http_release(&background, &response);
    free(send_error);
    free(url);
    return rc == 0 ? 0 : -1;
}

static int databrickstoken_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                 br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return databrickstoken_fail(error, "invalid or uninitialized DatabricksToken scan");
    const databrickstoken_patterns *patterns = detector->state;
    if (!patterns->domain || !patterns->token)
        return databrickstoken_fail(error, "uninitialized DatabricksToken patterns");
    size_t original_len = out->len;
    br_captures domains = {0}, tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->domain, input, &domains, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->token, input, &tokens, true, &owned_error);
    /* Domain TrimSpace is a no-op. Independently unique original byte sets;
     * deterministic insertion order is legal Go map order. Domain is required,
     * with the complete token-major product, not token-only fallback or cache. */
    for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
        br_slice token = br_captures_at(&tokens, t);
        for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
            br_result result = {0};
            br_slice domain = br_captures_at(&domains, d);
            if (br_finding_pair_bytes(&result, detector->type, token, "token", domain, "domain", (br_slice){0}) != 0)
                rc = databrickstoken_fail(&owned_error, "cannot create DatabricksToken result");
            if (rc == 0 && verify && databrickstoken_verify(ctx, token, domain, &result, &owned_error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = databrickstoken_fail(&owned_error, "cannot append DatabricksToken result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&domains);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static databrickstoken_patterns databrickstoken_compiled;
static const char *const databrickstoken_keywords[] = {"databricks", "dapi"};
static const br_detector databrickstoken_detector = {
    .type = 62, .version = 0, .name = "DatabricksToken", .custom_name = "",
    .description = "Databricks is a cloud data platform. Databricks tokens can be used to authenticate and interact with Databricks services and APIs.",
    .keywords = databrickstoken_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &databrickstoken_compiled, .scan = databrickstoken_scan,
};

int br_databrickstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return databrickstoken_fail(error, "invalid DatabricksToken detector output");
    *out = NULL;
    if (!databrickstoken_compiled.domain) {
        databrickstoken_patterns compiled = {0};
        /* BOTH regexes are direct, not PrefixRegex(dispatch keywords). Preserve
         * capture 1, ASCII boundaries/digit and optional-suffix backtracking. */
        if (br_regex_compile("\\b([a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(cloud\\.databricks\\.com|gcp\\.databricks\\.com|azuredatabricks\\.net))\\b", &compiled.domain, error) != 0 ||
            br_regex_compile("\\b(dapi[0-9a-f]{32}(-\\d)?)\\b", &compiled.token, error) != 0) {
            br_regex_free(compiled.domain);
            br_regex_free(compiled.token);
            return -1;
        }
        databrickstoken_compiled = compiled;
    }
    *out = &databrickstoken_detector;
    return 0;
}
