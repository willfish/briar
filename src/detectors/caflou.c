/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/caflou/caflou.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_cause(br_result *result, const char *cause)
{
    const br_slice token = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &token, 1) ? -1 : 0;
}

static int verify_caflou(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char auth[sizeof("Bearer ") + 155];
    int n = snprintf(auth, sizeof(auth), "Bearer %s", token);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.caflou.com/api/v1/accounts",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = 647,
    };
    /* Source uses SaneHttpClientTimeOut(10s), backed by Go DefaultTransport,
     * not saneTransport. This local timeout does not establish full native
     * dial/TLS/connection-pool parity or mutate any shared client. */
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = set_cause(result, cause);
    /* Source ignores all body/read/drain/close errors. ABI1 releases eagerly;
     * native Go streaming/drain/close timing parity remains unestablished. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_caflou(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_caflou, error);
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc ? -1 : 0; /* Every nonzero helper/setter return, including +1, fails. */
}

static const char *const keywords[] = {"caflou"};
static br_detector caflou = {
    .type = 647, .version = 0, .name = "Caflou", .custom_name = "",
    .description = "Caflou is a business management software used for managing projects, tasks, "
                   "and finances. Caflou API keys can be used to access and modify this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_caflou,
};

int br_caflou_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Caflou detector output");
        return -1;
    }
    *out = NULL;
    if (!caflou.state) {
        br_regex *pattern = NULL;
        /* caflou is dispatch-only. This exact literal header plus character
         * class is neither a PrefixRegex nor JWT/Base64/segment validation. */
        if (br_regex_compile("\\b(eyJhbGciOiJIUzI1NiJ9[a-zA-Z0-9._-]{135})\\b", &pattern, error)) return -1;
        caflou.state = pattern;
    }
    *out = &caflou;
    return 0;
}
