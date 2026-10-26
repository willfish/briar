/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bugherd. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    /* Source supplies zero secrets: token and Basic-auth echoes stay intact. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_bugherd(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    static const unsigned char password[] = "x";
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                            (br_slice){password, 1}, &authorization, NULL)) {
        free(authorization);
        return -1; /* Helper +1 is a resource failure, never a provider result. */
    }
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.bugherd.com/api_v2/projects.json",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
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
    /* Every body/read/drain/close error is ignored. Eager ABI1 release does not
     * establish native Go streaming/drain/close timing parity. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return rc ? -1 : 0;
}

static int scan_bugherd(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    /* TrimSpace is a no-op for lowercase ASCII alphanumerics. Keep duplicates. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_bugherd, error);
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"bugherd"};
static br_detector bugherd = {
    .type = 602, .version = 0, .name = "Bugherd", .custom_name = "",
    .description = "Bugherd is a visual feedback and bug tracking tool for websites. Bugherd API keys can be used to access and manage projects, tasks, and feedback data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bugherd,
};

int br_bugherd_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bugherd detector output");
    *out = NULL;
    if (br_key_pattern_init(&bugherd, "\\b([0-9a-z]{22})\\b", error)) return -1;
    *out = &bugherd;
    return 0;
}
