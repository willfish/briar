/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/browserstack/browserstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *username; } browserstack_patterns;

static int browserstack_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int browserstack_verify(const br_scan_ctx *ctx, br_slice key, br_slice username,
                                br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &key, 1) != 0)
            return browserstack_fail(error, "out of memory recording BrowserStack verification error");
        return 0;
    }
    char *authorization = NULL;
    /* Username's separator run is unbounded. Encode its complete captured bytes
     * dynamically rather than inferring a fixed maximum from the word groups. */
    if (br_http_basic_auth(username, key, &authorization, NULL) != 0) {
        free(authorization);
        return browserstack_fail(error, "out of memory constructing BrowserStack Basic authentication");
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://www.browserstack.com/automate/plan.json",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_BROWSERSTACK, .detector_type = 756,
    };
    /* This injected-only profile tags, but does not implement, source's fresh
     * public-suffix jar per pair, redirects or override-client Jar mutation.
     * The shared adapter supplies User-Agent once and leaves timeout zero. */
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        case 403:
            if (response.body_error) cause = response.body_error;
            else {
                static const unsigned char marker[] = "blocked";
                if (br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX)
                    cause = "blocked by browserstack";
            }
            break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Only the access key is supplied to the source error setter, not username. */
    int rc = br_result_set_verification_error(result, cause, &key, 1);
    /* Source closes only. ABI1 may already have buffered the body; release its
     * borrowed response once, without adding a provider-side body drain. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (rc != 0) return browserstack_fail(error, "out of memory recording BrowserStack verification error");
    return 0;
}

static int browserstack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return browserstack_fail(error, "invalid BrowserStack scan arguments");
    const browserstack_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->username)
        return browserstack_fail(error, "uninitialized BrowserStack detector");
    size_t original_len = out->len;
    br_captures keys = {0}, usernames = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->username, input, &usernames, false, error);
    /* TrimSpace is a no-op for both ASCII alphabets. Keep occurrences and the
     * key-major, username-minor product, even after successful verification. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
            br_slice username = br_captures_at(&usernames, u);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key, "key", username, "username", (br_slice){0}) != 0)
                rc = browserstack_fail(error, "out of memory creating BrowserStack result");
            else if (verify) rc = browserstack_verify(ctx, key, username, &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = browserstack_fail(error, "out of memory appending BrowserStack result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&usernames);
    return rc == 0 ? 0 : -1;
}

static browserstack_patterns browserstack_compiled;
static const char *const browserstack_keywords[] = {"browserstack"};
static const char *const key_prefixes[] = {
    "hub-cloud.browserstack.com", "accessKey", "\"access_Key\":", "ACCESS_KEY", "key",
    "browserstackKey", "BS_AUTHKEY", "BROWSERSTACK_ACCESS_KEY",
};
static const char *const username_prefixes[] = {
    "hub-cloud.browserstack.com", "userName", "\"username\":", "USER_NAME", "user",
    "browserstackUser", "BS_USERNAME", "BROWSERSTACK_USERNAME",
};
static const br_detector browserstack_detector = {
    .type = 756, .version = 0, .name = "BrowserStack", .custom_name = "",
    .description = "BrowserStack is a cloud web and mobile testing platform. "
                   "BrowserStack credentials can be used to access and manage testing environments.",
    .keywords = browserstack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &browserstack_compiled, .scan = browserstack_scan,
};

int br_browserstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return browserstack_fail(error, "invalid BrowserStack detector output");
    *out = NULL;
    /* Source PrefixRegex joins regex fragments, not escaped literal prefixes.
     * Keep its unescaped dots and use the extraction sets, not dispatch Keywords. */
    if (!browserstack_compiled.key && br_regex_compile_prefixed(key_prefixes, 8,
        "\\b([0-9a-zA-Z]{20})\\b", &browserstack_compiled.key, error) != 0) return -1;
    if (!browserstack_compiled.username && br_regex_compile_prefixed(username_prefixes, 8,
        "\\b([a-zA-Z\\d]{3,18}[._-]*[a-zA-Z\\d]{6,11})\\b", &browserstack_compiled.username, error) != 0) return -1;
    *out = &browserstack_detector;
    return 0;
}
