/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/besttime. */
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
    const br_slice secret = {result->raw.data, result->raw.len};
    /* Core's positive 1 is an allocation failure, never a candidate outcome. */
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int body_diagnostic(br_slice body, char **owned, const char **cause)
{
    static const char unsupported[] = "unsupported: Besttime non-UTF-8 or NUL response body diagnostic";
    static const char prefix[] = "unexpected response body: ";
    *owned = NULL;
    if (body.len && memchr(body.data, 0, body.len)) { *cause = unsupported; return 0; }

    br_slice decoded = {0};
    br_bytes storage = {0};
    char *decode_error = NULL;
    int rc = br_utf8_decode(body, &decoded, &storage, &decode_error);
    bool invalid_utf8 = storage.data != NULL;
    /* Only the ownership distinction is used as a validation predicate. Never
     * publish the decoder's normalized bytes or infer validity after failure. */
    free(storage.data);
    free(decode_error);
    if (rc) return -1;
    if (invalid_utf8) { *cause = unsupported; return 0; }

    if (body.len > SIZE_MAX - sizeof(prefix)) return -1;
    char *text = malloc(sizeof(prefix) + body.len);
    if (!text) return -1;
    memcpy(text, prefix, sizeof(prefix) - 1);
    if (body.len) memcpy(text + sizeof(prefix) - 1, body.data, body.len);
    text[sizeof(prefix) - 1 + body.len] = '\0';
    *owned = text;
    *cause = text;
    return 0;
}

static int verify_besttime(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    static const char endpoint[] = "https://besttime.app/api/v1/keys/";
    /* The source capture is exactly 36 ASCII bytes, safe directly in the path. */
    char url[sizeof(endpoint) + 36];
    snprintf(url, sizeof(url), "%s%s", endpoint, key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *owned_diagnostic = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status != 200) {
        /* Even 401/403 are errors; deferred body-drain errors are ignored. */
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    } else if (response.body_error) {
        cause = response.body_error; /* ReadAll's error precedes every marker. */
    } else {
        static const unsigned char ok[] = "\"status\": \"OK\"";
        static const unsigned char invalid[] = "\"message\": \"Invalid api_key_private";
        /* These are byte substrings, not JSON fields. Check before any encoding
         * guard, including when either marker occurs after NUL/invalid UTF-8. */
        if (br_slice_find(response.body, (br_slice){ok, sizeof(ok) - 1}, 0) != SIZE_MAX)
            result->verified = true;
        else if (br_slice_find(response.body, (br_slice){invalid, sizeof(invalid) - 1}, 0) == SIZE_MAX)
            rc = body_diagnostic(response.body, &owned_diagnostic, &cause);
    }
    if (!rc) rc = set_cause(result, cause);
    /* ABI1 eagerly releases each response; native Go streaming/drain/close
     * timing and byte-invalid diagnostic/output parity remain unestablished. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(owned_diagnostic);
    return rc ? -1 : 0;
}

static int scan_besttime(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    /* Source FindAllStringSubmatch keeps every occurrence, including duplicates. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_besttime, error);
}

static const char *const keywords[] = {"besttime"};
static br_detector besttime = {
    .type = 506, .version = 0, .name = "Besttime", .custom_name = "",
    .description = "Besttime is a service used to predict the best time to visit a place. Besttime API keys can be used to access and utilize this service.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_besttime,
};

int br_besttime_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Besttime detector output");
    *out = NULL;
    if (br_key_pattern_init(&besttime, "\\b(pri_[a-f0-9]{32})\\b", error)) return -1;
    *out = &besttime;
    return 0;
}
