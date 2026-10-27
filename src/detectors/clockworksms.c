/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clockworksms/clockworksms.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *token; } clockworksms_patterns;

static int clockworksms_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void clockworksms_verify(const br_scan_ctx *ctx, const char *key, const char *token, br_result *result)
{
    /* Go Header.Add canonicalizes these source names to User_key/Access_token.
     * Borrow complete captured strings, including any leading key zeroes. */
    const br_header headers[] = {{"User_key", key}, {"Access_token", token}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.textanywhere.com/API/v1.0/REST/status",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 189,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the combined setup/allocation/Do nonzero domain. ABI1 cannot
     * distinguish stages; do not infer resource or error identity from text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers close-only. Eager buffering and per-request ABI release
     * remain lifecycle gaps; response bodies/read errors never affect status. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int clockworksms_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return clockworksms_fail(error, "invalid ClockworkSMS scan arguments");
    const clockworksms_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->token)
        return clockworksms_fail(error, "uninitialized ClockworkSMS detector");
    size_t original_len = out->len;
    br_captures keys = {0}, tokens = {0};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) rc = br_captures_find(patterns->token, input, &tokens, false, error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t t = 0; rc == 0 && t < tokens.len; ++t) {
            /* The fixed method/URL and ASCII headers are constructor-safe except
             * for nil context, which source skips only in verification mode. */
            if (verify && !ctx) continue;
            br_result result = {0};
            /* TrimSpace is a no-op. Keep all key-major/token-minor occurrences,
             * original spelling and zeroes; never parse the user key numerically. */
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                      br_captures_at(&tokens, t), "token", (br_slice){0}) != 0)
                rc = clockworksms_fail(error, "out of memory creating ClockworkSMS result");
            else if (verify) clockworksms_verify(ctx, keys.items[k], tokens.items[t], &result);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = clockworksms_fail(error, "out of memory appending ClockworkSMS result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&tokens);
    return rc == 0 ? 0 : -1;
}

static clockworksms_patterns clockworksms_compiled;
static const char *const clockworksms_keywords[] = {"clockworksms", "textanywhere"};
static const char *const clockworksms_prefixes[] = {"clockwork", "textanywhere"};
static const br_detector clockworksms_detector = {
    .type = 189, .version = 0, .name = "ClockworkSMS", .custom_name = "",
    .description = "Clockwork SMS is a service used for sending SMS messages. "
                   "User keys and access tokens can be used to authenticate and send messages via the Clockwork SMS API.",
    .keywords = clockworksms_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &clockworksms_compiled, .scan = clockworksms_scan,
};

int br_clockworksms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return clockworksms_fail(error, "invalid ClockworkSMS detector output");
    *out = NULL;
    /* Extraction deliberately uses short clockwork, not dispatch clockworksms.
     * Thus the suffix sms consumes three of PrefixRegex's forty gap runes. */
    if (!clockworksms_compiled.key && br_regex_compile_prefixed(clockworksms_prefixes, 2,
        "\\b([0-9]{5})\\b", &clockworksms_compiled.key, error) != 0) return -1;
    if (!clockworksms_compiled.token && br_regex_compile_prefixed(clockworksms_prefixes, 2,
        "\\b([0-9a-zA-Z]{24})\\b", &clockworksms_compiled.token, error) != 0) return -1;
    *out = &clockworksms_detector;
    return 0;
}
