/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flightlabs/flightlabs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int flightlabs_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int flightlabs_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    static const char prefix[] = "https://www.goflightlabs.com/airports-by-filter?access_key=";
    static const char suffix[] = "&iata_code=JFK";
    const size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    _Static_assert(sizeof(prefix) - 1 + sizeof(suffix) == 74, "URL overhead must be 73 bytes plus NUL");
    /* The payload is UNBOUNDED. One necessary complete URL allocation precedes
     * the ctor, even for nil context. No cap, VLA, formatter or extra copy. */
    if (token.len > SIZE_MAX - overhead)
        return flightlabs_fail(error, "FlightLabs URL size overflow");
    char *url = malloc(overhead + token.len);
    if (!url) return flightlabs_fail(error, "cannot allocate FlightLabs URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, token.data, token.len);
    memcpy(url + sizeof(prefix) - 1 + token.len, suffix, sizeof(suffix));

    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    bool sent = false;
    int rc = 0;
    if (!ctx) cause = "net/http: nil Context"; /* RETAIN false, not a ctor skip. */
    else {
        const br_http_request request = {
            .method = "GET", .url = url, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        sent = true;
        /* Retain the WHOLE mixed shared setup/allocation/Do domain as a leaf
         * cause, without stripping diagnostics or classifying memory text. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status == 200)
            result->verified = true;
        else if (response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = flightlabs_fail(error, "cannot format FlightLabs verification status");
            else cause = status_error;
        }
    }
    /* Exactly one redaction secret: the COMPLETE original token. NULL is a
     * no-op; every nonzero setter result is fatal. Copy BEFORE release. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = flightlabs_fail(error, "cannot set FlightLabs verification error");
    /* The same complete allocation stays live through send AND release and is
     * freed only afterward, including Do/setter failures. Source drains/closes
     * after status and ignores body/read/drain errors. ABI1 logical empty body
     * cannot express http.NoBody identity; Reader/drain timing, private override/
     * default clients, full native SANE/RE2, map order and global engine/output
     * parity remain partial. */
    if (sent) br_http_release(ctx, &response);
    free(transport_error);
    free(url);
    return rc == 0 ? 0 : -1;
}

static int flightlabs_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flightlabs_fail(error, "invalid or uninitialized FlightLabs scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* Byte-original uniqueness. Native first-occurrence order is one possible
     * traversal of upstream's Go map. No trimming, JWT/claims/Base64/signature
     * validation, local filtering, cache or input/payload cap is added. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = flightlabs_fail(&owned_error, "cannot create FlightLabs result");
        if (rc == 0 && verify) rc = flightlabs_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = flightlabs_fail(&owned_error, "cannot append FlightLabs result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flightlabs_keywords[] = {"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"};
static br_detector flightlabs_detector = {
    .type = 848, .version = 0, .name = "FlightLabs", .custom_name = "",
    .description = "FlightLabs provides a comprehensive API for accessing real-time and historical flight data. The API keys can be used to query flight information, schedules, and other related data.",
    .keywords = flightlabs_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flightlabs_scan,
};

int br_flightlabs_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flightlabs_fail(error, "invalid FlightLabs detector output");
    *out = NULL;
    if (!flightlabs_detector.state) {
        br_regex *pattern = NULL;
        /* DIRECT case-sensitive regex, including source boundary/backtracking. */
        if (br_regex_compile("\\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\\.ey[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]{86})\\b", &pattern, error) != 0)
            return -1;
        flightlabs_detector.state = pattern;
    }
    *out = &flightlabs_detector;
    return 0;
}
