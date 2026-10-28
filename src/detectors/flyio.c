/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flyio/flyio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int flyio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool flyio_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    if (reason) *reason = NULL;
    br_slice raw = {result->raw.data, result->raw.len};
    static const unsigned char bypass[] = "AAAAAA";
    /* The exact-case binary bypass precedes UTF8 validation/lowercasing and
     * default terms/wordlists. False needs no gratuitous empty reason allocation. */
    if (br_slice_find(raw, (br_slice){bypass, sizeof(bypass) - 1}, 0) != SIZE_MAX) return false;
    static const char *const terms[] = {"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"};
    return br_known_false_positive(raw, terms, 7, true, reason);
}

static int flyio_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    /* Source ctor errors return false,nil: retain without an error, Bearer
     * allocation or setter. Finding resources have already been acquired. */
    if (!ctx) return 0;
    br_header headers[] = {{"Accept", "application/json"}, {"Authorization", NULL}};
    /* Go canonicalizes source's lowercase "accept". Prepare it BEFORE the
     * necessary complete Authorization allocation: digits make tokens unbounded. */
    if (token.len > SIZE_MAX - 8) return flyio_fail(error, "FlyIO Authorization size overflow");
    char *authorization = malloc(token.len + 8);
    if (!authorization) return flyio_fail(error, "cannot allocate FlyIO Authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, token.len);
    authorization[7 + token.len] = '\0';
    headers[1].value = authorization;
    const br_http_request request = {
        /* An empty org_slug is deliberate. Never invent a personal org. */
        .method = "GET", .url = "https://api.machines.dev/v1/apps?org_slug=",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    int rc = 0;
    /* Retain ALL mixed shared setup/allocation/Do causes, never classify text. */
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 400)
        result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = flyio_fail(error, "cannot format FlyIO verification status");
        else cause = status_error;
    }
    /* Source calls the setter ONLY for a non-NULL cause (even empty text).
     * Redact the WHOLE original token; any nonzero setter result is fatal. */
    if (rc == 0 && cause && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = flyio_fail(error, "cannot set FlyIO verification error");
    /* One complete Authorization remains live through send AND release, even
     * on setter/Do failures. Copy causes BEFORE release, then free once. Source
     * ignores body/read/drain errors. NoBody identity, eager buffering/release,
     * Reader/drain timing, private clients, full native SANE/RE2, map order and
     * global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int flyio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flyio_fail(error, "invalid or uninitialized FlyIO scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    /* Byte-original uniqueness; native first-occurrence order is one possible
     * traversal of the Go map. No trimming/validation/filter/cache/local cap. */
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = flyio_fail(&owned_error, "cannot create FlyIO result");
        if (rc == 0 && verify) rc = flyio_verify(ctx, token, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = flyio_fail(&owned_error, "cannot append FlyIO result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flyio_keywords[] = {"FlyV1"};
static br_detector flyio_detector = {
    .type = 980, .version = 0, .name = "FlyIO", .custom_name = "",
    .description = "Fly.io is a platform for running applications globally. Fly.io tokens can be used to access the Fly.io API and manage applications.",
    .keywords = flyio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flyio_scan, .false_positive = flyio_false_positive,
};

int br_flyio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flyio_fail(error, "invalid FlyIO detector output");
    *out = NULL;
    if (!flyio_detector.state) {
        br_regex *pattern = NULL;
        /* DIRECT case-sensitive regex: ASCII digits, literal space, original
         * greedy payload bounds and word-boundary backtracking, not validation. */
        if (br_regex_compile("\\b(FlyV1 fm\\d+_[A-Za-z0-9+\\/=,_-]{500,700})\\b", &pattern, error) != 0)
            return -1;
        flyio_detector.state = pattern;
    }
    *out = &flyio_detector;
    return 0;
}
