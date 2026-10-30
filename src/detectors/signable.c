/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/signable/signable.go. */
#include "detectors.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int signable_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

typedef struct { br_slice line; bool hit; } signable_keyword;

static int signable_keyword_hit(void *user, const br_span *groups, size_t ngroups)
{
    signable_keyword *found = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end < groups[1].begin ||
        groups[1].end > found->line.len) return 0;
    const unsigned char *letters = found->line.data + groups[1].begin;
    size_t n = groups[1].end - groups[1].begin;
    /* EqualFold: "as"/"AS" and "de"/"DE" are the same false positive. */
    if (n == 2) {
        unsigned char a = (unsigned char)(letters[0] | 32), b = (unsigned char)(letters[1] | 32);
        if ((a == 'a' && b == 's') || (a == 'd' && b == 'e')) found->hit = true;
    }
    return 0;
}

static int signable_false_positive(const br_regex *keyword, br_slice line, bool *hit, char **error)
{
    if (line.len >= sizeof("helper-explode-assignable-expression") - 1) {
        const char *needle = "helper-explode-assignable-expression";
        size_t nlen = sizeof("helper-explode-assignable-expression") - 1;
        for (size_t i = 0; i + nlen <= line.len; ++i)
            if (!memcmp(line.data + i, needle, nlen)) {
                *hit = true;
                return 0;
            }
    }
    signable_keyword found = {line, false};
    if (br_regex_each(keyword, line, signable_keyword_hit, &found, error) != 0)
        return signable_fail(error, *error ? *error : "cannot inspect Signable false positive");
    *hit = found.hit;
    return 0;
}

static int signable_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Encode token+":" before NewRequestWithContext. Encoding failure is
     * fatal. Nil context sets the error and the finding is still published. */
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const char *cause = NULL;
    char *transport_error = NULL;
    br_http_response response = {0};
    if (!ctx) {
        cause = "net/http: nil Context";
    } else {
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.signable.co.uk/v1/users",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        /* Every 2xx verifies. Other statuses, including 401, are unverified
         * with a nil error. Body and read errors are ignored. */
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status >= 200 && response.status < 300)
            result->verified = true;
    }
    br_slice secret = {key.data, key.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (rc != 0) return signable_fail(error, "cannot set Signable verification error");
    return 0;
}

typedef struct {
    const br_detector *detector;
    const br_regex *keyword;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    char *error;
} signable_matches;

static int signable_emit(void *user, const br_span *groups, size_t ngroups)
{
    signable_matches *matches = user;
    if (ngroups < 2 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[0].end > matches->input.len ||
        groups[1].end > matches->input.len)
        return signable_fail(&matches->error, "invalid Signable capture");
    br_slice line = {matches->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_slice key = {matches->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    if (key.len != 32) return signable_fail(&matches->error, "invalid Signable capture");
    bool filtered = false;
    if (signable_false_positive(matches->keyword, line, &filtered, &matches->error) != 0) return -1;
    if (filtered) return 0;
    br_result result = {0};
    int rc = 0;
    if (br_finding_key_bytes(&result, matches->detector->type, key, "key") != 0) {
        signable_fail(&matches->error, "cannot create Signable result");
        rc = -1;
    } else if (matches->verify && signable_verify(matches->ctx, key, &result, &matches->error) != 0) {
        rc = -1;
    } else if (br_results_push(matches->out, &result) != 0) {
        signable_fail(&matches->error, "cannot append Signable result");
        rc = -1;
    }
    br_result_clear(&result);
    return rc;
}

static int signable_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return signable_fail(error, "invalid or uninitialized Signable scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    signable_matches matches = {detector, patterns[1], ctx, input, out, verify, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(patterns[0], input, signable_emit, &matches, &regex_error);
    if (matches.error) {
        free(regex_error);
        regex_error = matches.error;
        rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = regex_error;
    else free(regex_error);
    return rc == 0 ? 0 : -1;
}

static const char *const signable_keywords[] = {"signable"};
static br_regex *signable_patterns[2];
static br_detector signable_detector = {
    .type = 785, .version = 0, .name = "Signable", .custom_name = "",
    .description = "Signable is a service used for electronic signatures. Signable tokens can be used to authenticate and access Signable's API services.",
    .keywords = signable_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = signable_scan, .state = signable_patterns,
};

int br_signable_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return signable_fail(error, "invalid Signable detector output");
    *out = NULL;
    if (!signable_patterns[0] &&
        (br_regex_compile_prefixed((const char *const[]){".{0,2}signable"}, 1,
                                   "\\b([a-zA-Z-0-9]{32})\\b", &signable_patterns[0], error) != 0 ||
         br_regex_compile("(?i)([a-z]{2})signable", &signable_patterns[1], error) != 0))
        return -1;
    *out = &signable_detector;
    return 0;
}
