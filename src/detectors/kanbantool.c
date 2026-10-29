/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kanbantool/kanbantool.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } kanbantool_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int assemble_url(const char *domain, char **url_out)
{
    /* Domain is 2-22 alphanumeric bytes. Concatenate; do not escape or lowercase. */
    size_t domain_len = strlen(domain);
    static const char suffix[] = ".kanbantool.com/api/v3/users/current.json";
    if (!url_out || domain_len < 2 || domain_len > 22 || domain_len > SIZE_MAX - 8 - sizeof(suffix))
        return -1;
    char *url = malloc(8 + domain_len + sizeof(suffix));
    if (!url) return 1;
    memcpy(url, "https://", 8);
    memcpy(url + 8, domain, domain_len);
    memcpy(url + 8 + domain_len, suffix, sizeof(suffix));
    *url_out = url;
    return 0;
}

static int send_pair(const br_scan_ctx *ctx, const char *key, const char *url, br_result *result)
{
    /* Authorization is built only after NewRequestWithContext succeeds. */
    size_t key_len = strlen(key);
    if (key_len != 12) return -1;
    char authorization[sizeof("Bearer ") + 12];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, key_len + 1);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies. Other statuses, the whole mixed send domain, and
     * body_error stay unverified. Never call the verification-error setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_kanbantool(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Kanbantool scan");
    const kanbantool_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->domain) return fail(error, "uninitialized Kanbantool patterns");
    br_captures keys = {0}, domains = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* Both FindAll sets run before a constructor drop, including a nil context
     * and an empty key set. Any nonzero, including +1, is fatal before that drop. */
    int capture_rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (capture_rc == 0)
        capture_rc = br_captures_find(compiled->domain, input, &domains, false, &owned_error);
    int rc = capture_rc == 0 ? 0 : -1;
    /* Independent FindAll sets, including duplicates. A key is a domain only
     * when the domain pattern captured it. Span 1024 is not applied here. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
            br_result result = {0};
            char *url = NULL;
            int finding_rc = br_finding_key(&result, detector->type, keys.items[k], "key");
            int url_rc = finding_rc == 0 && verify ? assemble_url(domains.items[d], &url) : 0;
            if (finding_rc != 0)
                rc = fail(&owned_error, "cannot create Kanbantool result");
            else if (url_rc != 0)
                rc = fail(&owned_error, "cannot allocate Kanbantool URL");
            else if (verify && !ctx) {
                /* NewRequestWithContext(nil) drops only this pair. No header, send, or release. */
                free(url);
                br_result_clear(&result);
                continue;
            } else if (verify && send_pair(ctx, keys.items[k], url, &result) != 0)
                rc = fail(&owned_error, "cannot verify Kanbantool candidate");
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append Kanbantool result");
            free(url);
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static kanbantool_patterns patterns;
static const char *const keywords[] = {"kanbantool"};
static br_detector kanbantool_detector = {
    .type = 853, .version = 0, .name = "Kanbantool", .custom_name = "",
    .description = "Kanbantool is a project management software that uses API keys for accessing and modifying project data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_kanbantool,
};

int br_kanbantool_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Kanbantool detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Z]{12})\\b", &patterns.key, error))
        return -1;
    if (!patterns.domain && br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9A-Z]{2,22})\\b", &patterns.domain, error)) {
        br_regex_free(patterns.key);
        patterns.key = NULL;
        return -1;
    }
    *out = &kanbantool_detector;
    return 0;
}
