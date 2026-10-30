/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sugester/sugester.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const char *const sugester_keywords[] = {"sugester"};

typedef struct { br_regex *key; br_regex *domain; } sugester_patterns;

static int sugester_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool sugester_verify(const br_scan_ctx *ctx, const char *domain, const char *key,
                            br_result *result)
{
    char url[8 + 32 + 41 + 32 + 1];
    size_t domain_len = strlen(domain), key_len = strlen(key);
    if (domain_len > 32 || key_len != 32) return true;
    /* Raw host and query insertion. The URL is complete before the constructor skip. */
    memcpy(url, "https://", 8);
    memcpy(url + 8, domain, domain_len);
    memcpy(url + 8 + domain_len, ".sugester.com/app/clients.json?api_token=", 41);
    memcpy(url + 8 + domain_len + 41, key, key_len);
    url[8 + domain_len + 41 + key_len] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Accept", "application/vnd.sugester+json; version=3"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do and close errors stay unverified. Source defers every close until return. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int sugester_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const sugester_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->domain || !out ||
        (!input.data && input.len))
        return sugester_fail(error, "invalid or uninitialized Sugester scan");
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    char *owned_error = NULL;
    /* Occurrence order. A 32-character key also matches the domain class. */
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
            br_slice domain = br_captures_at(&domains, d);
            br_result result = {0};
            bool keep = true;
            if (key.len != 32 || domain.len < 3 || domain.len > 32)
                rc = sugester_fail(&owned_error, "invalid Sugester capture");
            else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = sugester_fail(&owned_error, "cannot create Sugester result");
            else if (verify)
                keep = sugester_verify(ctx, domains.items[d], keys.items[k], &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = sugester_fail(&owned_error, "cannot append Sugester result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector sugester_detector = {
    .type = 705, .version = 0, .name = "Sugester", .custom_name = "",
    .description = "Sugester is a customer support software that offers various tools for managing customer interactions. Sugester API keys can be used to access and manage data within the Sugester platform.",
    .keywords = sugester_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = sugester_scan,
};

int br_sugester_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"sugester"};
    if (error) *error = NULL;
    if (!out) return sugester_fail(error, "invalid Sugester detector output");
    *out = NULL;
    if (!sugester_detector.state) {
        sugester_patterns *patterns = calloc(1, sizeof(*patterns));
        if (!patterns) return sugester_fail(error, "out of memory compiling Sugester patterns");
        if (br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9]{32})\\b", &patterns->key, error) != 0 ||
            br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9_.!+$#^*%]{3,32})\\b",
                                      &patterns->domain, error) != 0) {
            br_regex_free(patterns->key);
            br_regex_free(patterns->domain);
            free(patterns);
            return -1;
        }
        sugester_detector.state = patterns;
    }
    *out = &sugester_detector;
    return 0;
}
