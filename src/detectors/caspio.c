/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/caspio/caspio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *credential, *domain; } caspio_patterns;

static int caspio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int caspio_finding(br_result *result, int32_t type, br_slice key, br_slice id, br_slice domain)
{
    if (br_finding_key_bytes(result, type, key, "key") != 0) return -1;
    /* All three captures have fixed source lengths: 50 + 50 + 8 bytes. */
    result->raw_v2.len = 108;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) goto failed;
    memcpy(result->raw_v2.data, key.data, key.len);
    memcpy(result->raw_v2.data + key.len, id.data, id.len);
    memcpy(result->raw_v2.data + key.len + id.len, domain.data, domain.len);
    const char *names[] = {"id", "domain"};
    const br_slice values[] = {id, domain};
    for (size_t i = 0; i < 2; ++i) {
        br_json *part = json_object_new_string_len((const char *)values[i].data, (int)values[i].len);
        if (!part) goto failed;
        if (json_object_object_add(result->secret_parts, names[i], part) != 0) {
            json_object_put(part);
            goto failed;
        }
    }
    return 0;
failed:
    br_result_clear(result);
    return -1;
}

static void caspio_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, const char *domain, br_result *result)
{
    char url[64]; /* Domain capture is exactly eight unreserved ASCII bytes. */
    snprintf(url, sizeof(url), "https://%s.caspio.com/oauth/token", domain);
    static const char prefix[] = "grant_type=client_credentials&client_id=";
    static const char separator[] = "&client_secret=";
    unsigned char payload[sizeof(prefix) - 1 + 50 + sizeof(separator) - 1 + 50];
    size_t at = sizeof(prefix) - 1;
    memcpy(payload, prefix, at);
    memcpy(payload + at, id.data, id.len); at += id.len;
    memcpy(payload + at, separator, sizeof(separator) - 1); at += sizeof(separator) - 1;
    memcpy(payload + at, key.data, key.len);
    const br_header headers[] = {{"Content-Type", "text/plain"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = {payload, sizeof(payload)}, .profile = BR_HTTP_DETECTOR_PUBLIC,
        .timeout_ms = 10000, .detector_type = 648,
    };
    /* PUBLIC's no-local-address/no-redirect policy is injected-only. Native
     * rejection must not fall back to SANE or issue a token request. */
    br_http_response response = {0};
    char *transport_error = NULL;
    /* The single adapter/Do error domain is suppressed, including allocation,
     * setup and native-PUBLIC unsupported errors; no text classification. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close only until FromData returns. Eager buffering and
     * per-request ABI release remain lifecycle gaps; bodies are ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int caspio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return caspio_fail(error, "invalid Caspio scan arguments");
    const caspio_patterns *patterns = detector->state;
    if (!patterns->credential || !patterns->domain)
        return caspio_fail(error, "uninitialized Caspio detector");
    size_t original_len = out->len;
    br_captures credentials = {0}, domains = {0};
    /* Source key and ID patterns are identical and independently match the same
     * occurrences. Share storage, never remove self-pairs or duplicate entries. */
    int rc = br_captures_find(patterns->credential, input, &credentials, false, error);
    if (rc == 0) rc = br_captures_find(patterns->domain, input, &domains, false, error);
    for (size_t k = 0; rc == 0 && k < credentials.len; ++k) {
        br_slice key = br_captures_at(&credentials, k);
        for (size_t i = 0; rc == 0 && i < credentials.len; ++i) {
            br_slice id = br_captures_at(&credentials, i);
            for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
                /* The fixed method and ASCII request pieces are constructor-safe
                 * except for nil context, which source skips only in verify mode. */
                if (verify && !ctx) continue;
                br_slice domain = br_captures_at(&domains, d);
                br_result result = {0};
                if (caspio_finding(&result, detector->type, key, id, domain) != 0)
                    rc = caspio_fail(error, "out of memory creating Caspio result");
                else if (verify) caspio_verify(ctx, key, id, domains.items[d], &result);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = caspio_fail(error, "out of memory appending Caspio result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&credentials);
    br_captures_clear(&domains);
    return rc == 0 ? 0 : -1;
}

static caspio_patterns caspio_compiled;
static const char *const caspio_keywords[] = {"caspio"};
static const br_detector caspio_detector = {
    .type = 648, .version = 0, .name = "Caspio", .custom_name = "",
    .description = "Caspio is a cloud platform for building custom database applications. "
                   "Caspio credentials can be used to access and manage these applications.",
    .keywords = caspio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &caspio_compiled, .scan = caspio_scan,
};

int br_caspio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return caspio_fail(error, "invalid Caspio detector output");
    *out = NULL;
    if (!caspio_compiled.credential && br_regex_compile_prefixed(caspio_keywords, 1,
        "\\b([a-z0-9]{50})\\b", &caspio_compiled.credential, error) != 0) return -1;
    if (!caspio_compiled.domain && br_regex_compile_prefixed(caspio_keywords, 1,
        "\\b([a-z0-9]{8})\\b", &caspio_compiled.domain, error) != 0) return -1;
    *out = &caspio_detector;
    return 0;
}
