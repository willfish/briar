/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/deputy/deputy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } deputy_patterns;

static int deputy_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int deputy_verify(const br_scan_ctx *ctx, br_slice key, br_slice host,
                          br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://", path[] = "/api/v1/me";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(path); /* Includes URL NUL. */
    if (host.len > SIZE_MAX - fixed)
        return deputy_fail(error, "Deputy request URL size overflow");
    /* Source formats the complete unbounded URL BEFORE request construction.
     * Concatenate once, without hostname/DNS limits, normalization, truncation
     * or a second owned URL copy. Literal copying needs no printf int bound. */
    char *url = malloc(fixed + host.len);
    if (!url) return deputy_fail(error, "cannot allocate Deputy request URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, host.data, host.len);
    memcpy(url + sizeof(prefix) - 1 + host.len, path, sizeof(path));
    if (!ctx) {
        free(url);
        *keep = false; /* Known NewRequestWithContext(nil) failure skips THIS pair. */
        return 0;
    }
    /* Headers follow successful construction. Fixed 32-byte key: all 38 bytes
     * of literal OAuth + key, plus NUL, stay on the stack through release. */
    char authorization[39];
    memcpy(authorization, "OAuth ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All Do errors are suppressed. ABI1 mixes shared setup/allocation and Do
     * here: suppress the WHOLE domain, without a setter or text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* URL and auth live through send AND release. PUBLIC's native no-local-IP
     * policy must remain fail-closed before I/O, never a SANE alias. Injected
     * success is not native policy parity. Source scan-defers Close ONLY and
     * ignores body/read errors; eager release, full native client, regexp and
     * source/engine/output behavior remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    free(url);
    return 0;
}

static int deputy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return deputy_fail(error, "invalid or uninitialized Deputy scan");
    const deputy_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->host) return deputy_fail(error, "uninitialized Deputy patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, hosts = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->host, input, &hosts, false, &owned_error);
    /* TrimSpace cannot change either ASCII grammar. Preserve ALL key-major
     * occurrence products, including duplicates, without a local span cap. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
            br_result result = {0};
            bool keep = true;
            /* Host is REQUIRED but HIDDEN, even in verified findings. Prepare
             * own finding resources before URL allocation or constructor skip. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = deputy_fail(&owned_error, "cannot create Deputy result");
            if (rc == 0 && verify && deputy_verify(ctx, key, br_captures_at(&hosts, h), &result, &keep, &owned_error) != 0)
                rc = -1;
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = deputy_fail(&owned_error, "cannot append Deputy result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&hosts);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static deputy_patterns deputy_compiled;
static const char *const deputy_keywords[] = {"deputy"};
static const br_detector deputy_detector = {
    .type = 683, .version = 0, .name = "Deputy", .custom_name = "",
    .description = "Deputy is a workforce management software that provides various tools for scheduling, time tracking, and communication. Deputy API keys can be used to access and modify data within the Deputy platform.",
    .keywords = deputy_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &deputy_compiled, .scan = deputy_scan,
};

int br_deputy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return deputy_fail(error, "invalid Deputy detector output");
    *out = NULL;
    if (!deputy_compiled.key) {
        deputy_patterns compiled = {0};
        if (br_regex_compile_prefixed(deputy_keywords, 1, "\\b([0-9a-z]{32})\\b", &compiled.key, error) != 0 ||
            br_regex_compile("\\b([0-9a-z]{1,}\\.as\\.deputy\\.com)\\b", &compiled.host, error) != 0) {
            br_regex_free(compiled.key);
            br_regex_free(compiled.host);
            return -1;
        }
        deputy_compiled = compiled;
    }
    *out = &deputy_detector;
    return 0;
}
