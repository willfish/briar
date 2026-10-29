/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/host/host.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int host_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int host_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                       bool *keep, char **error)
{
    static const char prefix[] = "https://host.io/api/domains/ip/8.8.8.8?token=";
    /* The fixed ASCII capture needs no escaping. Complete the literal URL
     * before the source's nil-context request-constructor drop. */
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return host_fail(error, "cannot allocate Host URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole shared setup/Do failure domain is false-kept, with no setter.
     * The source never reads a body, even on success or a body-read error. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original URL and captures survive every release, including failed setup.
     * Ordinary ABI1 synthesized request/headers/UA end at send return. Source
     * instead scan-defers Close; this boundary releases once per attempt. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return 0;
}

static int host_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return host_fail(error, "invalid or uninitialized Host scan");
    const br_regex *pattern = *(br_regex *const *)detector->state;
    if (!pattern) return host_fail(error, "uninitialized Host pattern");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(pattern, input, &keys, false, &owned_error);
    /* FindAll preserves occurrences and duplicates. TrimSpace is a no-op for
     * the lower-case ASCII alphanumeric grammar; there is no local filter. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        br_result result = {0};
        bool keep = true;
        if (key.len != 14)
            rc = host_fail(&owned_error, "invalid Host capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = host_fail(&owned_error, "cannot create Host result");
        if (rc == 0 && verify)
            rc = host_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = host_fail(&owned_error, "cannot append Host result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_regex *host_pattern;
static const char *const host_keywords[] = {"host.io"};
/* Dispatch uses literal host.io; extraction deliberately uses only host. */
static const char *const host_extraction_keywords[] = {"host"};
static const br_detector host_detector = {
    .type = 556, .version = 0, .name = "Host", .custom_name = "",
    .description = "Host.io provides domain data and related services. Host.io tokens can be used to access and manage domain information.",
    .keywords = host_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &host_pattern, .scan = host_scan,
};

int br_host_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return host_fail(error, "invalid Host detector output");
    *out = NULL;
    if (!host_pattern && br_regex_compile_prefixed(host_extraction_keywords, 1,
        "\\b([a-z0-9]{14})\\b", &host_pattern, error) != 0) return -1;
    *out = &host_detector;
    return 0;
}
