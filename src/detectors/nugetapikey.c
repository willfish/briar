/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nugetapikey/nugetapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int nuget_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. A stack key cannot survive that
 * release, so the original header value stays with the response. The stack
 * header array is not retained. */
typedef struct nuget_pending nuget_pending;
struct nuget_pending {
    nuget_pending *next;
    br_http_response response;
    char *key;
};

static int nuget_retain(nuget_pending **pending, const br_http_response *response, char *key)
{
    nuget_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->key = key;
    *pending = item;
    return 0;
}

static void nuget_release_held(const br_scan_ctx *ctx, nuget_pending *pending)
{
    while (pending) {
        nuget_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->key);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. A nil context drops before key allocation. 1 drops
 * this occurrence. 0 publishes it. Any other status is fatal. Body and read
 * errors do not affect the status verdict. No setter on any path. */
static int nuget_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                        nuget_pending **pending, char **error)
{
    if (!ctx) return 1;
    char *owned = malloc(key.len + 1);
    if (!owned) return nuget_fail(error, "cannot allocate NuGetApiKey key");
    memcpy(owned, key.data, key.len);
    owned[key.len] = '\0';
    /* Header.Add stores X-Nuget-Apikey. Do not store the source spelling.
     * The header array dies at send return. Do not retain it. */
    const br_header headers[] = {
        {"Content-Length", "0"},
        {"X-Nuget-Apikey", owned},
    };
    const br_http_request request = {
        .method = "PUT", .url = "https://www.nuget.org/api/v2/package",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(owned);
        return 0;
    }
    if (nuget_retain(pending, &response, owned) != 0) {
        br_http_release(ctx, &response);
        free(owned);
        return nuget_fail(error, "cannot retain NuGetApiKey response for release");
    }
    /* Exactly 400. 200-299 and every other status stay unverified. */
    result->verified = response.status == 400;
    return 0;
}

static int nuget_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nuget_fail(error, "invalid or uninitialized NuGetApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    nuget_pending *pending = NULL;
    char *owned_error = NULL;
    /* TrimSpace is a no-op. Keep every duplicate. Finding resources precede
     * the nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        if (key.len != 46)
            rc = nuget_fail(&owned_error, "invalid NuGetApiKey capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nuget_fail(&owned_error, "cannot create NuGetApiKey result");
        else if (verify) {
            int verdict = nuget_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict == 1) keep = false;
            else if (verdict != 0) rc = -1;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = nuget_fail(&owned_error, "cannot append NuGetApiKey result");
        br_result_clear(&result);
    }
    /* Successful responses close after the verdict and publication, last
     * success first. Fatal paths drain the same list once, then roll back only
     * this invocation. */
    nuget_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const nuget_keywords[] = {"nuget"};
static br_detector nuget_detector = {
    .type = 916, .version = 0, .name = "NuGetApiKey", .custom_name = "",
    .description = "NuGet is a package manager for .NET. NuGet API keys can be used to publish and manage packages in the NuGet repository.",
    .keywords = nuget_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = nuget_scan,
};

int br_nugetapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nuget_fail(error, "invalid NuGetApiKey detector output");
    *out = NULL;
    if (!nuget_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(nuget_keywords, 1, "\\b([a-z0-9]{46})\\b", &regex, error) != 0)
            return -1;
        nuget_detector.state = regex;
    }
    *out = &nuget_detector;
    return 0;
}
