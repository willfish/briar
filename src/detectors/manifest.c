/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/manifest/manifest.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char manifest_url_prefix[] = "https://api.manifest.ly/api/v1/checklists/?api_key=";

static int manifest_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* False means the source constructor continue: drop this occurrence.
 * The class is URL-raw in the source, including the A-z punctuation run. */
static bool manifest_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[sizeof(manifest_url_prefix) + 32];
    _Static_assert(sizeof(url) == 84, "Manifest URL is the 51-byte prefix plus 32-byte key");
    memcpy(url, manifest_url_prefix, sizeof(manifest_url_prefix) - 1);
    memcpy(url + sizeof(manifest_url_prefix) - 1, key, 32);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do failures stay unverified with no setter. Body and close errors are ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int manifest_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return manifest_fail(error, "invalid or uninitialized Manifest scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Prefixed, occurrence order. TrimSpace is a no-op for this class.
     * The defaults constructor is commented out; this scanner still exists. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 32)
            rc = manifest_fail(&owned_error, "invalid Manifest capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = manifest_fail(&owned_error, "cannot create Manifest result");
        else if (verify)
            keep = manifest_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = manifest_fail(&owned_error, "cannot append Manifest result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const manifest_keywords[] = {"manifest"};
static br_detector manifest_detector = {
    .type = 644, .version = 0, .name = "Manifest", .custom_name = "",
    .description = "Manifest API keys are used to interact with the Manifest service, which provides checklist management and other features.",
    .keywords = manifest_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = manifest_scan,
};

int br_manifest_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return manifest_fail(error, "invalid Manifest detector output");
    *out = NULL;
    if (br_key_pattern_init(&manifest_detector, "\\b([a-zA-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &manifest_detector;
    return 0;
}
