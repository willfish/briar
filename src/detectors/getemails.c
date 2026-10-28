/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getemails/getemails.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } getemails_patterns;

static int getemails_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void getemails_verify(const br_scan_ctx *ctx, const char *key, const char *id,
                             br_result *result)
{
    const br_header headers[] = {{"Api-Key", key}, {"Api-Id", id}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.getemails.com/api/v1/contacts",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* The entire shared setup/Do failure domain is false-kept, without an
     * error setter. Status alone matters, even after a body read failure. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int getemails_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getemails_fail(error, "invalid or uninitialized GetEmails scan");
    const getemails_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return getemails_fail(error, "uninitialized GetEmails patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent non-overlapping occurrence sets, key-major full product.
     * ASCII captures contain no TrimSpace bytes. ID is required but hidden. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, k), "key") != 0)
                rc = getemails_fail(&owned_error, "cannot create GetEmails result");
            /* Source constructs the finding before NewRequestWithContext,
             * whose nil-context error skips this inner pair, not the scan. */
            bool keep = !verify || ctx;
            if (rc == 0 && verify && keep)
                getemails_verify(ctx, keys.items[k], ids.items[i], &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = getemails_fail(&owned_error, "cannot append GetEmails result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static getemails_patterns getemails_compiled;
static const char *const getemails_keywords[] = {"getemails"};
static const br_detector getemails_detector = {
    .type = 327, .version = 0, .name = "GetEmails", .custom_name = "",
    .description = "GetEmails is a service used to find email addresses of website visitors. The API keys can be used to access and manage contact data.",
    .keywords = getemails_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &getemails_compiled, .scan = getemails_scan,
};

int br_getemails_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getemails_fail(error, "invalid GetEmails detector output");
    *out = NULL;
    if (!getemails_compiled.key && br_regex_compile_prefixed(getemails_keywords, 1,
            "\\b([a-z0-9-]{26})\\b", &getemails_compiled.key, error) != 0) return -1;
    if (!getemails_compiled.id && br_regex_compile_prefixed(getemails_keywords, 1,
            "\\b([a-z0-9-]{18})\\b", &getemails_compiled.id, error) != 0) return -1;
    *out = &getemails_detector;
    return 0;
}
