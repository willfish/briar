/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getsandbox/getsandbox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } getsandbox_patterns;

static int getsandbox_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void getsandbox_verify(const br_scan_ctx *ctx, const char *key, const char *url,
                              br_result *result)
{
    const br_header headers[] = {{"Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* All shared setup/Do errors are false-kept. No body read or error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int getsandbox_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getsandbox_fail(error, "invalid or uninitialized GetSandbox scan");
    const getsandbox_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return getsandbox_fail(error, "uninitialized GetSandbox patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent occurrence sets, including overlaps between roles and
     * duplicates: full key-major product, without a detector-level span cap. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            /* TrimSpace cannot change these ASCII captures. ID stays hidden. */
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, k), "key") != 0)
                rc = getsandbox_fail(&owned_error, "cannot create GetSandbox result");
            else {
                bool keep = true;
                if (verify) {
                    static const char prefix[] = "https://getsandbox.com/api/1/sandboxes/";
                    char url[sizeof(prefix) + 30];
                    br_slice id = br_captures_at(&ids, i);
                    /* Literal URL + grammar-bounded ID + NUL is infallible;
                     * complete it before the nil-context constructor skip. */
                    memcpy(url, prefix, sizeof(prefix) - 1);
                    memcpy(url + sizeof(prefix) - 1, id.data, id.len);
                    url[sizeof(prefix) - 1 + id.len] = '\0';
                    if (!ctx) keep = false;
                    else getsandbox_verify(ctx, keys.items[k], url, &result);
                    /* Source URL/captures/header values survive release.
                     * Ordinary synthesized request/UA live only through send. */
                }
                if (keep && br_results_push(out, &result) != 0)
                    rc = getsandbox_fail(&owned_error, "cannot append GetSandbox result");
            }
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

static getsandbox_patterns getsandbox_compiled;
static const char *const getsandbox_keywords[] = {"getsandbox"};
static const br_detector getsandbox_detector = {
    .type = 633, .version = 0, .name = "GetSandbox", .custom_name = "",
    .description = "GetSandbox is a service for creating and managing sandboxes. GetSandbox API keys can be used to access and control these sandboxes.",
    .keywords = getsandbox_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &getsandbox_compiled, .scan = getsandbox_scan,
};

int br_getsandbox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getsandbox_fail(error, "invalid GetSandbox detector output");
    *out = NULL;
    if (!getsandbox_compiled.key && br_regex_compile_prefixed(getsandbox_keywords, 1,
            "\\b([a-z0-9-]{40})\\b", &getsandbox_compiled.key, error) != 0) return -1;
    if (!getsandbox_compiled.id && br_regex_compile_prefixed(getsandbox_keywords, 1,
            "\\b([a-z0-9-]{15,30})\\b", &getsandbox_compiled.id, error) != 0) return -1;
    *out = &getsandbox_detector;
    return 0;
}
