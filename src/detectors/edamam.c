/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/edamam/edamam.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } edamam_patterns;

static int edamam_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool edamam_verify_keep(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result)
{
    static const char prefix[] = "https://api.edamam.com/auto-complete?app_id=";
    static const char middle[] = "&app_key=", suffix[] = "&q=";
    /* Known 8/32-byte unreserved ASCII captures: concatenate the COMPLETE URL
     * on the stack, retaining query order and the empty q's trailing '='.
     * No encoder, heap duplicate, arbitrary cap or fallible formatting seam. */
    char url[sizeof(prefix) - 1 + 8 + sizeof(middle) - 1 + 32 + sizeof(suffix)];
    char *at = url;
    memcpy(at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(at, id.data, id.len); at += id.len;
    memcpy(at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(at, key.data, key.len); at += key.len;
    memcpy(at, suffix, sizeof(suffix));
    /* Source formats the complete URL before the known constructor skip. */
    if (!ctx) return false;
    const br_header header = {"Content-Type", "application/json"};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = &header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * setter or diagnostic classifier. Failed sends retain a false finding. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrow every URL byte through synchronous send AND release. Body/read
     * errors are ignored. Source scan-defers Close only; eager Reader/release,
     * private/native client, regexp and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int edamam_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return edamam_fail(error, "invalid or uninitialized Edamam scan");
    const edamam_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return edamam_fail(error, "uninitialized Edamam patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent original occurrence lists, key-major ALL products, duplicates
     * included. TrimSpace is a no-op; the span hint never limits local pairings. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            br_slice id = br_captures_at(&ids, i);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = edamam_fail(&owned_error, "cannot create Edamam result");
            /* Finding resources precede URL preparation and constructor skip. */
            if (rc == 0 && (!verify || edamam_verify_keep(ctx, key, id, &result))) {
                if (br_results_push(out, &result) != 0)
                    rc = edamam_fail(&owned_error, "cannot append Edamam result");
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static edamam_patterns edamam_compiled;
static const char *const edamam_keywords[] = {"edamam"};
static const br_detector edamam_detector = {
    .type = 424, .version = 0, .name = "Edamam", .custom_name = "",
    .description = "Edamam provides nutrition analysis and diet recommendations. Edamam API keys can be used to access and modify nutrition data and perform diet analysis.",
    .keywords = edamam_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &edamam_compiled, .scan = edamam_scan,
};

int br_edamam_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return edamam_fail(error, "invalid Edamam detector output");
    *out = NULL;
    if (!edamam_compiled.key && br_regex_compile_prefixed(edamam_keywords, 1,
            "\\b([0-9a-z]{32})\\b", &edamam_compiled.key, error) != 0) return -1;
    if (!edamam_compiled.id && br_regex_compile_prefixed(edamam_keywords, 1,
            "\\b([0-9a-z]{8})\\b", &edamam_compiled.id, error) != 0) return -1;
    *out = &edamam_detector;
    return 0;
}
