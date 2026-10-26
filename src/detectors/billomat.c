/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/billomat/billomat.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *key; } billomat_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* 0: candidate outcome; -1: resource failure. Only the successful 404-body
 * branch sets remove_id, reproducing the source's private sentinel identity. */
static int verify_billomat(const br_scan_ctx *ctx, const char *id, const char *key,
                            br_result *result, bool *remove_id)
{
    *remove_id = false;
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0 ? -1 : 0;
    char url[96];
    int n = snprintf(url, sizeof(url), "https://%s.billomat.net/api/v2/clients/myself", id);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-BillomatApiKey", key}};
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 385};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed"; /* Never classify transport text as the sentinel. */
    else if (response.status == 200) result->verified = true;
    else if (response.status == 404) {
        static const unsigned char marker[] = "account not found";
        /* Source suppresses ReadAll errors, even with a partial matching body. */
        if (!response.body_error && br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX)
            *remove_id = true;
    } else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0; /* Core may return positive allocation failures. */
}

static int scan_billomat(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Billomat scan arguments");
    const billomat_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->key) return fail(error, "uninitialized Billomat patterns");
    size_t original_len = out->len;
    br_captures ids = {0}, keys = {0};
    int rc = br_captures_find(patterns->id, input, &ids, true, error);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, true, error);
    bool *removed = !rc && ids.len && keys.len ? calloc(ids.len, sizeof(*removed)) : NULL;
    if (!rc && ids.len && keys.len && !removed) rc = fail(error, "out of memory tracking Billomat IDs");
    /* First-seen unique order is one valid source-map order. Do NOT reinterpret
     * captured context words as labels, and never consume a successful key. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            if (removed[i]) continue;
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[k], "key", ids.items[i], "id") != 0)
                rc = fail(error, "out of memory creating Billomat result");
            else if (verify) {
                bool remove_id = false;
                int checked = verify_billomat(ctx, ids.items[i], keys.items[k], &result, &remove_id);
                if (checked != 0) rc = fail(error, "out of memory recording Billomat verification error");
                else if (remove_id) {
                    removed[i] = true; /* Local to this scan; earlier emitted findings remain. */
                    br_result_clear(&result);
                    continue; /* Suppress the CURRENT finding as well as future uses of this ID. */
                }
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending Billomat result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(removed);
    br_captures_clear(&ids); br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static billomat_patterns patterns;
static const char *const keywords[] = {"billomat"};
static const br_detector billomat = {
    .type = 385, .version = 0, .name = "Billomat", .custom_name = "",
    .description = "Billomat is an online invoicing software. Billomat API keys can be used to access and manage invoices, clients, and other related data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_billomat,
};

int br_billomat_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Billomat detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-z]{4,20})\\b", &patterns.id, error) != 0) return -1;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{32})\\b", &patterns.key, error) != 0) return -1;
    *out = &billomat;
    return 0;
}
