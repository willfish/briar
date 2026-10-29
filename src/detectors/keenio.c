/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/keenio/keenio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } keenio_patterns;

static const char url_prefix[] = "https://api.keen.io/3.0/organizations/";
static const char url_suffix[] = "/projects";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* Source joins the id after the finding and before NewRequestWithContext. */
static char *assemble_url(const char *id)
{
    size_t id_len = strlen(id);
    if (id_len > SIZE_MAX - (sizeof(url_prefix) - 1) - sizeof(url_suffix)) return NULL;
    char *url = malloc(sizeof(url_prefix) - 1 + id_len + sizeof(url_suffix));
    if (!url) return NULL;
    memcpy(url, url_prefix, sizeof(url_prefix) - 1);
    memcpy(url + sizeof(url_prefix) - 1, id, id_len);
    memcpy(url + sizeof(url_prefix) - 1 + id_len, url_suffix, sizeof(url_suffix));
    return url;
}

static int scan_keenio(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized KeenIO scan");
    const keenio_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return fail(error, "uninitialized KeenIO detector");

    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    /* Both FindAll calls run even when verify is set, ctx is NULL, and there
     * are no keys. Any nonzero, including +1, is fatal before a drop. */
    char *key_error = NULL, *id_error = NULL;
    int key_rc = br_captures_find(patterns->key, input, &keys, false, &key_error);
    int id_rc = br_captures_find(patterns->id, input, &ids, false, &id_error);
    int rc = 0;
    if (key_rc != 0) {
        owned_error = key_error;
        free(id_error);
        rc = -1;
    } else if (id_rc != 0) {
        owned_error = id_error;
        free(key_error);
        rc = -1;
    } else {
        free(key_error);
        free(id_error);
    }
    /* Key is outer. No dedupe. The id is a request path segment only. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = fail(&owned_error, "out of memory creating KeenIO result");
            if (rc == 0 && verify) {
                char *url = assemble_url(ids.items[i]);
                if (!url)
                    rc = fail(&owned_error, "out of memory creating KeenIO request");
                else if (!ctx) {
                    /* NewRequestWithContext(nil) returns "net/http: nil Context".
                     * continue drops only this pair: no headers, send, or release. */
                    free(url);
                    br_result_clear(&result);
                    continue;
                } else {
                    const br_header headers[] = {
                        {"Content-Type", "application/json"},
                        {"Authorization", keys.items[k]}, /* Raw key. Not Bearer. */
                    };
                    const br_http_request request = {
                        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                        .profile = BR_HTTP_SANE, .detector_type = 140,
                    };
                    br_http_response response = {0};
                    char *transport_error = NULL;
                    /* Any 2xx verifies. Other statuses, send failures, and body
                     * errors stay unverified. Never set a verification error. */
                    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                        result.verified = response.status >= 200 && response.status < 300;
                    br_http_release(ctx, &response);
                    free(transport_error);
                    free(url);
                }
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "out of memory appending KeenIO result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static keenio_patterns patterns;
static const char *const keywords[] = {"keen"};
static const br_detector keenio = {
    .type = 140, .version = 0, .name = "KeenIO", .custom_name = "",
    .description = "KeenIO is an analytics platform that allows you to collect, analyze, and visualize event data. KeenIO API keys can be used to access and manage this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_keenio,
};

int br_keenio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid KeenIO detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Z]{64})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-z]{24})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &keenio;
    return 0;
}
