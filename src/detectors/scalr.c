/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scalr/scalr.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } scalr_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_scalr(const br_scan_ctx *ctx, const char *url, const char *key, br_result *result)
{
    char authorization[152];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n != 143) return;
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/vnd.api+json"},
        {"Prefer", "profile=preview"},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 852,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_scalr(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Scalr scan");
    const scalr_patterns *compiled = detector->state;
    br_captures keys = {0}, ids = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, &owned);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_slice key = br_captures_at(&keys, k), id = br_captures_at(&ids, i);
            br_result result = {0};
            char url[96];
            bool skip = false;
            int n = 0;
            if (key.len != 136 || id.len < 4 || id.len > 50)
                rc = fail(&owned, "invalid Scalr capture");
            else if (br_finding_key_bytes(&result, 852, key, "key") != 0)
                rc = fail(&owned, "cannot create Scalr result");
            else if (verify) {
                n = snprintf(url, sizeof(url), "https://%s.scalr.io/api/iacp/v3/agents", ids.items[i]);
                if (n != (int)(36 + id.len)) rc = fail(&owned, "cannot format Scalr URL");
                else if (!ctx) skip = true;
                else verify_scalr(ctx, url, keys.items[k], &result);
            }
            if (!rc && !skip && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Scalr result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static scalr_patterns patterns;
static const char *const keywords[] = {"scalr"};
static br_detector scalr = {
    .type = 852, .version = 0, .name = "Scalr", .custom_name = "",
    .description = "Scalr is a cloud management platform that allows users to manage and automate "
                   "cloud infrastructure. Scalr keys can be used to access and manage cloud resources "
                   "within the Scalr platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_scalr,
};

int br_scalr_init(const br_detector **out, char **error)
{
    static const char *const prefixes[] = {"scalr"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Scalr detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(prefixes, 1, "\\b([0-9a-zA-Z._]{136})", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(prefixes, 1, "\\b([0-9a-z]{4,50})\\b", &patterns.id, error) != 0)
        return -1;
    *out = &scalr;
    return 0;
}
