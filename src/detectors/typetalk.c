/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/typetalk/typetalk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } typetalk_patterns;

static int typetalk_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void typetalk_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_http_request request = {
        .method = "POST", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int typetalk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return typetalk_fail(error, "invalid or uninitialized Typetalk scan");
    const typetalk_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            bool keep = true;
            char url[256];
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = typetalk_fail(&owned_error, "cannot create Typetalk result");
            else if (verify) {
                int n = snprintf(url, sizeof(url),
                                 "https://typetalk.com/oauth2/access_token?client_id=%s&client_secret=%s&grant_type=client_credentials",
                                 ids.items[i], keys.items[k]);
                if (n < 0 || (size_t)n >= sizeof(url))
                    rc = typetalk_fail(&owned_error, "cannot create Typetalk URL");
                else if (!ctx) keep = false;
                else typetalk_verify(ctx, url, &result);
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = typetalk_fail(&owned_error, "cannot append Typetalk result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const typetalk_keywords[] = {"typetalk"};
static typetalk_patterns typetalk_state;
static br_detector typetalk_detector = {
    .type = 809, .version = 0, .name = "Typetalk", .custom_name = "",
    .description = "Typetalk is a Japanese chat app. API keys can be used to read potentially sensitive chat messages.",
    .keywords = typetalk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &typetalk_state, .scan = typetalk_scan,
};

int br_typetalk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return typetalk_fail(error, "invalid Typetalk detector output");
    *out = NULL;
    if (!typetalk_state.key &&
        br_regex_compile_prefixed(typetalk_keywords, 1, "\\b([0-9a-zA-Z]{64})\\b",
                                  &typetalk_state.key, error) != 0)
        return -1;
    if (!typetalk_state.id &&
        br_regex_compile_prefixed(typetalk_keywords, 1, "\\b([0-9a-zA-Z]{32})\\b",
                                  &typetalk_state.id, error) != 0)
        return -1;
    *out = &typetalk_detector;
    return 0;
}
