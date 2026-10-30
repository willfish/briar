/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/websitepulse/websitepulse.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } websitepulse_patterns;

static int websitepulse_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool websitepulse_contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > body.len || !body.data) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

static int websitepulse_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int outcome = 0;
    /* Status is ignored. A readable body containing Active verifies; a read
     * failure drops only this pair. */
    if (sent == 0 && response.body_error) outcome = 1;
    else if (sent == 0 && websitepulse_contains(response.body, "Active")) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int websitepulse_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return websitepulse_fail(error, "invalid or uninitialized Websitepulse scan");
    const websitepulse_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            int outcome = 0;
            char url[192];
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = websitepulse_fail(&owned_error, "cannot create Websitepulse result");
            else if (verify) {
                int n = snprintf(url, sizeof(url),
                                 "https://api.websitepulse.com/textserver.php?method=GetContacts&username=%s&key=%s",
                                 ids.items[i], keys.items[k]);
                if (n < 0 || (size_t)n >= sizeof(url))
                    rc = websitepulse_fail(&owned_error, "cannot create Websitepulse URL");
                else if (!ctx) outcome = 1;
                else outcome = websitepulse_verify(ctx, url, &result);
            }
            if (outcome < 0) rc = -1;
            if (rc == 0 && outcome == 0 && br_results_push(out, &result) != 0)
                rc = websitepulse_fail(&owned_error, "cannot append Websitepulse result");
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

static const char *const websitepulse_keywords[] = {"websitepulse"};
static websitepulse_patterns websitepulse_state;
static br_detector websitepulse_detector = {
    .type = 870, .version = 0, .name = "Websitepulse", .custom_name = "",
    .description = "Websitepulse is a web-based service that monitors websites and servers. The keys and IDs can be used to access and manage monitoring configurations.",
    .keywords = websitepulse_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &websitepulse_state, .scan = websitepulse_scan,
};

int br_websitepulse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return websitepulse_fail(error, "invalid Websitepulse detector output");
    *out = NULL;
    if (!websitepulse_state.key &&
        br_regex_compile_prefixed(websitepulse_keywords, 1, "\\b([0-9a-f]{32})\\b",
                                  &websitepulse_state.key, error) != 0)
        return -1;
    if (!websitepulse_state.id &&
        br_regex_compile_prefixed(websitepulse_keywords, 1, "\\b([0-9a-zA-Z._]{4,22})\\b",
                                  &websitepulse_state.id, error) != 0)
        return -1;
    *out = &websitepulse_detector;
    return 0;
}
