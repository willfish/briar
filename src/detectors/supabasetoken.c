/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/supabasetoken/supabasetoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef enum { SB_ABORT = -1, SB_KEEP = 0, SB_DROP = 1 } sb_outcome;

static int sb_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static sb_outcome sb_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return SB_DROP;
    if (strlen(key) != 44) return sb_fail(error, "unexpected SupabaseToken key length"), SB_ABORT;
    char authorization[7 + 44 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 45);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.supabase.com/v1/projects",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return SB_KEEP;
}

static int sb_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sb_fail(error, "invalid or uninitialized SupabaseToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* The token pattern is not prefixed. sbp_ is only the engine keyword. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        sb_outcome outcome = SB_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = sb_fail(&owned_error, "cannot create SupabaseToken result");
        else if (verify)
            outcome = sb_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == SB_ABORT) rc = -1;
        if (rc == 0 && outcome == SB_KEEP && br_results_push(out, &result) != 0)
            rc = sb_fail(&owned_error, "cannot append SupabaseToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sb_keywords[] = {"sbp_"};
static br_regex *sb_pattern;
static br_detector sb_detector = {
    .type = 915, .version = 0, .name = "SupabaseToken", .custom_name = "",
    .description = "Supabase is an open source Firebase alternative. Supabase tokens can be used to access and manage Supabase projects and data.",
    .keywords = sb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sb_scan,
};

int br_supabasetoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sb_fail(error, "invalid SupabaseToken detector output");
    *out = NULL;
    if (!sb_pattern && br_regex_compile("\\b(sbp_[a-z0-9]{40})\\b", &sb_pattern, error) != 0) return -1;
    sb_detector.state = sb_pattern;
    *out = &sb_detector;
    return 0;
}
