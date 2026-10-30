/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/thousandeyes/thousandeyes.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } thousandeyes_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_thousandeyes(const br_scan_ctx *ctx, br_slice key, br_slice email, br_result *result)
{
    /* SetBasicAuth happens after NewRequest succeeds. A nil context skips first. */
    if (!ctx) return 1;
    char *authorization = NULL;
    if (br_http_basic_auth(email, key, &authorization, NULL)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.thousandeyes.com/v6/endpoint-data/user-sessions/web.json",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int scan_thousandeyes(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ThousandEyes scan");
    const thousandeyes_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->email) return fail(error, "uninitialized ThousandEyes patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->email, input, &emails, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; !rc && i < emails.len; ++i) {
            br_result result = {0};
            int skip = 0;
            br_slice email = br_captures_at(&emails, i);
            if (br_finding_key_bytes(&result, detector->type, key, "key"))
                rc = fail(&owned_error, "cannot create ThousandEyes result");
            else if (verify) skip = verify_thousandeyes(ctx, key, email, &result);
            if (skip < 0) rc = fail(&owned_error, "cannot verify ThousandEyes candidate");
            if (!rc && !skip && br_results_push(out, &result))
                rc = fail(&owned_error, "cannot append ThousandEyes result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&emails);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static thousandeyes_patterns compiled;
static const char *const keywords[] = {"thousandeyes"};
static const br_detector detector = {
    .type = 640, .name = "ThousandEyes", .custom_name = "",
    .description = "ThousandEyes provides network intelligence and monitoring services. ThousandEyes API keys can be used to access and manage network performance data.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = 1024, .state = &compiled, .scan = scan_thousandeyes,
};

int br_thousandeyes_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ThousandEyes detector output");
    *out = NULL;
    if (!compiled.key && br_regex_compile_prefixed(keywords, 1,
            "\\b([a-zA-Z0-9]{32})\\b", &compiled.key, error))
        return -1;
    if (!compiled.email && br_regex_compile_prefixed(keywords, 1,
            "\\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\\b", &compiled.email, error))
        return -1;
    *out = &detector;
    return 0;
}
