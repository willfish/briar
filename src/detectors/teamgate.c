/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/teamgate/teamgate.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

typedef struct {
    br_regex *token, *app;
} teamgate_state;

/* Raw and the key part are the 40-character token, never the app key.
 * A nil context drops that pair. Do errors and non-2xx stay unverified
 * without a setter. Every token/app combination is retained. */
static int verify_teamgate(const br_scan_ctx *ctx, br_slice token, br_slice app,
                           br_result *result, char **error)
{
    (void)error;
    if (!ctx) return 1;
    const br_header headers[] = {
        {"X-Auth-Token", (const char *)token.data},
        {"X-App-Key", (const char *)app.data},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.teamgate.com/v4/users",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 319,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_teamgate(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    teamgate_state *state = detector ? (teamgate_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Teamgate scan");
    size_t before = out->len;
    br_captures tokens = {0}, apps = {0};
    char *owned = NULL;
    int rc = br_captures_find(state->token, input, &tokens, false, &owned);
    if (!rc) rc = br_captures_find(state->app, input, &apps, false, &owned);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        for (size_t j = 0; !rc && j < apps.len; ++j) {
            br_result result = {0};
            br_slice token = br_captures_at(&tokens, i);
            br_slice app = br_captures_at(&apps, j);
            if (br_finding_key_bytes(&result, detector->type, token, "key") != 0) {
                rc = fail(&owned, "cannot create Teamgate finding");
            } else if (verify) {
                int status = verify_teamgate(ctx, token, app, &result, &owned);
                if (status > 0) {
                    br_result_clear(&result);
                    continue;
                }
                if (status < 0) rc = -1;
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Teamgate finding");
            br_result_clear(&result);
        }
    }
    if (rc) rollback(out, before);
    br_captures_clear(&tokens);
    br_captures_clear(&apps);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"teamgate"};
static br_detector teamgate = {
    .type = 319, .version = 0, .name = "Teamgate", .custom_name = "",
    .description = "Teamgate is a sales CRM platform. Teamgate tokens and keys can be used to access and manage sales data and CRM functionalities.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_teamgate,
};

int br_teamgate_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Teamgate detector output");
    *out = NULL;
    if (teamgate.state) {
        *out = &teamgate;
        return 0;
    }
    teamgate_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Teamgate patterns");
    char *token_error = NULL, *app_error = NULL;
    if (br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{40})\\b", &state->token, &token_error) != 0 ||
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9]{80})\\b", &state->app, &app_error) != 0) {
        if (error) *error = token_error ? token_error : app_error;
        else { free(token_error); free(app_error); }
        if (token_error && app_error && error) free(app_error);
        free(state);
        return -1;
    }
    teamgate.state = state;
    *out = &teamgate;
    return 0;
}
