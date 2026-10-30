/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/trelloapikey/trelloapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *token; } trello_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_trello(const br_scan_ctx *ctx, br_slice key, br_slice token, br_result *result)
{
    if (key.len != 32 || token.len != 64) return -1;
    static const char prefix[] = "https://api.trello.com/1/members/me?key=";
    char url[sizeof(prefix) + 32 + 7 + 64];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, "&token=", 7);
    memcpy(url + sizeof(prefix) - 1 + 32 + 7, token.data, 64);
    url[sizeof(prefix) - 1 + 32 + 7 + 64] = '\0';
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_trello(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TrelloApiKey scan");
    const trello_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->token) return fail(error, "uninitialized TrelloApiKey patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->token, input, &tokens, false, &owned_error);
    /* Only the first key is used, against every token. Neither side alone yields a result. */
    if (!rc && keys.len) {
        br_slice key = br_captures_at(&keys, 0);
        for (size_t i = 0; !rc && i < tokens.len; ++i) {
            br_result result = {0};
            int skip = 0;
            br_slice token = br_captures_at(&tokens, i);
            if (br_finding_key_bytes(&result, detector->type, key, "key") ||
                !(result.redacted = strdup((const char *)key.data)))
                rc = fail(&owned_error, "cannot create TrelloApiKey result");
            else if (verify) skip = verify_trello(ctx, key, token, &result);
            if (skip < 0) rc = fail(&owned_error, "cannot verify TrelloApiKey candidate");
            if (!rc && !skip && br_results_push(out, &result))
                rc = fail(&owned_error, "cannot append TrelloApiKey result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static trello_patterns compiled;
static const char *const keywords[] = {"trello"};
static const br_detector detector = {
    .type = 94, .name = "TrelloApiKey", .custom_name = "",
    .description = "Trello is a collaboration tool that organizes your projects into boards. Trello API keys can be used to access and modify data within Trello.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = 1024, .state = &compiled, .scan = scan_trello,
};

int br_trelloapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TrelloApiKey detector output");
    *out = NULL;
    if (!compiled.key && br_regex_compile_prefixed(keywords, 1,
            "\\b([a-zA-Z-0-9]{32})\\b", &compiled.key, error))
        return -1;
    if (!compiled.token && br_regex_compile("\\b([a-zA-Z-0-9]{64})\\b", &compiled.token, error))
        return -1;
    *out = &detector;
    return 0;
}
