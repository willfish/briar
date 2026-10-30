/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/textmagic/textmagic.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *user; } textmagic_patterns;

static int textmagic_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void textmagic_verify(const br_scan_ctx *ctx, const char *authorization, br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://rest.textmagic.com/api/v2/user",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 612,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int textmagic_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    textmagic_patterns *patterns = detector ? (textmagic_patterns *)detector->state : NULL;
    if (!detector || !patterns || !out || (!input.data && input.len))
        return textmagic_fail(error, "invalid or uninitialized Textmagic scan");
    size_t original = out->len;
    br_captures keys = {0}, users = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(patterns->user, input, &users, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        for (size_t u = 0; !rc && u < users.len; ++u) {
            char *authorization = NULL;
            if (verify) {
                /* Basic is built before NewRequestWithContext, so its failure is fatal. */
                if (br_http_basic_auth(br_captures_at(&users, u), br_captures_at(&keys, i),
                                       &authorization, &owned) != 0) {
                    free(authorization);
                    rc = -1;
                    break;
                }
                if (!ctx) {
                    free(authorization);
                    continue;
                }
            }
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, keys.items[i], "key",
                                users.items[u], "username") != 0)
                rc = textmagic_fail(&owned, "cannot create Textmagic result");
            else if (verify) textmagic_verify(ctx, authorization, &result);
            if (!rc && br_results_push(out, &result) != 0)
                rc = textmagic_fail(&owned, "cannot append Textmagic result");
            br_result_clear(&result);
            free(authorization);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&users);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const textmagic_keywords[] = {"textmagic"};
static textmagic_patterns textmagic_state;
static br_detector textmagic_detector = {
    .type = 612, .version = 0, .name = "Textmagic", .custom_name = "",
    .description = "Textmagic is a service for sending and receiving text messages. Textmagic API keys can be used to access and manage text messaging services.",
    .keywords = textmagic_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = textmagic_scan, .state = &textmagic_state,
};

int br_textmagic_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return textmagic_fail(error, "invalid Textmagic detector output");
    *out = NULL;
    if (!textmagic_state.key &&
        br_regex_compile_prefixed(textmagic_keywords, 1, "\\b([0-9A-Za-z]{30})\\b",
                                 &textmagic_state.key, error) != 0)
        return -1;
    if (!textmagic_state.user &&
        br_regex_compile_prefixed(textmagic_keywords, 1, "\\b([0-9A-Za-z]{1,25})\\b",
                                 &textmagic_state.user, error) != 0)
        return -1;
    *out = &textmagic_detector;
    return 0;
}
