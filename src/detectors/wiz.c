/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/wiz/wiz.go.
 * Unique ids and secrets keep first-seen order. Go map iteration is random;
 * the verified-id break still stops later secrets for that id. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } wiz_patterns;

static int wiz_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int wiz_verify(const br_scan_ctx *ctx, const char *id, const char *secret, br_result *result)
{
    /* Alphanumeric captures need no QueryEscape. Encode sorts the four keys. */
    char body[256];
    int n = snprintf(body, sizeof(body),
                     "audience=wiz-api&client_id=%s&client_secret=%s&grant_type=client_credentials",
                     id, secret);
    if (n < 0 || (size_t)n >= sizeof(body)) return wiz_fail(NULL, "cannot build Wiz body");
    br_slice secrets[] = {
        {(const unsigned char *)id, strlen(id)},
        {(const unsigned char *)secret, strlen(secret)},
    };
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", secrets, 2) == 0 ? 0 : -1;
    const br_header headers[] = {
        {"Encoding", "UTF-8"},
        {"Content-Type", "application/x-www-form-urlencoded"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://auth.app.wiz.io/oauth/token",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, (size_t)n},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 984,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    int rc = br_result_set_verification_error(result, cause, secrets, 2) == 0 ? 0 : -1;
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int wiz_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    wiz_patterns *patterns = detector ? (wiz_patterns *)detector->state : NULL;
    if (!detector || !patterns || !out || (!input.data && input.len))
        return wiz_fail(error, "invalid or uninitialized Wiz scan");
    size_t original = out->len;
    br_captures ids = {0}, secrets = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, true, &owned);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned);
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, ids.items[i], "id",
                                secrets.items[s], "secret") != 0)
                rc = wiz_fail(&owned, "cannot create Wiz result");
            else if (verify && wiz_verify(ctx, ids.items[i], secrets.items[s], &result) != 0)
                rc = wiz_fail(&owned, "cannot record Wiz verification error");
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result) != 0)
                rc = wiz_fail(&owned, "cannot append Wiz result");
            br_result_clear(&result);
            if (!rc && verified) break;
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const wiz_keywords[] = {"wiz"};
static wiz_patterns wiz_state;
static br_detector wiz_detector = {
    .type = 984, .version = 0, .name = "Wiz", .custom_name = "",
    .description = "Wiz is a cloud security platform. Wiz credentials can be used to access and manage cloud security configurations.",
    .keywords = wiz_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = wiz_scan, .state = &wiz_state,
};

int br_wiz_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return wiz_fail(error, "invalid Wiz detector output");
    *out = NULL;
    if (!wiz_state.id &&
        br_regex_compile_prefixed(wiz_keywords, 1, "\\b([a-zA-Z0-9]{53})\\b", &wiz_state.id, error) != 0)
        return -1;
    if (!wiz_state.secret &&
        br_regex_compile_prefixed(wiz_keywords, 1, "\\b([a-zA-Z0-9]{64})\\b", &wiz_state.secret, error) != 0)
        return -1;
    *out = &wiz_detector;
    return 0;
}
