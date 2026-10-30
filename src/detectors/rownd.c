/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rownd/rownd.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *key, *secret; } rownd_patterns;

static int rownd_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rownd_verify(const br_scan_ctx *ctx, const char *key, const char *secret,
                         const char *url, br_result *result)
{
    /* Header.Add canonicalizes these names before Do. Briar keeps the source names. */
    const br_header headers[] = {
        {"x-rownd-app-key", key},
        {"x-rownd-app-secret", secret},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 673,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int rownd_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    rownd_patterns *patterns = detector ? (rownd_patterns *)detector->state : NULL;
    if (!detector || !patterns || !out || (!input.data && input.len))
        return rownd_fail(error, "invalid or uninitialized Rownd scan");
    size_t original = out->len;
    br_captures ids = {0}, keys = {0}, secrets = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned);
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            for (size_t s = 0; !rc && s < secrets.len; ++s) {
                char url[96] = "";
                if (verify) {
                    int n = snprintf(url, sizeof(url),
                                     "https://api.rownd.io/applications/%s/users/data", ids.items[i]);
                    if (n < 0 || (size_t)n >= sizeof(url)) {
                        rc = rownd_fail(&owned, "cannot build Rownd URL");
                        break;
                    }
                    /* Nil context is the reachable NewRequestWithContext error. */
                    if (!ctx) continue;
                }
                br_result result = {0};
                if (br_finding_pair(&result, detector->type, keys.items[k], "key",
                                    secrets.items[s], "secret") != 0)
                    rc = rownd_fail(&owned, "cannot create Rownd result");
                else if (verify)
                    rownd_verify(ctx, keys.items[k], secrets.items[s], url, &result);
                if (!rc && br_results_push(out, &result) != 0)
                    rc = rownd_fail(&owned, "cannot append Rownd result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const rownd_keywords[] = {"rownd"};
static rownd_patterns rownd_state;
static br_detector rownd_detector = {
    .type = 673, .version = 0, .name = "Rownd", .custom_name = "",
    .description = "Rownd is a platform for user data management. Rownd credentials can be used to access and modify user data and application settings.",
    .keywords = rownd_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = rownd_scan, .state = &rownd_state,
};

int br_rownd_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rownd_fail(error, "invalid Rownd detector output");
    *out = NULL;
    const char *captures[] = {
        "\\b([0-9]{18})\\b",
        "\\b([a-z0-9]{8}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{4}\\-[a-z0-9]{12})\\b",
        "\\b([a-z0-9]{48})\\b",
    };
    br_regex **slots[] = {&rownd_state.id, &rownd_state.key, &rownd_state.secret};
    for (size_t i = 0; i < 3; ++i) {
        if (*slots[i]) continue;
        if (br_regex_compile_prefixed(rownd_keywords, 1, captures[i], slots[i], error) != 0)
            return -1;
    }
    *out = &rownd_detector;
    return 0;
}
