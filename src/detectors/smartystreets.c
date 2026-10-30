/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/smartystreets/smartystreets.go.
 * Raw is the 20-character token. The 36-character id is only a URL parameter. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *key_re, *id_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_smarty(const br_scan_ctx *ctx, const char *key, const char *id,
                         br_result *result, char **error)
{
    char url[192];
    int n = snprintf(url, sizeof(url),
                     "https://us-zipcode.api.smartystreets.com/lookup?auth-id=%s&auth-token=%s&state=CA&zipcode=94035",
                     id, key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format SmartyStreets URL");
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_smarty(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !id_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SmartyStreets scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(id_re, input, &ids, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        for (size_t j = 0; !rc && j < ids.len; ++j) {
            br_result result = {0};
            int outcome = 0;
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
                fail(&owned_error, "cannot create SmartyStreets result");
                outcome = -1;
            } else if (verify)
                outcome = verify_smarty(ctx, keys.items[i], ids.items[j], &result, &owned_error);
            if (outcome == 0 && br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append SmartyStreets result");
                outcome = -1;
            }
            br_result_clear(&result);
            if (outcome < 0) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"smartystreets"};
static br_detector smarty = {
    .type = 562, .version = 0, .name = "SmartyStreets", .custom_name = "",
    .description = "SmartyStreets provides address validation services. The detected API keys can be used to access and validate addresses.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_smarty,
};

int br_smartystreets_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"smartystreets"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SmartyStreets detector output");
    *out = NULL;
    if (!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9]{20})\\b", &key_re, error) != 0)
        return -1;
    if (!id_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-z0-9-]{36})\\b", &id_re, error) != 0)
        return -1;
    smarty.state = key_re;
    *out = &smarty;
    return 0;
}
