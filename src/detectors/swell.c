/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/swell/swell.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } swell_patterns;

static const char swell_url[] = "https://api.swell.store/products?limit=100";

static int swell_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int swell_verify(const br_scan_ctx *ctx, br_slice id, br_slice token,
                        br_result *result, bool *keep, char **error)
{
    *keep = false;
    if (token.len != 32 || id.len < 6 || id.len > 24)
        return swell_fail(error, "invalid Swell capture");
    if (!ctx) return 0;
    char *authorization = NULL;
    if (br_http_basic_auth(id, token, &authorization, error) != 0) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = swell_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int swell_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return swell_fail(error, "invalid or uninitialized Swell scan");
    const swell_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return swell_fail(error, "uninitialized Swell patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            bool keep = true;
            br_slice token = br_captures_at(&keys, k);
            if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
                rc = swell_fail(&owned_error, "cannot create Swell result");
            else if (verify && swell_verify(ctx, br_captures_at(&ids, i), token, &result, &keep, &owned_error) != 0)
                rc = -1;
            else if (keep && br_results_push(out, &result) != 0)
                rc = swell_fail(&owned_error, "cannot append Swell result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const swell_keywords[] = {"swell"};
static swell_patterns swell_compiled;
static br_detector swell_detector = {
    .type = 365, .version = 0, .name = "Swell", .custom_name = "",
    .description = "Swell is an eCommerce platform that allows businesses to create and manage online stores. Swell API keys can be used to access and modify store data.",
    .keywords = swell_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &swell_compiled, .scan = swell_scan,
};

int br_swell_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return swell_fail(error, "invalid Swell detector output");
    *out = NULL;
    if (!swell_compiled.key &&
        br_regex_compile_prefixed(swell_keywords, 1, "\\b([a-zA-Z0-9]{32})\\b", &swell_compiled.key, error) != 0)
        return -1;
    if (!swell_compiled.id &&
        br_regex_compile_prefixed(swell_keywords, 1, "\\b([a-zA-Z0-9]{6,24})\\b", &swell_compiled.id, error) != 0)
        return -1;
    *out = &swell_detector;
    return 0;
}
