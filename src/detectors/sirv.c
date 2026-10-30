/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sirv/sirv.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } sirv_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_sirv(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result)
{
    if (key.len != 88 || id.len != 26) return -1;
    char body[2 + 13 + 26 + 18 + 88 + 2];
    size_t n = 0;
    memcpy(body + n, "{\"clientId\":\"", 13); n += 13;
    memcpy(body + n, id.data, 26); n += 26;
    memcpy(body + n, "\",\"clientSecret\":\"", 18); n += 18;
    memcpy(body + n, key.data, 88); n += 88;
    memcpy(body + n, "\"}", 2); n += 2;
    /* The JSON body is an argument to NewRequest. A nil context skips. The
     * source also sets the shared client timeout to 10s before that call. */
    if (!ctx) return 1;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.sirv.com/v2/token",
        .headers = headers, .nheaders = 1, .body = {(unsigned char *)body, n},
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = result->detector_type,
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

static int scan_sirv(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Sirv scan");
    const sirv_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return fail(error, "uninitialized Sirv patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            int skip = 0;
            br_slice id = br_captures_at(&ids, i);
            if (br_finding_key_bytes(&result, detector->type, key, "key"))
                rc = fail(&owned_error, "cannot create Sirv result");
            else if (verify) skip = verify_sirv(ctx, key, id, &result);
            if (skip < 0) rc = fail(&owned_error, "cannot verify Sirv candidate");
            if (!rc && !skip && br_results_push(out, &result))
                rc = fail(&owned_error, "cannot append Sirv result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static sirv_patterns compiled;
static const char *const keywords[] = {"sirv"};
static const br_detector detector = {
    .type = 725, .name = "Sirv", .custom_name = "",
    .description = "Sirv is a media management service used for image optimization and delivery. Sirv API keys can be used to access and manage media files.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = 1024, .state = &compiled, .scan = scan_sirv,
};

int br_sirv_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Sirv detector output");
    *out = NULL;
    /* Go \S is not ASCII whitespace, including VT. PCRE2 \S excludes VT. */
    if (!compiled.key && br_regex_compile_prefixed(keywords, 1,
            "\\b([^\\t\\n\\f\\r ]{88})", &compiled.key, error))
        return -1;
    if (!compiled.id && br_regex_compile_prefixed(keywords, 1,
            "\\b([a-zA-Z0-9]{26})\\b", &compiled.id, error))
        return -1;
    *out = &detector;
    return 0;
}
