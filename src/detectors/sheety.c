/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sheety/sheety.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } sheety_patterns;

static int sheety_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int sheety_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                         br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://api.sheety.co/";
    static const char suffix[] = "/restaurantMenu/menuItems";
    _Static_assert(sizeof(prefix) - 1 + 32 + sizeof(suffix) - 1 == 79, "Sheety URL length");
    *keep = false;
    if (key.len != 64 || id.len != 32) return sheety_fail(error, "invalid Sheety capture");
    char url[80];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, id.data, 32);
    memcpy(url + sizeof(prefix) - 1 + 32, suffix, sizeof(suffix));
    if (!ctx) return 0;
    char authorization[7 + 64 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, 64);
    authorization[71] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int status = response.status;
    br_http_release(ctx, &response);
    free(transport_error);
    if (send_rc == 0) result->verified = status >= 200 && status < 300;
    *keep = true;
    return 0;
}

static int sheety_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sheety_fail(error, "invalid or uninitialized Sheety scan");
    const sheety_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return sheety_fail(error, "uninitialized Sheety patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, &owned_error);
    /* Every key/id pair is kept, including duplicates. Raw and the only secret
     * part are the key. A nil context drops that pair after the URL is built. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            bool keep = true;
            br_slice key = br_captures_at(&keys, k);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = sheety_fail(&owned_error, "cannot create Sheety result");
            else if (verify && sheety_verify(ctx, key, br_captures_at(&ids, i), &result, &keep, &owned_error) != 0)
                rc = -1;
            else if (keep && br_results_push(out, &result) != 0)
                rc = sheety_fail(&owned_error, "cannot append Sheety result");
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

static const char *const sheety_keywords[] = {"sheety"};
static sheety_patterns sheety_compiled;
static br_detector sheety_detector = {
    .type = 469, .version = 0, .name = "Sheety", .custom_name = "",
    .description = "Sheety is a service that allows you to turn Google Sheets into a REST API. Sheety API keys can be used to access and modify the data in your Google Sheets.",
    .keywords = sheety_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &sheety_compiled, .scan = sheety_scan,
};

int br_sheety_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sheety_fail(error, "invalid Sheety detector output");
    *out = NULL;
    if (!sheety_compiled.key &&
        br_regex_compile_prefixed(sheety_keywords, 1, "\\b([0-9a-z]{64})\\b", &sheety_compiled.key, error) != 0)
        return -1;
    if (!sheety_compiled.id &&
        br_regex_compile_prefixed(sheety_keywords, 1, "\\b([0-9a-z]{32})\\b", &sheety_compiled.id, error) != 0)
        return -1;
    *out = &sheety_detector;
    return 0;
}
