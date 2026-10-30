/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nutritionix/nutritionix.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const char nutritionix_body[] =
    "{\"query\":\"for breakfast i ate 2 eggs, bacon, and french toast\",\"timezone\":\"US/Eastern\"}";
static const char nutritionix_url[] = "https://trackapi.nutritionix.com/v2/natural/nutrients";

typedef struct {
    br_regex *key, *id;
} nutritionix_patterns;

enum { NUT_KEEP = 0, NUT_DROP = 1, NUT_FATAL = -1 };

static int nutritionix_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return NUT_FATAL;
}

/* The constant body exists before NewRequestWithContext. Nil context drops
 * this pair only. Do and close errors stay unpublished. */
static int nutritionix_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                              br_result *result, char **error)
{
    if (key.len != 32 || id.len != 8) return nutritionix_fail(error, "invalid Nutritionix capture");
    if (!ctx) return NUT_DROP;
    char app_id[9], app_key[33];
    memcpy(app_id, id.data, 8);
    app_id[8] = '\0';
    memcpy(app_key, key.data, 32);
    app_key[32] = '\0';
    /* Header.Add canonicalizes x-app-id and x-app-key. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-App-Id", app_id},
        {"X-App-Key", app_key},
    };
    const br_http_request request = {
        .method = "POST", .url = nutritionix_url, .headers = headers, .nheaders = 3,
        .body = {(const unsigned char *)nutritionix_body, sizeof(nutritionix_body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return NUT_KEEP;
}

static int nutritionix_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const nutritionix_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->id || !out ||
        (!input.data && input.len))
        return nutritionix_fail(error, "invalid or uninitialized Nutritionix scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    /* Duplicates remain. Neither side alone is a finding. Id is not stored. */
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice id = br_captures_at(&ids, i);
            int outcome = NUT_KEEP;
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                outcome = nutritionix_fail(&owned_error, "cannot create Nutritionix result");
            else if (verify)
                outcome = nutritionix_verify(ctx, key, id, &result, &owned_error);
            if (outcome == NUT_FATAL) rc = -1;
            if (outcome == NUT_DROP) {
                br_result_clear(&result);
                continue;
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = nutritionix_fail(&owned_error, "cannot append Nutritionix result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const nutritionix_keywords[] = {"nutritionix"};
static const char *const nutritionix_prefix[] = {"nutritionix"};
static nutritionix_patterns nutritionix_state;
static br_detector nutritionix_detector = {
    .type = 364, .version = 0, .name = "Nutritionix", .custom_name = "",
    .description = "Nutritionix provides a food tracking API. The API keys can be used to access and log nutritional data.",
    .keywords = nutritionix_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = nutritionix_scan,
};

int br_nutritionix_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nutritionix_fail(error, "invalid Nutritionix detector output");
    *out = NULL;
    if (!nutritionix_state.key &&
        br_regex_compile_prefixed(nutritionix_prefix, 1, "\\b([a-z0-9]{32})\\b",
                                  &nutritionix_state.key, error) != 0)
        return -1;
    if (!nutritionix_state.id &&
        br_regex_compile_prefixed(nutritionix_prefix, 1, "\\b([a-z0-9]{8})\\b",
                                  &nutritionix_state.id, error) != 0)
        return -1;
    nutritionix_detector.state = &nutritionix_state;
    *out = &nutritionix_detector;
    return 0;
}
