/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/harvest/harvest.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } harvest_patterns;

static int harvest_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source request constructor's nil-context skip. */
static bool harvest_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                           br_result *result)
{
    static const char prefix[] = "https://api.harvestapp.com/v2/users/me?access_token=";
    static const char account[] = "&account_id=";
    char url[sizeof(prefix) - 1 + 97 + sizeof(account) - 1 + 9 + 1];
    /* Both captures are grammar-bounded ASCII. Complete the literal URL before
     * the context-bound constructor; no allocation, escaping or normalization. */
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, key.data, key.len);
    at += key.len;
    memcpy(url + at, account, sizeof(account) - 1);
    at += sizeof(account) - 1;
    memcpy(url + at, id.data, id.len);
    url[at + id.len] = '\0';
    if (!ctx) return false;

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The entire shared setup/Do error domain is false-kept, without a setter.
     * All successful-send 2xx statuses verify; bodies/read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider URL and captures survive release. Ordinary shared effective
     * request/header/UA storage ends at send return, not at release. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int harvest_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return harvest_fail(error, "invalid or uninitialized Harvest scan");
    const harvest_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return harvest_fail(error, "uninitialized Harvest patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent occurrence sets, not unique credentials or nearby pairs.
     * The multipart span is an engine hint, never a direct-scanner limit. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            /* TrimSpace cannot alter these captures. ID is required but hidden. */
            br_slice key = br_captures_at(&keys, k);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = harvest_fail(&owned_error, "cannot create Harvest result");
            bool keep = true;
            if (rc == 0 && verify)
                keep = harvest_verify(ctx, key, br_captures_at(&ids, i), &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = harvest_fail(&owned_error, "cannot append Harvest result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static harvest_patterns harvest_compiled;
static const char *const harvest_keywords[] = {"harvest"};
static const br_detector harvest_detector = {
    .type = 260, .version = 0, .name = "Harvest", .custom_name = "",
    .description = "Harvest is a time tracking and invoicing software. Harvest API keys can be used to access and manage time tracking data and invoices.",
    .keywords = harvest_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &harvest_compiled, .scan = harvest_scan,
};

int br_harvest_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return harvest_fail(error, "invalid Harvest detector output");
    *out = NULL;
    if (!harvest_compiled.key && br_regex_compile_prefixed(harvest_keywords, 1,
            "\\b([a-z0-9A-Z._]{97})\\b", &harvest_compiled.key, error) != 0) return -1;
    if (!harvest_compiled.id && br_regex_compile_prefixed(harvest_keywords, 1,
            "\\b([0-9]{4,9})\\b", &harvest_compiled.id, error) != 0) return -1;
    *out = &harvest_detector;
    return 0;
}
