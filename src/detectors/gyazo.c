/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gyazo/gyazo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int gyazo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the source request constructor's nil-context skip. */
static bool gyazo_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://api.gyazo.com/api/images?access_token=";
    char url[sizeof(prefix) + 43];
    /* Construct the complete literal URL before the context-bound constructor.
     * The capture is exactly 43 ASCII bytes, with no escaping or normalization. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 43);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) return false;

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The whole shared setup/allocation/Do failure domain is false-kept.
     * Only status matters; body bytes and read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Retain only the provider's original URL through release, not the shared
     * adapter's temporary effective request, headers or synthesized UA. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int gyazo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gyazo_fail(error, "invalid or uninitialized Gyazo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace cannot alter this grammar. Keep original occurrences,
         * including duplicates and boundary-dependent leading/trailing '-'. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = gyazo_fail(&owned_error, "cannot create Gyazo result");
        if (rc == 0 && verify) keep = gyazo_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = gyazo_fail(&owned_error, "cannot append Gyazo result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const gyazo_keywords[] = {"gyazo"};
static br_detector gyazo_detector = {
    .type = 467, .version = 0, .name = "Gyazo", .custom_name = "",
    .description = "Gyazo is an image sharing service. Gyazo access tokens can be used to access and manage images stored in a Gyazo account.",
    .keywords = gyazo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = gyazo_scan,
};

int br_gyazo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gyazo_fail(error, "invalid Gyazo detector output");
    *out = NULL;
    if (!gyazo_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(gyazo_keywords, 1,
                "\\b([0-9A-Za-z-]{43})\\b", &regex, error) != 0)
            return -1;
        gyazo_detector.state = regex;
    }
    *out = &gyazo_detector;
    return 0;
}
