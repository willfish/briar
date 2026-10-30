/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/uclassify/uclassify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_uclassify(const br_scan_ctx *ctx, const char *key, br_slice body, br_result *result)
{
    char authorization[24];
    int n = snprintf(authorization, sizeof(authorization), "Token %s", key);
    if (n != 18) return;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.uclassify.com/v1/uClassify/Sentiment/classify",
        .headers = headers, .nheaders = 2, .body = body, .profile = BR_HTTP_SANE, .detector_type = 871,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_uclassify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    static const unsigned char payload[] = "{\"texts\":[\"I am so happy today\"]}";
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Uclassify scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        br_slice body = {payload, sizeof(payload) - 1};
        if (key.len != 12) rc = fail(&owned, "invalid Uclassify capture");
        else if (br_finding_key_bytes(&result, 871, key, "key") != 0)
            rc = fail(&owned, "cannot create Uclassify result");
        else if (verify) {
            /* The JSON payload exists before NewRequestWithContext's nil-context skip. */
            if (body.len != 33) rc = fail(&owned, "invalid Uclassify payload");
            else if (!ctx) skip = true;
            else verify_uclassify(ctx, keys.items[i], body, &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Uclassify result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"uclassify"};
static br_detector uclassify = {
    .type = 871, .version = 0, .name = "Uclassify", .custom_name = "",
    .description = "Uclassify is a text classification service. Uclassify API keys can be used to "
                   "classify text into various categories such as sentiment, topic, etc.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_uclassify,
};

int br_uclassify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Uclassify detector output");
    *out = NULL;
    if (!uclassify.state) {
        static const char *const prefixes[] = {"uclassify"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([a-z0-9A-Z]{12})\\b", &compiled, error) != 0)
            return -1;
        uclassify.state = compiled;
    }
    *out = &uclassify;
    return 0;
}
