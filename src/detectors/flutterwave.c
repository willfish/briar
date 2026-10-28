/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flutterwave/flutterwave.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int flutterwave_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void flutterwave_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Constructor's known nil-context skip has passed. Complete bounded Bearer
     * value: 7 + KEY42 + NUL, no formatter/encoder/heap copy or artificial cap. */
    char authorization[50];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 43);
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.flutterwave.com/v3/subaccounts", .profile = BR_HTTP_SANE,
        .headers = &header, .nheaders = 1, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding without setter/classifier. All successful-send 2xx verify;
     * response contents and read errors are deliberately ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Full stack authorization lives through send AND release. Source scan-
     * defers Close; ABI1 eagerly reads/releases owned responses even failures.
     * Reader/native/private client/regexp and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int flutterwave_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flutterwave_fail(error, "invalid or uninitialized Flutterwave scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Original occurrences/duplicates, not validated
         * hex or normalized prefixes. Owned finding resources precede the
         * constructor's ordinary nil-context skip; no filtering/cache. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = flutterwave_fail(&owned_error, "cannot create Flutterwave result");
        else if (!verify || ctx) {
            if (verify) flutterwave_verify(ctx, keys.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = flutterwave_fail(&owned_error, "cannot append Flutterwave result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const flutterwave_keywords[] = {"FLWSECK-"};
static br_detector flutterwave_detector = {
    .type = 173, .version = 0, .name = "Flutterwave", .custom_name = "",
    .description = "Flutterwave is a payment technology company providing seamless and secure payment solutions for businesses. Flutterwave API keys can be used to access and manage payment services and transactions.",
    .keywords = flutterwave_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = flutterwave_scan,
};

int br_flutterwave_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flutterwave_fail(error, "invalid Flutterwave detector output");
    *out = NULL;
    if (!flutterwave_detector.state) {
        /* DIRECT case-sensitive extraction. Dispatch prefilter folding never
         * licenses changing the source's uppercase prefix/suffix or body class. */
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(FLWSECK-[0-9a-z]{32}-X)\\b", &pattern, error) != 0) return -1;
        flutterwave_detector.state = pattern;
    }
    *out = &flutterwave_detector;
    return 0;
}
