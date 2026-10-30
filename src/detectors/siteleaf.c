/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Siteleaf, from pinned TruffleHog pkg/detectors/siteleaf/siteleaf.go.
 * The key and id patterns are the same expression, so every match is paired
 * with every match, including itself. Only the key is stored. Basic auth is id:key.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.siteleaf.com/v2/sites";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *auth, br_result *result, char **error)
{
    (void)error;
    if (!ctx) return 1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .timeout_ms = 5000, .detector_type = 263, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Siteleaf scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t k = 0; !rc && k < found.len; ++k) {
        for (size_t i = 0; !rc && i < found.len; ++i) {
            br_result result = {0};
            char *auth = NULL;
            int outcome = 0;
            if (br_finding_key(&result, detector->type, found.items[k], "key") != 0)
                rc = fail(&owned, "cannot create Siteleaf finding");
            else if (verify_requested &&
                     br_http_basic_auth((br_slice){(const unsigned char *)found.items[i], strlen(found.items[i])},
                                        (br_slice){(const unsigned char *)found.items[k], strlen(found.items[k])},
                                        &auth, &owned) != 0)
                rc = -1;
            else if (verify_requested && (outcome = verify(ctx, auth, &result, &owned)) < 0)
                rc = -1;
            else if (!outcome && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Siteleaf finding");
            free(auth);
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Siteleaf", .type = 263, .description =
        "Siteleaf is a content management system (CMS) designed for managing websites. Siteleaf API keys can be used to access and modify site content and settings.",
    .keywords = (const char *[]){"siteleaf", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_siteleaf_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Siteleaf detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([0-9Aa-z]{32})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
