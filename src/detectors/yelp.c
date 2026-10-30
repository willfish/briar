/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/yelp/yelp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_yelp(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[160];
    int n = snprintf(auth, sizeof(auth), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    if (!ctx) return 1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.yelp.com/v3/businesses/search?term=delis&latitude=37.786882&longitude=-122.399972",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc == 0 ? 0 : -1;
}

static int scan_yelp(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Yelp scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(error, "out of memory creating Yelp result");
        else if (verify) {
            int checked = verify_yelp(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct Yelp Authorization header");
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Yelp result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"yelp"};
static br_detector yelp = {
    .type = 799, .version = 0, .name = "Yelp", .custom_name = "",
    .description = "Yelp API keys allow access to Yelp's business data and services. Unauthorized access can lead to data breaches and misuse of Yelp's services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_yelp,
};

int br_yelp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Yelp detector output");
    *out = NULL;
    /* Go raw class keeps a literal backslash plus '=', '.' and '-'. */
    if (br_key_pattern_init(&yelp, "\\b([a-zA-Z0-9_\\\\=\\.\\-]{128})\\b", error) != 0) return -1;
    *out = &yelp;
    return 0;
}
