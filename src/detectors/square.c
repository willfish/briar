/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/square/square.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool has_square(br_slice input)
{
    static const char word[] = "square";
    for (size_t i = 0; i + 6 <= input.len; ++i) {
        size_t j = 0;
        for (; j < 6; ++j) {
            unsigned char c = input.data[i + j];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            if (c != (unsigned char)word[j]) break;
        }
        if (j == 6) return true;
    }
    return false;
}

static int rotation(br_result *result)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/square/");
    if (!result->extra_data || !guide || json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return -1;
    }
    return 0;
}

static int verify_square(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[80];
    int n = snprintf(auth, sizeof(auth), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    if (!ctx) return 1;
    const br_header headers[] = {{"Authorization", auth}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = "https://connect.squareupsandbox.com/v2/merchants",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    /* 200 and 403 both verify. Every other status and every Do error is
     * swallowed, including 401. The body is closed and ignored. */
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status == 200 || response.status == 403;
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_square(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Square scan");
    if (!has_square(input)) return 0;
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0 || rotation(&result) != 0)
            rc = fail(error, "out of memory creating Square result");
        else if (verify) {
            int checked = verify_square(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct Square Authorization header");
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending Square result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"EAAA"};
static br_detector square = {
    .type = 14, .version = 0, .name = "Square", .custom_name = "",
    .description = "Square is a financial services and mobile payment company. Square API keys can be used to access and manage payments, transactions, and other financial data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_square,
};

int br_square_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Square detector output");
    *out = NULL;
    const char *const prefix[] = {"square"};
    br_regex *pattern = NULL;
    if (br_regex_compile_prefixed(prefix, 1, "(EAAA[a-zA-Z0-9\\-_+=]{60})", &pattern, error) != 0) {
        br_regex_free(pattern);
        return -1;
    }
    square.state = pattern;
    *out = &square;
    return 0;
}
