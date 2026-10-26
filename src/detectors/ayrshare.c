/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ayrshare/ayrshare.go. */
#include "detectors.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ayrshare_read_email(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    if (name.len != 5 || memcmp(name.data, "email", 5)) return 0;
    br_json **email = user;
    json_object_put(*email);
    /* A later map value replaces the previous email, even null/non-string. */
    *email = json_object_is_type(value, json_type_string) ? json_object_get(value) : NULL;
    return 0;
}

static int ayrshare_enrich_email(br_slice body, br_result *result)
{
    br_json *root = NULL, *email = NULL;
    char *cause = NULL;
    int rc = br_json_document(body, &root, &cause);
    if (!rc && root && json_object_is_type(root, json_type_object)) {
        /* Unmarshal into map[string]any converts every original number to
         * float64, including nested and subsequently overwritten values. */
        rc = br_json_check_float64_numbers(body, &cause);
        if (!rc) rc = br_json_each_member(body, ayrshare_read_email, &email);
        if (!rc && email) {
            result->extra_data = json_object_new_object();
            if (!result->extra_data ||
                json_object_object_add(result->extra_data, "email", email) != 0)
                rc = -1;
            else email = NULL; /* Move the complete string, including NUL bytes. */
        }
    }
    json_object_put(email);
    json_object_put(root);
    free(cause);
    /* Invalid documents, root types and numeric conversions only suppress
     * enrichment; status 200 still verifies. Resource failures remain failures. */
    return rc < 0 ? -1 : 0;
}

static int ayrshare_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[sizeof("Bearer ") + 35];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.ayrshare.com/api/user",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 163,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            /* ReadAll errors precede even a complete, valid response document. */
            if (response.body_error) cause = response.body_error;
            else {
                result->verified = true;
                rc = ayrshare_enrich_email(response.body, result);
            }
            break;
        case 401: break;
        case 403: {
            static const unsigned char invalid_key[] = "API Key not valid";
            if (response.body_error) { cause = response.body_error; break; }
            if (br_slice_find(response.body, (br_slice){invalid_key, sizeof(invalid_key) - 1}, 0)
                != SIZE_MAX) break;
        }
            /* fall through */
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    if (!rc) {
        br_slice secret = {result->raw.data, result->raw.len};
        rc = br_result_set_verification_error(result, cause, &secret, 1);
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int ayrshare_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", ayrshare_verify, error);
}

static const char *const ayrshare_keywords[] = {"ayrshare"};
static br_detector ayrshare_detector = {
    .type = 163, .version = 0, .name = "Ayrshare", .custom_name = "",
    .description = "Ayrshare provides social media management services. "
                   "Ayrshare API keys can be used to manage social media accounts and posts.",
    .keywords = ayrshare_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ayrshare_scan,
};

int br_ayrshare_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Ayrshare detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&ayrshare_detector,
        "\\b([A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8})\\b", error) != 0)
        return -1;
    *out = &ayrshare_detector;
    return 0;
}
