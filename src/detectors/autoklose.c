/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/autoklose/autoklose.go. */
#include "detectors.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_email(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    if (name.len != 5 || memcmp(name.data, "email", 5)) return 0;
    br_json **email = user;
    json_object_put(*email);
    /* Map entries replace previous values, including null and non-strings. */
    *email = json_object_is_type(value, json_type_string) ? json_object_get(value) : NULL;
    return 0;
}

/* Own *email (string or NULL) and *cause. 0 success, 1 decode cause, -1 resource
 * failure. Root type errors precede float conversion, as in Unmarshal(&map). */
static int decode_me(br_slice body, br_json **email, char **cause)
{
    *email = NULL;
    br_json *root = NULL;
    int rc = br_json_document(body, &root, cause);
    if (!rc && root && !json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, "map[string]interface {}", cause) == 0 ? 1 : -1;
    } else if (!rc && root) {
        rc = br_json_check_float64_numbers(body, cause);
        if (!rc) rc = br_json_each_member(body, read_email, email);
    }
    json_object_put(root);
    if (rc) { json_object_put(*email); *email = NULL; }
    return rc;
}

static int verify_autoklose(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128];
    snprintf(url, sizeof(url), "https://api.autoklose.com/api/me/?api_token=%s", key);
    const br_header headers[] = {{"Accept", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 323,
    };
    br_http_response response = {0};
    br_json *email = NULL;
    char *error = NULL, *decode_cause = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            /* ReadAll errors win even when a complete document was received. */
            if (response.body_error) cause = response.body_error;
            else {
                int decoded = decode_me(response.body, &email, &decode_cause);
                if (decoded < 0) rc = -1;
                else if (decoded > 0) cause = decode_cause;
                else {
                    if (email) {
                        result->extra_data = json_object_new_object();
                        if (!result->extra_data || json_object_object_add(result->extra_data, "email", email) != 0) rc = -1;
                        else email = NULL; /* Moved, including empty/embedded-NUL strings. */
                    }
                    if (!rc) result->verified = true;
                }
            }
            break;
        case 401: break;
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
    json_object_put(email);
    free(decode_cause);
    free(error);
    return rc;
}

static int scan_autoklose(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_autoklose, error);
}

static const char *const keywords[] = {"autoklose"};
static br_detector autoklose = {
    .type = 323, .version = 0, .name = "Autoklose", .custom_name = "",
    .description = "Autoklose is a sales automation tool that allows users to streamline their email outreach and follow-up processes. "
                   "Autoklose API tokens can be used to access and manage campaigns, contacts, and other related data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_autoklose,
};

int br_autoklose_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Autoklose detector output");
        return -1;
    }
    *out = NULL;
    if (!autoklose.state && br_key_pattern_init(&autoklose, "\\b([a-zA-Z0-9-]{32})\\b", error) != 0) return -1;
    *out = &autoklose;
    return 0;
}
