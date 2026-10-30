/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/screenshotapi/screenshotapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char screenshot_prefix[] = "https://shot.screenshotapi.net/screenshot?token=";
static const char screenshot_suffix[] = "&url=https://google.com&width=1920&height=1080";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

typedef struct {
    char *text;
    size_t len;
    char *cause;
    int failed;
    int rc;
} screenshot_field;

static int screenshot_type_cause_real(br_json *value, char **cause)
{
    return br_json_type_cause(value, "response.screenshot", "string", cause);
}

static int (*screenshot_type_cause)(br_json *, char **) = screenshot_type_cause_real;

static int screenshot_keep(screenshot_field *out, char *cause, int typed)
{
    if (typed < 0) { free(cause); out->rc = -1; return -1; }
    if (typed > 0 || cause) {
        if (!out->failed) { out->failed = 1; out->cause = cause; out->rc = 1; }
        else free(cause);
        return 0;
    }
    free(cause);
    return 0;
}

static int screenshot_member(void *user, br_slice name, br_json *field, br_slice encoded)
{
    (void)encoded;
    screenshot_field *out = user;
    if (!br_json_field_name(name, "screenshot")) return 0;
    enum json_type kind = json_object_get_type(field);
    /* encoding/json ignores null for a string, so a prior value stays. */
    if (kind == json_type_null) return 0;
    if (kind != json_type_string) {
        char *cause = NULL;
        int typed = screenshot_type_cause(field, &cause);
        return screenshot_keep(out, cause, typed);
    }
    br_slice bytes = br_json_text(field);
    char *copy = malloc(bytes.len + 1);
    if (!copy) { out->rc = -1; return -1; }
    memcpy(copy, bytes.data, bytes.len);
    copy[bytes.len] = '\0';
    free(out->text);
    out->text = copy;
    out->len = bytes.len;
    return 0;
}

static int screenshot_text(br_slice body, const char *read_error, char **text, size_t *text_len,
                              char **cause)
{
    if (text_len) *text_len = 0;
    br_json *value = NULL;
    size_t end = 0;
    int decoded = br_json_first_document(body, read_error, &value, &end, cause);
    if (decoded < 0 || decoded > 1) { json_object_put(value); return -1; }
    if (decoded == 1) { json_object_put(value); return 1; }
    if (!value || json_object_get_type(value) == json_type_null) {
        json_object_put(value);
        *text = strdup("");
        return *text ? 0 : -1;
    }
    if (json_object_get_type(value) != json_type_object) {
        int typed = br_json_type_cause(value, NULL, "screenshotapi.response", cause);
        json_object_put(value);
        return typed == 0 ? 1 : -1;
    }
    json_object_put(value);
    screenshot_field found = {0};
    int walked = br_json_each_member((br_slice){body.data, end}, screenshot_member, &found);
    if (walked != 0 || found.rc < 0) { free(found.text); free(found.cause); return -1; }
    if (found.rc > 0) { free(found.text); *cause = found.cause; return 1; }
    if (!found.text) {
        *text = strdup("");
        return *text ? 0 : -1;
    }
    *text = found.text;
    if (text_len) *text_len = found.len;
    return 0;
}

static int verify_screenshot(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[sizeof(screenshot_prefix) + 31 + sizeof(screenshot_suffix)];
    memcpy(url, screenshot_prefix, sizeof(screenshot_prefix) - 1);
    memcpy(url + sizeof(screenshot_prefix) - 1, key, 31);
    memcpy(url + sizeof(screenshot_prefix) - 1 + 31, screenshot_suffix, sizeof(screenshot_suffix));
    if (!ctx) return 1;
    /* Source mutates the shared sane client's timeout to 10s. The request
     * carries that timeout; this process does not mutate other detectors. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = 451,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (sent != 0) {
        br_http_release(ctx, &response);
        return 0;
    }
    char *shot = NULL, *cause = NULL;
    size_t shot_len = 0;
    int decoded = screenshot_text(response.body, response.body_error, &shot, &shot_len, &cause);
    if (decoded < 0) {
        br_http_release(ctx, &response);
        free(shot); free(cause);
        return fail(error, "cannot decode ScreenshotAPI response");
    }
    if (decoded > 0) {
        br_slice secret = {(const unsigned char *)key, strlen(key)};
        int rc = br_result_set_verification_error(result, cause, &secret, 1);
        free(cause); free(shot);
        br_http_release(ctx, &response);
        if (rc) return fail(error, "cannot record ScreenshotAPI verification error");
        return 1; /* Decode failure drops the finding after the setter. */
    }
    free(cause);
    if (response.status >= 200 && response.status < 300 && shot_len > 0) result->verified = true;
    free(shot);
    br_http_release(ctx, &response);
    return 0;
}

static int scan_screenshot(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ScreenshotAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        if (br_captures_at(&keys, i).len != 31) { rc = fail(error, "invalid ScreenshotAPI capture"); break; }
        br_result result = {0};
        int drop = 0;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = fail(error, "out of memory creating ScreenshotAPI result");
        else if (verify) drop = verify_screenshot(ctx, keys.items[i], &result, error);
        if (rc == 0 && drop < 0) rc = -1;
        else if (rc == 0 && drop == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append ScreenshotAPI result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const screenshot_keywords[] = {"screenshotapi"};
static br_detector screenshot_detector = {
    .type = 451, .version = 0, .name = "ScreenshotAPI", .custom_name = "",
    .description = "A service for taking screenshots of websites. Websites can include internal or sensitive websites, API keys can access the screenshots.",
    .keywords = screenshot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_screenshot,
};

int br_screenshotapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ScreenshotAPI detector output");
    *out = NULL;
    if (br_key_pattern_init(&screenshot_detector,
            "\\b([0-9A-Z]{7}\\-[0-9A-Z]{7}\\-[0-9A-Z]{7}\\-[0-9A-Z]{7})\\b", error) != 0)
        return -1;
    *out = &screenshot_detector;
    return 0;
}
