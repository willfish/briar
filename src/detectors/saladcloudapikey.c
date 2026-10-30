/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/saladcloudapikey/saladcloudapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://api.salad.com/api/public";
static const char guide[] = "https://howtorotate.com/docs/tutorials/saladcloudapikey/";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int rotation_guide(br_result *result)
{
    br_json *data = json_object_new_object();
    br_json *value = data ? json_object_new_string(guide) : NULL;
    if (!data || !value || json_object_object_add(data, "rotation_guide", value)) {
        json_object_put(value);
        json_object_put(data);
        return -1;
    }
    result->extra_data = data;
    return 0;
}

static int verify_salad(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) {
        json_object_put(result->extra_data);
        result->extra_data = NULL;
        return set_cause(result, "net/http: nil Context");
    }
    if (key.len >= 256) return -1;
    char value[256];
    memcpy(value, key.data, key.len);
    value[key.len] = '\0';
    const br_header headers[] = {{"Salad-Api-Key", value}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 204) verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    result->verified = verified;
    /* verifyMatch always returns a nil extra-data map, replacing the guide. */
    json_object_put(result->extra_data);
    result->extra_data = NULL;
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_salad(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SaladCloudApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") || rotation_guide(&result))
            rc = fail(&owned_error, "cannot create SaladCloudApiKey result");
        else if (verify && verify_salad(ctx, key, &result))
            rc = fail(&owned_error, "cannot verify SaladCloudApiKey candidate");
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append SaladCloudApiKey result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"salad_cloud_"};
static br_detector detector = {
    .type = 1001, .name = "SaladCloudApiKey", .custom_name = "",
    .description = "SaladCloud is a cloud service provider offering GPUs and NPUs for high-performance computing. SaladCloud API keys can be used to access and modify compute and data resources in your account.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_salad,
};

int br_saladcloudapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SaladCloudApiKey detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile("\\b(salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235})\\b",
                         (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
