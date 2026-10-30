/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/maxmindlicense v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char rotation_guide[] = "https://howtorotate.com/docs/tutorials/maxmind/";
static const char v1_url[] = "https://geoip.maxmind.com/geoip/v2.1/country/8.8.8.8";
static const char v2_url[] = "https://secret-scanning.maxmind.com/secrets/validate-license-key";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_extra(br_result *result, const char *version, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string(rotation_guide);
    br_json *ver = json_object_new_string(version);
    if (!result->extra_data || !guide || !ver) {
        json_object_put(guide);
        json_object_put(ver);
        return fail(error, "cannot allocate MaxMindLicense metadata");
    }
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        json_object_put(ver);
        return fail(error, "cannot store MaxMindLicense metadata");
    }
    if (json_object_object_add(result->extra_data, "version", ver) != 0) {
        json_object_put(ver);
        return fail(error, "cannot store MaxMindLicense metadata");
    }
    return 0;
}

static int send_v1(const br_scan_ctx *ctx, const char *id, const char *key, br_result *result,
                   char **error)
{
    char *authorization = NULL, *helper_error = NULL;
    /* Basic auth exists only after the constructor succeeds. Helper failure
     * is fatal before send. Do not hand-roll Basic. */
    if (br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                           (br_slice){(const unsigned char *)key, strlen(key)},
                           &authorization, &helper_error) != 0) {
        free(authorization);
        if (helper_error && error && !*error) *error = helper_error;
        else {
            free(helper_error);
            fail(error, "cannot verify MaxMindLicense v1 candidate");
        }
        return -1;
    }
    free(helper_error);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = v1_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 96,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Any 2xx verifies. Body and body_error are not inspected. No setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

typedef struct { br_regex *key, *id; } v1_patterns;

static int scan_v1(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized MaxMindLicense v1 scan");
    const v1_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return fail(error, "uninitialized MaxMindLicense v1 detector");

    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    /* Both FindAll calls run even when verify is set, ctx is NULL, and there
     * are no keys. Any nonzero, including +1, is fatal before a drop. */
    char *key_error = NULL, *id_error = NULL;
    int key_rc = br_captures_find(patterns->key, input, &keys, false, &key_error);
    int id_rc = br_captures_find(patterns->id, input, &ids, false, &id_error);
    int rc = 0;
    if (key_rc != 0) {
        owned_error = key_error;
        free(id_error);
        rc = -1;
    } else if (id_rc != 0) {
        owned_error = id_error;
        free(key_error);
        rc = -1;
    } else {
        free(key_error);
        free(id_error);
    }
    /* Key outer, id inner, source order, no dedupe. Both are required in NoV.
     * The 1024 span is not a distance cap. A 16-digit key is not an id. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = fail(&owned_error, "out of memory creating MaxMindLicense v1 result");
            if (rc == 0) {
                result.redacted = strdup(ids.items[i]);
                if (!result.redacted)
                    rc = fail(&owned_error, "out of memory copying MaxMindLicense account id");
            }
            if (rc == 0) rc = set_extra(&result, "1", &owned_error);
            if (rc == 0 && verify) {
                /* The URL is the constant above. It is not allocated. A nil
                 * context is NewRequestWithContext's "net/http: nil Context". */
                if (!ctx) {
                    br_result_clear(&result);
                    continue;
                }
                if (send_v1(ctx, ids.items[i], keys.items[k], &result, &owned_error) != 0)
                    rc = -1;
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "cannot append MaxMindLicense v1 result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static int finish_v2(const br_scan_ctx *ctx, const char *key, size_t key_len, const char *body,
                     br_result *result)
{
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = v2_url, .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, 12 + key_len},
        .profile = BR_HTTP_SANE, .detector_type = 96,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 204)
        result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* A body read error does not change the status decision. Release once
     * after that decision and before the setter. NULL cause is a no-op. */
    br_http_release(ctx, &response);
    br_slice secret = {(const unsigned char *)key, key_len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    free(transport_error);
    return rc;
}

typedef struct { br_regex *key; } v2_patterns;

static int scan_v2(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized MaxMindLicense v2 scan");
    const v2_patterns *patterns = detector->state;
    if (!patterns->key) return fail(error, "uninitialized MaxMindLicense v2 detector");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Unique exact strings, first-seen source order. Capture runs even when
     * verify is set, ctx is NULL, and there are no keys. */
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating MaxMindLicense v2 result");
        if (rc == 0) rc = set_extra(&result, "2", &owned_error);
        if (rc == 0 && verify) {
            /* Assemble the raw body before the constructor. Do not
             * percent-encode. The URL is constant and is not allocated. */
            if (keys.lengths[i] != 40)
                rc = fail(&owned_error, "invalid MaxMindLicense v2 key");
            else {
                char body[sizeof("license_key=") + 40];
                memcpy(body, "license_key=", 12);
                memcpy(body + 12, keys.items[i], 41);
                br_slice secret = {(const unsigned char *)keys.items[i], 40};
                int setter = 0;
                if (!ctx) {
                    /* verify returns the constructor error. FromData still
                     * sets it and appends. Do not send and do not release. */
                    setter = br_result_set_verification_error(
                        &result, "net/http: nil Context", &secret, 1);
                } else setter = finish_v2(ctx, keys.items[i], 40, body, &result);
                if (setter != 0)
                    rc = fail(&owned_error, "out of memory sanitizing verification error");
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append MaxMindLicense v2 result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static v1_patterns v1_state;
static const char *const v1_keywords[] = {"maxmind", "geoip"};
static const br_detector v1 = {
    .type = 96, .version = 1, .name = "MaxMindLicense", .custom_name = "",
    .description = "MaxMind provides IP intelligence through their GeoIP service which can be used to determine geographical location and other information about an IP address.",
    .keywords = v1_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &v1_state, .scan = scan_v1,
};

static v2_patterns v2_state;
static const char *const v2_keywords[] = {"_mmk"};
static const br_detector v2 = {
    .type = 96, .version = 2, .name = "MaxMindLicense", .custom_name = "",
    .description = "MaxMind provides IP intelligence through its GeoIP databases and services. "
                   "MaxMind license keys are used to access these services and databases.",
    .keywords = v2_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &v2_state, .scan = scan_v2,
};

int br_maxmindlicense_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid MaxMindLicense v1 detector output");
    *out = NULL;
    if (!v1_state.key &&
        br_regex_compile_prefixed(v1_keywords, 2, "\\b([0-9A-Za-z]{16})\\b", &v1_state.key, error) != 0)
        return -1;
    if (!v1_state.id &&
        br_regex_compile_prefixed(v1_keywords, 2, "\\b([0-9]{2,7})\\b", &v1_state.id, error) != 0)
        return -1;
    *out = &v1;
    return 0;
}

int br_maxmindlicense_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid MaxMindLicense v2 detector output");
    *out = NULL;
    if (!v2_state.key &&
        br_regex_compile("\\b([a-zA-Z0-9]{6}_[a-zA-Z0-9]{29}_mmk)\\b", &v2_state.key, error) != 0)
        return -1;
    *out = &v2;
    return 0;
}
