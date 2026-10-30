/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twilioapikey/twilioapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include <json-c/json.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const twilio_keywords[] = {"twilio"};
static const char twilio_url[] = "https://verify.twilio.com/v2/Services";

typedef struct { br_regex *key; br_regex *secret; } twilio_patterns;
typedef struct {
    char *friendly;
    char *account;
    size_t friendly_len;
    size_t account_len;
    size_t len;
    size_t seen;
    bool slot_live;
    bool capture;
    bool ordinary;
} twilio_service;

static int twilio_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void twilio_reset_slot(twilio_service *service)
{
    free(service->friendly);
    free(service->account);
    service->friendly = service->account = NULL;
    service->friendly_len = service->account_len = 0;
    service->len = 0;
    service->seen = 0;
    service->slot_live = false;
    service->capture = false;
}

static int twilio_copy(char **slot, size_t *slot_len, br_slice text)
{
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*slot);
    *slot = copy;
    *slot_len = text.len;
    return 0;
}

static int twilio_string(twilio_service *service, br_json *value, char **slot, size_t *slot_len)
{
    /* Null leaves a string, including a reused first slot, unchanged. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        service->ordinary = true;
        return 0;
    }
    if (!service->capture || !slot || !slot_len) return 0;
    return twilio_copy(slot, slot_len, br_json_text(value));
}

static int twilio_service_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    twilio_service *service = user;
    if (br_json_field_name(name, "friendly_name"))
        return twilio_string(service, value, &service->friendly, &service->friendly_len);
    if (br_json_field_name(name, "account_sid"))
        return twilio_string(service, value, &service->account, &service->account_len);
    if (br_json_field_name(name, "sid")) return twilio_string(service, value, NULL, NULL);
    return 0;
}

static int twilio_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    twilio_service *service = user;
    service->seen = index + 1;
    service->capture = index == 0;
    if (index == 0 && !service->slot_live) {
        free(service->friendly);
        free(service->account);
        service->friendly = service->account = NULL;
        service->friendly_len = service->account_len = 0;
    }
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        service->ordinary = true;
        return 0;
    }
    return br_json_each_member(encoded, twilio_service_member, service);
}

static int twilio_root(void *user, br_slice name, br_json *value, br_slice encoded)
{
    twilio_service *service = user;
    if (!br_json_field_name(name, "services")) return 0;
    /* null and [] replace the slice. A type error must not clear a saved error or the slot. */
    if (!value || json_object_is_type(value, json_type_null)) {
        twilio_reset_slot(service);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) {
        service->ordinary = true;
        return 0;
    }
    service->seen = 0;
    service->capture = false;
    int rc = br_json_each_element(encoded, twilio_element, service);
    if (rc != 0) return rc;
    if (service->seen == 0) {
        twilio_reset_slot(service);
        return 0;
    }
    service->len = service->seen;
    service->slot_live = true;
    return 0;
}

static int twilio_add_len(br_json *object, const char *key, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *text = json_object_new_string_len(value ? value : "", (int)len);
    if (!text || json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static int twilio_extra(br_result *result, br_slice body, char **error)
{
    bool blank = !body.len;
    for (size_t i = 0; !blank && i < body.len; ++i)
        if (body.data[i] != ' ' && body.data[i] != '\t' && body.data[i] != '\r' && body.data[i] != '\n')
            blank = false;
    if (blank) return 0;
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    /* Decoder reads one value. A decode error after status 200 suppresses metadata only. */
    int decoded = br_json_first_document(body, NULL, &root, &end, &cause);
    free(cause);
    if (decoded < 0 || decoded > 1) { json_object_put(root); return -1; }
    if (decoded == 1) { json_object_put(root); return 0; }
    bool object = root && json_object_is_type(root, json_type_object);
    json_object_put(root);
    if (!object) return 0;
    twilio_service service = {0};
    int rc = br_json_each_member((br_slice){body.data, end}, twilio_root, &service);
    if (rc != 0) {
        twilio_reset_slot(&service);
        return -1;
    }
    if (!service.ordinary && service.len > 0 &&
        (twilio_add_len(result->extra_data, "friendly_name", service.friendly, service.friendly_len) != 0 ||
         twilio_add_len(result->extra_data, "account_sid", service.account, service.account_len) != 0))
        rc = twilio_fail(error, "cannot create TwilioApiKey metadata");
    twilio_reset_slot(&service);
    return rc < 0 ? -1 : 0;
}

static int twilio_verify(const br_scan_ctx *ctx, const char *key, const char *secret,
                         br_result *result, char **error)
{
    unsigned char dedup_key[72];
    memcpy(dedup_key, "1011:", 5);
    memcpy(dedup_key + 5, key, 34);
    memcpy(dedup_key + 39, secret, 32);
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, 34},
                           (br_slice){(const unsigned char *)secret, 32},
                           &authorization, error) != 0)
        return twilio_fail(error, "cannot encode TwilioApiKey basic authentication");
    /* NewRequest and Do errors are swallowed. A nil context never reaches send. */
    if (!ctx) { free(authorization); return 0; }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "*/*"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = twilio_url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 1011,
        .dedup_key = {dedup_key, 71},
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int rc = 0;
    /* Status is known before the body is read. A 200 decode or read failure stays verified. */
    if (send_rc == 0 && response.status == 200) {
        result->verified = true;
        if (!response.body_error) rc = twilio_extra(result, response.body, error);
    } else if (send_rc == 0 && response.status != 401 && response.status != 403) {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = twilio_fail(error, "cannot format TwilioApiKey status");
        else if (br_result_set_verification_error(result, status_error, NULL, 0) != 0)
            rc = twilio_fail(error, "cannot set TwilioApiKey verification error");
    }
    free(transport_error);
    free(authorization);
    br_http_release(ctx, &response);
    return rc;
}

static int twilio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const twilio_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->secret || !out ||
        (!input.data && input.len))
        return twilio_fail(error, "invalid or uninitialized TwilioApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            br_result result = {0};
            char redacted[9];
            if (key.len != 34 || secret.len != 32)
                rc = twilio_fail(&owned_error, "invalid TwilioApiKey capture");
            else if (br_finding_key_bytes(&result, 26, key, "key") != 0)
                rc = twilio_fail(&owned_error, "cannot create TwilioApiKey result");
            else {
                result.raw_v2.len = 66;
                result.raw_v2.data = malloc(66);
                memcpy(redacted, secret.data, 5);
                memcpy(redacted + 5, "...", 4);
                result.redacted = strdup(redacted);
                result.extra_data = json_object_new_object();
                br_json *sid = json_object_new_string_len(secrets.items[s], 32);
                if (!result.raw_v2.data || !result.redacted || !result.extra_data || !sid ||
                    json_object_object_add(result.secret_parts, "sid", sid) != 0) {
                    json_object_put(sid);
                    rc = twilio_fail(&owned_error, "cannot create TwilioApiKey result");
                } else {
                    memcpy(result.raw_v2.data, key.data, 34);
                    memcpy(result.raw_v2.data + 34, secret.data, 32);
                    if (verify) rc = twilio_verify(ctx, keys.items[k], secrets.items[s], &result, &owned_error);
                }
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = twilio_fail(&owned_error, "cannot append TwilioApiKey result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector twilio_detector = {
    .type = 1011, .version = 0, .name = "TwilioApiKey", .custom_name = "",
    .description = "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs.",
    .keywords = twilio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = twilio_scan,
};

int br_twilioapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return twilio_fail(error, "invalid TwilioApiKey detector output");
    *out = NULL;
    if (!twilio_detector.state) {
        twilio_patterns *patterns = calloc(1, sizeof(*patterns));
        if (!patterns) return twilio_fail(error, "out of memory compiling TwilioApiKey patterns");
        if (br_regex_compile("\\b(SK[a-zA-Z0-9]{32})\\b", &patterns->key, error) != 0 ||
            br_regex_compile("\\b([0-9a-zA-Z]{32})\\b", &patterns->secret, error) != 0) {
            br_regex_free(patterns->key);
            br_regex_free(patterns->secret);
            free(patterns);
            return -1;
        }
        twilio_detector.state = patterns;
    }
    *out = &twilio_detector;
    return 0;
}
