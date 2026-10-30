/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twilio/twilio.go.
 * The source client is deduplicated RetryableHTTPClient. Borrowed transports
 * reject that profile before send; a Do error is swallowed. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *sid, *key; } twilio_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int add_text_len(br_json *object, const char *name, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value ? value : "", (int)len);
    if (!part || json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int add_text(br_json *object, const char *name, const char *value)
{
    return add_text_len(object, name, value, value ? strlen(value) : 0);
}

static int make_twilio(br_result *result, const char *sid, const char *key)
{
    if (br_finding_pair(result, 26, sid, "sid", key, "key") != 0) return -1;
    /* Pair helper names the first part "sid" and stores Raw as the SID.
     * Source RawV2 is sid+key with no separator, which that helper already builds. */
    result->redacted = strdup(sid);
    result->extra_data = json_object_new_object();
    if (!result->redacted || !result->extra_data) return -1;
    return add_text(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/twilio/");
}

typedef struct {
    char *friendly, *account;
    size_t friendly_len, account_len;
    bool have_first, ordinary;
    char *cause;
} twilio_proj;

typedef struct { twilio_proj *proj; bool capture; } twilio_elem;

static int twilio_replace(char **slot, size_t *len, br_slice text)
{
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*slot);
    *slot = copy;
    *len = text.len;
    return 0;
}

/* First ordinary text sticks, including a NULL diagnostic. Later helpers still run. */
static int twilio_note(twilio_proj *proj, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!proj->ordinary) {
        proj->ordinary = true;
        proj->cause = next;
    } else free(next);
    return 0;
}

static int twilio_string(twilio_proj *proj, br_json *value, char **slot, bool capture, const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return twilio_note(proj, value, field, "string");
    if (!capture) return 0;
    size_t *len = slot == &proj->friendly ? &proj->friendly_len : &proj->account_len;
    return twilio_replace(slot, len, br_json_text(value));
}

static int twilio_service_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    twilio_elem *elem = user;
    twilio_proj *proj = elem->proj;
    if (br_json_field_name(name, "friendly_name"))
        return twilio_string(proj, value, &proj->friendly, elem->capture, "service.services.friendly_name");
    if (br_json_field_name(name, "sid"))
        return twilio_string(proj, value, NULL, false, "service.services.sid");
    if (br_json_field_name(name, "account_sid"))
        return twilio_string(proj, value, &proj->account, elem->capture, "service.services.account_sid");
    return 0;
}

static void twilio_reset_slot(twilio_proj *proj)
{
    free(proj->friendly); free(proj->account);
    proj->friendly = proj->account = NULL;
    proj->friendly_len = proj->account_len = 0;
    proj->have_first = false;
}

static int twilio_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    twilio_proj *proj = user;
    if (index == 0) {
        twilio_reset_slot(proj);
        proj->have_first = true;
    }
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return twilio_note(proj, value, "serviceResponse.services", "twilio.service");
    twilio_elem elem = {proj, index == 0};
    return br_json_each_member(encoded, twilio_service_member, &elem);
}

static int twilio_root(void *user, br_slice name, br_json *value, br_slice encoded)
{
    twilio_proj *proj = user;
    if (!br_json_field_name(name, "services")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        twilio_reset_slot(proj);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array))
        return twilio_note(proj, value, "serviceResponse.services", "[]twilio.service");
    /* Stage the last slice. A failed walk must not discard the committed first slot. */
    twilio_proj stage = *proj;
    stage.friendly = stage.account = NULL;
    stage.friendly_len = stage.account_len = 0;
    stage.have_first = false;
    int rc = br_json_each_element(encoded, twilio_element, &stage);
    proj->ordinary = stage.ordinary;
    proj->cause = stage.cause;
    if (rc != 0) { twilio_reset_slot(&stage); return rc; }
    twilio_reset_slot(proj);
    proj->friendly = stage.friendly;
    proj->account = stage.account;
    proj->friendly_len = stage.friendly_len;
    proj->account_len = stage.account_len;
    proj->have_first = stage.have_first;
    return 0;
}

static void twilio_proj_clear(twilio_proj *proj)
{
    free(proj->friendly); free(proj->account); free(proj->cause);
}

/* 0 keeps the finding verified. Document +1 is ordinary and drops service fields.
 * Document +2 and any visitor nonzero are fatal, even after a saved type error. */
static int copy_service(br_json *extra, br_slice body, const char *read_error)
{
    br_json *document = NULL;
    size_t end = 0;
    char *cause = NULL;
    int decoded = br_json_first_document(body, read_error, &document, &end, &cause);
    if (decoded < 0 || decoded > 1) { json_object_put(document); free(cause); return -1; }
    if (decoded == 1) { json_object_put(document); free(cause); return 0; }
    free(cause);
    twilio_proj proj = {0};
    int walked = 0;
    if (document && json_object_is_type(document, json_type_null)) {
        /* JSON null is a zero serviceResponse. */
    } else if (document && !json_object_is_type(document, json_type_object)) {
        if (twilio_note(&proj, document, NULL, "twilio.serviceResponse") != 0) walked = -1;
    } else if (document) {
        walked = br_json_each_member((br_slice){body.data, end}, twilio_root, &proj);
    }
    json_object_put(document);
    if (walked != 0) { twilio_proj_clear(&proj); return -1; }
    int rc = 0;
    if (!proj.ordinary && proj.have_first) {
        rc = add_text_len(extra, "friendly_name", proj.friendly, proj.friendly_len);
        if (!rc) rc = add_text_len(extra, "account_sid", proj.account, proj.account_len);
    }
    twilio_proj_clear(&proj);
    return rc;
}

static int verify_twilio(const br_scan_ctx *ctx, const char *sid, const char *key,
                         br_result *result, char **error)
{
    /* Constructor failure is swallowed: unverified, no setter, guide retained. */
    if (!ctx) return 0;
    char *auth = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)sid, strlen(sid)},
                           (br_slice){(const unsigned char *)key, strlen(key)}, &auth, error) != 0)
        return -1;
    unsigned char dedup[80];
    int dedup_len = snprintf((char *)dedup, sizeof(dedup), "26:%s%s", sid, key);
    if (dedup_len < 0 || (size_t)dedup_len >= sizeof(dedup)) { free(auth); return fail(error, "Twilio dedup key too large"); }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "*/*"},
        {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://verify.twilio.com/v2/Services",
        .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_RETRYABLE, .detector_type = 26,
        .dedup_key = {dedup, (size_t)dedup_len},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* DoWithDedup errors, including the borrowed retryable/dedup guard, are swallowed. */
    } else if (response.status == 200) {
        result->verified = true;
        if (copy_service(result->extra_data, response.body, response.body_error) != 0)
            rc = fail(error, "out of memory copying Twilio service metadata");
    } else if (response.status != 401 && response.status != 403) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* No secrets are passed, so the status text is not redacted. */
    if (!rc && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = fail(error, "out of memory recording Twilio verification error");
    br_http_release(ctx, &response);
    free(send_error);
    free(auth);
    return rc;
}

static int scan_twilio(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Twilio scan");
    const twilio_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures sids = {0}, keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned);
    if (!rc) rc = br_captures_find(patterns->sid, input, &sids, true, &owned);
    for (size_t s = 0; !rc && s < sids.len; ++s) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            br_result result = {0};
            if (make_twilio(&result, sids.items[s], keys.items[k]) != 0 ||
                (verify && verify_twilio(ctx, sids.items[s], keys.items[k], &result, &owned) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(&owned, "out of memory creating Twilio result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&sids);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sid", "twilio"};
static twilio_patterns patterns;
static br_detector twilio = {
    .type = 26, .version = 0, .name = "Twilio", .custom_name = "",
    .description = "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_twilio,
};

int br_twilio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Twilio detector output");
    *out = NULL;
    if (!patterns.sid && br_regex_compile("\\b(AC[0-9a-f]{32})\\b", &patterns.sid, error) != 0) return -1;
    if (!patterns.key && br_regex_compile("\\b([0-9a-f]{32})\\b", &patterns.key, error) != 0) return -1;
    *out = &twilio;
    return 0;
}
