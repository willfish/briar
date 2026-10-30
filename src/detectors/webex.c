/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/webex/webex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>

static const char *const webex_keywords[] = {"webex"};
static const char webex_url[] = "https://webexapis.com/v1/access_token";
static const char webex_prefix[] =
    "grant_type=authorization_code&code=362ad374-735c-4f69-aa8e-bf384f8602de&client_id=";
static const char webex_middle[] = "&client_secret=";
static const char webex_suffix[] = "&redirect_uri=http%3A%2F%2Flocalhost.com%2Fb";

typedef struct { br_regex *key; br_regex *id; br_regex *mismatch; } webex_patterns;

static int webex_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int webex_mark(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups;
    (void)ngroups;
    *(bool *)user = true;
    return 0;
}

typedef struct {
    char *message;
    size_t message_len;
    bool ordinary;
    char *cause;
} webex_msg;

static const char webex_message_type[] = "struct { Message string \"json:\\\"message\\\"\" }";

static int webex_note(webex_msg *msg, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!msg->ordinary) {
        msg->ordinary = true;
        msg->cause = next;
    } else free(next);
    return 0;
}

static int webex_copy_message(webex_msg *msg, br_slice text)
{
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(msg->message);
    msg->message = copy;
    msg->message_len = text.len;
    return 0;
}

static int webex_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    webex_msg *msg = user;
    if (!br_json_field_name(name, "message")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return webex_note(msg, value, ".message", "string");
    return webex_copy_message(msg, br_json_text(value));
}

static void webex_msg_clear(webex_msg *msg)
{
    free(msg->message);
    free(msg->cause);
}

static int webex_verify(const br_scan_ctx *ctx, const webex_patterns *patterns,
                        const char *key, const char *id, br_result *result, bool *keep, char **error)
{
    char body[sizeof(webex_prefix) + 65 + sizeof(webex_middle) + 64 + sizeof(webex_suffix)];
    size_t at = sizeof(webex_prefix) - 1;
    memcpy(body, webex_prefix, at);
    memcpy(body + at, id, 65); at += 65;
    memcpy(body + at, webex_middle, sizeof(webex_middle) - 1); at += sizeof(webex_middle) - 1;
    memcpy(body + at, key, 64); at += 64;
    memcpy(body + at, webex_suffix, sizeof(webex_suffix));
    at += sizeof(webex_suffix) - 1;
    *keep = false;
    /* Complete form body before the nil-context continue. Each call uses a new Sane client. */
    if (!ctx) return 0;
    *keep = true;
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = webex_url, .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, at},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    free(transport_error);
    if (send_rc == 0 && !response.body_error) {
        br_json *root = NULL;
        char *cause = NULL;
        int decoded = br_json_document(response.body, &root, &cause);
        /* Only document +1 is an ordinary ignored unmarshal error. */
        if (decoded < 0 || decoded > 1) {
            json_object_put(root);
            free(cause);
            br_http_release(ctx, &response);
            return webex_fail(error, "cannot decode Webex response");
        }
        if (decoded == 1) {
            json_object_put(root);
            free(cause);
        } else {
            free(cause);
            webex_msg msg = {0};
            int walked = 0;
            if (root && json_object_is_type(root, json_type_null)) {
                /* JSON null is a zero message. */
            } else if (!root || !json_object_is_type(root, json_type_object)) {
                if (webex_note(&msg, root, NULL, webex_message_type) != 0) walked = -1;
            } else walked = br_json_each_member(response.body, webex_member, &msg);
            json_object_put(root);
            if (walked != 0) {
                webex_msg_clear(&msg);
                br_http_release(ctx, &response);
                return webex_fail(error, "cannot decode Webex response");
            }
            if (!msg.ordinary && msg.message) {
                bool matched = false;
                char *regex_error = NULL;
                br_slice text = {(const unsigned char *)msg.message, msg.message_len};
                if (br_regex_each(patterns->mismatch, text, webex_mark, &matched, &regex_error) != 0) {
                    webex_msg_clear(&msg);
                    br_http_release(ctx, &response);
                    if (error && !*error) *error = regex_error ? regex_error : strdup("cannot scan Webex message");
                    else free(regex_error);
                    return -1;
                }
                free(regex_error);
                result->verified = matched;
            }
            webex_msg_clear(&msg);
        }
    }
    br_http_release(ctx, &response);
    return 0;
}

static int webex_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const webex_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->id || !patterns->mismatch ||
        !out || (!input.data && input.len))
        return webex_fail(error, "invalid or uninitialized Webex scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    /* Occurrence product. Raw and the only part are the key, not the id. */
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            bool keep = true;
            if (key.len != 64 || id.len != 65)
                rc = webex_fail(&owned_error, "invalid Webex capture");
            else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = webex_fail(&owned_error, "cannot create Webex result");
            else if (verify)
                rc = webex_verify(ctx, patterns, keys.items[k], ids.items[i], &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = webex_fail(&owned_error, "cannot append Webex result");
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

static br_detector webex_detector = {
    .type = 101, .version = 0, .name = "Webex", .custom_name = "",
    .description = "Webex is a collaboration tool that provides video conferencing, online meetings, screen share, and webinars. Webex API keys can be used to access and manage these services.",
    .keywords = webex_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = webex_scan,
};

int br_webex_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"webex"};
    static const char *const error_prefix[] = {"error"};
    if (error) *error = NULL;
    if (!out) return webex_fail(error, "invalid Webex detector output");
    *out = NULL;
    if (!webex_detector.state) {
        webex_patterns *patterns = calloc(1, sizeof(*patterns));
        if (!patterns) return webex_fail(error, "out of memory compiling Webex patterns");
        if (br_regex_compile_prefixed(prefix, 1, "\\b([a-f0-9]{64})\\b", &patterns->key, error) != 0 ||
            br_regex_compile_prefixed(prefix, 1, "\\b(C[a-f0-9]{64})\\b", &patterns->id, error) != 0 ||
            br_regex_compile_prefixed(error_prefix, 1, "(redirect_uri_mismatch)", &patterns->mismatch, error) != 0) {
            br_regex_free(patterns->key);
            br_regex_free(patterns->id);
            br_regex_free(patterns->mismatch);
            free(patterns);
            return -1;
        }
        webex_detector.state = patterns;
    }
    *out = &webex_detector;
    return 0;
}
