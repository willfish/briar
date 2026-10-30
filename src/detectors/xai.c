/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/xai/xai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

typedef struct {
    char *text;
    size_t len;
} xai_slot;

typedef struct {
    char *name, *acls, *cause;
    size_t name_len, acls_len;
    xai_slot *slots;
    size_t len, cap;
    bool ordinary, fatal;
} xai_doc;

static void xai_clear(xai_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) free(doc->slots[i].text);
    free(doc->slots);
    free(doc->name); free(doc->acls); free(doc->cause);
    *doc = (xai_doc){0};
}

static void xai_discard_acls(xai_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) free(doc->slots[i].text);
    free(doc->slots);
    doc->slots = NULL;
    doc->len = 0;
    doc->cap = 0;
    free(doc->acls);
    doc->acls = NULL;
    doc->acls_len = 0;
}

static int xai_grow(xai_doc *doc, size_t n)
{
    if (n <= doc->cap) return 0;
    xai_slot *slots = realloc(doc->slots, n * sizeof(*slots));
    if (!slots) return -1;
    memset(slots + doc->cap, 0, (n - doc->cap) * sizeof(*slots));
    doc->slots = slots;
    doc->cap = n;
    return 0;
}

static int xai_join(xai_doc *doc)
{
    size_t total = doc->len ? doc->len - 1 : 0;
    for (size_t i = 0; i < doc->len; ++i) {
        if (doc->slots[i].len > SIZE_MAX - total) return -1;
        total += doc->slots[i].len;
    }
    char *joined = malloc(total + 1);
    if (!joined) return -1;
    size_t at = 0;
    for (size_t i = 0; i < doc->len; ++i) {
        if (i) joined[at++] = ',';
        if (doc->slots[i].len && doc->slots[i].text)
            memcpy(joined + at, doc->slots[i].text, doc->slots[i].len);
        at += doc->slots[i].len;
    }
    joined[at] = '\0';
    free(doc->acls);
    doc->acls = joined;
    doc->acls_len = total;
    return 0;
}

static int xai_type(xai_doc *doc, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!doc->ordinary) {
        doc->ordinary = true;
        doc->cause = next;
    } else free(next);
    return 0;
}

static int copy_text(char **slot, size_t *len, br_slice text)
{
    char *owned = malloc(text.len + 1);
    if (!owned) return -1;
    if (text.len) memcpy(owned, text.data, text.len);
    owned[text.len] = '\0';
    free(*slot);
    *slot = owned;
    if (len) *len = text.len;
    return 0;
}

static int xai_acl(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)encoded;
    xai_doc *doc = user;
    /* Null into a string is ignored, so a reused slot keeps its text. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return xai_type(doc, value, ".acls", "string");
    return copy_text(&doc->slots[index].text, &doc->slots[index].len, br_json_text(value));
}

static int xai_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    xai_doc *doc = user;
    if (br_json_field_name(name, "name")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string)) return xai_type(doc, value, ".name", "string");
        return copy_text(&doc->name, &doc->name_len, br_json_text(value));
    }
    if (!br_json_field_name(name, "acls")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        xai_discard_acls(doc);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) return xai_type(doc, value, ".acls", "[]string");
    size_t n = json_object_array_length(value);
    if (!n) {
        xai_discard_acls(doc);
        return 0;
    }
    if (xai_grow(doc, n) != 0) return -1;
    int rc = br_json_each_element(encoded, xai_acl, doc);
    if (rc) return rc;
    doc->len = n;
    return xai_join(doc);
}

static const char *json_word(br_json *value)
{
    if (json_object_is_type(value, json_type_array)) return "array";
    if (json_object_is_type(value, json_type_boolean)) return "bool";
    if (json_object_is_type(value, json_type_string)) return "string";
    return "number";
}

/* 0 keeps name/acls. 1 is an ordinary decode error in doc->cause, still verified. */
static int xai_decode(br_slice body, const char *read_error, xai_doc *doc, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_json_first_document(body, read_error, &root, &end, &decode);
    if (rc < 0 || rc > 1) {
        json_object_put(root);
        free(decode);
        return fail(error, "cannot decode xAI response");
    }
    if (rc == 1) {
        json_object_put(root);
        doc->ordinary = true;
        doc->cause = decode;
        return 1;
    }
    free(decode);
    br_slice document = {body.data, end};
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return fail(error, "unsupported: xAI invalid UTF-8 in consumed JSON document");
    }
    if (!root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        if (copy_text(&doc->name, &doc->name_len, (br_slice){0}) != 0 ||
            copy_text(&doc->acls, &doc->acls_len, (br_slice){0}) != 0)
            return fail(error, "cannot store xAI metadata");
        return 0;
    }
    if (!json_object_is_type(root, json_type_object)) {
        char message[192];
        snprintf(message, sizeof(message),
                 "json: cannot unmarshal %s into Go value of type struct { Name string \"json:\\\"name\\\"\"; Acls []string \"json:\\\"acls\\\"\" }",
                 json_word(root));
        char *next = strdup(message);
        json_object_put(root);
        if (!next) return fail(error, "cannot store xAI decode error");
        if (doc->ordinary) { free(next); return 1; }
        doc->ordinary = true;
        doc->cause = next;
        return 1;
    }
    rc = br_json_each_member(document, xai_member, doc);
    json_object_put(root);
    if (rc != 0 || doc->fatal) return fail(error, "cannot project xAI response");
    if (doc->ordinary) return 1;
    if ((!doc->name && copy_text(&doc->name, &doc->name_len, (br_slice){0}) != 0) ||
        (!doc->acls && copy_text(&doc->acls, &doc->acls_len, (br_slice){0}) != 0))
        return fail(error, "cannot store xAI metadata");
    return 0;
}

static int add_extra_len(br_json *extra, const char *key, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *owned = json_object_new_string_len(value ? value : "", (int)len);
    if (!owned || json_object_object_add(extra, key, owned) != 0) {
        json_object_put(owned);
        return -1;
    }
    return 0;
}

/* Constant URL. Nil context is kept. Release precedes the caller setter.
 * 200 with a decode error stays verified and has no extra data. */
static int verify_xai(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0
            ? 0 : fail(error, "cannot set xAI verification error");
    char *auth = malloc(7 + secret.len + 1);
    if (!auth) return fail(error, "cannot format xAI authorization");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, secret.data, secret.len);
    auth[7 + secret.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.x.ai/v1/api-key",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 1023,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    xai_doc doc = {0};
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status == 200) {
        verified = true;
        int decoded = xai_decode(response.body, response.body_error, &doc, error);
        if (decoded < 0) rc = -1;
        else if (decoded > 0) cause = doc.cause;
        else {
            result->extra_data = json_object_new_object();
            if (!result->extra_data ||
                add_extra_len(result->extra_data, "name", doc.name, doc.name_len) != 0 ||
                add_extra_len(result->extra_data, "acls", doc.acls, doc.acls_len) != 0)
                rc = fail(error, "cannot store xAI extra data");
        }
    } else if (response.status != 400 && response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fail(error, "cannot format xAI status");
        else cause = status_error;
    }
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
            rc = fail(error, "cannot set xAI verification error");
    }
    xai_clear(&doc);
    free(send_error);
    free(auth);
    return rc;
}

static int scan_xai(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized xAI scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    /* Go's map iteration order is unspecified. First-seen is the stable projection. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
            rc = fail(&owned, "cannot create xAI finding");
        if (!rc && verify) rc = verify_xai(ctx, secret, &result, &owned);
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append xAI finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"xai-"};
static br_detector xai = {
    .type = 1023, .version = 0, .name = "XAI", .custom_name = "",
    .description = "xAI is an AI company with the mission of advancing scientific discovery and gaining a deeper understanding of our universe.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_xai,
};

int br_xai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid xAI detector output");
    *out = NULL;
    if (xai.state) { *out = &xai; return 0; }
    br_regex *regex = NULL;
    if (br_regex_compile("\\b(xai-[0-9a-zA-Z_]{80})\\b", &regex, error) != 0) return -1;
    xai.state = regex;
    *out = &xai;
    return 0;
}
