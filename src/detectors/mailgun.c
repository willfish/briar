/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailgun/mailgun.go. */
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
    char *name, *state, *type;
    size_t name_len, state_len, type_len;
    bool disabled;
} mg_item;

typedef struct {
    mg_item *items;
    size_t len, cap;
    char *cause;
    bool ordinary, fatal;
    mg_item *current;
} mg_doc;

static void mg_clear(mg_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) {
        free(doc->items[i].name); free(doc->items[i].state); free(doc->items[i].type);
    }
    free(doc->items); free(doc->cause);
    *doc = (mg_doc){0};
}

/* Null and empty arrays replace the slice, including retained slots. */
static void mg_discard_items(mg_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) {
        free(doc->items[i].name); free(doc->items[i].state); free(doc->items[i].type);
    }
    free(doc->items);
    doc->items = NULL;
    doc->len = 0;
    doc->cap = 0;
    doc->current = NULL;
}

static int mg_grow_items(mg_doc *doc, size_t n)
{
    if (n <= doc->cap) return 0;
    if (n > SIZE_MAX / sizeof(*doc->items)) return -1;
    mg_item *items = realloc(doc->items, n * sizeof(*items));
    if (!items) return -1;
    memset(items + doc->cap, 0, (n - doc->cap) * sizeof(*items));
    doc->items = items;
    doc->cap = n;
    return 0;
}

/* Call the helper first. Any nonzero is fatal. Only the first ordinary diagnostic is kept. */
static int mg_type(mg_doc *doc, br_json *value, const char *field, const char *expected)
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

static int mg_copy(char **slot, size_t *len, br_slice text)
{
    if (text.len == SIZE_MAX) return -1;
    char *owned = malloc(text.len + 1);
    if (!owned) return -1;
    if (text.len && text.data) memcpy(owned, text.data, text.len);
    owned[text.len] = '\0';
    free(*slot);
    *slot = owned;
    if (len) *len = text.len;
    return 0;
}

/* JSON null leaves a reused string unchanged. */
static int mg_string(mg_doc *doc, br_json *value, char **slot, size_t *len, const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) return mg_type(doc, value, field, "string");
    return mg_copy(slot, len, br_json_text(value));
}

static int mg_item_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    mg_doc *doc = user;
    mg_item *item = doc->current;
    if (br_json_field_name(name, "name"))
        return mg_string(doc, value, &item->name, &item->name_len, "item.items.name");
    if (br_json_field_name(name, "state"))
        return mg_string(doc, value, &item->state, &item->state_len, "item.items.state");
    if (br_json_field_name(name, "type"))
        return mg_string(doc, value, &item->type, &item->type_len, "item.items.type");
    if (br_json_field_name(name, "id")) {
        char *unused = NULL;
        int rc = mg_string(doc, value, &unused, NULL, "item.items.id");
        free(unused);
        return rc;
    }
    if (!br_json_field_name(name, "is_disabled")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_boolean))
        return mg_type(doc, value, "item.items.is_disabled", "bool");
    item->disabled = json_object_get_boolean(value);
    return 0;
}

static int mg_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    mg_doc *doc = user;
    doc->current = &doc->items[index];
    /* Null into a struct is ignored, so a reused slot keeps its fields. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return mg_type(doc, value, "domainResponse.items", "mailgun.item");
    return br_json_each_member(encoded, mg_item_field, doc);
}

/* Go int is the original lexeme, not a json-c saturated int64. */
static bool mg_int_lexeme(br_slice encoded)
{
    if (!encoded.data || !encoded.len) return false;
    size_t i = 0;
    bool neg = encoded.data[0] == '-';
    if (neg) ++i;
    if (i >= encoded.len) return false;
    uint64_t mag = 0;
    for (; i < encoded.len; ++i) {
        unsigned char c = encoded.data[i];
        if (c < '0' || c > '9') return false;
        unsigned digit = (unsigned)(c - '0');
        if (mag > (UINT64_MAX - digit) / 10) return false;
        mag = mag * 10 + digit;
    }
    if (neg) return mag <= (uint64_t)INT64_MAX + 1;
    return mag <= (uint64_t)INT64_MAX;
}

static int mg_int_cause(mg_doc *doc, br_slice encoded)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field domainResponse.total_count of type int";
    if (encoded.len > SIZE_MAX - (sizeof(prefix) + sizeof(suffix))) return -1;
    char *next = malloc(sizeof(prefix) - 1 + encoded.len + sizeof(suffix));
    if (!next) return -1;
    memcpy(next, prefix, sizeof(prefix) - 1);
    if (encoded.len && encoded.data) memcpy(next + sizeof(prefix) - 1, encoded.data, encoded.len);
    memcpy(next + sizeof(prefix) - 1 + encoded.len, suffix, sizeof(suffix));
    if (doc->ordinary) { free(next); return 0; }
    doc->ordinary = true;
    doc->cause = next;
    return 0;
}

static int mg_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    mg_doc *doc = user;
    if (br_json_field_name(name, "total_count")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
            if (mg_int_lexeme(encoded)) return 0;
            return mg_int_cause(doc, encoded);
        }
        return mg_type(doc, value, "domainResponse.total_count", "int");
    }
    if (!br_json_field_name(name, "items")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) {
        mg_discard_items(doc);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array))
        return mg_type(doc, value, "domainResponse.items", "[]mailgun.item");
    size_t n = json_object_array_length(value);
    if (!n) {
        mg_discard_items(doc);
        return 0;
    }
    if (mg_grow_items(doc, n) != 0) return -1;
    int rc = br_json_each_element(encoded, mg_element, doc);
    if (rc) return rc;
    doc->len = n;
    return 0;
}

static int mg_decode(br_slice body, const char *read_error, mg_doc *doc, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_json_first_document(body, read_error, &root, &end, &decode);
    if (rc < 0 || rc > 1) { json_object_put(root); free(decode); return fail(error, "cannot decode Mailgun response"); }
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
        return fail(error, "unsupported: Mailgun invalid UTF-8 in consumed JSON document");
    }
    if (root && !json_object_is_type(root, json_type_null) && !json_object_is_type(root, json_type_object))
        rc = mg_type(doc, root, NULL, "mailgun.domainResponse");
    else if (root && json_object_is_type(root, json_type_object))
        rc = br_json_each_member(document, mg_member, doc);
    json_object_put(root);
    if (rc != 0 || doc->fatal) return fail(error, "cannot project Mailgun response");
    return doc->ordinary ? 1 : 0;
}

static int domains_text(const mg_doc *doc, char **out, size_t *out_len)
{
    size_t total = 0;
    for (size_t i = 0; i < doc->len; ++i) {
        const mg_item *item = &doc->items[i];
        size_t fixed = 4 + (item->disabled ? 9 : 0) + (i ? 2 : 0);
        if (item->name_len > SIZE_MAX - fixed || item->state_len > SIZE_MAX - fixed - item->name_len ||
            item->type_len > SIZE_MAX - fixed - item->name_len - item->state_len) return -1;
        size_t piece = item->name_len + item->state_len + item->type_len + fixed;
        if (total == SIZE_MAX || piece > SIZE_MAX - total - 1) return -1;
        total += piece;
    }
    char *text = malloc(total + 1);
    if (!text) return -1;
    size_t at = 0;
    for (size_t i = 0; i < doc->len; ++i) {
        const mg_item *item = &doc->items[i];
        if (i) { memcpy(text + at, ", ", 2); at += 2; }
        if (item->name_len && item->name) memcpy(text + at, item->name, item->name_len);
        at += item->name_len;
        memcpy(text + at, " (", 2); at += 2;
        if (item->state_len && item->state) memcpy(text + at, item->state, item->state_len);
        at += item->state_len;
        text[at++] = ',';
        if (item->type_len && item->type) memcpy(text + at, item->type, item->type_len);
        at += item->type_len;
        if (item->disabled) { memcpy(text + at, ",disabled", 9); at += 9; }
        text[at++] = ')';
    }
    text[at] = '\0';
    *out = text;
    if (out_len) *out_len = at;
    return 0;
}

static int verify_mailgun(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    char *auth = NULL;
    if (secret.len == 72) {
        auth = malloc(6 + secret.len + 1);
        if (!auth) return fail(error, "cannot format Mailgun authorization");
        memcpy(auth, "Basic ", 6);
        memcpy(auth + 6, secret.data, secret.len);
        auth[6 + secret.len] = '\0';
    } else if (br_http_basic_auth((br_slice){(const unsigned char *)"api", 3}, secret, &auth, error) != 0) {
        return fail(error, "cannot format Mailgun basic authorization");
    }
    if (!ctx) {
        free(auth);
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0
            ? 0 : fail(error, "cannot set Mailgun verification error");
    }
    const br_header headers[] = {
        {"Authorization", auth},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.mailgun.net/v3/domains",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 34,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    mg_doc doc = {0};
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status == 200) {
        int decoded = mg_decode(response.body, response.body_error, &doc, error);
        if (decoded < 0) rc = -1;
        else if (decoded > 0) cause = doc.cause;
        else {
            verified = true;
            if (doc.len) {
                char *domains = NULL;
                size_t domains_len = 0;
                if (domains_text(&doc, &domains, &domains_len) != 0) rc = fail(error, "cannot format Mailgun domains");
                else {
                    result->extra_data = json_object_new_object();
                    br_json *value = domains_len > INT_MAX ? NULL : json_object_new_string_len(domains, (int)domains_len);
                    if (!result->extra_data || !value ||
                        json_object_object_add(result->extra_data, "Domains", value) != 0) {
                        json_object_put(value);
                        rc = fail(error, "cannot store Mailgun extra data");
                    }
                    free(domains);
                }
            }
        }
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fail(error, "cannot format Mailgun status");
        else cause = status_error;
    }
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        /* SetVerificationError is called with the error only, not the token. */
        if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
            rc = fail(error, "cannot set Mailgun verification error");
    }
    mg_clear(&doc);
    free(send_error);
    free(auth);
    return rc;
}

typedef struct { br_regex *original, *key, *hex; } mailgun_state;

static int scan_mailgun(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    mailgun_state *state = detector ? (mailgun_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Mailgun scan");
    size_t before = out->len;
    br_captures found = {0}, unique = {0};
    char *owned = NULL;
    br_regex *patterns[] = {state->original, state->key, state->hex};
    int rc = 0;
    for (size_t p = 0; !rc && p < 3; ++p) {
        br_captures_clear(&found);
        found = (br_captures){0};
        rc = br_captures_find(patterns[p], input, &found, false, &owned);
        for (size_t i = 0; !rc && i < found.len; ++i)
            rc = br_captures_push(&unique, br_captures_at(&found, i), true, &owned);
    }
    for (size_t i = 0; !rc && i < unique.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&unique, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
            rc = fail(&owned, "cannot create Mailgun finding");
        if (!rc && verify) rc = verify_mailgun(ctx, secret, &result, &owned);
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Mailgun finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&found);
    br_captures_clear(&unique);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"mailgun", "key-"};
static br_detector mailgun = {
    .type = 34, .version = 0, .name = "Mailgun", .custom_name = "",
    .description = "Mailgun is an email automation service. Mailgun tokens can be used to send, receive, and track emails.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_mailgun,
};

int br_mailgun_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Mailgun detector output");
    *out = NULL;
    if (mailgun.state) { *out = &mailgun; return 0; }
    mailgun_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Mailgun patterns");
    if (br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9-]{72})\\b", &state->original, error) != 0 ||
        br_regex_compile("\\b(key-[a-z0-9]{32})\\b", &state->key, error) != 0 ||
        br_regex_compile("\\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\\b", &state->hex, error) != 0) {
        free(state);
        return -1;
    }
    mailgun.state = state;
    *out = &mailgun;
    return 0;
}
