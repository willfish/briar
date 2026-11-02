/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pinecone/pinecone.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char pinecone_url[] = "https://api.pinecone.io/indexes";

typedef struct {
    char *name, *host, *cloud, *region;
    size_t name_len, host_len, cloud_len, region_len;
    bool serverless;
} pinecone_index;

typedef struct {
    pinecone_index *items;
    size_t len, cap;
    bool present, failed;
    char *cause;
} pinecone_doc;

typedef struct {
    pinecone_index *item;
    pinecone_doc *doc;
} pinecone_walk;

static int pinecone_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void pinecone_index_clear(pinecone_index *item)
{
    free(item->name); free(item->host); free(item->cloud); free(item->region);
    memset(item, 0, sizeof(*item));
}

static void pinecone_doc_clear(pinecone_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) pinecone_index_clear(&doc->items[i]);
    free(doc->items);
    free(doc->cause);
    memset(doc, 0, sizeof(*doc));
}

static int pinecone_note(pinecone_doc *doc, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    if (br_json_type_cause(value, field, expected, &next) != 0) return -1;
    if (!doc->failed) {
        doc->failed = true;
        doc->cause = next;
    } else free(next);
    return 0;
}

static int pinecone_copy(char **dest, size_t *len, br_slice text)
{
    if (text.len == SIZE_MAX) return -1;
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len && text.data) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*dest);
    *dest = copy;
    *len = text.len;
    return 0;
}

static int pinecone_string(br_json *value, char **dest, size_t *len, const char *field, pinecone_doc *doc)
{
    /* JSON null leaves a Go string unchanged. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) return pinecone_note(doc, value, field, "string");
    return pinecone_copy(dest, len, br_json_text(value));
}

static int pinecone_add_len(br_json *object, const char *name, const char *value, size_t len)
{
    br_json *item = json_object_new_string_len(value ? value : "", (int)len);
    if (!item) return -1;
    if (!json_object_object_add(object, name, item)) return 0;
    json_object_put(item);
    return -1;
}

static int pinecone_add(br_json *object, const char *name, const char *value)
{
    return pinecone_add_len(object, name, value, value ? strlen(value) : 0);
}

static void pinecone_discard(pinecone_doc *doc)
{
    for (size_t i = 0; i < doc->cap; ++i) pinecone_index_clear(&doc->items[i]);
    free(doc->items);
    doc->items = NULL;
    doc->len = 0;
    doc->cap = 0;
}

static int pinecone_grow(pinecone_doc *doc, size_t n)
{
    if (n <= doc->cap) return 0;
    if (n > SIZE_MAX / sizeof(*doc->items)) return -1;
    pinecone_index *items = realloc(doc->items, n * sizeof(*items));
    if (!items) return -1;
    memset(items + doc->cap, 0, (n - doc->cap) * sizeof(*items));
    doc->items = items;
    doc->cap = n;
    return 0;
}

static int pinecone_serverless_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    pinecone_walk *walk = user;
    if (br_json_field_name(name, "cloud"))
        return pinecone_string(value, &walk->item->cloud, &walk->item->cloud_len,
                               "serverlessSpec.indexes.spec.serverless.cloud", walk->doc);
    if (br_json_field_name(name, "region"))
        return pinecone_string(value, &walk->item->region, &walk->item->region_len,
                               "serverlessSpec.indexes.spec.serverless.region", walk->doc);
    return 0;
}

static int pinecone_spec_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    pinecone_walk *walk = user;
    if (!br_json_field_name(name, "serverless")) return 0;
    /* A nil pointer is cleared. A duplicate object merges into the existing one. */
    if (!value || json_object_is_type(value, json_type_null)) {
        free(walk->item->cloud); walk->item->cloud = NULL; walk->item->cloud_len = 0;
        free(walk->item->region); walk->item->region = NULL; walk->item->region_len = 0;
        walk->item->serverless = false;
        return 0;
    }
    if (!json_object_is_type(value, json_type_object))
        return pinecone_note(walk->doc, value, "indexSpec.indexes.spec.serverless", "pinecone.serverlessSpec");
    walk->item->serverless = true;
    return br_json_each_member(encoded, pinecone_serverless_member, walk);
}

static int pinecone_index_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    pinecone_walk *walk = user;
    if (br_json_field_name(name, "name"))
        return pinecone_string(value, &walk->item->name, &walk->item->name_len,
                               "indexInfo.indexes.name", walk->doc);
    if (br_json_field_name(name, "host"))
        return pinecone_string(value, &walk->item->host, &walk->item->host_len,
                               "indexInfo.indexes.host", walk->doc);
    if (!br_json_field_name(name, "spec")) return 0;
    /* spec is a value struct, so null leaves the previous value in place. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return pinecone_note(walk->doc, value, "indexInfo.indexes.spec", "pinecone.indexSpec");
    return br_json_each_member(encoded, pinecone_spec_member, walk);
}

static int pinecone_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    pinecone_doc *doc = user;
    pinecone_walk walk = {&doc->items[index], doc};
    /* Null into a struct is ignored, so a reused slot keeps its fields. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return pinecone_note(doc, value, "listIndexesResponse.indexes", "pinecone.indexInfo");
    return br_json_each_member(encoded, pinecone_index_member, &walk);
}

static int pinecone_root_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    pinecone_doc *doc = user;
    if (!br_json_field_name(name, "indexes")) return 0;
    /* Null replaces the slice with nil. A type error leaves the previous slice. */
    if (!value || json_object_is_type(value, json_type_null)) {
        pinecone_discard(doc);
        doc->present = false;
        return 0;
    }
    if (!json_object_is_type(value, json_type_array))
        return pinecone_note(doc, value, "listIndexesResponse.indexes", "[]pinecone.indexInfo");
    size_t n = json_object_array_length(value);
    if (!n) {
        pinecone_discard(doc);
        doc->present = true;
        return 0;
    }
    if (pinecone_grow(doc, n) != 0) return -1;
    int rc = br_json_each_element(encoded, pinecone_element, doc);
    if (rc) return rc;
    doc->len = n;
    doc->present = true;
    return 0;
}

static int pinecone_replace_utf8(br_slice body, unsigned char **owned, br_slice *out)
{
    *owned = NULL;
    *out = body;
    if (br_utf8_valid(body)) return 0;
    if (body.len > (SIZE_MAX - 1) / 3) return -1;
    unsigned char *copy = malloc(body.len * 3 + 1);
    if (!copy) return -1;
    size_t at = 0;
    for (size_t i = 0; i < body.len;) {
        uint32_t rune = 0;
        size_t width = br_utf8_rune((br_slice){body.data + i, body.len - i}, &rune);
        if (width) {
            memcpy(copy + at, body.data + i, width);
            at += width;
            i += width;
        } else {
            memcpy(copy + at, "\xef\xbf\xbd", 3);
            at += 3;
            ++i;
        }
    }
    *owned = copy;
    *out = (br_slice){copy, at};
    return 0;
}

static int pinecone_find(br_slice hay, const char *needle, size_t nlen, size_t *at)
{
    if (!hay.data || hay.len < nlen) return 0;
    for (size_t i = 0; i + nlen <= hay.len; ++i)
        if (!memcmp(hay.data + i, needle, nlen)) {
            *at = i;
            return 1;
        }
    return 0;
}

static int pinecone_project(br_slice host, char **id, size_t *id_len)
{
    *id = NULL;
    *id_len = 0;
    size_t mark = 0;
    if (!pinecone_find(host, ".svc.", 5, &mark) || !mark) return 0;
    size_t dash = mark;
    for (size_t i = 0; i < mark; ++i)
        if (host.data[i] == '-') dash = i;
    if (dash == mark || dash + 1 == mark) return 0;
    size_t len = mark - (dash + 1);
    char *copy = malloc(len + 1);
    if (!copy) return -1;
    memcpy(copy, host.data + dash + 1, len);
    copy[len] = '\0';
    *id = copy;
    *id_len = len;
    return 1;
}

static int pinecone_extra(br_result *result, const pinecone_index *items, size_t count)
{
    if (!result->extra_data && !(result->extra_data = json_object_new_object())) return -1;
    char total[32];
    snprintf(total, sizeof(total), "%zu", count);
    if (pinecone_add(result->extra_data, "total_indexes", total) != 0) return -1;
    for (size_t i = 0; i < count; ++i) {
        char *project = NULL;
        size_t project_len = 0;
        int found = pinecone_project((br_slice){(const unsigned char *)items[i].host, items[i].host_len},
                                     &project, &project_len);
        if (found < 0) return -1;
        if (!found || !project_len) {
            free(project);
            continue;
        }
        int rc = pinecone_add_len(result->extra_data, "project_id", project, project_len);
        free(project);
        if (rc) return -1;
        break;
    }
    size_t shown = count < 5 ? count : 5;
    for (size_t i = 0; i < shown; ++i) {
        char name[32], host[32], cloud[32], region[32];
        snprintf(name, sizeof(name), "index_%zu_name", i);
        snprintf(host, sizeof(host), "index_%zu_host", i);
        snprintf(cloud, sizeof(cloud), "index_%zu_cloud", i);
        snprintf(region, sizeof(region), "index_%zu_region", i);
        if (pinecone_add_len(result->extra_data, name, items[i].name, items[i].name_len) != 0) return -1;
        if (pinecone_add_len(result->extra_data, host, items[i].host, items[i].host_len) != 0) return -1;
        if (!items[i].serverless) continue;
        if (pinecone_add_len(result->extra_data, cloud, items[i].cloud, items[i].cloud_len) != 0) return -1;
        if (pinecone_add_len(result->extra_data, region, items[i].region, items[i].region_len) != 0) return -1;
    }
    return 0;
}

static int pinecone_decode(br_slice body, pinecone_doc *doc, char **error)
{
    if (body.len > (1u << 20)) body.len = 1u << 20;
    unsigned char *replaced = NULL;
    br_slice text = body;
    if (pinecone_replace_utf8(body, &replaced, &text) != 0)
        return pinecone_fail(error, "cannot normalize Pinecone response");
    br_json *root = NULL;
    char *cause = NULL;
    int rc = br_json_document(text, &root, &cause);
    /* Only exact document status +1 is ordinary. Null success is 0.
     * The source %w wrapper is unwrapped by SetVerificationError. */
    if (rc == 1) {
        doc->failed = true;
        doc->cause = cause;
        free(replaced);
        json_object_put(root);
        return 1;
    }
    if (rc != 0) {
        free(cause);
        free(replaced);
        json_object_put(root);
        return pinecone_fail(error, "cannot decode Pinecone response");
    }
    free(cause);
    if (root && json_object_is_type(root, json_type_object)) {
        int visit = br_json_each_member(text, pinecone_root_member, doc);
        if (visit != 0) rc = -1;
    } else if (root && !json_object_is_type(root, json_type_null)) {
        if (pinecone_note(doc, root, NULL, "pinecone.listIndexesResponse") != 0) rc = -1;
    }
    json_object_put(root);
    free(replaced);
    if (rc != 0) return pinecone_fail(error, "cannot project Pinecone response");
    if (doc->failed) return 1;
    if (!doc->present) {
        doc->cause = strdup("unexpected response body structure");
        return doc->cause ? 1 : pinecone_fail(error, "cannot format Pinecone structure error");
    }
    return 0;
}

static int pinecone_redact(br_result *result, br_slice token)
{
    if (token.len < 12) return -1;
    result->redacted = malloc(16);
    if (!result->redacted) return -1;
    memcpy(result->redacted, token.data, 8);
    memcpy(result->redacted + 8, "...", 3);
    memcpy(result->redacted + 11, token.data + token.len - 4, 4);
    result->redacted[15] = '\0';
    return 0;
}

static int pinecone_label(br_slice token, char label[7])
{
    if (token.len != 74 && token.len != 75) return -1;
    size_t n = token.len - 69;
    if (token.data[5 + n] != '_') return -1;
    memcpy(label, token.data + 5, n);
    label[n] = '\0';
    return 0;
}

static int pinecone_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &token, 1)
            ? pinecone_fail(error, "cannot set Pinecone verification error") : 0;
    char api_key[76];
    memcpy(api_key, token.data, token.len);
    api_key[token.len] = '\0';
    const br_header headers[] = {
        {"Api-Key", api_key},
        {"X-Pinecone-Api-Version", "2025-10"},
        {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = pinecone_url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    pinecone_doc doc = {0};
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) {
        if (response.body_error) cause = response.body_error;
        else {
            int decoded = pinecone_decode(response.body, &doc, error);
            if (decoded < 0) rc = -1;
            else if (decoded == 1) cause = doc.cause;
            else if (decoded != 0) rc = -1;
            else if (pinecone_extra(result, doc.items, doc.len) != 0)
                rc = pinecone_fail(error, "cannot store Pinecone extra data");
            else verified = true;
        }
    } else if (response.status == 403) {
        verified = true;
        if (pinecone_add(result->extra_data, "permission", "restricted") != 0)
            rc = pinecone_fail(error, "cannot store Pinecone permission");
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = pinecone_fail(error, "cannot format Pinecone status");
        else cause = status_error;
    }
    if (!rc) result->verified = verified;
    if (!rc && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = pinecone_fail(error, "cannot set Pinecone verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    pinecone_doc_clear(&doc);
    return rc;
}

static int pinecone_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pinecone_fail(error, "invalid or uninitialized Pinecone scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        char label[7];
        if (pinecone_label(token, label) != 0)
            rc = pinecone_fail(&owned_error, "invalid Pinecone capture");
        else if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = pinecone_fail(&owned_error, "cannot create Pinecone result");
        else if (pinecone_redact(&result, token) != 0)
            rc = pinecone_fail(&owned_error, "cannot redact Pinecone result");
        else if (!(result.extra_data = json_object_new_object()) ||
                 pinecone_add(result.extra_data, "key_id", label) != 0)
            rc = pinecone_fail(&owned_error, "cannot store Pinecone key id");
        else if (verify && pinecone_verify(ctx, token, &result, &owned_error) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = pinecone_fail(&owned_error, "cannot append Pinecone result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pinecone_keywords[] = {"pcsk_"};
static br_detector pinecone_detector = {
    .type = 1049, .version = 0, .name = "Pinecone", .custom_name = "",
    .description = "Pinecone is a vector database service. API keys can be used to manage indexes and perform vector operations.",
    .keywords = pinecone_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pinecone_scan,
};

int br_pinecone_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pinecone_fail(error, "invalid Pinecone detector output");
    *out = NULL;
    if (!pinecone_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(pcsk_([A-Za-z0-9]{5,6})_[A-Za-z0-9]{63})\\b", &regex, error) != 0)
            return -1;
        pinecone_detector.state = regex;
    }
    *out = &pinecone_detector;
    return 0;
}
