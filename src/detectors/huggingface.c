/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/huggingface/huggingface.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *value; br_slice text; br_bytes repair; } hf_string;
typedef struct { hf_string name, role; } hf_organization;
typedef struct {
    hf_string name, email, display_name, role, auth_type;
    hf_organization *orgs;
    size_t logical_len, backing_cap;
    char *cause; /* First ordinary type error sticks; visitation continues. */
} hf_whoami;
typedef struct { bool verified; br_json *extra; char *cause; } hf_verdict;
typedef struct { hf_whoami *whoami; hf_organization *slot; } hf_org_context;

static int hf_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int hf_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : hf_fail(error, "cannot allocate HuggingFace verification cause");
}

static void hf_string_clear(hf_string *s)
{
    json_object_put(s->value);
    free(s->repair.data);
    memset(s, 0, sizeof(*s));
}

static int hf_string_set(hf_string *s, br_json *value)
{
    br_slice text = {0};
    br_bytes repair = {0};
    if (br_gcp_json_text(value, &text, &repair, NULL) != 0) {
        free(repair.data);
        return -1;
    }
    /* Ordered-visit callback values are ephemeral, including backing slots
     * hidden by a shorter duplicate orgs array. Keep the original JSON alive. */
    br_json *retained = json_object_get(value);
    if (!retained) { free(repair.data); return -1; }
    hf_string_clear(s);
    *s = (hf_string){retained, text, repair};
    return 0;
}

static void hf_orgs_clear(hf_whoami *whoami)
{
    for (size_t i = 0; i < whoami->backing_cap; ++i) {
        hf_string_clear(&whoami->orgs[i].name);
        hf_string_clear(&whoami->orgs[i].role);
    }
    free(whoami->orgs);
    whoami->orgs = NULL;
    whoami->logical_len = whoami->backing_cap = 0;
}

static void hf_whoami_clear(hf_whoami *whoami)
{
    hf_string_clear(&whoami->name);
    hf_string_clear(&whoami->email);
    hf_string_clear(&whoami->display_name);
    hf_string_clear(&whoami->role);
    hf_string_clear(&whoami->auth_type);
    hf_orgs_clear(whoami);
    free(whoami->cause);
}

static void hf_verdict_clear(hf_verdict *verdict)
{
    json_object_put(verdict->extra);
    free(verdict->cause);
}

static int hf_type_error(hf_whoami *whoami, br_json *value,
                         const char *field, const char *expected)
{
    return whoami->cause ? 0 : br_json_type_cause(value, field, expected, &whoami->cause);
}

static int hf_string_field(hf_whoami *whoami, hf_string *s, br_json *value, const char *field)
{
    if (!value) return 0; /* null into a string leaves the previous value. */
    if (!json_object_is_type(value, json_type_string))
        return hf_type_error(whoami, value, field, "string");
    return hf_string_set(s, value);
}

static int hf_access_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    hf_whoami *whoami = opaque;
    if (br_json_field_name(name, "displayname"))
        return hf_string_field(whoami, &whoami->display_name, value, ".auth.accessToken.displayName");
    if (br_json_field_name(name, "role"))
        return hf_string_field(whoami, &whoami->role, value, ".auth.accessToken.role");
    return 0;
}

static int hf_auth_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    hf_whoami *whoami = opaque;
    if (br_json_field_name(name, "type"))
        return hf_string_field(whoami, &whoami->auth_type, value, "auth.auth.type");
    if (!br_json_field_name(name, "accesstoken") || !value) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        static const char access_type[] =
            "struct { DisplayName string \"json:\\\"displayName,omitempty\\\"\"; "
            "Role string \"json:\\\"role,omitempty\\\"\" }";
        return hf_type_error(whoami, value, "auth.auth.accessToken", access_type);
    }
    /* Nested value structs merge across duplicate objects; null is a no-op. */
    return br_json_each_member(encoded, hf_access_member, whoami);
}

static int hf_org_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    hf_org_context *context = opaque;
    if (br_json_field_name(name, "name"))
        return hf_string_field(context->whoami, &context->slot->name, value, "organization.orgs.name");
    if (br_json_field_name(name, "roleinorg"))
        return hf_string_field(context->whoami, &context->slot->role, value, "organization.orgs.roleInOrg");
    return 0;
}

static int hf_org_element(void *opaque, size_t index, br_json *value, br_slice encoded)
{
    hf_whoami *whoami = opaque;
    /* Go grows/initializes each value-struct slot BEFORE inspecting its type. */
    if (index >= whoami->backing_cap) {
        if (whoami->backing_cap > SIZE_MAX / sizeof(*whoami->orgs) / 2) return -1;
        size_t next = whoami->backing_cap ? whoami->backing_cap * 2 : 1;
        if (next <= index) return -1;
        hf_organization *items = realloc(whoami->orgs, next * sizeof(*items));
        if (!items) return -1;
        memset(items + whoami->backing_cap, 0, (next - whoami->backing_cap) * sizeof(*items));
        whoami->orgs = items;
        whoami->backing_cap = next;
    }
    whoami->logical_len = index + 1;
    /* Shorter nonempty arrays retain hidden slots. null preserves the entire
     * slot, while an object merges only fields actually present in it. */
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_object))
        return hf_type_error(whoami, value, "whoamiResponse.orgs", "huggingface.organization");
    hf_org_context context = {whoami, &whoami->orgs[index]};
    return br_json_each_member(encoded, hf_org_member, &context);
}

static int hf_root_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    hf_whoami *whoami = opaque;
    if (br_json_field_name(name, "name"))
        return hf_string_field(whoami, &whoami->name, value, "whoamiResponse.name");
    if (br_json_field_name(name, "email"))
        return hf_string_field(whoami, &whoami->email, value, "whoamiResponse.email");
    if (br_json_field_name(name, "auth")) {
        if (!value) return 0;
        if (!json_object_is_type(value, json_type_object))
            return hf_type_error(whoami, value, "whoamiResponse.auth", "huggingface.auth");
        return br_json_each_member(encoded, hf_auth_member, whoami);
    }
    if (br_json_field_name(name, "orgs")) {
        if (!value) { hf_orgs_clear(whoami); return 0; }
        if (!json_object_is_type(value, json_type_array))
            return hf_type_error(whoami, value, "whoamiResponse.orgs", "[]huggingface.organization");
        whoami->logical_len = 0;
        int rc = br_json_each_element(encoded, hf_org_element, whoami);
        if (!rc && !whoami->logical_len) hf_orgs_clear(whoami); /* [] discards backing slots too. */
        return rc;
    }
    return 0; /* Unknown values are skipped, not decoded as float64 maps. */
}

static int hf_put(br_json *map, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text.len ? (const char *)text.data : "", (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(map, name, value) != 0) { json_object_put(value); return -1; }
    return 0;
}

static int hf_token_info(const hf_whoami *whoami, br_slice *text, br_bytes *owned)
{
    br_slice display = whoami->display_name.text, role = whoami->role.text;
    if (display.len || role.len) {
        if (display.len > SIZE_MAX - 4 || role.len > SIZE_MAX - display.len - 4) return -1;
        owned->len = display.len + role.len + 3;
        owned->data = malloc(owned->len + 1);
        if (!owned->data) return -1;
        if (display.len) memcpy(owned->data, display.data, display.len);
        memcpy(owned->data + display.len, " (", 2);
        if (role.len) memcpy(owned->data + display.len + 2, role.data, role.len);
        owned->data[owned->len - 1] = ')';
        owned->data[owned->len] = 0;
        *text = (br_slice){owned->data, owned->len};
    } else if (whoami->auth_type.text.len) *text = whoami->auth_type.text;
    else *text = (br_slice){(const unsigned char *)"Unknown Token Type", sizeof("Unknown Token Type") - 1};
    return 0;
}

static int hf_project_orgs(const hf_whoami *whoami, br_json *map)
{
    size_t count = whoami->logical_len;
    if (!count) return 0;
    if (count > SIZE_MAX / sizeof(br_bytes)) return -1;
    br_bytes *rows = malloc(count * sizeof(*rows));
    if (!rows) return -1;
    memset(rows, 0, count * sizeof(*rows));
    br_bytes joined = {0};
    size_t len = 0;
    int rc = -1;
    for (size_t i = 0; i < count; ++i) {
        br_slice name = whoami->orgs[i].name.text, role = whoami->orgs[i].role.text;
        if (name.len > SIZE_MAX - 2 || role.len > SIZE_MAX - name.len - 2) goto done;
        rows[i].len = name.len + role.len + 1;
        rows[i].data = malloc(rows[i].len + 1);
        if (!rows[i].data) goto done;
        if (name.len) memcpy(rows[i].data, name.data, name.len);
        rows[i].data[name.len] = ':';
        if (role.len) memcpy(rows[i].data + name.len + 1, role.data, role.len);
        rows[i].data[rows[i].len] = 0;
        size_t separator = i ? 2 : 0;
        if (len > SIZE_MAX - separator || rows[i].len > SIZE_MAX - len - separator) goto done;
        len += separator + rows[i].len;
    }
    if (len == SIZE_MAX) goto done;
    joined.data = malloc(len + 1);
    if (!joined.data) goto done;
    joined.len = len;
    size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        if (i) { memcpy(joined.data + at, ", ", 2); at += 2; }
        memcpy(joined.data + at, rows[i].data, rows[i].len);
        at += rows[i].len;
    }
    joined.data[at] = 0;
    rc = hf_put(map, "Organizations", (br_slice){joined.data, joined.len});
done:
    free(joined.data);
    for (size_t i = 0; i < count; ++i) free(rows[i].data);
    free(rows);
    return rc;
}

static int hf_project(const hf_whoami *whoami, br_json **extra, char **error)
{
    br_slice token = {0};
    br_bytes owned = {0};
    /* Token formatting precedes the initial mandatory map; organization row
     * collection/allocation follows all three initial map insertions. */
    int rc = hf_token_info(whoami, &token, &owned);
    if (!rc) {
        *extra = json_object_new_object();
        if (!*extra) rc = -1;
    }
    if (!rc) rc = hf_put(*extra, "Username", whoami->name.text);
    if (!rc) rc = hf_put(*extra, "Email", whoami->email.text);
    if (!rc) rc = hf_put(*extra, "Token", token);
    free(owned.data);
    if (!rc) rc = hf_project_orgs(whoami, *extra);
    return rc ? hf_fail(error, "cannot project HuggingFace metadata") : 0;
}

static int hf_decode(const br_http_response *response, hf_verdict *verdict, char **error)
{
    br_json *document = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &document, &end, &verdict->cause);
    if (rc) {
        json_object_put(document);
        return rc == 1 ? 0 : hf_fail(error, "cannot decode HuggingFace response");
    }
    hf_whoami whoami = {0};
    if (document && !json_object_is_type(document, json_type_object))
        rc = hf_type_error(&whoami, document, NULL, "huggingface.whoamiResponse");
    else if (document)
        rc = br_json_each_member((br_slice){response->body.data, end}, hf_root_member, &whoami);
    json_object_put(document);
    if (rc) rc = hf_fail(error, "cannot decode HuggingFace response");
    else if (whoami.cause) {
        verdict->cause = whoami.cause;
        whoami.cause = NULL;
    } else rc = hf_project(&whoami, &verdict->extra, error);
    hf_whoami_clear(&whoami);
    return rc;
}

static int hf_verify(const br_scan_ctx *ctx, int32_t type, br_slice token,
                      hf_verdict *verdict, char **error)
{
    /* The fixed-URL constructor's nil-context branch keeps the finding with
     * false/nil/nil, BEFORE constructing Authorization. The caller still sets. */
    if (!ctx) return 0;
    char auth[7 + 42 + 1];
    if (token.len > sizeof(auth) - sizeof("Bearer "))
        return hf_fail(error, "invalid HuggingFace Authorization length");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, token.data, token.len);
    auth[7 + token.len] = 0;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://huggingface.co/api/whoami-v2",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = type,
    };
    br_http_response response = {0};
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &verdict->cause) != 0) {
        if (!verdict->cause) rc = hf_cause(&verdict->cause, "HTTP transport failed", error);
    } else if (response.status >= 200 && response.status < 300) {
        /* First typed Decoder document, not ReadAll: ordinary decode/type/read
         * errors still verify, while owned/resource failures remain fatal. */
        rc = hf_decode(&response, verdict, error);
        if (!rc) verdict->verified = true;
    } else if (response.status != 401) {
        char message[80];
        int n = snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(message)) rc = hf_fail(error, "cannot format HuggingFace HTTP status");
        else rc = hf_cause(&verdict->cause, message, error);
    }
    /* Provider-original headers/URL/captures survive exactly one release per
     * attempt, including setup failure. Synthesized UA/headers do not. */
    br_http_release(ctx, &response);
    return rc;
}

static int hf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hf_fail(error, "invalid or uninitialized HuggingFace scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, false, &owned_error);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        hf_verdict verdict = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = hf_fail(&owned_error, "cannot create HuggingFace result");
        if (!rc && verify) {
            rc = hf_verify(ctx, detector->type, token, &verdict, &owned_error);
            /* The helper releases before publishing Verified/ExtraData and
             * before the checked setter, including its NULL-cause no-op. */
            if (!rc) {
                result.verified = verdict.verified;
                result.extra_data = verdict.extra;
                verdict.extra = NULL;
                if (br_result_set_verification_error(&result, verdict.cause, &token, 1) != 0)
                    rc = hf_fail(&owned_error, "cannot set HuggingFace verification error");
            }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = hf_fail(&owned_error, "cannot append HuggingFace result");
        hf_verdict_clear(&verdict);
        br_result_clear(&result);
    }
    if (rc) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        if (!owned_error) hf_fail(&owned_error, "cannot collect HuggingFace tokens");
    }
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const hf_keywords[] = {"hf_", "api_org_"};
static br_detector hf_detector = {
    .type = 926, .version = 0, .name = "HuggingFace", .custom_name = "",
    .description = "Hugging Face is a platform for natural language processing tasks and model hosting. Hugging Face API keys can be used to access various services and resources on the platform.",
    .keywords = hf_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = hf_scan,
};

int br_huggingface_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hf_fail(error, "invalid HuggingFace detector output");
    *out = NULL;
    if (!hf_detector.state) {
        br_regex *pattern = NULL;
        /* Capture 1 is exactly upstream match 0; boundaries consume no bytes.
         * TrimSpace cannot change either ASCII-alphanumeric-bounded token. */
        if (br_regex_compile("\\b((?:hf_|api_org_)[a-zA-Z0-9]{34})\\b", &pattern, error) != 0) return -1;
        hf_detector.state = pattern;
    }
    *out = &hf_detector;
    return 0;
}
