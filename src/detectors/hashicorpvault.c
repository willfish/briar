/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hashicorpvault/{common.go,
 * hashicorpvaultbatchtoken/hashicorpvaultbatchtoken.go,
 * hashicorpvaulttoken/hashicorpvaulttoken.go}. Not the AppRole detector. */
#include "detectors.h"
#include "endpoints.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *token, *url; } vault_patterns;
typedef struct { br_json *value; br_slice text; br_bytes repair; } vault_string;
typedef struct {
    vault_string strings[4]; /* display_name, entity_id, expire_time, type */
    bool orphan, renewable;
    vault_string *policies;
    size_t npolicies, capacity;
    char *cause; /* First ordinary type error sticks; visitation continues. */
} vault_lookup;
typedef struct {
    bool verified, decoded;
    vault_lookup lookup;
    char *cause;
} vault_verdict;

static int vault_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int vault_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : vault_fail(error, "cannot allocate Vault verification cause");
}

static void vault_string_clear(vault_string *s)
{
    json_object_put(s->value);
    free(s->repair.data);
    memset(s, 0, sizeof(*s));
}

static int vault_string_set(vault_string *s, br_json *value)
{
    br_slice text = {0};
    br_bytes repair = {0};
    /* This existing string codec supplies Go's invalid-UTF8 replacement. The
     * callback's value is ephemeral, including strings in old backing slots. */
    if (br_gcp_json_text(value, &text, &repair, NULL) != 0) return -1;
    br_json *retained = json_object_get(value);
    if (!retained) { free(repair.data); return -1; }
    vault_string_clear(s);
    *s = (vault_string){retained, text, repair};
    return 0;
}

static void vault_policies_clear(vault_lookup *lookup)
{
    for (size_t i = 0; i < lookup->capacity; ++i) vault_string_clear(&lookup->policies[i]);
    free(lookup->policies);
    lookup->policies = NULL;
    lookup->npolicies = lookup->capacity = 0;
}

static void vault_lookup_clear(vault_lookup *lookup)
{
    for (size_t i = 0; i < 4; ++i) vault_string_clear(&lookup->strings[i]);
    vault_policies_clear(lookup);
    free(lookup->cause);
    memset(lookup, 0, sizeof(*lookup));
}

static void vault_verdict_clear(vault_verdict *verdict)
{
    vault_lookup_clear(&verdict->lookup);
    free(verdict->cause);
    memset(verdict, 0, sizeof(*verdict));
}

static int vault_type_error(vault_lookup *lookup, br_json *value,
                            const char *field, const char *expected)
{
    return lookup->cause ? 0 : br_json_type_cause(value, field, expected, &lookup->cause);
}

static int vault_policy_element(void *opaque, size_t index, br_json *value, br_slice encoded)
{
    (void)encoded;
    vault_lookup *lookup = opaque;
    if (index >= lookup->capacity) {
        if (lookup->capacity > SIZE_MAX / sizeof(*lookup->policies) / 2) return -1;
        size_t next = lookup->capacity ? lookup->capacity * 2 : 1;
        if (next <= index) return -1;
        vault_string *items = realloc(lookup->policies, next * sizeof(*items));
        if (!items) return -1;
        memset(items + lookup->capacity, 0, (next - lookup->capacity) * sizeof(*items));
        lookup->policies = items;
        lookup->capacity = next;
    }
    lookup->npolicies = index + 1;
    /* Null into a string leaves its previous slot unchanged. Shrinking a slice
     * must NOT clear its backing slots: a later duplicate array can reuse them. */
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_string))
        return vault_type_error(lookup, value, ".Data.policies", "string");
    return vault_string_set(&lookup->policies[index], value);
}

static int vault_data_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    vault_lookup *lookup = opaque;
    static const char *const names[] = {"display_name", "entity_id", "expire_time", "type"};
    static const char *const fields[] = {".Data.display_name", ".Data.entity_id", ".Data.expire_time", ".Data.type"};
    for (size_t i = 0; i < 4; ++i) {
        if (!br_json_field_name(name, names[i])) continue;
        if (!value) return 0;
        if (!json_object_is_type(value, json_type_string))
            return vault_type_error(lookup, value, fields[i], "string");
        return vault_string_set(&lookup->strings[i], value);
    }
    if (br_json_field_name(name, "orphan") || br_json_field_name(name, "renewable")) {
        if (!value) return 0;
        bool orphan = br_json_field_name(name, "orphan");
        if (!json_object_is_type(value, json_type_boolean))
            return vault_type_error(lookup, value, orphan ? ".Data.orphan" : ".Data.renewable", "bool");
        if (orphan) lookup->orphan = json_object_get_boolean(value);
        else lookup->renewable = json_object_get_boolean(value);
    } else if (br_json_field_name(name, "policies")) {
        if (!value) { vault_policies_clear(lookup); return 0; }
        if (!json_object_is_type(value, json_type_array))
            return vault_type_error(lookup, value, ".Data.policies", "[]string");
        lookup->npolicies = 0;
        int rc = br_json_each_element(encoded, vault_policy_element, lookup);
        if (!rc && !lookup->npolicies) vault_policies_clear(lookup); /* [] resets capacity too. */
        return rc;
    }
    return 0;
}

static int vault_root_member(void *opaque, br_slice name, br_json *value, br_slice encoded)
{
    vault_lookup *lookup = opaque;
    if (!br_json_field_name(name, "data") || !value) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        static const char data_type[] =
            "struct { DisplayName string \"json:\\\"display_name\\\"\"; EntityId string \"json:\\\"entity_id\\\"\"; "
            "ExpireTime string \"json:\\\"expire_time\\\"\"; Orphan bool \"json:\\\"orphan\\\"\"; "
            "Policies []string \"json:\\\"policies\\\"\"; Renewable bool \"json:\\\"renewable\\\"\"; "
            "Type string \"json:\\\"type\\\"\" }";
        return vault_type_error(lookup, value, "LookupResponse.Data", data_type);
    }
    /* Data is a value struct: duplicate objects merge, and null is a no-op. */
    return br_json_each_member(encoded, vault_data_member, lookup);
}

static int vault_decode(const br_http_response *response, vault_verdict *verdict, char **error)
{
    br_json *document = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &document, &end, &verdict->cause);
    if (rc) {
        json_object_put(document);
        return rc == 1 ? 0 : vault_fail(error, "cannot decode Vault lookup response");
    }
    if (document && !json_object_is_type(document, json_type_object))
        rc = vault_type_error(&verdict->lookup, document, NULL, "hashicorpvault.LookupResponse");
    else if (document)
        rc = br_json_each_member((br_slice){response->body.data, end}, vault_root_member, &verdict->lookup);
    json_object_put(document);
    if (rc != 0) return vault_fail(error, "cannot decode Vault lookup response");
    if (verdict->lookup.cause) {
        free(verdict->cause);
        verdict->cause = verdict->lookup.cause;
        verdict->lookup.cause = NULL;
    }
    if (!rc && !verdict->cause) verdict->verified = verdict->decoded = true;
    return 0;
}

static bool vault_alnum(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

/* Deliberately NOT a general Go URL implementation. NoV never reaches this
 * boundary. Parse/JoinPath/String are supported only for this canonical ASCII
 * origin/path subset; reject everything else explicitly, even with nil ctx. */
static int vault_lookup_url(br_slice base, char **url, char **error)
{
    size_t at;
    if (base.len >= 8 && !memcmp(base.data, "https://", 8)) at = 8;
    else if (base.len >= 7 && !memcmp(base.data, "http://", 7)) at = 7;
    else return vault_fail(error, "unsupported Vault endpoint URL form at JoinPath");
    size_t begin = at;
    while (at < base.len && (vault_alnum(base.data[at]) || base.data[at] == '.' || base.data[at] == '-')) ++at;
    if (at == begin) return vault_fail(error, "unsupported Vault endpoint URL form at JoinPath");
    if (at < base.len && base.data[at] == ':') {
        begin = ++at;
        while (at < base.len && base.data[at] >= '0' && base.data[at] <= '9') ++at;
        if (at == begin) return vault_fail(error, "unsupported Vault endpoint URL form at JoinPath");
    }
    size_t origin = at;
    if (at < base.len && base.data[at] == '/') {
        ++at;
        while (at < base.len && (vault_alnum(base.data[at]) || base.data[at] == '.' ||
               base.data[at] == '_' || base.data[at] == '~' || base.data[at] == '-' || base.data[at] == '/')) ++at;
    }
    if (at != base.len) return vault_fail(error, "unsupported Vault endpoint URL form at JoinPath");
    static const char suffix[] = "/v1/auth/token/lookup-self";
    if (base.len > SIZE_MAX - sizeof(suffix) - 1) return vault_fail(error, "Vault lookup URL too large");
    char *joined = malloc(base.len + sizeof(suffix) + 1);
    if (!joined) return vault_fail(error, "cannot allocate Vault lookup URL");
    memcpy(joined, base.data, base.len);
    joined[base.len] = '/';
    memcpy(joined + base.len + 1, suffix, sizeof(suffix));

    /* Rooted Clean subset derived from Go 1.26.7 src/path/path.go, Clean/Join.
     * Copyright 2009 The Go Authors. All rights reserved. BSD-3-Clause;
     * see LICENSES/BSD-3-Clause-Go.txt. Join does not reset at a later absolute
     * element. Lexical dot-dot removal stops at the root, with no filesystem IO. */
    char *path = joined + origin;
    size_t n = base.len - origin + sizeof(suffix), r = 1, w = 1;
    while (r < n) {
        if (path[r] == '/') { ++r; continue; }
        if (path[r] == '.' && (r + 1 == n || path[r + 1] == '/')) { ++r; continue; }
        if (path[r] == '.' && r + 1 < n && path[r + 1] == '.' &&
            (r + 2 == n || path[r + 2] == '/')) {
            r += 2;
            if (w > 1) {
                --w;
                while (w > 1 && path[w] != '/') --w;
            }
            continue;
        }
        if (w != 1) path[w++] = '/';
        while (r < n && path[r] != '/') path[w++] = path[r++];
    }
    path[w] = 0;
    *url = joined;
    return 0;
}

static int vault_verify(const br_scan_ctx *ctx, int32_t type, br_slice base, br_slice token,
                         vault_verdict *verdict, char **error)
{
    char *url = NULL;
    int rc = vault_lookup_url(base, &url, error); /* BEFORE NewRequestWithContext. */
    if (rc) return rc;
    if (!ctx) {
        free(url);
        return vault_cause(&verdict->cause, "net/http: nil Context", error);
    }
    char prefix[32];
    int printed = snprintf(prefix, sizeof(prefix), "%d:", (int)type);
    if (printed < 0 || (size_t)printed >= sizeof(prefix) ||
        base.len > SIZE_MAX - (size_t)printed - 1 ||
        token.len > SIZE_MAX - (size_t)printed - base.len - 1) {
        free(url);
        return vault_fail(error, "Vault request key too large");
    }
    size_t keylen = (size_t)printed + base.len + 1 + token.len;
    unsigned char *key = malloc(keylen);
    if (!key) { free(url); return vault_fail(error, "cannot allocate Vault request key"); }
    memcpy(key, prefix, (size_t)printed);
    memcpy(key + printed, base.data, base.len);
    key[(size_t)printed + base.len] = ':';
    memcpy(key + (size_t)printed + base.len + 1, token.data, token.len);
    const br_header headers[] = {{"X-Vault-Token", (const char *)token.data}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000, .detector_type = type,
        .dedup_key = {key, keylen}, /* Complete TYPE:ORIGINAL_BASE:TOKEN, never stripped. */
    };
    br_http_response response = {0};
    int sent = br_http_send(ctx, &request, &response, &verdict->cause);
    if (sent) {
        if (!verdict->cause) rc = vault_cause(&verdict->cause, "HTTP transport failed", error);
    } else if (response.status == 200) rc = vault_decode(&response, verdict, error);
    else if (response.status != 403 && response.status != 401) {
        char message[80];
        int formatted = snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
        if (formatted < 0 || (size_t)formatted >= sizeof(message))
            rc = vault_fail(error, "cannot format Vault HTTP status");
        else rc = vault_cause(&verdict->cause, message, error);
    }
    /* One ordinary release per attempt, even a failed send or fatal decode.
     * Owned PUBLIC clients promote ALL body-read errors to Do errors first.
     * Only provider-original values are retained here, never prepared headers. */
    br_http_release(ctx, &response);
    free(key);
    free(url);
    return rc;
}

static int vault_put(br_json *map, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text.len ? (const char *)text.data : "", (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(map, name, value) != 0) { json_object_put(value); return -1; }
    return 0;
}

static int vault_put_bool(br_json *map, const char *name, bool value)
{
    return vault_put(map, name, (br_slice){(const unsigned char *)(value ? "true" : "false"), value ? 4 : 5});
}

static int vault_policy_join(const vault_lookup *lookup, br_slice *text, br_bytes *owned)
{
    *text = (br_slice){(const unsigned char *)"", 0};
    if (!lookup->npolicies) return 0;
    if (lookup->npolicies == 1) { *text = lookup->policies[0].text; return 0; }
    size_t len = 0;
    for (size_t i = 0; i < lookup->npolicies; ++i) {
        size_t n = lookup->policies[i].text.len;
        if ((i && len > SIZE_MAX - 2) || n > SIZE_MAX - len - (i ? 2 : 0)) return -1;
        len += n + (i ? 2 : 0);
    }
    if (len == SIZE_MAX) return -1;
    owned->data = malloc(len + 1);
    if (!owned->data) return -1;
    owned->len = len;
    size_t at = 0;
    for (size_t i = 0; i < lookup->npolicies; ++i) {
        if (i) { memcpy(owned->data + at, ", ", 2); at += 2; }
        br_slice item = lookup->policies[i].text;
        if (item.len) memcpy(owned->data + at, item.data, item.len);
        at += item.len;
    }
    owned->data[at] = 0;
    *text = (br_slice){owned->data, len};
    return 0;
}

static int vault_project(br_result *result, const vault_lookup *lookup, bool batch, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return vault_fail(error, "cannot allocate Vault metadata");
    br_slice policies = {0};
    br_bytes joined = {0};
    int rc = 0;
    if (!batch) {
        rc = vault_policy_join(lookup, &policies, &joined);
        if (!rc) rc = vault_put(result->extra_data, "policies", policies);
    }
    if (!rc) rc = vault_put_bool(result->extra_data, "orphan", lookup->orphan);
    if (!rc) rc = vault_put_bool(result->extra_data, "renewable", lookup->renewable);
    if (!rc) rc = vault_put(result->extra_data, "type", lookup->strings[3].text);
    if (!rc) rc = vault_put(result->extra_data, "entity_id", lookup->strings[1].text);
    /* Batch creates its initial four-entry map BEFORE joining policies. */
    if (!rc && batch) {
        rc = vault_policy_join(lookup, &policies, &joined);
        if (!rc) rc = vault_put(result->extra_data, "policies", policies);
    }
    free(joined.data);
    return rc ? vault_fail(error, "cannot project Vault metadata") : 0;
}

static int vault_finding(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice token, br_slice endpoint, br_results *out, char **error)
{
    br_result result = {0};
    vault_verdict verdict = {0};
    int rc = br_finding_pair_bytes(&result, detector->type, token, "key", endpoint, "url",
                                   (br_slice){(const unsigned char *)":", 1});
    if (!rc) {
        result.redacted = malloc(12);
        if (!result.redacted) rc = -1;
        else { memcpy(result.redacted, token.data, 8); memcpy(result.redacted + 8, "...", 4); }
    }
    if (rc) rc = vault_fail(error, "cannot construct Vault finding");
    if (!rc && verify) {
        rc = vault_verify(ctx, detector->type, endpoint, token, &verdict, error);
        /* The helper has released its response before any caller publication. */
        if (!rc && br_result_set_verification_error(&result, verdict.cause, &token, 1) != 0)
            rc = vault_fail(error, "cannot set Vault verification error");
        if (!rc) {
            result.verified = verdict.verified;
            if (verdict.decoded) rc = vault_project(&result, &verdict.lookup, detector->type == 1061, error);
        }
    }
    if (!rc && br_results_push(out, &result) != 0) rc = vault_fail(error, "cannot append Vault finding");
    vault_verdict_clear(&verdict);
    br_result_clear(&result);
    return rc;
}

static int vault_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return vault_fail(error, "invalid HashiCorp Vault scan");
    const vault_patterns *patterns = detector->state;
    size_t original = out->len;
    br_captures tokens = {0}, found = {0};
    br_byte_endpoints endpoints = {0};
    int rc = br_captures_find(patterns->token, input, &tokens, true, error);
    /* Both capture edges are ASCII nonspace, so source TrimSpace is a no-op.
     * RE2's nonspace class admits VT/NUL/Unicode inside this ORIGIN capture. */
    if (!rc) rc = br_captures_find(patterns->url, input, &found, true, error);
    if (!rc) rc = br_endpoints_collect_bytes(ctx ? ctx->endpoints : NULL, "", &found, &endpoints, error);
    bool batch = detector->type == 1061;
    size_t outer = batch ? endpoints.len : tokens.len;
    size_t inner = batch ? tokens.len : endpoints.len;
    for (size_t i = 0; !rc && i < outer; ++i) {
        for (size_t j = 0; !rc && j < inner; ++j)
            rc = vault_finding(detector, ctx, verify, br_captures_at(&tokens, batch ? j : i),
                               br_byte_endpoints_at(&endpoints, batch ? i : j), out, error);
    }
    if (rc) {
        while (out->len > original) br_result_clear(&out->items[--out->len]);
        if (error && !*error) vault_fail(error, "cannot collect Vault credentials/endpoints");
    }
    br_captures_clear(&tokens);
    br_captures_clear(&found);
    br_byte_endpoints_clear(&endpoints);
    return rc ? -1 : 0;
}

static const char *const batch_keywords[] = {"hvb."};
static const char *const token_keywords[] = {"hvs.", "vault"};
static br_detector batch_detector = {
    .type = 1061, .version = 0, .name = "HashiCorpVaultBatchToken", .custom_name = "",
    .description = "This detector detects and verifies HashiCorp Vault batch tokens",
    .keywords = batch_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = vault_scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};
static br_detector token_detector = {
    .type = 1062, .version = 0, .name = "HashiCorpVaultToken", .custom_name = "",
    .description = "HashiCorp Vault is a secrets management service. Vault tokens (periodic, service, and admin) can be used to access and manage stored secrets and resources.",
    .keywords = token_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = vault_scan, .validate_endpoints = br_endpoints_validate_configured, .cloud_endpoint = "",
};
static vault_patterns batch_patterns, token_patterns;

static int vault_init(br_detector *detector, vault_patterns *patterns, const char *token_pattern,
                      const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return vault_fail(error, "invalid HashiCorp Vault detector output");
    *out = NULL;
    if (!detector->state) {
        /* Explicit RE2 whitespace, not PCRE2's larger \\s (which includes VT). */
        static const char url_pattern[] =
            "(https?://[^\\x09\\x0a\\x0c\\x0d\\x20/]*\\.hashicorp\\.cloud(?::[0-9]+)?)(?:/[^\\x09\\x0a\\x0c\\x0d\\x20]*)?";
        if (br_regex_compile(token_pattern, &patterns->token, error) != 0) return -1;
        if (br_regex_compile(url_pattern, &patterns->url, error) != 0) {
            br_regex_free(patterns->token);
            patterns->token = NULL;
            return -1;
        }
        detector->state = patterns;
    }
    *out = detector;
    return 0;
}

int br_hashicorpvaultbatchtoken_init(const br_detector **out, char **error)
{
    return vault_init(&batch_detector, &batch_patterns,
        "\\b(hvb\\.[A-Za-z0-9_.-]{50,300})(?:[^A-Za-z0-9_.-]|\\z)", out, error);
}

int br_hashicorpvaulttoken_init(const br_detector **out, char **error)
{
    return vault_init(&token_detector, &token_patterns,
        "\\b(hvs\\.[A-Za-z0-9_-]{90,120}|s\\.[A-Za-z0-9_-]{18,40})(?:$|[^A-Za-z0-9_-])", out, error);
}
