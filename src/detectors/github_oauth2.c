/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2 github_oauth2 and the reachable token flow in
 * golang.org/x/oauth2 v0.34.0 (BSD-3-Clause). No SDK transport is substituted. */
#include "detectors.h"
#include "github_oauth2_private.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "gcp_json.h"
#include "../utf8.h"
#include "../go_unicode.h"
#include <json-c/json.h>
#include <openssl/evp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
#define BODY_LIMIT ((size_t)1 << 20)

static int fail(char **error, const char *text)
{
    if (error && !*error) *error = strdup(text);
    return -1;
}
static bool needle(br_slice text)
{
    static const char target[] = "bad_verification_code";
    for (size_t i = 0; i < text.len && text.len - i >= sizeof(target) - 1; ++i)
        if (!memcmp(text.data + i, target, sizeof(target) - 1)) return true;
    return false;
}
static size_t space(br_slice text, size_t at)
{
    while (at < text.len) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){text.data + at, text.len - at}, &rune);
        if (!n || !(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        at += n;
    }
    return at;
}
static bool mime_token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        (c && strchr("!#$%&'*+-.^_`{|}~", c));
}
static bool mime_special(unsigned char c) { return c && strchr("()<>@,;:\\\"/[]?=", c); }
typedef struct { br_slice name, value; size_t next; bool quoted; } parameter;
static bool parameter_read(br_slice text, size_t at, parameter *p)
{
    at = space(text, at);
    if (at == text.len || text.data[at++] != ';') return false;
    at = space(text, at); size_t begin = at;
    while (at < text.len && mime_token(text.data[at])) ++at;
    if (at == begin) return false;
    p->name = (br_slice){text.data + begin, at - begin}; at = space(text, at);
    if (at == text.len || text.data[at++] != '=') return false;
    at = space(text, at); begin = at; p->quoted = at < text.len && text.data[at] == '"';
    if (p->quoted) {
        ++at;
        while (at < text.len && text.data[at] != '"') {
            unsigned char c = text.data[at++];
            if (c == '\r' || c == '\n') return false;
            if (c == '\\' && at < text.len && mime_special(text.data[at])) ++at;
        }
        if (at == text.len) return false;
        ++at;
    } else {
        while (at < text.len && mime_token(text.data[at])) ++at;
        if (at == begin) return false;
    }
    p->value = (br_slice){text.data + begin, at - begin}; p->next = at; return true;
}
static unsigned char parameter_byte(const parameter *p, size_t *at)
{
    unsigned char c = p->value.data[(*at)++];
    if (p->quoted && c == '\\' && *at < p->value.len - 1 && mime_special(p->value.data[*at])) c = p->value.data[(*at)++];
    return c;
}
static bool parameter_equal(const parameter *a, const parameter *b)
{
    size_t x = a->quoted ? 1 : 0, y = b->quoted ? 1 : 0;
    size_t end_a = a->value.len - (a->quoted ? 1 : 0), end_b = b->value.len - (b->quoted ? 1 : 0);
    while (x < end_a && y < end_b) if (parameter_byte(a, &x) != parameter_byte(b, &y)) return false;
    return x == end_a && y == end_b;
}
static bool fold_equal(br_slice a, br_slice b)
{
    if (a.len != b.len) return false;
    for (size_t i = 0; i < a.len; ++i) {
        unsigned char x = a.data[i], y = b.data[i];
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return false;
    }
    return true;
}
static bool mime_base(br_slice base, const char *expected)
{
    size_t at = space(base, 0), i = 0;
    while (expected[i]) {
        if (at == base.len) return false;
        uint32_t rune; size_t n = br_utf8_rune((br_slice){base.data + at, base.len - at}, &rune);
        if (!n || br_go_unicode_lower(rune) != (unsigned char)expected[i++]) return false;
        at += n;
    }
    return space(base, at) == base.len;
}
/* ParseMediaType keeps its base on bad parameters, but conflicting duplicate
 * full parameter names return an empty base. Only decoder selection is needed. */
static bool form_response(br_slice content_type)
{
    size_t end = 0; while (end < content_type.len && content_type.data[end] != ';') ++end;
    br_slice base = {content_type.data, end};
    if (!mime_base(base, "application/x-www-form-urlencoded") && !mime_base(base, "text/plain")) return false;
    size_t at = end;
    while (space(content_type, at) < content_type.len) {
        parameter current;
        if (!parameter_read(content_type, at, &current)) break;
        size_t previous = end;
        while (previous < at) {
            parameter old;
            if (!parameter_read(content_type, previous, &old)) break;
            if (fold_equal(old.name, current.name) && !parameter_equal(&old, &current)) return false;
            previous = old.next;
        }
        at = current.next;
    }
    return true;
}

typedef struct { br_json *root; br_slice text; br_bytes owned; } token_string;
static void string_clear(token_string *s)
{
    json_object_put(s->root); free(s->owned.data); *s = (token_string){0};
}
static int string_set(token_string *s, br_json *value, char **error)
{
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_string)) return 1;
    br_slice text = {0}; br_bytes repair = {0};
    if (br_gcp_json_text(value, &text, &repair, error) != 0) { free(repair.data); return -1; }
    br_json *root = json_object_get(value);
    if (!root) { free(repair.data); return fail(error, "cannot retain GitHub OAuth2 string"); }
    string_clear(s); *s = (token_string){root, text, repair}; return 0;
}
static const char *const names[] = {"access_token", "token_type", "refresh_token", "error", "error_description", "error_uri"};
typedef struct { token_string fields[6]; bool bad, parse_match; char **error; } token;
static void token_clear(token *t)
{
    for (size_t i = 0; i < 6; ++i) string_clear(&t->fields[i]);
}
static bool json_number(br_slice text)
{
    size_t at = 0;
    if (at < text.len && text.data[at] == '-') ++at;
    if (at == text.len) return false;
    if (text.data[at] == '0') ++at;
    else { size_t begin = at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false; }
    if (at < text.len && text.data[at] == '.') { size_t begin = ++at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false; }
    if (at < text.len && (text.data[at] == 'e' || text.data[at] == 'E')) {
        ++at; if (at < text.len && (text.data[at] == '+' || text.data[at] == '-')) ++at;
        size_t begin = at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false;
    }
    return at == text.len;
}
/* strconv.ParseInt's early uint64 overflow precedes later invalid bytes. The
 * actual value/expiry is discarded by this detector, never freshness-tested. */
static bool integer(br_slice text)
{
    size_t at = 0; bool negative = false;
    if (text.len && (text.data[0] == '+' || text.data[0] == '-')) { negative = text.data[0] == '-'; ++at; }
    if (at == text.len) return false;
    uint64_t n = 0;
    for (; at < text.len; ++at) {
        unsigned char c = text.data[at];
        if (c < '0' || c > '9') return false;
        unsigned digit = c - '0';
        if (n > (UINT64_MAX - digit) / 10) return false;
        n = n * 10 + digit;
    }
    return negative ? n <= (UINT64_C(1) << 63) : n <= INT64_MAX;
}
static int expiration(token *t, br_json *value, br_slice encoded)
{
    if (!value) return 0;
    br_slice number = encoded; br_bytes repair = {0};
    if (json_object_is_type(value, json_type_string)) {
        if (br_gcp_json_text(value, &number, &repair, t->error) != 0) { free(repair.data); return -1; }
        if (!json_number(number)) {
            /* json.Number's invalid-literal diagnostic quotes ORIGINAL JSON
             * bytes, not the decoded string. Go %q preserves this ASCII needle. */
            t->parse_match = needle(encoded); free(repair.data); return 1;
        }
    } else if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double)) return 1;
    bool valid = integer(number);
    /* ParseInt diagnostics quote the DECODED valid JSON number. Neither such a
     * number nor its quoting can contain the needle; do not search encoded text. */
    free(repair.data); return valid ? 0 : 1;
}
static int token_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    token *t = user;
    if (br_json_field_name(name, "expires_in")) return expiration(t, value, encoded);
    for (size_t i = 0; i < 6; ++i) if (br_json_field_name(name, names[i])) {
        int rc = string_set(&t->fields[i], value, t->error);
        if (rc < 0) return -1;
        if (rc > 0) t->bad = true; /* First typed error sticks, but decoding continues. */
        break;
    }
    return 0;
}
static int json_token(br_slice body, token *t)
{
    br_json *root = NULL; char *cause = NULL;
    int rc = br_json_document(body, &root, &cause); free(cause);
    if (rc) { json_object_put(root); return rc < 0 ? fail(t->error, "cannot decode GitHub OAuth2 JSON") : 1; }
    if (root && !json_object_is_type(root, json_type_object)) rc = 1;
    else if (root) rc = br_json_each_member(body, token_member, t);
    /* Syntax/type diagnostics have only fixed field/type names or one invalid
     * rune. Custom expires_in errors above are the sole variable-text path. */
    json_object_put(root); return rc < 0 ? -1 : rc > 0 || t->bad ? 1 : 0;
}
static int hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool query_valid(br_slice text)
{
    for (size_t i = 0; i < text.len; ++i) if (text.data[i] == '%') {
        if (text.len - i < 3 || hex(text.data[i + 1]) < 0 || hex(text.data[i + 2]) < 0) return false;
        i += 2;
    }
    return true;
}
static unsigned char query_byte(br_slice text, size_t *at)
{
    unsigned char c = text.data[(*at)++];
    if (c == '+') return ' ';
    if (c == '%') { int x = hex(text.data[*at]), y = hex(text.data[*at + 1]); *at += 2; return (unsigned char)(x * 16 + y); }
    return c;
}
static bool query_key(br_slice key, const char *name)
{
    size_t at = 0, i = 0;
    while (at < key.len && name[i]) if (query_byte(key, &at) != (unsigned char)name[i++]) return false;
    return at == key.len && !name[i];
}
static int query_value(br_slice value, token_string *out, char **error)
{
    unsigned char *data = malloc(value.len + 1);
    if (!data) return fail(error, "cannot allocate GitHub OAuth2 form value");
    size_t at = 0, n = 0; while (at < value.len) data[n++] = query_byte(value, &at);
    data[n] = 0; out->owned = (br_bytes){data, n}; out->text = (br_slice){data, n}; return 0;
}
static int form_token(br_slice body, token *t)
{
    size_t parameters = 1; for (size_t i = 0; i < body.len; ++i) parameters += body.data[i] == '&';
    /* Pinned Go default; nondefault GODEBUG urlmaxqueryparams is not modeled. */
    if (parameters > 10000) return 1;
    size_t at = 0;
    while (at < body.len) {
        size_t end = at; while (end < body.len && body.data[end] != '&') ++end;
        br_slice segment = {body.data + at, end - at}; at = end < body.len ? end + 1 : end;
        if (memchr(segment.data, ';', segment.len) || !query_valid(segment)) return 1;
    }
    bool seen[7] = {0}; at = 0;
    while (at < body.len) {
        size_t end = at; while (end < body.len && body.data[end] != '&') ++end;
        br_slice segment = {body.data + at, end - at}; at = end < body.len ? end + 1 : end;
        size_t equal = 0; while (equal < segment.len && segment.data[equal] != '=') ++equal;
        br_slice key = {segment.data, equal}, value = {segment.data + equal + (equal < segment.len), segment.len - equal - (equal < segment.len)};
        for (size_t i = 0; i < 7; ++i) if (!seen[i] && query_key(key, i < 6 ? names[i] : "expires_in")) {
            seen[i] = true;
            if (i < 6 && query_value(value, &t->fields[i], t->error) != 0) return -1;
            /* Atoi error and expiry value are both discarded by this caller. */
            break;
        }
    }
    /* ParseQuery errors quote at most three escape bytes, or fixed messages;
     * none can contain the needle. Failure statuses instead use the raw body. */
    return 0;
}

static int read_body(const br_github_oauth2_state *s, br_github_oauth2_response *r,
                     br_bytes *body, br_bytes *cause, char **error)
{
    body->data = malloc(BODY_LIMIT);
    if (!body->data) return fail(error, "cannot allocate GitHub OAuth2 response body");
    while (body->len < BODY_LIMIT) {
        size_t n = 0, capacity = BODY_LIMIT - body->len;
        int rc = s->io->read(s->user, r, body->data + body->len, capacity, &n, cause);
        if (n > capacity) return fail(error, "invalid GitHub OAuth2 reader count");
        body->len += n;
        if (rc < 0) return fail(error, "GitHub OAuth2 reader failed fatally");
        if (rc > 0) return 1; /* Even final bytes with error beat HTTP status. */
        free(cause->data); *cause = (br_bytes){0};
        if (!n) break;
    }
    return 0; /* LimitReader makes no extra underlying read at exactly 1 MiB. */
}
/* 0 token success, +1 ordinary SDK error, -1 fatal. Match is a projection of
 * err.Error(), never JSON-code-only or transport diagnostic classification.
 * Quoting cannot change this ASCII needle in RetrieveError's decoded strings. */
static int attempt(const br_github_oauth2_state *s, const br_scan_ctx *ctx,
                   br_slice id, br_slice secret, bool params, bool *match, char **error)
{
    br_bytes form = {0}, auth = {0}, body = {0}, cause = {0}; int outcome = -1;
    size_t n = params ? sizeof("client_id=&client_secret=&grant_type=client_credentials") - 1 + id.len + secret.len : sizeof("grant_type=client_credentials") - 1;
    form.data = malloc(n + 1);
    if (!form.data) return fail(error, "cannot allocate GitHub OAuth2 request body");
    form.len = n;
    if (params) {
        size_t at = 0;
#define APPEND(slc) do { br_slice v_ = (slc); memcpy(form.data + at, v_.data, v_.len); at += v_.len; } while (0)
        APPEND(TEXT("client_id=")); APPEND(id); APPEND(TEXT("&client_secret=")); APPEND(secret); APPEND(TEXT("&grant_type=client_credentials"));
#undef APPEND
    } else memcpy(form.data, "grant_type=client_credentials", n);
    form.data[n] = 0;
    br_github_oauth2_header headers[2] = {{"Content-Type", TEXT("application/x-www-form-urlencoded")}};
    if (!params) {
        /* Captures are entirely QueryEscape-safe ASCII. */
        unsigned char credentials[62]; memcpy(credentials, id.data, id.len); credentials[id.len] = ':'; memcpy(credentials + id.len + 1, secret.data, secret.len);
        size_t encoded = 4 * ((id.len + 1 + secret.len + 2) / 3);
        auth.data = malloc(6 + encoded + 1);
        if (!auth.data) { free(form.data); return fail(error, "cannot allocate GitHub OAuth2 Basic auth"); }
        memcpy(auth.data, "Basic ", 6);
        int written = EVP_EncodeBlock(auth.data + 6, credentials, (int)(id.len + 1 + secret.len));
        if (written < 0 || (size_t)written != encoded) { fail(error, "cannot encode GitHub OAuth2 Basic auth"); goto storage; }
        auth.len = 6 + encoded; headers[1] = (br_github_oauth2_header){"Authorization", {auth.data, auth.len}};
    }
    /* Source builds both deterministic form/Basic values BEFORE WithContext. */
    if (!ctx) { fail(error, "unsupported: GitHub OAuth2 Request.WithContext(nil) panic boundary"); goto storage; }
    if (!s->io) { fail(error, "unsupported: GitHub OAuth2 native SDK HTTP byte I/O is not implemented"); goto storage; }
    if (!s->io->send || !s->io->read || !s->io->release) { fail(error, "invalid GitHub OAuth2 byte I/O"); goto storage; }
    const br_github_oauth2_request request = {"POST", TEXT("https://github.com/login/oauth/access_token"), {form.data, form.len}, headers, params ? 1 : 2};
    br_github_oauth2_response response = {0}; token t = {.error = error};
    int rc = s->io->send(s->user, ctx, &request, &response, &cause);
    if (rc < 0) { fail(error, "GitHub OAuth2 send failed fatally"); goto release; }
    if (rc > 0) { *match = needle((br_slice){cause.data, cause.len}); outcome = 1; goto release; }
    free(cause.data); cause = (br_bytes){0};
    rc = read_body(s, &response, &body, &cause, error);
    if (rc < 0) goto release;
    if (rc > 0) { *match = needle((br_slice){cause.data, cause.len}); outcome = 1; goto release; }
    bool failed = response.status < 200 || response.status > 299;
    rc = form_response(response.content_type) ? form_token((br_slice){body.data, body.len}, &t) : json_token((br_slice){body.data, body.len}, &t);
    if (rc < 0) { fail(error, "cannot project GitHub OAuth2 token response"); goto release; }
    if (rc > 0 && !failed) { *match = t.parse_match; outcome = 1; goto release; }
    if (failed || t.fields[3].text.len) {
        if (!rc && t.fields[3].text.len) *match = needle(t.fields[3].text) || needle(t.fields[4].text) || needle(t.fields[5].text);
        else *match = needle(response.status_text) || needle((br_slice){body.data, body.len});
        outcome = 1; goto release;
    }
    outcome = t.fields[0].text.len ? 0 : 1; /* Missing-token fixed diagnostic. */
release:
    s->io->release(s->user, &response); /* Storage stays alive through release, even failures. */
    token_clear(&t);
storage:
    free(cause.data); free(body.data); free(auth.data); free(form.data); return outcome;
}
static int scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!d || !d->state || !out) return fail(error, "invalid GitHub OAuth2 scan");
    const br_github_oauth2_state *s = d->state;
    br_captures ids = {0}, secrets = {0}; size_t original = out->len; int rc = 0;
    if (br_captures_find(s->id_pattern, input, &ids, false, error) != 0 || br_captures_find(s->secret_pattern, input, &secrets, false, error) != 0) rc = -1;
    for (size_t i = 0; !rc && i < ids.len; ++i) for (size_t j = 0; !rc && j < secrets.len; ++j) {
        br_result result = {0}; br_slice id = br_captures_at(&ids, i), secret = br_captures_at(&secrets, j);
        if (br_finding_pair_bytes(&result, d->type, id, "id", secret, "secret", (br_slice){0}) != 0) rc = fail(error, "cannot create GitHub OAuth2 finding");
        if (!rc) {
            result.extra_data = json_object_new_object(); br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/github/");
            if (!result.extra_data || !guide) { json_object_put(guide); rc = fail(error, "cannot create GitHub OAuth2 metadata"); }
            else if (json_object_object_add(result.extra_data, "rotation_guide", guide) != 0) { json_object_put(guide); rc = fail(error, "cannot add GitHub OAuth2 metadata"); }
        }
        if (!rc && verify) {
            bool match = false; int status = attempt(s, ctx, id, secret, false, &match, error);
            if (status > 0) { match = false; status = attempt(s, ctx, id, secret, true, &match, error); }
            if (status < 0) rc = -1;
            else result.verified = status > 0 && match;
        }
        if (!rc && br_results_push(out, &result) != 0) rc = fail(error, "cannot append GitHub OAuth2 finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&secrets); return rc;
}
static const char *const keywords[] = {"github"};
static br_github_oauth2_state state;
static br_detector detector = {
    .type = 924, .version = 0, .name = "GitHubOauth2", .custom_name = "",
    .description = "GitHub OAuth2 credentials are used to authenticate and authorize applications to access GitHub's API on behalf of a user or organization. These credentials include a client ID and client secret, which can be used to obtain access tokens for accessing GitHub resources.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024, .scan = scan,
};
int br_github_oauth2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GitHub OAuth2 detector output");
    *out = NULL;
    if (!detector.state) {
        br_regex *id = NULL, *secret = NULL;
        if (br_regex_compile("(?i:github)(?:.|[\\n\\r]){0,40}?\\b([a-zA-Z0-9]{20})\\b", &id, error) != 0) return -1;
        if (br_regex_compile("(?i:github)(?:.|[\\n\\r]){0,40}?\\b([a-f0-9]{40})\\b", &secret, error) != 0) { br_regex_free(id); return -1; }
        state = (br_github_oauth2_state){.id_pattern = id, .secret_pattern = secret}; detector.state = &state;
    }
    *out = &detector; return 0;
}
