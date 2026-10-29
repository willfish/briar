/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define ROLE "01234567-89ab-cdef-0123-456789abcdef"
#define ROLE2 "fedcba98-7654-3210-fedc-ba9876543210"
#define SECRET "ABCDEF01-2345-6789-aBcD-EF0123456789"
#define SECRET2 "abcdef01-2345-6789-abcd-ef0123456789"
#define ORIGIN "https://offline.hashicorp.cloud"
#define URL ORIGIN "/vault//./parent/../"
#define SUFFIX "/v1/auth/approle/login"
#define PAYLOAD "{\"role_id\":\"" ROLE "\",\"secret_id\":\"" SECRET "\"}"
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static br_slice view(br_bytes b) { return (br_slice){b.data, b.len}; }

/* Targeted real resource failures, confined to this executable and using the
 * existing test support. No provider-specific production fault interface. */
static size_t fail_size, fail_after, allocation_failures, fail_push_size;
static const char *fail_field, *fail_duplicate;
static size_t fail_field_after, fail_duplicate_after;
static bool arm_shared_headers;
static const char *watch_text;
static size_t watch_copies;
static test_http *watch_http;
void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, n);
}
void *realloc(void *old, size_t n)
{
    if (fail_push_size && n == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!n) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(n);
    if (copy) { if (old) memcpy(copy, old, before < n ? before : n); free(old); }
    return copy;
}
char *strdup(const char *s)
{
    if (watch_text && !strcmp(s, watch_text)) {
        ++watch_copies;
        CHECK(watch_http && watch_http->calls == 1);
        CHECK(watch_http->releases == (watch_copies == 1 ? 0u : 1u));
    }
    if (fail_duplicate_after && !strcmp(s, fail_duplicate) && --fail_duplicate_after == 0) {
        ++allocation_failures; return NULL;
    }
    size_t n = strlen(s) + 1; char *copy = malloc(n);
    if (copy) memcpy(copy, s, n);
    return copy;
}
int json_object_object_add(br_json *object, const char *name, br_json *value)
{
    if (fail_field_after && !strcmp(name, fail_field) && --fail_field_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_shared_headers && !strcmp(name, "URL")) {
        arm_shared_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

static br_bytes input_for(const char *role, const char *secret, br_slice url)
{
    char first[300];
    int n = snprintf(first, sizeof(first), "role %s\n%64s\nsecret %s\n", role, "", secret);
    CHECK(n > 0 && (size_t)n < sizeof(first));
    br_bytes input = {.len = (size_t)n + url.len + 1};
    input.data = malloc(input.len + 1); CHECK(input.data);
    memcpy(input.data, first, (size_t)n);
    if (url.len) memcpy(input.data + n, url.data, url.len);
    input.data[input.len - 1] = '\n'; input.data[input.len] = 0;
    return input;
}
static void field(br_json *map, const char *name, br_slice expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(map, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len));
}
static void finding(const br_result *r, const char *role, const char *secret, br_slice url, bool verified, const char *cause)
{
    CHECK(r->detector_type == 1036 && !r->detector_name && r->raw.len == 36 && !memcmp(r->raw.data, secret, 36));
    CHECK(r->raw_v2.len == 73 && !memcmp(r->raw_v2.data, role, 36) && r->raw_v2.data[36] == ':' && !memcmp(r->raw_v2.data + 37, secret, 36));
    CHECK(!r->redacted && !r->structured_data && !r->verification_from_cache && r->verified == verified);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    field(r->secret_parts, "role_id", text(role)); field(r->secret_parts, "secret_id", text(secret));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1); field(r->extra_data, "URL", url);
    CHECK((r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(ROLE) == 36 && strlen(SECRET) == 36 && strlen(ROLE2) == 36 && strlen(SECRET2) == 36);
    CHECK(br_hashicorpvaultauth_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_hashicorpvaultauth_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:role)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_hashicorpvaultauth_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    fail_size = sizeof("(?i:secret)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_hashicorpvaultauth_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_hashicorpvaultauth_init(&d, &error) == 0 && d && !error);
    CHECK(br_hashicorpvaultauth_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1036 && d->version == 0 && !strcmp(d->name, "HashiCorpVaultAuth") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "HashiCorp Vault AppRole authentication method uses role_id and secret_id for machine-to-machine authentication. These credentials can be used to authenticate with Vault and obtain tokens for accessing secrets."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "hashicorp"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && d->validate_endpoints && !d->cloud_endpoint);
    br_endpoints empty = {0}; const char *one[] = {""};
    CHECK(d->validate_endpoints(&empty, &error) != 0 && error); free(error); error = NULL;
    empty.configured = one; empty.nconfigured = 1;
    CHECK(d->validate_endpoints(&empty, &error) == 0 && !error);
    return d;
}

static void extraction(const br_detector *d)
{
    const char *bad_roles[] = {"", "01234567-89ab-Cdef-0123-456789abcdef", "_" ROLE, ROLE "_", ROLE "0", "01234567-89ab-cdef-0123-456789abcde"};
    for (size_t i = 0; i < sizeof(bad_roles) / sizeof(*bad_roles); ++i) {
        br_bytes input = input_for(bad_roles[i], SECRET, TEXT(URL));
        br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    const char *bad_secrets[] = {"", "GBCDEF01-2345-6789-aBcD-EF0123456789", "_" SECRET, SECRET "_", SECRET "A"};
    for (size_t i = 0; i < sizeof(bad_secrets) / sizeof(*bad_secrets); ++i) {
        br_bytes input = input_for(ROLE, bad_secrets[i], TEXT(URL));
        br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    const char *no_urls[] = {"", "HTTPS://offline.hashicorp.cloud/path", "https://offline.HASHICORP.cloud/path", "https://vault.invalid/path", "https://hashicorp.cloud/path"};
    for (size_t i = 0; i < sizeof(no_urls) / sizeof(*no_urls); ++i) {
        br_bytes input = input_for(ROLE, SECRET, text(no_urls[i]));
        br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    char input[700];
    for (size_t which = 0; which < 2; ++which) for (size_t gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "RoLe%*s%s\n%64s\nSeCrEt%*s%s\n%s", (int)(which ? 1 : gap), "", ROLE, "", (int)(which ? gap : 1), "", SECRET, URL);
        CHECK(n > 0); br_results out = test_scan(d, NULL, false, input, (size_t)n); CHECK(out.len == (gap == 40 ? 1u : 0u));
        if (out.len) finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, NULL);
        br_results_clear(&out);
    }
    int n = snprintf(input, sizeof(input), "RoLe\r\n%s\n%64s\nSeCrEt\r\n%s\n%s", ROLE, "", SECRET, URL);
    CHECK(n > 0); br_results out = test_scan(d, NULL, false, input, (size_t)n); CHECK(out.len == 1);
    finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, NULL); br_results_clear(&out);
    /* Prefix distance counts runes, not bytes. Only keyword scope folds case. */
    size_t at = 0; memcpy(input, "ROLE", 4); at = 4;
    for (size_t i = 0; i < 40; ++i) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
    n = snprintf(input + at, sizeof(input) - at, "%s\n%64s\nSECRET %s\n%s", ROLE, "", SECRET, URL); CHECK(n > 0);
    out = test_scan(d, NULL, false, input, at + (size_t)n); CHECK(out.len == 1); finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, NULL); br_results_clear(&out);
}

static void endpoints_and_bytes(const br_detector *d)
{
    const br_slice addresses[] = {
        TEXT(URL), TEXT("http://offline.hashicorp.cloud:999999/a"),
        TEXT(ORIGIN "/a\0b/c"), TEXT(ORIGIN "/a\vb/\xc2\xa0mid"),
        TEXT(ORIGIN "/quote\"?q=%2f#fragment"), TEXT("https://x.hashicorp.cloud.hashicorp.cloud/path"),
        TEXT("https://user@offline.hashicorp.cloud/path"), TEXT("https://off\vline.hashicorp.cloud/path"),
    };
    for (size_t i = 0; i < sizeof(addresses) / sizeof(*addresses); ++i) {
        br_bytes input = input_for(ROLE, SECRET, addresses[i]);
        test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results out = test_scan(d, &ctx, false, input.data, input.len); CHECK(out.len == 1 && !http.calls && !http.releases);
        finding(&out.items[0], ROLE, SECRET, addresses[i], false, NULL); br_results_clear(&out); free(input.data);
    }
    br_bytes input = input_for(ROLE, SECRET, TEXT(URL "\v\xc2\x85\xc2\xa0\xe1\x9a\x80\xe2\x80\x83\xe2\x80\xa8\xe3\x80\x80"));
    br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, NULL); br_results_clear(&out); free(input.data);
    input = input_for(ROLE, SECRET, TEXT(URL "\xe2\x80\x8b")); /* U+200B is NOT Go whitespace. */
    out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); finding(&out.items[0], ROLE, SECRET, TEXT(URL "\xe2\x80\x8b"), false, NULL); br_results_clear(&out); free(input.data);
    input = input_for(ROLE, SECRET, TEXT(URL "\n" URL "\v\xc2\xa0"));
    const char *configured[] = {URL, URL, "https://configured.invalid/p", ""};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 4, .cloud = URL, .use_cloud = true, .use_found = true};
    br_scan_ctx ctx = {.endpoints = &endpoints};
    out = test_scan(d, &ctx, false, input.data, input.len); CHECK(out.len == 3);
    finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, NULL);
    finding(&out.items[1], ROLE, SECRET, TEXT("https://configured.invalid/p"), false, NULL);
    finding(&out.items[2], ROLE, SECRET, TEXT(""), false, NULL); br_results_clear(&out);
    endpoints = (br_endpoints){0};
    out = test_scan(d, &ctx, true, input.data, input.len); CHECK(!out.len); br_results_clear(&out);
    endpoints = (br_endpoints){.cloud = "https://configured.invalid/cloud", .use_cloud = true};
    out = test_scan(d, &ctx, false, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], ROLE, SECRET, TEXT("https://configured.invalid/cloud"), false, NULL); br_results_clear(&out);
    endpoints = (br_endpoints){.configured = configured + 3, .nconfigured = 1};
    out = test_scan(d, &ctx, false, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], ROLE, SECRET, TEXT(""), false, NULL); br_results_clear(&out); free(input.data);
}

typedef struct {
    const char *role, *secret; br_slice url;
    int status, send_rc; br_slice body; const char *read_error, *send_error;
    const char *fail_cause; bool fail_setter, fail_push;
} row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx;
    const char *borrowed_url; br_slice borrowed_body;
    char *mutate_read_error;
} script;
static void request_bytes(const br_http_request *request, const row *r)
{
    CHECK(strlen(request->url) == r->url.len + sizeof(SUFFIX) - 1);
    CHECK(!r->url.len || !memcmp(request->url, r->url.data, r->url.len));
    CHECK(!memcmp(request->url + r->url.len, SUFFIX, sizeof(SUFFIX)));
    char expected[160]; int n = snprintf(expected, sizeof(expected), "{\"role_id\":\"%s\",\"secret_id\":\"%s\"}", r->role, r->secret);
    CHECK(n > 0 && request->body.len == (size_t)n && !memcmp(request->body.data, expected, (size_t)n));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at && !s->borrowed_url && !s->borrowed_body.data);
    const row *r = &s->rows[at];
    CHECK(!strcmp(request->method, "POST") && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 1036);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Vault-Namespace") && !strcmp(request->headers[1].value, "admin"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog approle-offline" : "TruffleHog"));
    request_bytes(request, r);
    s->borrowed_url = request->url; s->borrowed_body = request->body;
    http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error};
    http->send_rc = r->send_rc; http->send_error = r->send_error;
    if (r->fail_cause) { fail_duplicate = r->fail_cause; fail_duplicate_after = 1; }
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_url) {
        br_http_request borrowed = {.url = s->borrowed_url, .body = s->borrowed_body};
        request_bytes(&borrowed, &s->rows[http->calls - 1]);
        const row *r = &s->rows[http->calls - 1];
        if (r->fail_setter) { fail_duplicate = r->read_error ? r->read_error : r->send_error; CHECK(fail_duplicate); fail_duplicate_after = 1; }
        if (r->fail_push) fail_push_size = 2 * sizeof(br_result);
        if (s->mutate_read_error) s->mutate_read_error[0] = '!';
    } else {
        CHECK(!response->status && !response->body.data && !response->body_error && !s->borrowed_body.data);
    }
    s->borrowed_url = NULL; s->borrowed_body = (br_slice){0}; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice input, bool verify, script *s, const br_endpoints *endpoints, bool suffix)
{
    test_http http = {.inspect = inspect_request, .user = s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = suffix ? "approle-offline" : NULL, .endpoints = endpoints}; s->ctx = &ctx;
    watch_http = &http;
    br_results out = test_scan(d, &ctx, verify, input.data, input.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url && !s->borrowed_body.data);
    watch_http = NULL;
    return out;
}
static br_results one(const br_detector *d, row r)
{
    if (!r.role) r.role = ROLE;
    if (!r.secret) r.secret = SECRET;
    if (!r.url.data) r.url = TEXT(URL);
    br_bytes input = input_for(r.role, r.secret, r.url); script s = {.rows = &r, .count = 1};
    br_results out = run(d, view(input), true, &s, NULL, false); CHECK(out.len == 1); free(input.data); return out;
}
static void statuses_and_errors(const br_detector *d)
{
    const row cases[] = {
        {.status = 200, .body = TEXT("\0\xffnot JSON"), .read_error = "ignored read"},
        {.status = 200, .read_error = ""},
        {.status = 400, .body = TEXT("invalid role or secret ID")},
        {.status = 400, .body = TEXT("prefix\0invalid role or secret ID\xffsuffix")},
        {.status = 400, .body = TEXT("invalid role or secret ID"), .read_error = "read failed"},
        {.status = 400, .body = TEXT("invalid role or secret ID"), .read_error = ""},
    };
    const char *causes[] = {NULL, NULL, NULL, NULL, "read failed", ""};
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, cases[i]); finding(&out.items[0], ROLE, SECRET, TEXT(URL), i < 2, causes[i]); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 201, 204, 299, 302, 400, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        row r = {.status = statuses[i], .body = TEXT("Invalid role or secret ID"), .read_error = statuses[i] == 400 ? NULL : "ignored"};
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        br_results out = one(d, r); finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, cause); br_results_clear(&out);
    }
    char echo[400]; snprintf(echo, sizeof(echo), "mixed setup: %s / %s / %s / %s", ROLE, SECRET, URL, ROLE);
    const char *send_causes[] = {echo, "", NULL, "cannot marshal HashiCorp Vault AppRole JSON payload", "unsupported HashiCorp Vault AppRole request URL form", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_causes) / sizeof(*send_causes); ++i) {
        row r = {.status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = send_causes[i]};
        const char *cause = i == 0 ? "mixed setup: [REDACTED] / [REDACTED] / [REDACTED] / [REDACTED]" : send_causes[i] ? send_causes[i] : "HTTP transport failed";
        br_results out = one(d, r); finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, cause); br_results_clear(&out);
    }
    snprintf(echo, sizeof(echo), "read %s %s %s", ROLE, SECRET, URL);
    row r = {.role = ROLE, .secret = SECRET, .url = TEXT(URL), .status = 400, .read_error = echo};
    br_bytes input = input_for(ROLE, SECRET, TEXT(URL)); script s = {.rows = &r, .count = 1, .mutate_read_error = echo};
    char watched[400]; memcpy(watched, echo, strlen(echo) + 1); watch_text = watched; watch_copies = 0;
    br_results out = run(d, view(input), true, &s, NULL, true); CHECK(watch_copies == 2 && echo[0] == '!'); watch_text = NULL;
    finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, "read [REDACTED] [REDACTED] [REDACTED]"); br_results_clear(&out); free(input.data);
}

static void products_and_long_input(const br_detector *d)
{
    char input[5000]; int n = snprintf(input, sizeof(input), "role %s\nrole %s\nrole %s\n%2048s\nsecret %s\nsecret %s\nsecret %s\n%s\n%s\n%s\v\xc2\xa0\n", ROLE, ROLE2, ROLE, "", SECRET, SECRET2, SECRET, URL, ORIGIN "/other", URL); CHECK(n > 0 && (size_t)n < sizeof(input));
    row rows[8]; const char *roles[] = {ROLE, ROLE2}, *secrets[] = {SECRET, SECRET2}; br_slice urls[] = {TEXT(URL), TEXT(ORIGIN "/other")};
    for (size_t i = 0; i < 8; ++i) rows[i] = (row){.role = roles[i / 4], .secret = secrets[(i / 2) % 2], .url = urls[i % 2], .status = i % 2 ? 400 : 200, .body = TEXT("invalid role or secret ID")};
    script none = {0}; br_results out = run(d, (br_slice){(const unsigned char *)input, (size_t)n}, false, &none, NULL, false); CHECK(out.len == 8);
    for (size_t i = 0; i < 8; ++i) finding(&out.items[i], rows[i].role, rows[i].secret, rows[i].url, false, NULL);
    br_results_clear(&out);
    script s = {.rows = rows, .count = 8}; out = run(d, (br_slice){(const unsigned char *)input, (size_t)n}, true, &s, NULL, true); CHECK(out.len == 8);
    for (size_t i = 0; i < 8; ++i) finding(&out.items[i], rows[i].role, rows[i].secret, rows[i].url, i % 2 == 0, NULL);
    br_results_clear(&out);
    char long_url[3000]; memcpy(long_url, ORIGIN "/", sizeof(ORIGIN));
    memset(long_url + sizeof(ORIGIN), 'x', sizeof(long_url) - sizeof(ORIGIN) - 1); long_url[sizeof(long_url) - 1] = 0;
    row r = {.role = ROLE, .secret = SECRET, .url = text(long_url), .status = 200, .read_error = "ignored"};
    out = one(d, r); finding(&out.items[0], ROLE, SECRET, text(long_url), true, NULL); br_results_clear(&out);
    /* Configured endpoints need not match the discovery regex or keyword. */
    br_bytes data = input_for(ROLE, SECRET, TEXT("")); const char *configured[] = {"http://-.invalid:999999/a//../_~", "http://-.invalid:999999/a//../_~"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 2, .cloud = configured[0], .use_cloud = true};
    r.url = text(configured[0]); s = (script){.rows = &r, .count = 1}; out = run(d, view(data), true, &s, &endpoints, false); CHECK(out.len == 1);
    finding(&out.items[0], ROLE, SECRET, r.url, true, NULL); br_results_clear(&out); free(data.data);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key"); free(error); br_results_clear(out);
}
static bool cancelled(void *user) { (void)user; return true; }
static void constructor_and_shared_failures(const br_detector *d)
{
    br_bytes input = input_for(ROLE, SECRET, TEXT(ORIGIN "/a\0b"));
    br_results out = test_scan(d, NULL, true, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], ROLE, SECRET, TEXT(ORIGIN "/a\0b"), false, "net/http: nil Context"); br_results_clear(&out); free(input.data);
    const br_slice unsupported[] = {TEXT(ORIGIN "/a\0b"), TEXT(ORIGIN "/a\vb"), TEXT(ORIGIN "/\xc3\xa9"), TEXT(ORIGIN "/q?x"), TEXT(ORIGIN "/%2f"), TEXT("https://user@offline.hashicorp.cloud/path")};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i) {
        input = input_for(ROLE, SECRET, unsupported[i]); test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        out = caller_owned(); char *error = NULL; int rc = d->scan(d, &ctx, true, view(input), &out, &error);
        CHECK(!http.calls && !http.releases && error && strstr(error, "unsupported HashiCorp Vault AppRole request URL form")); rolled_back(&out, rc, error); free(input.data);
    }
    input = input_for(ROLE, SECRET, TEXT(URL));
    for (size_t i = 0; i < 5; ++i) {
        script s = {0}; test_http http = {.user = &s}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport};
        const char *causes[] = {"context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers", "HTTP transport not installed"};
        if (i == 0) ctx.cancelled = cancelled;
        if (i == 1) ctx.deadline_monotonic_ms = 1;
        if (i == 2) ctx.user_agent = "bad\nagent";
        if (i == 3) arm_shared_headers = true;
        if (i == 4) ctx.transport = NULL;
        out = test_scan(d, &ctx, true, input.data, input.len); CHECK(out.len == 1 && !http.calls && http.releases == (i == 4 ? 0u : 1u));
        finding(&out.items[0], ROLE, SECRET, TEXT(URL), false, causes[i]); br_results_clear(&out);
    }
    free(input.data);
    const char *configured[] = {""}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1}; br_scan_ctx ctx = {.endpoints = &endpoints};
    input = input_for(ROLE, SECRET, TEXT("")); out = caller_owned(); char *error = NULL;
    int rc = d->scan(d, &ctx, true, view(input), &out, &error); CHECK(error && strstr(error, "unsupported")); rolled_back(&out, rc, error); free(input.data);
}
static int invoke(const br_detector *d, br_slice input, script *s, br_results *out, char **error)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url && !s->borrowed_body.data); return rc;
}
static void owned_failures_and_rollback(const br_detector *d)
{
    br_bytes input = input_for(ROLE, SECRET, TEXT(URL));
    /* Capture, final endpoint copies, finding bytes, marshal and literal URL
     * allocations must fail even when nil context would otherwise be retained. */
    const size_t sizes[] = {37, sizeof(URL), sizeof(URL), sizeof(URL), 36, 73, sizeof(PAYLOAD), sizeof(URL) + sizeof(SUFFIX) - 1};
    const size_t counts[] = {1, 1, 2, 3, 1, 1, 1, 1};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = counts[i]; int rc = d->scan(d, NULL, true, view(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    const char *fields[] = {"role_id", "secret_id", "URL"};
    for (size_t i = 0; i < 3; ++i) {
        br_results out = caller_owned(); char *error = NULL; fail_field = fields[i]; fail_field_after = 1;
        int rc = d->scan(d, NULL, true, view(input), &out, &error); CHECK(!fail_field_after); rolled_back(&out, rc, error);
    }
    row r = {.role = ROLE, .secret = SECRET, .url = TEXT(URL), .status = 400, .read_error = "distinct synthetic read cause"};
    for (size_t i = 0; i < 4; ++i) {
        r.fail_cause = i == 0 ? r.read_error : i == 2 ? "unexpected HTTP response status 500" : NULL;
        r.fail_setter = i == 1; r.fail_push = i == 3; r.status = i == 2 ? 500 : 400;
        script s = {.rows = &r, .count = 1}; br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        if (i == 3) out.cap = out.len;
        int rc = invoke(d, view(input), &s, &out, &error); CHECK(!fail_duplicate_after && !fail_push_size && allocation_failures == before + 1);
        if (i == 1) CHECK(error && !strcmp(error, "cannot set HashiCorp Vault AppRole verification error"));
        rolled_back(&out, rc, error);
    }
    /* A later failure rolls back this invocation's already verified product,
     * without clearing an unrelated caller finding or skipping the release. */
    free(input.data); input = input_for(ROLE, SECRET, TEXT(URL "\n" ORIGIN "/later"));
    row rows[] = {{.role = ROLE, .secret = SECRET, .url = TEXT(URL), .status = 200},
                  {.role = ROLE, .secret = SECRET, .url = TEXT(ORIGIN "/later"), .status = 400, .read_error = "later read", .fail_setter = true}};
    script s = {.rows = rows, .count = 2}; br_results out = caller_owned(); char *error = NULL;
    int rc = invoke(d, view(input), &s, &out, &error); CHECK(!fail_duplicate_after); rolled_back(&out, rc, error); free(input.data);
    input = input_for(ROLE, SECRET, TEXT(URL "\n" ORIGIN "/?unsupported"));
    s = (script){.rows = rows, .count = 1}; out = caller_owned(); error = NULL;
    rc = invoke(d, view(input), &s, &out, &error); CHECK(error && strstr(error, "unsupported")); rolled_back(&out, rc, error); free(input.data);
    out = caller_owned(); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error && out.len == 1); free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    endpoints_and_bytes(d);
    statuses_and_errors(d);
    products_and_long_input(d);
    constructor_and_shared_failures(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_field_after && !fail_duplicate_after && !fail_push_size && !arm_shared_headers);
    return test_finish("HashiCorpVaultAuth");
}
