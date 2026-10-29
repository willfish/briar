/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <dlfcn.h>

#define br_result_set_verification_error harness_real_setter
#define br_results_push harness_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

static size_t fail_size, fail_after, fail_object_after, fail_tokener_after;
static size_t fail_key_after, fail_meta_after, fail_setter_after, fail_push_after;
static size_t allocation_failures, tokener_calls, setter_calls;
static const char *fail_duplicate;
static bool fail_login_string;
static test_http *ordered_http;
static bool ordered_verified;
static const char *ordered_login;
static char key[73], other[73], input[512];

/* Exercise actual common-helper failure conventions, including +1. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    if (fail_duplicate && !strcmp(text, fail_duplicate)) {
        fail_duplicate = NULL; ++allocation_failures; return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}
struct json_object *json_object_new_object(void)
{
    if (fail_object_after && --fail_object_after == 0) { ++allocation_failures; return NULL; }
    struct json_object *(*real_new)(void);
    void *symbol = dlsym(RTLD_NEXT, "json_object_new_object"); CHECK(symbol);
    memcpy(&real_new, &symbol, sizeof(real_new)); return real_new();
}
struct json_object *json_object_new_string_len(const char *text, const int len)
{
    if (fail_login_string && len == 1 && text[0] == '7') {
        fail_login_string = false; ++allocation_failures; return NULL;
    }
    struct json_object *(*real_new)(const char *, int);
    void *symbol = dlsym(RTLD_NEXT, "json_object_new_string_len"); CHECK(symbol);
    memcpy(&real_new, &symbol, sizeof(real_new)); return real_new(text, len);
}
struct json_tokener *json_tokener_new_ex(int depth)
{
    ++tokener_calls;
    if (fail_tokener_after && --fail_tokener_after == 0) { ++allocation_failures; return NULL; }
    struct json_tokener *(*real_new)(int);
    void *symbol = dlsym(RTLD_NEXT, "json_tokener_new_ex"); CHECK(symbol);
    memcpy(&real_new, &symbol, sizeof(real_new)); return real_new(depth);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    if (!strcmp(name, "last_login") && fail_meta_after && --fail_meta_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static void login_check(const br_result *r, const char *expected)
{
    if (!expected) { CHECK(!r->extra_data); return; }
    br_json *value = NULL;
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
    CHECK(json_object_object_get_ex(r->extra_data, "last_login", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), expected));
}
int br_result_set_verification_error(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    CHECK(count == 1 && secrets && secrets[0].len == 72);
    CHECK(r->raw.len == 72 && !memcmp(r->raw.data, secrets[0].data, 72));
    if (ordered_http) {
        CHECK(ordered_http->calls == ordered_http->releases);
        CHECK(r->verified == ordered_verified);
        login_check(r, ordered_login);
    }
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return harness_real_setter(r, cause, secrets, count);
}
int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return harness_real_push(out, owned);
}

static void result_check(const br_result *r, const char *token, bool verified,
                         const char *login, const char *cause)
{
    br_result plain = *r; plain.extra_data = NULL;
    test_key_result(&plain, 1020, token, "key");
    CHECK(r->raw.len == 72 && r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    login_check(r, login);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_harness_init(NULL, &error) == -1 && error); free(error);
    CHECK(br_harness_init(&d, &error) == 0 && d && !error);
    CHECK(br_harness_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1020 && d->version == 0 && !strcmp(d->name, "Harness") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Harness.io is an AI-driven CI/CD platform that automates software delivery, streamlining code building, testing, and deployment with intelligent optimization and multi-cloud support."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "harness"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->scan && d->state && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    memcpy(key, "pat.", 4); test_secret(key + 4, 22, 1); key[5] = 'Q'; key[8] = '_'; key[26] = '.';
    const char hex[] = "a19b28c37d46e50f";
    for (size_t i = 0; i < 24; ++i) key[27 + i] = hex[i % (sizeof(hex) - 1)];
    key[51] = '.'; test_secret(key + 52, 20, 5); key[60] = 'Z';
    memcpy(other, key, sizeof(key)); other[5] = 'q';
    CHECK(strlen(key) == 72 && strlen(other) == 72);
    return d;
}
static void extraction_case(const br_detector *d, const void *text, size_t len, bool match)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = setter_calls;
    br_results r = test_scan(d, &ctx, false, text, len);
    CHECK(r.len == (match ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (match) result_check(&r.items[0], key, false, NULL, NULL);
    br_results_clear(&r);
}
static void extraction(const br_detector *d)
{
    const char *good[] = {"harness %s", "HaRnEsS\r\n%s", "myharness: '%s'", "harness (%s)", "harness %s-"};
    const char *bad[] = {"%s", "harness%s", "harness x%s", "harness _%s", "harness %s_", "harness %sX", "harness %.71s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, strlen(input), true);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, strlen(input), false);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "harness%*s%s", (int)gap, "", key);
        extraction_case(d, input, strlen(input), gap == 40);
        memcpy(input, "harness", 7);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 7 + i * 2, "\xc3\xa9", 2);
        memcpy(input + 7 + gap * 2, key, 73);
        extraction_case(d, input, 7 + gap * 2 + 72, gap == 40);
    }
    const struct { size_t at; char byte; } changes[] = {
        {0, 'P'}, {2, 'T'}, {3, '-'}, {26, '-'}, {51, '-'}, {10, '-'}, {27, 'A'}, {50, 'g'}, {60, '_'},
    };
    char changed[73];
    for (size_t i = 0; i < sizeof(changes) / sizeof(*changes); ++i) {
        memcpy(changed, key, 73); changed[changes[i].at] = changes[i].byte;
        snprintf(input, sizeof(input), "harness %s", changed); extraction_case(d, input, strlen(input), false);
    }
    memcpy(input, "harness\0", 8); memcpy(input + 8, key, 72); extraction_case(d, input, 80, true);
    extraction_case(d, NULL, 0, false);
    snprintf(input, sizeof(input), "harness %s\nharness %s\nharness %s", key, other, key);
    br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 2);
    result_check(&r.items[0], key, false, NULL, NULL); result_check(&r.items[1], other, false, NULL, NULL); br_results_clear(&r);
    snprintf(input, sizeof(input), "harness %s %s", key, other);
    r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 1);
    result_check(&r.items[0], key, false, NULL, NULL); br_results_clear(&r);
}

typedef struct {
    const char *tokens[2], *borrowed_token;
    char *poison_body;
    size_t arm_call, objects, tokeners;
    bool string;
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx && http->calls == http->releases + 1 && !s->borrowed_token);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.harness.io/ng/api/user/currentUser"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1020);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(http->calls <= 2 && !strcmp(request->headers[0].value, s->tokens[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog harness-offline"));
    s->borrowed_token = request->headers[0].value; /* Only ORIGINAL provider storage. */
    if (http->calls == s->arm_call) {
        fail_object_after = s->objects; fail_tokener_after = s->tokeners; fail_login_string = s->string;
    }
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_token && !strcmp(s->borrowed_token, s->tokens[http->calls - 1]));
    s->borrowed_token = NULL;
    if (s->poison_body) memset(s->poison_body, '!', strlen(s->poison_body));
    test_http_release(user, response);
}
static void outcome(const br_detector *d, int status, const char *body, const char *read_error,
                    int send_rc, const char *send_error, bool verified, const char *login, const char *cause)
{
    script s = {.tokens = {key}};
    test_http http = {.user = &s, .inspect = inspect, .send_rc = send_rc, .send_error = send_error,
        .response = {.status = status, .body = {(const unsigned char *)body, strlen(body)}, .body_error = read_error}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "harness-offline"};
    snprintf(input, sizeof(input), "harness %s", key);
    ordered_http = &http; ordered_verified = verified; ordered_login = login;
    size_t before = setter_calls;
    br_results r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_token && setter_calls == before + 1);
    result_check(&r.items[0], key, verified, login, cause);
    ordered_http = NULL; br_results_clear(&r);
}
static void verification(const br_detector *d)
{
    const struct { const char *body, *login; } decoded[] = {
        {"{}", "0"}, {"null", "0"}, {"{\"data\":null}", "0"}, {"{\"data\":{}}", "0"},
        {"{\"data\":{\"lastLogin\":null}}", "0"}, {"{\"data\":{\"lastLogin\":-0}}", "0"},
        {"{\"data\":{\"lastLogin\":9007199254740993}}", "9007199254740993"},
        {"{\"data\":{\"lastLogin\":9223372036854775807}}", "9223372036854775807"},
        {"{\"data\":{\"lastLogin\":-9223372036854775808}}", "-9223372036854775808"},
        {"{\"DATA\":{\"LASTLOGIN\":3,\"lastLogin\":7,\"lastLogin\":null},\"data\":null,\"data\":{}}", "7"},
        {"{\"data\":{\"lastLogin\":9},\"data\":{\"lastLogin\":-42}}", "-42"},
        {"{\"d\\u0061ta\":{\"la\\u017ftLogin\":11}}", "11"},
        {"{\"unknown\":1e999999,\"data\":{\"lastLogin\":7,\"ignored\":999999999999999999999999999999}}", "7"},
        {"{\"data\":{\"lastLogin\":7}} trailing {", "7"},
    };
    for (size_t i = 0; i < sizeof(decoded) / sizeof(*decoded); ++i)
        outcome(d, 200, decoded[i].body, NULL, 0, NULL, true, decoded[i].login, NULL);
    const char *invalid[] = {
        "", "{", "not JSON", "[]", "7", "true", "\"text\"", "{\"data\":[]}",
        "{\"data\":{\"lastLogin\":\"7\"}}", "{\"data\":{\"lastLogin\":1.0}}", "{\"data\":{\"lastLogin\":1e0}}",
        "{\"data\":{\"lastLogin\":9223372036854775808}}", "{\"data\":{\"lastLogin\":-9223372036854775809}}",
        "{\"data\":{\"lastLogin\":1e999999}}", "{\"data\":false,\"data\":{\"lastLogin\":7}}",
        "{\"data\":{\"lastLogin\":false,\"lastLogin\":7}}", "{\"data\":{\"lastLogin\":7,\"lastLogin\":{}}}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i)
        outcome(d, 200, invalid[i], NULL, 0, NULL, true, NULL, NULL);
    outcome(d, 200, "{\"data\":{\"lastLogin\":7}}", "later read failure", 0, NULL, true, "7", NULL);
    outcome(d, 200, "{\"data\":{\"lastLogin\":7", "partial read failure", 0, NULL, true, NULL, NULL);
    outcome(d, 200, "", "", 0, NULL, true, NULL, NULL);
    outcome(d, 401, "{", "ignored", 0, NULL, false, NULL, NULL);
    const int statuses[] = {0, 201, 204, 299, 400, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char expected[64]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", statuses[i]);
        outcome(d, statuses[i], "{}", "ignored", 0, NULL, false, NULL, expected);
    }
    char exposed[256]; snprintf(exposed, sizeof(exposed), "send %s then %s", key, key);
    outcome(d, 200, "{}", NULL, 1, exposed, false, NULL, "send [REDACTED] then [REDACTED]");
    const char *causes[] = {"context canceled", "context deadline exceeded", "out of memory constructing HTTP headers", "cannot allocate Harness metadata", ""};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i)
        outcome(d, 200, "{}", NULL, -7, causes[i], false, NULL, causes[i]);
    outcome(d, 200, "{}", NULL, 1, NULL, false, NULL, "HTTP transport failed");

    char body[] = "{\"data\":{\"lastLogin\":7}}";
    script s = {.tokens = {key, other}, .poison_body = body};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "harness-offline"};
    snprintf(input, sizeof(input), "harness %s", key);
    br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(http.calls == 1 && http.releases == 1);
    result_check(&r.items[0], key, true, "7", NULL); CHECK(body[0] == '!'); br_results_clear(&r);
    s.poison_body = NULL; http.calls = http.releases = 0; http.response = (br_http_response){.status = 401};
    snprintf(input, sizeof(input), "harness %s\nharness %s\nharness %s", key, other, key);
    r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 2 && http.calls == 2 && http.releases == 2); br_results_clear(&r);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static void setup(const br_detector *d)
{
    snprintf(input, sizeof(input), "harness %s", key);
    br_results r = test_scan(d, NULL, true, input, strlen(input));
    result_check(&r.items[0], key, false, NULL, "net/http: nil Context"); br_results_clear(&r);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = i ? &transport : NULL, .cancelled = i == 1 ? cancelled : i == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = i == 2 ? 1 : 0, .user_agent = i == 3 ? "bad\r\nagent" : NULL};
        r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(!http.calls && http.releases == (i ? 1u : 0u) && !fail_after);
        result_check(&r.items[0], key, false, NULL, causes[i]); br_results_clear(&r);
    }
    br_result probe = {0}; probe.verification_error = strdup("caller-owned"); CHECK(probe.verification_error);
    char *original = probe.verification_error;
    CHECK(harness_real_setter(&probe, NULL, NULL, 0) == 0 && probe.verification_error == original);
    fail_duplicate = "setter probe";
    CHECK(harness_real_setter(&probe, "setter probe", NULL, 0) == 1 && !fail_duplicate && probe.verification_error == original);
    br_result_clear(&probe);
}

static void fatal_scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_results *out, const char *expected)
{
    br_result caller = out->items[0]; char *error = NULL;
    CHECK(d->scan(d, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, &error) == -1);
    CHECK(error && !strcmp(error, expected));
    CHECK(out->len == 1 && !memcmp(&out->items[0], &caller, sizeof(caller)));
    CHECK(!fail_after && !fail_object_after && !fail_tokener_after && !fail_key_after && !fail_meta_after && !fail_setter_after && !fail_push_after && !fail_duplicate && !fail_login_string);
    free(error);
}
static void resources(const br_detector *d)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 777, "caller", "key") == 0);
    caller.verified = true; caller.verification_error = strdup("caller-owned"); CHECK(caller.verification_error);
    CHECK(br_results_push(&out, &caller) == 0);
    snprintf(input, sizeof(input), "harness %s\nharness %s", key, other);
    /* Capture/regex failures happen before any constructor or transport attempt. */
    fail_size = 73; fail_after = 2;
    fatal_scan(d, NULL, true, &out, "out of memory copying detector capture");
    fail_size = 2 * sizeof(br_span); fail_after = 1;
    fatal_scan(d, NULL, false, &out, "out of memory iterating regex");
    /* Late finding, insertion and push failures roll back an earlier append. */
    fail_size = 72; fail_after = 2;
    fatal_scan(d, NULL, false, &out, "cannot create Harness finding");
    fail_key_after = 2;
    fatal_scan(d, NULL, false, &out, "cannot create Harness finding");
    fail_push_after = 2;
    fatal_scan(d, NULL, false, &out, "cannot append Harness finding");

    script s = {.tokens = {key, other}};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "harness-offline"};
    /* An initial map failure cannot be swallowed by the malformed-body fallback. */
    s.arm_call = 1; s.objects = 1; size_t before = tokener_calls;
    fatal_scan(d, &ctx, true, &out, "cannot allocate Harness metadata");
    CHECK(http.calls == 1 && http.releases == 1 && tokener_calls == before);
    s.objects = 0; s.tokeners = 1; http.calls = http.releases = 0;
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 1 && http.releases == 1);

    const char *body = "{\"data\":false,\"data\":{\"lastLogin\":7}}";
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    http.calls = http.releases = 0; s.arm_call = 2; s.tokeners = 4;
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 2 && http.releases == 2); /* Continued AFTER first ordinary type error. */
    body = "{\"data\":{\"lastLogin\":false,\"lastLogin\":7}}";
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    http.calls = http.releases = 0; s.tokeners = 6;
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 2 && http.releases == 2);
    s.arm_call = 0; s.tokeners = 0; http.calls = http.releases = 0;
    fail_duplicate = "json: cannot unmarshal bool into Go struct field .data.lastLogin of type int";
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 1 && http.releases == 1);
    /* A later numeric-cause allocation must beat an earlier ordinary type error. */
    body = "{\"data\":{\"lastLogin\":false,\"lastLogin\":9223372036854775808}}";
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    http.calls = http.releases = 0;
    fail_size = sizeof("json: cannot unmarshal number ") - 1 +
        sizeof(" into Go struct field .data.lastLogin of type int") + 19;
    fail_after = 1;
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 1 && http.releases == 1);
    http.response.body = (br_slice){0}; http.calls = http.releases = 0; fail_duplicate = "EOF";
    fatal_scan(d, &ctx, true, &out, "cannot decode Harness response");
    CHECK(http.calls == 1 && http.releases == 1);

    body = "{\"data\":{\"lastLogin\":7}}";
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    http.calls = http.releases = 0; s.arm_call = 2; s.string = true;
    fatal_scan(d, &ctx, true, &out, "cannot allocate Harness last login");
    CHECK(http.calls == 2 && http.releases == 2);
    s.arm_call = 0; s.string = false; http.calls = http.releases = 0; fail_meta_after = 2;
    fatal_scan(d, &ctx, true, &out, "cannot insert Harness last login");
    CHECK(http.calls == 2 && http.releases == 2);
    /* NULL-cause setters are still called/checked after successful publication. */
    http.calls = http.releases = 0; fail_setter_after = 2;
    ordered_http = &http; ordered_verified = true; ordered_login = "7";
    fatal_scan(d, &ctx, true, &out, "cannot store Harness verification error");
    CHECK(http.calls == 2 && http.releases == 2); ordered_http = NULL;
    http.calls = http.releases = 0; http.response.status = 500;
    fail_duplicate = "unexpected HTTP response status 500";
    fatal_scan(d, &ctx, true, &out, "cannot store Harness verification error");
    CHECK(http.calls == 1 && http.releases == 1);
    fail_duplicate = "net/http: nil Context";
    fatal_scan(d, NULL, true, &out, "cannot store Harness verification error");
    CHECK(allocation_failures >= 13 && !s.borrowed_token);
    br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); verification(d); setup(d); resources(d);
    return test_finish("Harness");
}
