/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <dlfcn.h>

static size_t fail_size, fail_after, fail_object_after, fail_string_after, fail_add_after;
static size_t allocation_failures;
static test_http *ordered_http;
static size_t ordered_copies, ordered_environments;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (ordered_http && !strcmp(text, ordered_http->send_error)) {
        /* The fake copies before release; the real setter copies after it. */
        CHECK(ordered_http->calls == ordered_copies / 2 + 1);
        CHECK(ordered_http->releases == (ordered_copies + 1) / 2);
        CHECK(ordered_environments == ordered_copies / 2);
        ++ordered_copies;
    }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

struct json_object *json_object_new_object(void)
{
    if (fail_object_after && --fail_object_after == 0) return NULL;
    struct json_object *(*real_new)(void) = NULL;
    void *symbol = dlsym(RTLD_NEXT, "json_object_new_object"); CHECK(symbol);
    memcpy(&real_new, &symbol, sizeof(real_new)); return real_new();
}

struct json_object *json_object_new_string(const char *text)
{
    if (ordered_http) {
        CHECK(ordered_http->releases == ordered_http->calls);
        CHECK(ordered_copies == ordered_http->calls * 2);
        ++ordered_environments;
    }
    if (fail_string_after && --fail_string_after == 0) return NULL;
    struct json_object *(*real_new)(const char *) = NULL;
    void *symbol = dlsym(RTLD_NEXT, "json_object_new_string"); CHECK(symbol);
    memcpy(&real_new, &symbol, sizeof(real_new)); return real_new(text);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

typedef struct {
    const br_detector *detector;
    char keys[2][38], secrets[2][23], input[512];
    const char *url, *environment;
    size_t key_len;
} fixture;

static fixture make_fixture(int version)
{
    fixture f = {.key_len = version == 1 ? 37u : 35u,
        .url = version == 1 ? "https://api.ote-godaddy.com/v1/domains/available?domain=example.com" : "https://api.godaddy.com/v1/domains/available?domain=example.com",
        .environment = version == 1 ? "OTE" : "Prod"};
    char *error = NULL; const br_detector *again = NULL;
    int (*init)(const br_detector **, char **) = version == 1 ? br_godaddy_v1_init : br_godaddy_v2_init;
    CHECK(init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(init(&f.detector, &error) == 0 && !error && f.detector);
    CHECK(init(&again, NULL) == 0 && again == f.detector);
    CHECK(f.detector->type == 1008 && f.detector->version == version && !strcmp(f.detector->name, "GoDaddy"));
    CHECK(f.detector->custom_name && !*f.detector->custom_name);
    CHECK(!strcmp(f.detector->description, "GoDaddy offers website building, hosting and security tools and services to construct, expand and protect the online presence.GoDaddy provides applications and access to relevant third-party products and platforms to connect their customers"));
    CHECK(f.detector->nkeywords == 1 && !strcmp(f.detector->keywords[0], "godaddy"));
    CHECK(f.detector->max_secret_size == -1 && f.detector->start_offset == -1 && f.detector->max_credential_span == -1);
    CHECK(f.detector->state && !f.detector->clean && !f.detector->clean_always && !f.detector->false_positive && !f.detector->validate_endpoints && !f.detector->cloud_endpoint);
    test_secret(f.keys[0], f.key_len, 0); f.keys[0][0] = 'Z'; f.keys[0][17] = '_';
    memcpy(f.keys[1], f.keys[0], f.key_len + 1); f.keys[1][0] = 'z';
    test_secret(f.secrets[0], 22, 7); f.secrets[0][0] = 'Q';
    memcpy(f.secrets[1], f.secrets[0], 23); f.secrets[1][0] = 'q';
    snprintf(f.input, sizeof(f.input), "godaddy %s\nGODADDY %s\ngodaddy %s\ngodaddy %s\ngodaddy %s\ngodaddy %s", f.keys[0], f.secrets[0], f.keys[1], f.secrets[1], f.keys[0], f.secrets[0]);
    return f;
}

static void check_result(const fixture *f, const br_result *r, const char *key, bool verify, bool valid, const char *cause)
{
    CHECK(r->detector_type == 1008 && r->raw.len == f->key_len && !memcmp(r->raw.data, key, f->key_len));
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(!r->verification_from_cache && r->verified == valid);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(r->extra_data && json_object_is_type(r->extra_data, json_type_object));
    CHECK(json_object_object_length(r->extra_data) == (verify ? 1 : 0));
    if (verify) { CHECK(json_object_object_get_ex(r->extra_data, "Environment", &part)); CHECK(!strcmp(json_object_get_string(part), f->environment)); }
}

static void extraction_case(const fixture *f, const char *key_text, const char *secret_text, const char *expected)
{
    char input[512]; snprintf(input, sizeof(input), "%s\n%80s\n%s", key_text, "!", secret_text);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(f->detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(f, &results.items[0], expected, false, false, NULL);
    br_results_clear(&results);
}

static void grammar(const fixture *f)
{
    char k[160], s[160], changed[40]; snprintf(s, sizeof(s), "godaddy %s", f->secrets[0]);
    const char *accepted[] = {"godaddy '%s'", "GODADDY\r\n%s", "mygodaddy-%s-"};
    for (size_t i = 0; i < 3; ++i) { snprintf(k, sizeof(k), accepted[i], f->keys[0]); extraction_case(f, k, s, f->keys[0]); }
    const char *rejected[] = {"%s", "godaddy%s", "godaddy x%s", "godaddy %s_", "godaddy %s9", "godaddy %.34s"};
    for (size_t i = 0; i < 6; ++i) { snprintf(k, sizeof(k), rejected[i], f->keys[0]); extraction_case(f, k, s, NULL); }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(k, sizeof(k), "godaddy%*s%s", (int)gap, "", f->keys[0]); extraction_case(f, k, s, gap == 40 ? f->keys[0] : NULL);
        snprintf(k, sizeof(k), "godaddy %s", f->keys[0]); snprintf(s, sizeof(s), "godaddy%*s%s", (int)gap, "", f->secrets[0]); extraction_case(f, k, s, gap == 40 ? f->keys[0] : NULL);
    }
    snprintf(s, sizeof(s), "godaddy %s", f->secrets[0]);
    const char invalid[] = "-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, f->keys[0], f->key_len + 1); changed[15] = invalid[i]; snprintf(k, sizeof(k), "godaddy %s", changed); extraction_case(f, k, s, NULL);
    }
    snprintf(k, sizeof(k), "godaddy %s", f->keys[0]);
    memcpy(changed, f->secrets[0], 23); changed[10] = '_'; snprintf(s, sizeof(s), "godaddy %s", changed); extraction_case(f, k, s, NULL);
    snprintf(s, sizeof(s), "godaddy %sX", f->secrets[0]); extraction_case(f, k, s, NULL);
    extraction_case(f, k, "", NULL); extraction_case(f, "", "godaddy AbCdEf0123456789GhIjKlM", NULL);
    memset(changed, '_', f->key_len); changed[f->key_len] = '\0'; snprintf(k, sizeof(k), "godaddy %s", changed); snprintf(s, sizeof(s), "godaddy %s", f->secrets[0]); extraction_case(f, k, s, changed);
    br_results empty = test_scan(f->detector, NULL, false, NULL, 0); CHECK(!empty.len); br_results_clear(&empty);
}

typedef struct {
    const fixture *f;
    size_t products, fault_call, fault_size;
    const char *borrowed_auth;
    char auth[69];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t n = http->calls - 1;
    CHECK(ctx && n < s->products && http->releases == n && !s->borrowed_auth);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, s->f->url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1008);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog godaddy-offline"));
    size_t key = s->products == 4 ? n / 2 : 0, secret = s->products == 4 ? n % 2 : 0;
    snprintf(s->auth, sizeof(s->auth), "sso-key %s:%s", s->f->keys[key], s->f->secrets[secret]);
    CHECK(!strcmp(request->headers[0].value, s->auth) && strlen(s->auth) == 9 + s->f->key_len + 22);
    s->borrowed_auth = request->headers[0].value; /* Only provider value survives send. */
    if (http->calls == s->fault_call) { fail_size = s->fault_size; fail_after = 2; }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (http == ordered_http) {
        CHECK(ordered_copies == http->calls * 2 - 1);
        CHECK(ordered_environments == http->calls - 1);
    }
    if (s->borrowed_auth) { CHECK(!strcmp(s->borrowed_auth, s->auth)); s->borrowed_auth = NULL; }
    else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void products_and_outcomes(const fixture *f)
{
    script s = {.f = f, .products = 4}; test_http http = {.user = &s, .inspect = inspect, .response = {.status = 403, .body_error = "ignored"}};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "godaddy-offline"};
    for (int verify = 0; verify < 2; ++verify) {
        http.calls = http.releases = 0;
        br_results results = test_scan(f->detector, &ctx, verify, f->input, strlen(f->input)); CHECK(results.len == 4);
        CHECK(http.calls == (verify ? 4u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 4; ++i) check_result(f, &results.items[i], f->keys[i / 2], verify, verify, NULL);
        CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].extra_data != results.items[1].extra_data); br_results_clear(&results);
    }
    char input[128]; snprintf(input, sizeof(input), "godaddy %s\ngodaddy %s", f->keys[0], f->secrets[0]); s.products = 1;
    const int statuses[] = {200, 403, 401, 201, 204, 299, 400, 429, 503};
    static const unsigned char body[] = {0, 0xff, 'n', 'o'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "" : "ignored read error"};
        br_results results = test_scan(f->detector, &ctx, true, input, strlen(input)); char expected[64]; snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(f, &results.items[0], f->keys[0], true, statuses[i] == 200 || statuses[i] == 403, statuses[i] == 200 || statuses[i] == 403 || statuses[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[300], expected[300];
    snprintf(cause, sizeof(cause), "literal failed to create request: %s; sso-key %s:%s; %s", f->keys[0], f->keys[0], f->secrets[0], f->secrets[0]);
    snprintf(expected, sizeof(expected), "literal failed to create request: %s; sso-key %s:[REDACTED]; [REDACTED]", f->keys[0], f->keys[0]);
    const char *causes[] = {cause, "context deadline exceeded", "cannot create GoDaddy result", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i];
        br_results results = test_scan(f->detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(f, &results.items[0], f->keys[0], true, false, i == 0 ? expected : causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&results);
    }
    br_results results = test_scan(f->detector, NULL, true, input, strlen(input)); CHECK(results.len == 1); check_result(f, &results.items[0], f->keys[0], true, false, "net/http: nil Context"); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }

static void setup_errors(const fixture *f)
{
    char input[128]; snprintf(input, sizeof(input), "godaddy %s\ngodaddy %s", f->keys[0], f->secrets[0]);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        script s = {.f = f}; test_http http = {.user = &s}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL, .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results results = test_scan(f->detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u) && !fail_after);
        check_result(f, &results.items[0], f->keys[0], true, false, causes[mode]); br_results_clear(&results);
    }
}

static void resource_failures(const fixture *f)
{
    br_result seed = {0}; br_results out = {0}; CHECK(br_finding_key(&seed, 777, "caller", "key") == 0); seed.verified = true; CHECK(br_results_push(&out, &seed) == 0);
    unsigned char *original = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts;
    const char *expected[] = {"out of memory copying detector capture", "cannot create GoDaddy result", "cannot create GoDaddy extra data", "cannot create GoDaddy environment", "cannot store GoDaddy environment", "cannot store GoDaddy verification error", "cannot append GoDaddy result", "cannot create GoDaddy result", "out of memory copying detector capture"};
    for (int mode = 0; mode < 9; ++mode) {
        char *error = NULL; size_t capacity = out.cap;
        script s = {.f = f, .products = 4}; test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "godaddy-offline"};
        switch (mode) {
        case 0: fail_size = f->key_len + 1; fail_after = 1; break;
        case 1: fail_add_after = 3; break; /* Late finding failure after first append. */
        case 2: fail_object_after = 2; break; /* Extra object, before nil context. */
        case 3: fail_string_after = 2; break;
        case 4: fail_add_after = 4; break;
        case 5: fail_size = sizeof("net/http: nil Context"); fail_after = 2; break;
        case 6: out.cap = 0; break; /* Actual +1 push guard. */
        case 7: fail_size = f->key_len; fail_after = 2; break;
        case 8: fail_size = 23; fail_after = 2; break; /* Hidden secret capture. */
        }
        size_t before = allocation_failures;
        CHECK(f->detector->scan(f->detector, mode == 2 || mode == 5 ? NULL : &ctx, true, (br_slice){(const unsigned char *)f->input, strlen(f->input)}, &out, &error) == -1);
        out.cap = capacity;
        CHECK(error && !strcmp(error, expected[mode]) && !fail_after && !fail_object_after && !fail_string_after && !fail_add_after);
        CHECK(out.len == 1 && out.items[0].raw.data == original && out.items[0].secret_parts == parts && out.items[0].verified && !memcmp(original, "caller", 6));
        CHECK(http.calls == http.releases && !s.borrowed_auth);
        if (mode == 0 || mode == 5 || mode == 7 || mode == 8) CHECK(allocation_failures == before + 1);
        free(error);
    }
    /* Observe fake copy -> release -> real setter copy -> Environment. The
     * second setter copy fails (+1): no second Environment, and rollback must
     * preserve caller data after the earlier error-bearing product. */
    script s = {.f = f, .products = 4, .fault_call = 2, .fault_size = sizeof("synthetic leaf cause copy")};
    test_http http = {.user = &s, .inspect = inspect, .send_rc = 1, .send_error = "synthetic leaf cause copy"};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "godaddy-offline"}; char *error = NULL;
    ordered_http = &http; ordered_copies = ordered_environments = 0;
    CHECK(f->detector->scan(f->detector, &ctx, true, (br_slice){(const unsigned char *)f->input, strlen(f->input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot store GoDaddy verification error") && !fail_after && http.calls == 2 && http.releases == 2 && !s.borrowed_auth);
    CHECK(ordered_copies == 4 && ordered_environments == 1);
    ordered_http = NULL;
    CHECK(out.len == 1 && out.items[0].raw.data == original && out.items[0].secret_parts == parts); free(error); br_results_clear(&out);
    br_result probe = {0}; probe.verification_error = strdup("keep"); char *saved = probe.verification_error;
    CHECK(br_result_set_verification_error(&probe, NULL, NULL, 0) == 0 && probe.verification_error == saved); br_result_clear(&probe);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    fixture v1 = make_fixture(1), v2 = make_fixture(2);
    CHECK(v1.detector != v2.detector && v1.detector->state != v2.detector->state);
    grammar(&v1); grammar(&v2);
    char wrong_key[80], secret[80];
    snprintf(wrong_key, sizeof(wrong_key), "godaddy %s", v2.keys[0]);
    snprintf(secret, sizeof(secret), "godaddy %s", v1.secrets[0]);
    extraction_case(&v1, wrong_key, secret, NULL);
    snprintf(wrong_key, sizeof(wrong_key), "godaddy %s", v1.keys[0]);
    extraction_case(&v2, wrong_key, secret, NULL);
    products_and_outcomes(&v1); products_and_outcomes(&v2);
    setup_errors(&v1); setup_errors(&v2);
    resource_failures(&v1); resource_failures(&v2);
    return test_finish("GoDaddy v1/v2");
}
