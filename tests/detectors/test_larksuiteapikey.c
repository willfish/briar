/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error larksuite_real_setter
#define br_results_push larksuite_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_larksuiteapikey_init(const br_detector **out, char **error);

/* Inclusion seam: the library visitor cannot return +1 after a successful walk. */
static int larksuite_seam_visit(br_slice, br_json_member_fn, void *);
#define br_json_each_member larksuite_seam_visit
#define br_larksuiteapikey_init observed_larksuiteapikey_init
#include "../../src/detectors/larksuiteapikey.c"
#undef br_json_each_member
#undef br_larksuiteapikey_init

static char ida[21], idb[21], seca[33], secb[33];
static const char description[] =
    "LarkSuite is a collaboration platform that provides tools for communication, calendar, and cloud storage. LarkSuite API keys can be used to access and manage these services programmatically.";
static const char url[] = "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal";
static size_t fail_size, fail_after, fail_key_after, fail_push_after, fail_setter_after, setter_calls, body_allocations;
static size_t setters_before_visit;
static bool track_body, visit_before_setter;
static int fail_visit;
static char seen_secret[64];
static size_t seen_secret_len;

void *malloc(size_t size)
{
    if (track_body && size == 85) ++body_allocations;
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    seen_secret_len = 0;
    if (count == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(seen_secret)) {
        memcpy(seen_secret, secrets[0].data, secrets[0].len);
        seen_secret[secrets[0].len] = '\0';
        seen_secret_len = secrets[0].len;
    }
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return larksuite_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return larksuite_real_push(out, owned);
}

static void fill_id(char *out, const char *tail)
{
    memcpy(out, "cli_", 4);
    memcpy(out + 4, tail, 16);
    out[20] = '\0';
}

static void fill_secret(char *out, char fill)
{
    memset(out, fill, 32);
    out[32] = '\0';
}

static size_t add_marked(char *buf, size_t cap, size_t at, const char *keyword, const char *key)
{
    int n = snprintf(buf + at, cap - at, "%s %s ", keyword, key);
    CHECK(n > 0 && (size_t)n < cap - at);
    return at + (size_t)n;
}

static void result_is(const br_result *result, const char *id, const char *secret, bool verified, const char *cause)
{
    CHECK(result->detector_type == 992 && !result->detector_name);
    CHECK(result->raw.len == 20 && !memcmp(result->raw.data, id, 20));
    CHECK(result->raw_v2.len == 52 && !memcmp(result->raw_v2.data, id, 20));
    CHECK(!memcmp(result->raw_v2.data + 20, secret, 32) && result->verified == verified);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), id, 20));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), secret, 32));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    fill_id(ida, "AbCdEfGh12345678");
    fill_id(idb, "aaaaaaaaaaaaaaaa");
    fill_secret(seca, 'c');
    fill_secret(secb, 'd');
    CHECK(BR_ABI_REVISION == 1 && strlen(ida) == 20 && strlen(seca) == 32);
    CHECK(br_larksuiteapikey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LarkSuiteApiKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_larksuiteapikey_init(NULL, NULL) == -1);
    CHECK(br_larksuiteapikey_init(&d, &error) == 0 && d && !error);
    CHECK(br_larksuiteapikey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 992 && d->version == 0 && !strcmp(d->name, "LarkSuiteApiKey") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(d->nkeywords == 3 && !strcmp(d->keywords[0], "lark") && !strcmp(d->keywords[1], "larksuite"));
    CHECK(!strcmp(d->keywords[2], "cli_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, text, len);
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[320];
    size_t n = add_marked(input, sizeof(input), 0, "lark", idb);
    n = add_marked(input, sizeof(input), n, "larksuite", ida);
    n = add_marked(input, sizeof(input), n, "LARK", secb);
    n = add_marked(input, sizeof(input), n, "LarkSuite", seca);
    n = add_marked(input, sizeof(input), n, "lark", idb);
    br_results out = test_scan(d, &ctx, false, input, n);
    CHECK(out.len == 4 && !http.calls && !setter_calls);
    result_is(&out.items[0], idb, secb, false, NULL);
    result_is(&out.items[1], idb, seca, false, NULL);
    result_is(&out.items[2], ida, secb, false, NULL);
    result_is(&out.items[3], ida, seca, false, NULL);
    br_results_clear(&out);

    n = add_marked(input, sizeof(input), 0, "lark", ida);
    expect_none(d, input, n);
    n = add_marked(input, sizeof(input), 0, "larksuite", seca);
    expect_none(d, input, n);
    n = snprintf(input, sizeof(input), "cli_ note %s %s", ida, seca);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "lark%s lark %s", ida, seca);
    expect_none(d, input, (size_t)n);

    n = snprintf(input, sizeof(input), "lark %s %s", ida, seca);
    out = test_scan(d, &ctx, false, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false, NULL);
    br_results_clear(&out);

    memcpy(input, "lark", 4);
    memset(input + 4, '.', 40);
    memcpy(input + 44, ida, 20);
    memcpy(input + 64, " lark ", 6);
    memcpy(input + 70, seca, 32);
    out = test_scan(d, &ctx, false, input, 102);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false, NULL);
    br_results_clear(&out);
    memset(input + 4, '.', 41);
    memcpy(input + 45, ida, 20);
    out = test_scan(d, &ctx, false, input, 65);
    CHECK(!out.len);
    br_results_clear(&out);

    char wide[1300];
    n = add_marked(wide, sizeof(wide), 0, "lark", ida);
    memset(wide + n, '.', 1100);
    n += 1100;
    n = add_marked(wide, sizeof(wide), n, "lark", seca);
    out = test_scan(d, &ctx, false, wide, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false, NULL);
    br_results_clear(&out);
    CHECK(!http.calls && !http.releases);
}

static void expect_body(const char *body, size_t len, const char *id, const char *secret)
{
    char want[96];
    int n = snprintf(want, sizeof(want), "{\"app_id\": \"%s\", \"app_secret\": \"%s\"}", id, secret);
    CHECK(n == 84 && (size_t)n == len && body && !memcmp(body, want, (size_t)n));
}

typedef struct {
    const char *id[4];
    const char *secret[4];
    const char *borrowed_body;
    size_t borrowed_len;
    int status, send_rc;
    const char *send_error, *body_error, *body;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *id = s->id[http->calls - 1];
    const char *secret = s->secret[http->calls - 1];
    CHECK(ctx && http->calls == http->releases + 1 && id && secret);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 992);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    expect_body((const char *)request->body.data, request->body.len, id, secret);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(strcmp(request->headers[0].name, "Authorization") != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog larksuite-offline"));
    s->borrowed_body = (const char *)request->body.data;
    s->borrowed_len = request->body.len;
    http->response = (br_http_response){
        .status = s->status,
        .body = {(const unsigned char *)s->body, s->body ? strlen(s->body) : 0},
        .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (visit_before_setter)
        CHECK(setter_calls == setters_before_visit);
    if (s->borrowed_body) {
        expect_body(s->borrowed_body, s->borrowed_len, s->id[http->releases], s->secret[http->releases]);
        s->borrowed_body = NULL;
    }
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.id = {ida}, .secret = {seca}, .status = 200, .body = "{\"code\":0,\"msg\":\"ok\"}"};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "larksuite-offline"};
    char input[160];
    size_t n = add_marked(input, sizeof(input), 0, "lark", ida);
    n = add_marked(input, sizeof(input), n, "lark", seca);
    size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_body);
    CHECK(setter_calls == before + 1 && seen_secret_len == 20 && !strcmp(seen_secret, ida));
    result_is(&out.items[0], ida, seca, true, NULL);
    br_results_clear(&out);

    const char *successes[] = {"{}", "{\"msg\":\"ignored\"}", "{\"code\":null}", "null", "{\"code\":0,\"msg\":null}"};
    for (size_t i = 0; i < sizeof(successes) / sizeof(successes[0]); ++i) {
        s.body = successes[i];
        s.body_error = NULL;
        s.status = 200;
        s.send_rc = 0;
        http.calls = http.releases = 0;
        before = setter_calls;
        out = test_scan(d, &ctx, true, input, n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == before + 1);
        result_is(&out.items[0], ida, seca, true, NULL);
        br_results_clear(&out);
    }

    char message[160];
    CHECK(snprintf(message, sizeof(message), "{\"code\":12,\"msg\":\"no %s %s\"}", ida, seca) > 0);
    s.body = message;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    char want[160];
    CHECK(snprintf(want, sizeof(want), "verification failed code 12, message no [REDACTED] %s", seca) > 0);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], ida, seca, false, want);
    CHECK(!strstr(out.items[0].verification_error, ida));
    CHECK(strstr(out.items[0].verification_error, seca) != NULL);
    CHECK(!strcmp(seen_secret, ida));
    br_results_clear(&out);

    s.body = "{\"code\":\"bad\",\"code\":0,\"msg\":\"later\"}";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false,
              "json: cannot unmarshal string into Go struct field verificationResponse.code of type int");
    br_results_clear(&out);

    s.body = "{\"code\":1e2}";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false,
              "json: cannot unmarshal number 1e2 into Go struct field verificationResponse.code of type int");
    br_results_clear(&out);

    s.body = "{\"msg\":false}";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false,
              "json: cannot unmarshal bool into Go struct field verificationResponse.msg of type string");
    br_results_clear(&out);

    s.body = "{";
    s.body_error = "read failed";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false, "read failed");
    CHECK(strcmp(out.items[0].verification_error, "failed to decode response") != 0);
    br_results_clear(&out);

    s.body = "{\"code\":9,\"msg\":\"used\"}";
    s.body_error = "ignored on non-200";
    s.status = 500;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == before + 1);
    result_is(&out.items[0], ida, seca, false, NULL);
    br_results_clear(&out);

    s.status = 401;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ida, seca, false, NULL);
    br_results_clear(&out);

    char rejected[120];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s %s", ida, seca) == 62);
    s.status = 200;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    char redacted[80];
    CHECK(snprintf(redacted, sizeof(redacted), "rejected [REDACTED] %s", seca) > 0);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], ida, seca, false, redacted);
    CHECK(strstr(out.items[0].verification_error, seca) != NULL);
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "larksuite-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, input, n);
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    result_is(&out.items[0], ida, seca, false, "context canceled");
    br_results_clear(&out);

    track_body = true;
    size_t bodies = body_allocations, setters = setter_calls;
    http.calls = http.releases = 0;
    char wide[200];
    size_t w = add_marked(wide, sizeof(wide), 0, "lark", idb);
    w = add_marked(wide, sizeof(wide), w, "lark", ida);
    w = add_marked(wide, sizeof(wide), w, "lark", secb);
    w = add_marked(wide, sizeof(wide), w, "lark", seca);
    out = test_scan(d, NULL, true, wide, w);
    CHECK(out.len == 4 && !http.calls && !http.releases && body_allocations == bodies + 4);
    CHECK(setter_calls == setters + 4);
    result_is(&out.items[0], idb, secb, false, "net/http: nil Context");
    result_is(&out.items[1], idb, seca, false, "net/http: nil Context");
    result_is(&out.items[2], ida, secb, false, "net/http: nil Context");
    result_is(&out.items[3], ida, seca, false, "net/http: nil Context");
    CHECK(!strcmp(seen_secret, ida));
    br_results_clear(&out);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(out->items[0].verified && !strcmp(out->items[0].verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[160];
    size_t n = add_marked(input, sizeof(input), 0, "lark", ida);
    n = add_marked(input, sizeof(input), n, "lark", seca);
    n = add_marked(input, sizeof(input), n, "lark", secb);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.id = {ida, ida}, .secret = {seca, secb}, .status = 200, .body = "{\"code\":0}"};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "larksuite-offline"};
    char *error = NULL;

    fail_key_after = 1;
    size_t bodies = body_allocations, setters = setter_calls;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LarkSuiteApiKey finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && body_allocations == bodies && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record LarkSuiteApiKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && body_allocations == bodies + 1);
    prior_unchanged(&out, &prior);

    bodies = body_allocations;
    fail_size = 85;
    fail_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing LarkSuite request body") && !fail_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && body_allocations == bodies + 1);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    s.status = 500;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record LarkSuiteApiKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_body);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
}

static int larksuite_seam_visit(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    if (rc != 0) return rc;
    if (!fail_visit) return 0;
    int injected = fail_visit;
    fail_visit = 0;
    return injected;
}

static void body_before_nil(const br_detector *d)
{
    char input[80];
    size_t n = add_marked(input, sizeof(input), 0, "lark", ida);
    n = add_marked(input, sizeof(input), n, "lark", seca);
    br_slice data = {(const unsigned char *)input, n};
    track_body = true;
    size_t bodies = body_allocations, setters = setter_calls;
    br_results out = test_scan(d, NULL, true, input, n);
    CHECK(out.len == 1 && body_allocations == bodies + 1 && setter_calls == setters + 1);
    CHECK(seen_secret_len == 20 && !strcmp(seen_secret, ida));
    result_is(&out.items[0], ida, seca, false, "net/http: nil Context");
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    bodies = body_allocations;
    setters = setter_calls;
    fail_size = 85;
    fail_after = 1;
    char *error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing LarkSuite request body") && !fail_after);
    CHECK(body_allocations == bodies + 1 && setter_calls == setters);
    prior_unchanged(&out, &prior);
    free(error);
    br_results_clear(&out);
}

static void visitor_plus_one(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_larksuiteapikey_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_larksuiteapikey_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[80];
    size_t n = add_marked(input, sizeof(input), 0, "lark", ida);
    n = add_marked(input, sizeof(input), n, "lark", seca);
    br_slice data = {(const unsigned char *)input, n};
    const char *bodies[] = {
        "{\"code\":0,\"msg\":\"ok\"}",
        "{\"code\":\"bad\",\"code\":0,\"msg\":\"later\"}",
    };
    script s = {.id = {ida}, .secret = {seca}, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "larksuite-offline"};
    visit_before_setter = true;
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        s.body = bodies[i];
        s.borrowed_body = NULL;
        http.calls = http.releases = 0;
        setters_before_visit = setter_calls;
        fail_visit = 1;
        CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot decode LarkSuite verification response") && !fail_visit);
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_body);
        CHECK(setter_calls == setters_before_visit);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    visit_before_setter = false;
    br_results_clear(&out);
}

static void nul_message(const br_detector *d)
{
    char input[80];
    size_t n = add_marked(input, sizeof(input), 0, "lark", ida);
    n = add_marked(input, sizeof(input), n, "lark", seca);
    br_slice data = {(const unsigned char *)input, n};
    script s = {.id = {ida}, .secret = {seca}, .status = 200, .body = "{\"code\":12,\"msg\":\"ab\\u0000cd\"}"};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "larksuite-offline"};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    size_t setters = setter_calls;
    char *error = NULL;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: LarkSuiteApiKey verification message contains embedded NUL"));
    CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_body && setter_calls == setters);
    prior_unchanged(&out, &prior);
    free(error);
    error = NULL;

    s.body = "{\"code\":0,\"msg\":\"ab\\u0000cd\"}";
    http.calls = http.releases = 0;
    br_results kept = test_scan(d, &ctx, true, input, n);
    CHECK(kept.len == 1 && http.releases == 1);
    result_is(&kept.items[0], ida, seca, true, NULL);
    br_results_clear(&kept);

    s.body = "{\"code\":\"bad\",\"msg\":\"ab\\u0000cd\"}";
    http.calls = http.releases = 0;
    kept = test_scan(d, &ctx, true, input, n);
    CHECK(kept.len == 1);
    result_is(&kept.items[0], ida, seca, false,
              "json: cannot unmarshal string into Go struct field verificationResponse.code of type int");
    br_results_clear(&kept);

    s.status = 500;
    s.body = "{\"code\":12,\"msg\":\"ab\\u0000cd\"}";
    http.calls = http.releases = 0;
    setters = setter_calls;
    kept = test_scan(d, &ctx, true, input, n);
    CHECK(kept.len == 1 && http.releases == 1 && setter_calls == setters + 1);
    result_is(&kept.items[0], ida, seca, false, NULL);
    br_results_clear(&kept);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    body_before_nil(d);
    visitor_plus_one();
    nul_message(d);
    return test_finish("LarkSuiteApiKey");
}
