/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"
#include <string.h>

/* Inclusion seam: the owned source is compiled here so tests can observe the
 * mandatory setter count and inject visitor +1 without a shared helper. */
static int larksuite_intercept_setter(br_result *result, const char *cause,
                                      const br_slice *secrets, size_t nsecrets);
static int larksuite_intercept_visit(br_slice object, br_json_member_fn callback, void *user);
static char *larksuite_test_strdup(const char *text);
#define br_result_set_verification_error larksuite_intercept_setter
#define br_json_each_member larksuite_intercept_visit
#define strdup larksuite_test_strdup
#include "../../src/detectors/larksuite.c"
#undef strdup
#undef br_json_each_member
#undef br_result_set_verification_error

static int setter_inject, visit_inject;
static size_t setter_calls, setter_count, releases_at_setter, seam_releases, visit_members;
static size_t empty_strdup_attempts;
static bool fail_empty_strdup;
static unsigned char setter_bytes[64];
static br_slice setter_secret;
static const char *setter_cause_seen;

typedef struct {
    br_json_member_fn fn;
    void *user;
} member_wrap;

static int counting_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    member_wrap *wrap = user;
    ++visit_members;
    return wrap->fn(wrap->user, name, value, encoded);
}

static int larksuite_intercept_setter(br_result *result, const char *cause,
                                      const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_count = nsecrets;
    setter_secret = (br_slice){0};
    if (secrets && nsecrets && secrets[0].data && secrets[0].len <= sizeof(setter_bytes)) {
        memcpy(setter_bytes, secrets[0].data, secrets[0].len);
        setter_secret = (br_slice){setter_bytes, secrets[0].len};
    }
    setter_cause_seen = cause;
    releases_at_setter = seam_releases;
    if (setter_inject) return setter_inject;
    return br_result_set_verification_error(result, cause, secrets, nsecrets);
}

static int larksuite_intercept_visit(br_slice object, br_json_member_fn callback, void *user)
{
    member_wrap wrap = {callback, user};
    int rc = br_json_each_member(object, counting_member, &wrap);
    if (visit_inject && rc == 0) return visit_inject;
    return rc;
}

static char *larksuite_test_strdup(const char *text)
{
    if (text && !*text) ++empty_strdup_attempts;
    if (fail_empty_strdup && text && !*text) return NULL;
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const char tenant[] = "t-1234567890abcd";
static const char user[] = "u-1234567890abcd";
static const char app[] = "a-1234567890abcd";
static const char other[] = "t-1234567890abce";
static size_t fail_part_after;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(tenant) == 16 && strlen(user) == 16 && strlen(app) == 16);
    CHECK(br_larksuite_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LarkSuite detector output"));
    free(error);
    error = NULL;
    CHECK(br_larksuite_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_larksuite_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 991 && detector->version == 0 && !strcmp(detector->name, "LarkSuite"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "LarkSuite is a collaborative suite that includes chat, calendar, and cloud storage features. The detected token can be used to access and interact with these services."));
    CHECK(detector->nkeywords == 2 && detector->keywords);
    CHECK(!strcmp(detector->keywords[0], "lark") && !strcmp(detector->keywords[1], "larksuite"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    CHECK(detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *key, const char *token_type)
{
    CHECK(result->detector_type == 991);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, result->raw.len));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), key));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    br_json *extra = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "token_type", &extra));
    CHECK(json_object_is_type(extra, json_type_string) && !strcmp(json_object_get_string(extra), token_type));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_nov(const br_detector *detector, const void *data, size_t len,
                       const char *key, const char *token_type)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, data, len);
    CHECK(http.calls == 0 && http.releases == 0);
    if (!key) CHECK(out.len == 0);
    else {
        CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
        expect_key(&out.items[0], key, token_type);
    }
    br_results_clear(&out);
}

static void grammar(const br_detector *detector)
{
    char input[160];
    CHECK(snprintf(input, sizeof(input), "lark %s", tenant) > 0);
    expect_nov(detector, input, strlen(input), tenant, "Tenant Access Token");
    CHECK(snprintf(input, sizeof(input), "TENANT %s", tenant) > 0);
    expect_nov(detector, input, strlen(input), tenant, "Tenant Access Token");
    CHECK(snprintf(input, sizeof(input), "user %s", user) > 0);
    expect_nov(detector, input, strlen(input), user, "User Access Token");
    CHECK(snprintf(input, sizeof(input), "larksuite %s", app) > 0);
    expect_nov(detector, input, strlen(input), app, "App Access Token");
    CHECK(snprintf(input, sizeof(input), "app %s", app) > 0);
    expect_nov(detector, input, strlen(input), app, "App Access Token");
    expect_nov(detector, tenant, strlen(tenant), NULL, NULL);
    expect_nov(detector, "lark", 4, NULL, NULL);

    CHECK(snprintf(input, sizeof(input), "lark-%s", tenant) > 0);
    expect_nov(detector, input, strlen(input), NULL, NULL);
    CHECK(snprintf(input, sizeof(input), "lark %s-", tenant) > 0);
    expect_nov(detector, input, strlen(input), NULL, NULL);
    char short_token[16];
    memcpy(short_token, tenant, 15);
    short_token[15] = '\0';
    CHECK(snprintf(input, sizeof(input), "lark %s", short_token) > 0);
    expect_nov(detector, input, strlen(input), NULL, NULL);
    char long_token[56];
    memcpy(long_token, "t-", 2);
    memset(long_token + 2, 'a', 51);
    long_token[53] = '\0';
    CHECK(snprintf(input, sizeof(input), "lark %s", long_token) > 0);
    expect_nov(detector, input, strlen(input), NULL, NULL);
    memset(long_token + 2, 'a', 50);
    long_token[52] = '\0';
    CHECK(snprintf(input, sizeof(input), "lark %s", long_token) > 0);
    expect_nov(detector, input, strlen(input), long_token, "Tenant Access Token");

    char gap[80];
    memcpy(gap, "lark", 4);
    memset(gap + 4, ' ', 41);
    memcpy(gap + 45, tenant, 16);
    expect_nov(detector, gap, 61, tenant, "Tenant Access Token");
    memset(gap + 4, ' ', 42);
    memcpy(gap + 46, tenant, 16);
    expect_nov(detector, gap, 62, NULL, NULL);

    CHECK(snprintf(input, sizeof(input), "user %s tenant %s", user, tenant) > 0);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], tenant, "Tenant Access Token");
    expect_key(&out.items[1], user, "User Access Token");
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "lark %s tenant %s lark %s", tenant, other, tenant) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], tenant, "Tenant Access Token");
    expect_key(&out.items[1], other, "Tenant Access Token");
    br_results_clear(&out);
}

typedef struct {
    const char *key, *url, *send_error, *body_error, *body;
    int status, send_rc;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    const char *authorization;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    char expected[80];
    CHECK(snprintf(expected, sizeof(expected), "Bearer %s", row->key) == (int)strlen(row->key) + 7);
    CHECK(request->detector_type == 991 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, row->url));
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, expected));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    steps->authorization = request->headers[0].value;
    http->response = (br_http_response){
        .status = row->status,
        .body = {(const unsigned char *)row->body, row->body ? strlen(row->body) : 0},
        .body_error = row->body_error,
    };
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *steps = http->user;
    size_t at = http->releases;
    char expected[80];
    CHECK(at < steps->count && steps->authorization);
    CHECK(snprintf(expected, sizeof(expected), "Bearer %s", steps->rows[at].key) > 0);
    CHECK(!strcmp(steps->authorization, expected));
    steps->authorization = NULL;
    ++seam_releases;
    test_http_release(user, response);
}

static br_results verify_scan(const br_detector *detector, const void *data, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, data, len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->authorization);
    return out;
}

static void verification(const br_detector *detector)
{
    char input[128];
    CHECK(snprintf(input, sizeof(input), "user %s app %s lark %s", user, app, tenant) > 0);
    const reply rows[] = {
        {.key = tenant, .url = "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
         .status = 500, .body = "{\"CODE\":0}"},
        {.key = user, .url = "https://open.larksuite.com/open-apis/authen/v1/user_info",
         .status = 401, .body = "{\"code\":20005,\"msg\":\"bad\"}"},
        {.key = app, .url = "https://open.larksuite.com/open-apis/calendar/v4/calendars",
         .status = 404, .body = "{\"code\":123,\"msg\":\"nope\"}"},
    };
    script steps = {.rows = rows, .count = 3};
    br_results out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 3);
    expect_key(&out.items[0], tenant, "Tenant Access Token");
    CHECK(out.items[0].verified && !out.items[0].verification_error);
    expect_key(&out.items[1], user, "User Access Token");
    CHECK(!out.items[1].verified && !out.items[1].verification_error);
    expect_key(&out.items[2], app, "App Access Token");
    CHECK(!out.items[2].verified && out.items[2].verification_error);
    CHECK(!strcmp(out.items[2].verification_error, "verification failed (status 404, code 123): nope"));
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "lark %s", tenant) > 0);
    const reply success[] = {
        {.key = tenant, .url = rows[0].url, .status = 200, .body = "{}"},
        {.key = tenant, .url = rows[0].url, .status = 201, .body = "{\"code\":null}"},
        {.key = tenant, .url = rows[0].url, .status = 200, .body = "{\"code\":99991672,\"msg\":\"special\"}"},
    };
    for (size_t i = 0; i < 3; ++i) {
        steps = (script){.rows = &success[i], .count = 1};
        out = verify_scan(detector, input, strlen(input), &steps);
        CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
        expect_key(&out.items[0], tenant, "Tenant Access Token");
        br_results_clear(&out);
    }

    const reply failed = {.key = tenant, .url = rows[0].url, .status = 200,
                          .body = "{\"code\":7,\"msg\":\"t-1234567890abcd\"}"};
    steps = (script){.rows = &failed, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error, "verification failed (status 200, code 7): [REDACTED]"));
    CHECK(!strstr(out.items[0].verification_error, tenant));
    expect_key(&out.items[0], tenant, "Tenant Access Token");
    br_results_clear(&out);

    const reply typed = {.key = tenant, .url = rows[0].url, .status = 200, .body = "{\"code\":\"0\"}"};
    steps = (script){.rows = &typed, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error,
                  "failed to decode response (status 200): json: cannot unmarshal string into Go struct field verificationResponse.code of type int"));
    br_results_clear(&out);

    const reply unread = {.key = tenant, .url = rows[0].url, .status = 200, .body = "",
                          .body_error = "synthetic read failure"};
    steps = (script){.rows = &unread, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified &&
          !strcmp(out.items[0].verification_error, "failed to decode response (status 200): synthetic read failure"));
    br_results_clear(&out);
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void nil_and_send(const br_detector *detector)
{
    char input[64];
    CHECK(snprintf(input, sizeof(input), "lark %s", tenant) > 0);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    prior.extra_data = json_object_new_object();
    CHECK(prior.verification_error && prior.extra_data);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    br_json *extra = out.items[0].extra_data;
    char *error = NULL;
    test_http http = {0};
    br_transport transport = test_transport(&http);
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0);
    CHECK(!error && out.len == 2 && http.calls == 0 && http.releases == 0);
    CHECK(out.items[0].raw.data == raw && out.items[0].extra_data == extra && out.items[0].secret_parts == parts);
    CHECK(out.items[0].verification_error == saved);
    CHECK(!out.items[1].verified && out.items[1].extra_data);
    CHECK(!strcmp(out.items[1].verification_error, "net/http: nil Context"));
    expect_key(&out.items[1], tenant, "Tenant Access Token");
    br_results_clear(&out);

    char cause[80];
    CHECK(snprintf(cause, sizeof(cause), "dial %s", tenant) > 0);
    const reply row = {.key = tenant, .url = "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
                       .status = 200, .send_rc = 1, .send_error = cause, .body = "{\"code\":0}"};
    script steps = {.rows = &row, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified && out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error, "dial [REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 0 && http.releases == 1);
    CHECK(!out.items[0].verified && out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error, "context canceled"));
    br_results_clear(&out);
}

static void set_raw(br_result *result, char *text)
{
    result->raw.data = (unsigned char *)text;
    result->raw.len = strlen(text);
}

static void false_positives(const br_detector *detector)
{
    char json[] = "notes.JSON", pdf[] = "dir/file.PDF", slash[] = "dir\\file.json";
    char earlier[] = "1234.5678/90", sample[] = "sample", token[] = "t-1234567890abcd";
    br_result result = {0};
    char *reason = NULL;
    set_raw(&result, json);
    CHECK(detector->false_positive(detector, &result, &reason) && reason && !*reason);
    free(reason);
    size_t before = empty_strdup_attempts;
    CHECK(detector->false_positive(detector, &result, NULL));
    CHECK(empty_strdup_attempts == before);
    reason = (char *)1;
    fail_empty_strdup = true;
    CHECK(detector->false_positive(detector, &result, &reason) && !reason);
    fail_empty_strdup = false;
    CHECK(empty_strdup_attempts == before + 1);
    set_raw(&result, pdf);
    reason = NULL;
    CHECK(detector->false_positive(detector, &result, &reason) && reason && !*reason);
    free(reason);
    set_raw(&result, slash);
    reason = NULL;
    CHECK(detector->false_positive(detector, &result, &reason) && reason && !*reason);
    free(reason);
    set_raw(&result, earlier);
    reason = (char *)1;
    CHECK(!detector->false_positive(detector, &result, &reason) && !reason);

    set_raw(&result, sample);
    CHECK(detector->false_positive(detector, &result, &reason));
    CHECK(reason && !strcmp(reason, "matches term: sample"));
    free(reason);
    set_raw(&result, token);
    reason = NULL;
    CHECK(!detector->false_positive(detector, &result, &reason) && !reason);
}

static void allocation_rollback(const br_detector *detector)
{
    char input[80];
    CHECK(snprintf(input, sizeof(input), "lark %s tenant %s", tenant, other) > 0);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    prior.extra_data = json_object_new_object();
    CHECK(prior.verification_error && prior.extra_data);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    br_json *extra = out.items[0].extra_data;
    size_t capacity = out.cap;
    const reply rows[] = {
        {.key = tenant, .url = "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
         .status = 200, .body = "{\"code\":0}"},
        {.key = other, .url = "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
         .status = 200, .body = "{\"code\":0}"},
    };
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LarkSuite result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0 && out.len == 1 && out.items[0].extra_data == extra);
    free(error);
    error = NULL;

    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LarkSuite extra data") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0 && out.items[0].raw.data == raw);
    CHECK(out.items[0].verification_error == saved && out.items[0].secret_parts == parts);
    free(error);
    error = NULL;

    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append LarkSuite result"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.authorization);
    CHECK(out.len == 1 && out.items[0].extra_data == extra && out.items[0].verification_error == saved);
    out.cap = capacity;
    free(error);
    br_results_clear(&out);
}

static void later_valid_code(void)
{
    decoded fields = {0};
    br_json *bad = json_object_new_string("x");
    br_json *ok = json_object_new_int(7);
    br_slice name = {(const unsigned char *)"code", 4};
    br_slice bad_text = {(const unsigned char *)"\"x\"", 3};
    br_slice ok_text = {(const unsigned char *)"7", 1};
    CHECK(bad && ok && read_member(&fields, name, bad, bad_text) == 0 && fields.cause);
    char *first = fields.cause;
    CHECK(read_member(&fields, name, ok, ok_text) == 0);
    CHECK(fields.code == 7 && fields.cause == first &&
          !strcmp(first, "json: cannot unmarshal string into Go struct field verificationResponse.code of type int"));
    json_object_put(bad);
    json_object_put(ok);
    decoded_clear(&fields);
}

static void reset_seam(void)
{
    setter_inject = 0;
    visit_inject = 0;
    setter_calls = 0;
    setter_count = 0;
    releases_at_setter = 0;
    seam_releases = 0;
    visit_members = 0;
    setter_secret = (br_slice){0};
    setter_cause_seen = NULL;
}

static void expect_setter_token(void)
{
    CHECK(setter_count == 1 && setter_secret.len == strlen(tenant));
    CHECK(setter_secret.data && !memcmp(setter_secret.data, tenant, setter_secret.len));
}

static void policy_regressions(const br_detector *detector)
{
    char input[64];
    CHECK(snprintf(input, sizeof(input), "lark %s", tenant) > 0);
    const char *url = "https://open.larksuite.com/open-apis/tenant/v2/tenant/query";
    br_slice data = {(const unsigned char *)input, strlen(input)};

    reset_seam();
    const reply nul_ok = {.key = tenant, .url = url, .status = 500,
                          .body = "{\"code\":0,\"msg\":\"ab\\u0000cd\"}"};
    script steps = {.rows = &nul_ok, .count = 1};
    br_results out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(setter_calls == 1 && !setter_cause_seen && releases_at_setter == 1);
    expect_setter_token();
    br_results_clear(&out);

    reset_seam();
    const reply nul_invalid = {.key = tenant, .url = url, .status = 200,
                               .body = "{\"code\":20005,\"msg\":\"ab\\u0000cd\"}"};
    steps = (script){.rows = &nul_invalid, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    CHECK(setter_calls == 1 && !setter_cause_seen && releases_at_setter == 1);
    expect_setter_token();
    br_results_clear(&out);

    reset_seam();
    const reply special = {.key = tenant, .url = url, .status = 401, .body = "{\"code\":99991672}"};
    steps = (script){.rows = &special, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    reset_seam();
    const reply terminal = {.key = tenant, .url = url, .status = 503, .body = "{\"code\":0}",
                            .body_error = "terminal read"};
    steps = (script){.rows = &terminal, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(setter_calls == 1 && !setter_cause_seen && releases_at_setter == 1);
    br_results_clear(&out);

    reset_seam();
    const reply number = {.key = tenant, .url = url, .status = 200, .body = "{\"code\":1e2}"};
    steps = (script){.rows = &number, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error,
                  "failed to decode response (status 200): json: cannot unmarshal number 1e2 into Go struct field verificationResponse.code of type int"));
    CHECK(!strstr(out.items[0].verification_error, "verification failed"));
    CHECK(releases_at_setter == 1 && setter_count == 1);
    br_results_clear(&out);

    reset_seam();
    const reply bool_msg = {.key = tenant, .url = url, .status = 200, .body = "{\"msg\":false}"};
    steps = (script){.rows = &bool_msg, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error,
                  "failed to decode response (status 200): json: cannot unmarshal bool into Go struct field verificationResponse.msg of type string"));
    br_results_clear(&out);

    reset_seam();
    const reply later = {.key = tenant, .url = url, .status = 200,
                         .body = "{\"msg\":\"one\",\"code\":7,\"msg\":\"two\"}"};
    steps = (script){.rows = &later, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!strcmp(out.items[0].verification_error, "verification failed (status 200, code 7): two"));
    CHECK(visit_members == 3 && releases_at_setter == 1 && setter_count == 1);
    br_results_clear(&out);

    reset_seam();
    const reply sticky = {.key = tenant, .url = url, .status = 404, .body = "{\"code\":\"x\",\"code\":0}"};
    steps = (script){.rows = &sticky, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!out.items[0].verified);
    CHECK(!strcmp(out.items[0].verification_error,
                  "failed to decode response (status 404): json: cannot unmarshal string into Go struct field verificationResponse.code of type int"));
    br_results_clear(&out);

    reset_seam();
    const reply dial = {.key = tenant, .url = url, .status = 200, .send_rc = 1, .send_error = "dial down"};
    steps = (script){.rows = &dial, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(!strcmp(out.items[0].verification_error, "dial down"));
    CHECK(setter_calls == 1 && setter_count == 1 && releases_at_setter == 1);
    expect_setter_token();
    br_results_clear(&out);

    reset_seam();
    br_results nilout = {0};
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, data, &nilout, &error) == 0);
    CHECK(!error && setter_calls == 1 && setter_count == 1 && releases_at_setter == 0);
    CHECK(setter_cause_seen && !strcmp(setter_cause_seen, "net/http: nil Context"));
    expect_setter_token();
    br_results_clear(&nilout);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    prior.extra_data = json_object_new_object();
    CHECK(prior.verification_error && prior.extra_data);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    unsigned char *raw = kept.items[0].raw.data;
    char *saved = kept.items[0].verification_error;
    br_json *extra = kept.items[0].extra_data;

    reset_seam();
    visit_inject = 1;
    const reply visited = {.key = tenant, .url = url, .status = 200,
                           .body = "{\"code\":\"x\",\"msg\":\"later\"}"};
    steps = (script){.rows = &visited, .count = 1};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    CHECK(detector->scan(detector, &ctx, true, data, &kept, &error) == -1);
    CHECK(error && !strcmp(error, "cannot visit LarkSuite response"));
    CHECK(visit_members == 2 && setter_calls == 0 && http.calls == 1 && http.releases == 1);
    CHECK(seam_releases == 1 && kept.len == 1 && kept.items[0].raw.data == raw);
    CHECK(kept.items[0].verification_error == saved && kept.items[0].extra_data == extra);
    free(error);
    error = NULL;

    reset_seam();
    const reply nulmsg = {.key = tenant, .url = url, .status = 200,
                          .body = "{\"code\":7,\"msg\":\"ab\\u0000cd\"}"};
    steps = (script){.rows = &nulmsg, .count = 1};
    http = (test_http){.inspect = inspect_request, .user = &steps};
    transport = (br_transport){&http, test_http_send, release_response};
    ctx = (br_scan_ctx){.transport = &transport};
    steps.ctx = &ctx;
    CHECK(detector->scan(detector, &ctx, true, data, &kept, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: LarkSuite verification message"));
    CHECK(setter_calls == 0 && http.releases == 1 && seam_releases == 1);
    CHECK(kept.len == 1 && kept.items[0].verification_error == saved && kept.items[0].extra_data == extra);
    free(error);
    error = NULL;

    reset_seam();
    setter_inject = 1;
    const reply plus = {.key = tenant, .url = url, .status = 200, .body = "{\"code\":0}"};
    steps = (script){.rows = &plus, .count = 1};
    http = (test_http){.inspect = inspect_request, .user = &steps};
    transport = (br_transport){&http, test_http_send, release_response};
    ctx = (br_scan_ctx){.transport = &transport};
    steps.ctx = &ctx;
    CHECK(detector->scan(detector, &ctx, true, data, &kept, &error) == -1);
    CHECK(error && !strcmp(error, "cannot store LarkSuite verification error"));
    CHECK(setter_calls == 1 && setter_count == 1 && !setter_cause_seen && releases_at_setter == 1);
    expect_setter_token();
    CHECK(http.releases == 1 && kept.len == 1 && kept.items[0].raw.data == raw);
    CHECK(kept.items[0].verification_error == saved && kept.items[0].extra_data == extra);
    free(error);
    setter_inject = 0;
    br_results_clear(&kept);
}

int main(void)
{
    const br_detector *detector = descriptor();
    grammar(detector);
    verification(detector);
    nil_and_send(detector);
    false_positives(detector);
    allocation_rollback(detector);
    policy_regressions(detector);
    later_valid_code();
    return test_finish("LarkSuite");
}
