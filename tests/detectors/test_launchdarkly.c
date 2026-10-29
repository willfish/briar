/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <stdarg.h>

/* Inclusion seam: observe caller order and inject visitor or formatter failure. */
static int ld_intercept_setter(br_result *result, const char *cause, const br_slice *secrets,
                               size_t nsecrets);
static int ld_intercept_visit(br_slice object, br_json_member_fn callback, void *user);
static int ld_test_snprintf(char *buf, size_t n, const char *fmt, ...);
#define br_result_set_verification_error ld_intercept_setter
#define br_json_each_member ld_intercept_visit
#define snprintf ld_test_snprintf
#include "../../src/detectors/launchdarkly.c"
#undef snprintf
#undef br_json_each_member
#undef br_result_set_verification_error

static int setter_inject, visit_inject, format_inject;
static size_t setter_calls, setter_count, releases_at_setter;
static bool setter_verified, setter_extra_empty, setter_cause_null;
static char setter_cause_copy[256];
static test_http *seam_http;

typedef struct {
    br_json_member_fn fn;
    void *user;
} member_wrap;

static int counting_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    member_wrap *wrap = user;
    return wrap->fn(wrap->user, name, value, encoded);
}

static int ld_intercept_setter(br_result *result, const char *cause, const br_slice *secrets,
                               size_t nsecrets)
{
    ++setter_calls;
    setter_count = nsecrets;
    setter_verified = result && result->verified;
    setter_extra_empty = result && result->extra_data &&
                         json_object_is_type(result->extra_data, json_type_object) &&
                         json_object_object_length(result->extra_data) == 0;
    setter_cause_null = !cause;
    setter_cause_copy[0] = '\0';
    if (cause) snprintf(setter_cause_copy, sizeof(setter_cause_copy), "%s", cause);
    releases_at_setter = seam_http ? seam_http->releases : 0;
    if (setter_inject) return setter_inject;
    return br_result_set_verification_error(result, cause, secrets, nsecrets);
}

static int ld_intercept_visit(br_slice object, br_json_member_fn callback, void *user)
{
    member_wrap wrap = {callback, user};
    int rc = br_json_each_member(object, counting_member, &wrap);
    if (visit_inject && rc == 0) {
        int injected = visit_inject;
        visit_inject = 0;
        return injected;
    }
    return rc;
}

static int ld_test_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    if (format_inject) {
        int rc = format_inject;
        format_inject = 0;
        return rc;
    }
    va_list ap;
    va_start(ap, fmt);
    int wrote = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return wrote;
}

static void reset_seam(void)
{
    setter_inject = visit_inject = format_inject = 0;
    setter_calls = setter_count = releases_at_setter = 0;
    setter_verified = setter_extra_empty = setter_cause_null = false;
    setter_cause_copy[0] = '\0';
    seam_http = NULL;
}

static char api_key[41], sdk_key[41];
static size_t fail_part_after;
static const char url[] = "https://app.launchdarkly.com/api/v2/caller-identity";

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void fill_key(char *out, const char *prefix, char version, size_t shift)
{
    char a[9], b[5], c[4], d[5], e[13];
    test_secret(a, 8, shift);
    test_secret(b, 4, shift + 3);
    test_secret(c, 3, shift + 5);
    test_secret(d, 4, shift + 7);
    test_secret(e, 12, shift + 11);
    CHECK(snprintf(out, 41, "%s-%s-%s-%c%s-%s-%s", prefix, a, b, version, c, d, e) == 40);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(api_key) == 40 && strlen(sdk_key) == 40 && api_key[18] == '4' && sdk_key[18] == '4');
    CHECK(br_launchdarkly_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LaunchDarkly detector output"));
    free(error);
    error = NULL;
    CHECK(br_launchdarkly_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_launchdarkly_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 191 && detector->version == 0 && !strcmp(detector->name, "LaunchDarkly"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "LaunchDarkly is a feature management platform that allows teams to control the visibility of features to users. LaunchDarkly API keys can be used to access and modify feature flags and other resources within a LaunchDarkly account."));
    CHECK(detector->nkeywords == 2 && detector->keywords);
    CHECK(!strcmp(detector->keywords[0], "api-") && !strcmp(detector->keywords[1], "sdk-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *key)
{
    CHECK(result->detector_type == 191);
    CHECK(result->raw.len == 40 && !memcmp(result->raw.data, key, 40));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), key));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_nov(const br_detector *detector, const void *data, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, data, len);
    CHECK(http.calls == 0 && http.releases == 0);
    if (!expected) CHECK(out.len == 0);
    else {
        CHECK(out.len == 1);
        expect_key(&out.items[0], expected);
        CHECK(!out.items[0].verified && !out.items[0].verification_error);
        CHECK(out.items[0].extra_data && json_object_is_type(out.items[0].extra_data, json_type_object));
        CHECK(json_object_object_length(out.items[0].extra_data) == 0);
    }
    br_results_clear(&out);
}

static void grammar(const br_detector *detector)
{
    char input[160], changed[41];
    CHECK(snprintf(input, sizeof(input), " %s ", api_key) == 42);
    expect_nov(detector, input, 42, api_key);
    CHECK(snprintf(input, sizeof(input), "-%s", sdk_key) == 41);
    expect_nov(detector, input, 41, sdk_key);
    expect_nov(detector, api_key, 40, api_key);
    expect_nov(detector, "api-", 4, NULL);
    expect_nov(detector, "sdk-", 4, NULL);
    expect_nov(detector, "", 0, NULL);

    memcpy(changed, api_key, 41);
    memcpy(changed, "mob", 3);
    CHECK(snprintf(input, sizeof(input), " %s ", changed) == 42);
    expect_nov(detector, input, 42, NULL);
    memcpy(changed, api_key, 41);
    changed[18] = '3';
    expect_nov(detector, changed, 40, NULL);
    changed[18] = '5';
    expect_nov(detector, changed, 40, NULL);
    changed[18] = 'a';
    expect_nov(detector, changed, 40, NULL);
    memcpy(changed, api_key, 41);
    changed[4] = 'A';
    expect_nov(detector, changed, 40, NULL);
    memcpy(changed, api_key, 41);
    changed[0] = 'A';
    expect_nov(detector, changed, 40, NULL);
    CHECK(snprintf(input, sizeof(input), "x%s", api_key) == 41);
    expect_nov(detector, input, 41, NULL);
    CHECK(snprintf(input, sizeof(input), "%sa", api_key) == 41);
    expect_nov(detector, input, 41, NULL);
    expect_nov(detector, api_key, 39, NULL);

    CHECK(snprintf(input, sizeof(input), "%s %s", api_key, sdk_key) == 81);
    br_results out = test_scan(detector, NULL, false, input, 81);
    CHECK(out.len == 2 && out.items[0].extra_data != out.items[1].extra_data);
    expect_key(&out.items[0], api_key);
    expect_key(&out.items[1], sdk_key);
    CHECK(json_object_object_length(out.items[0].extra_data) == 0);
    CHECK(json_object_object_length(out.items[1].extra_data) == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "%s %s", api_key, api_key) == 81);
    out = test_scan(detector, NULL, false, input, 81);
    CHECK(out.len == 2);
    expect_key(&out.items[0], api_key);
    expect_key(&out.items[1], api_key);
    br_results_clear(&out);
}

typedef struct {
    const char *key;
    int status, send_rc;
    const char *send_error, *body_error, *body;
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
    CHECK(request->detector_type == 191 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && request->headers[0].value);
    CHECK(!strcmp(request->headers[0].value, row->key) && !strstr(request->headers[0].value, "Bearer"));
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
    CHECK(at < steps->count && steps->authorization && !strcmp(steps->authorization, steps->rows[at].key));
    steps->authorization = NULL;
    test_http_release(user, response);
}

static br_results verify_scan(const br_detector *detector, const void *data, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    seam_http = &http;
    br_results out = test_scan(detector, &ctx, true, data, len);
    seam_http = NULL;
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->authorization);
    return out;
}

static const char *extra_get(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, name, &value) && value);
    return json_object_get_string(value);
}

static void expect_absent(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->extra_data && !json_object_object_get_ex(result->extra_data, name, &value));
}

static void expect_empty_identity(const br_result *result)
{
    const char *names[] = {
        "type", "account", "environment_id", "project_id", "environment_name", "project_name",
        "auth_kind", "token_kind", "client_id", "token_name", "member_id",
    };
    CHECK(json_object_object_length(result->extra_data) == 11);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        CHECK(extra_get(result, names[i]) && !*extra_get(result, names[i]));
    expect_absent(result, "token_type");
    expect_absent(result, "tokenId");
}

static void statuses(const br_detector *detector)
{
    const char *full =
        "{\"accountId\":\"acct\",\"environmentId\":\"env\",\"projectId\":\"proj\","
        "\"environmentName\":\"ename\",\"projectName\":\"pname\",\"authKind\":\"kind\","
        "\"tokenKind\":\"auth\",\"clientId\":\"client\",\"tokenName\":\"tname\","
        "\"tokenId\":\"hidden\",\"memberId\":\"member\",\"serviceToken\":true}";
    reply row = {.key = api_key, .status = 200, .body = full};
    script steps = {.rows = &row, .count = 1};
    reset_seam();
    br_results out = verify_scan(detector, api_key, 40, &steps);
    CHECK(setter_calls == 1 && setter_count == 0 && setter_cause_null && setter_verified);
    CHECK(setter_extra_empty && releases_at_setter == 1);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    expect_key(&out.items[0], api_key);
    CHECK(!strcmp(extra_get(&out.items[0], "type"), "acct"));
    CHECK(!strcmp(extra_get(&out.items[0], "account"), "acct"));
    CHECK(!strcmp(extra_get(&out.items[0], "environment_id"), "env"));
    CHECK(!strcmp(extra_get(&out.items[0], "project_id"), "proj"));
    CHECK(!strcmp(extra_get(&out.items[0], "environment_name"), "ename"));
    CHECK(!strcmp(extra_get(&out.items[0], "project_name"), "pname"));
    CHECK(!strcmp(extra_get(&out.items[0], "auth_kind"), "kind"));
    CHECK(!strcmp(extra_get(&out.items[0], "token_kind"), "auth"));
    CHECK(!strcmp(extra_get(&out.items[0], "client_id"), "client"));
    CHECK(!strcmp(extra_get(&out.items[0], "token_name"), "tname"));
    CHECK(!strcmp(extra_get(&out.items[0], "member_id"), "member"));
    CHECK(!strcmp(extra_get(&out.items[0], "token_type"), "service"));
    expect_absent(&out.items[0], "tokenId");
    CHECK(json_object_object_length(out.items[0].extra_data) == 12);
    br_results_clear(&out);

    row.body = "{\"tokenKind\":\"auth\",\"accountId\":\"\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !out.items[0].verification_error);
    CHECK(!*extra_get(&out.items[0], "account") && !strcmp(extra_get(&out.items[0], "token_type"), "personal"));
    expect_absent(&out.items[0], "tokenId");
    br_results_clear(&out);

    row.body = "{\"tokenKind\":\"auth\",\"serviceToken\":false}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !strcmp(extra_get(&out.items[0], "token_type"), "personal"));
    br_results_clear(&out);

    row.body = "{\"tokenKind\":\"Auth\",\"serviceToken\":true,\"AccountId\":\"Folded\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !strcmp(extra_get(&out.items[0], "type"), "Folded"));
    CHECK(!strcmp(extra_get(&out.items[0], "account"), "Folded"));
    CHECK(!strcmp(extra_get(&out.items[0], "token_kind"), "Auth"));
    expect_absent(&out.items[0], "token_type");
    br_results_clear(&out);

    row.body = "null";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !out.items[0].verification_error);
    expect_empty_identity(&out.items[0]);
    br_results_clear(&out);

    row.body = "{\"accountId\":\"first\",\"accountId\":\"last\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !strcmp(extra_get(&out.items[0], "account"), "last"));
    br_results_clear(&out);

    row.body = "{\"accountId\":\"kept\",\"accountId\":null}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !strcmp(extra_get(&out.items[0], "account"), "kept"));
    br_results_clear(&out);

    row.body = "{\"accountId\":\"acct\"}{\"tokenId\":1}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(out.items[0].verified && !strcmp(extra_get(&out.items[0], "account"), "acct"));
    expect_absent(&out.items[0], "tokenId");
    br_results_clear(&out);

    row.body = "{\"accountId\":\"nope\"}";
    row.status = 401;
    row.body_error = "ignored on 401";
    reset_seam();
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(setter_calls == 1 && setter_count == 0 && setter_cause_null && !setter_verified);
    CHECK(setter_extra_empty && releases_at_setter == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error && !out.items[0].extra_data);
    br_results_clear(&out);

    row.status = 201;
    row.body_error = NULL;
    reset_seam();
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(setter_calls == 1 && setter_count == 0 && !setter_verified && setter_extra_empty);
    CHECK(releases_at_setter == 1 && !strcmp(setter_cause_copy, "unexpected status code: 201"));
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "unexpected status code: 201"));
    br_results_clear(&out);

    row.status = 500;
    row.body = full;
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&out);
}

static void decode_errors(const br_detector *detector)
{
    reply row = {.key = api_key, .status = 200, .body = "{\"accountId\":1,\"accountId\":\"rescued\"}"};
    script steps = {.rows = &row, .count = 1};
    br_results out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field callerIdentity.accountId of type string"));
    br_results_clear(&out);

    row.body = "{\"accountId\":1e2,\"tokenKind\":\"auth\",\"serviceToken\":true,\"tokenId\":\"hidden\",\"memberId\":\"kept\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field callerIdentity.accountId of type string"));
    br_results_clear(&out);

    row.body = "{\"serviceToken\":1e2}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field callerIdentity.serviceToken of type bool"));
    br_results_clear(&out);

    row.body = "{\"serviceToken\":\"yes\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal string into Go struct field callerIdentity.serviceToken of type bool"));
    br_results_clear(&out);

    row.body = "[1]";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal array into Go value of type launchdarkly.callerIdentity"));
    br_results_clear(&out);

    row.body = "{\"tokenId\":true,\"accountId\":\"a\"}";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error,
                  "json: cannot unmarshal bool into Go struct field callerIdentity.tokenId of type string"));
    br_results_clear(&out);

    row.body = "";
    row.body_error = "synthetic read failure";
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(!strcmp(out.items[0].verification_error, "synthetic read failure"));
    br_results_clear(&out);

    row.body = "{";
    row.body_error = NULL;
    visit_inject = 1;
    reset_seam();
    visit_inject = 1;
    out = verify_scan(detector, api_key, 40, &steps);
    CHECK(setter_calls == 1 && out.len == 1);
    CHECK(!out.items[0].verified && !out.items[0].extra_data && out.items[0].verification_error);
    CHECK(strncmp(out.items[0].verification_error, "unexpected status code:", 23));
    CHECK(strcmp(out.items[0].verification_error, "cannot visit LaunchDarkly response"));
    visit_inject = 0;
    br_results_clear(&out);
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void send_failures(const br_detector *detector)
{
    char cause[80];
    CHECK(snprintf(cause, sizeof(cause), "dial failed %s", api_key) > 40);
    reply row = {.key = api_key, .status = 200, .send_rc = 1, .send_error = cause,
                 .body = "{\"accountId\":\"acct\"}"};
    script steps = {.rows = &row, .count = 1};
    reset_seam();
    br_results out = verify_scan(detector, api_key, 40, &steps);
    CHECK(setter_calls == 1 && setter_count == 0 && setter_extra_empty && releases_at_setter == 1);
    CHECK(!setter_verified && !strcmp(setter_cause_copy, cause));
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cause));
    br_results_clear(&out);

    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    reset_seam();
    seam_http = &http;
    out = test_scan(detector, &ctx, true, api_key, 40);
    seam_http = NULL;
    CHECK(setter_calls == 1 && setter_count == 0 && setter_extra_empty && releases_at_setter == 1);
    CHECK(!setter_verified && !strcmp(setter_cause_copy, "context canceled"));
    CHECK(out.len == 1 && http.calls == 0 && http.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].extra_data);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "context canceled"));
    br_results_clear(&out);
}

static void nil_context(const br_detector *detector)
{
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
    br_scan_ctx ctx = {.transport = &transport};
    reset_seam();
    seam_http = &http;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)api_key, 40}, &out, &error) == 0);
    seam_http = NULL;
    CHECK(setter_calls == 1 && setter_count == 0 && setter_extra_empty && releases_at_setter == 0);
    CHECK(!setter_verified && !strcmp(setter_cause_copy, "net/http: nil Context"));
    CHECK(!error && out.len == 2 && http.calls == 0 && http.releases == 0);
    CHECK(out.items[0].raw.data == raw && out.items[0].secret_parts == parts && out.items[0].extra_data == extra);
    CHECK(out.items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(!out.items[1].verified && !out.items[1].extra_data);
    CHECK(out.items[1].verification_error && !strcmp(out.items[1].verification_error, "net/http: nil Context"));
    expect_key(&out.items[1], api_key);
    (void)ctx;
    br_results_clear(&out);
}

static void check_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts, br_json *extra)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].secret_parts == parts && out->items[0].extra_data == extra);
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
}

static void allocation_rollback(const br_detector *detector)
{
    char input[96];
    CHECK(snprintf(input, sizeof(input), "%s %s", api_key, sdk_key) == 81);
    br_slice data = {(const unsigned char *)input, 81};
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
        {.key = api_key, .status = 200, .body = "{\"accountId\":\"acct\"}"},
        {.key = sdk_key, .status = 200, .body = "{\"accountId\":\"other\"}"},
    };
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LaunchDarkly result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    error = NULL;

    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LaunchDarkly extra data") && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1 && !steps.authorization);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append LaunchDarkly result"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.authorization);
    check_prior(&out, raw, saved, parts, extra);
    out.cap = capacity;
    free(error);
    br_results_clear(&out);
}

static void later_valid_fields(void)
{
    const char *body =
        "{\"accountId\":1e2,\"tokenKind\":\"auth\",\"serviceToken\":true,"
        "\"tokenId\":\"hidden\",\"memberId\":\"kept\",\"accountId\":\"rescued\"}";
    identity id = {0};
    int rc = br_json_each_member((br_slice){(const unsigned char *)body, strlen(body)}, read_member, &id);
    CHECK(rc == 0 && id.cause);
    CHECK(!strcmp(id.cause,
                  "json: cannot unmarshal number into Go struct field callerIdentity.accountId of type string"));
    CHECK(id.service);
    CHECK(id.len[6] == 4 && id.text[6] && !memcmp(id.text[6], "auth", 4));
    CHECK(id.len[9] == 6 && id.text[9] && !memcmp(id.text[9], "hidden", 6));
    CHECK(id.len[10] == 4 && id.text[10] && !memcmp(id.text[10], "kept", 4));
    CHECK(id.len[0] == 7 && id.text[0] && !memcmp(id.text[0], "rescued", 7));
    identity_clear(&id);
}

static void policy_regressions(const br_detector *detector)
{
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
    const reply row = {.key = api_key, .status = 200,
                       .body = "{\"accountId\":1e2,\"tokenKind\":\"auth\",\"serviceToken\":true}"};
    script steps = {.rows = &row, .count = 1};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;
    br_slice data = {(const unsigned char *)api_key, 40};

    reset_seam();
    visit_inject = 1;
    seam_http = &http;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    seam_http = NULL;
    CHECK(error && !strcmp(error, "cannot visit LaunchDarkly response") && !visit_inject);
    CHECK(setter_calls == 0 && http.calls == 1 && http.releases == 1 && !steps.authorization);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    reply status = {.key = api_key, .status = 500, .body = "{\"accountId\":\"acct\"}"};
    steps.rows = &status;
    reset_seam();
    format_inject = -1;
    seam_http = &http;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    seam_http = NULL;
    CHECK(error && !strcmp(error, "cannot format LaunchDarkly status") && !format_inject);
    CHECK(setter_calls == 0 && http.calls == 1 && http.releases == 1);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    format_inject = 64;
    seam_http = &http;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    seam_http = NULL;
    CHECK(error && !strcmp(error, "cannot format LaunchDarkly status") && !format_inject);
    CHECK(setter_calls == 0 && http.calls == 1 && http.releases == 1);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    steps.rows = &row;
    reset_seam();
    setter_inject = 1;
    seam_http = &http;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    seam_http = NULL;
    CHECK(error && !strcmp(error, "cannot store LaunchDarkly verification error"));
    CHECK(setter_calls == 1 && setter_count == 0 && setter_extra_empty && releases_at_setter == 1);
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&out, raw, saved, parts, extra);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    fill_key(api_key, "api", '4', 0);
    fill_key(sdk_key, "sdk", '4', 9);
    const br_detector *detector = descriptor();
    grammar(detector);
    statuses(detector);
    decode_errors(detector);
    send_failures(detector);
    nil_context(detector);
    allocation_rollback(detector);
    policy_regressions(detector);
    later_valid_fields();
    return test_finish("LaunchDarkly");
}
