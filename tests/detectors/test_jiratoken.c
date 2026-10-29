/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/endpoints.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/host_cache.h"
#include "../../src/detectors/jiratoken_url.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <stdarg.h>

int br_jiratoken_v1_init(const br_detector **out, char **error);
int br_jiratoken_v2_init(const br_detector **out, char **error);

static int checked_find(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_endpoints(const br_endpoints *, const char *, const br_captures *, br_endpoint_list *, char **);
static int checked_endpoint_host(br_slice, br_bytes *, char **);
static int checked_target_init(br_slice, bool, br_jiratoken_target *, char **);
static void checked_target_clear(br_jiratoken_target *);
static int checked_cache_contains(br_host_cache *, const char *, bool *);
static int checked_cache_add(br_host_cache *, const char *);
static int checked_basic(br_slice, br_slice, char **, char **);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_json(br_slice, const char *, br_json **, size_t *, char **);
static int checked_members(br_slice, br_json_member_fn, void *);
static int checked_snprintf(char *, size_t, const char *, ...);
static void note_before_release(const br_result *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_push(br_results *, br_result *);
#define br_captures_find checked_find
#define br_endpoints_collect checked_endpoints
#define br_jiratoken_endpoint_host checked_endpoint_host
#define br_jiratoken_target_init checked_target_init
#define br_jiratoken_target_clear checked_target_clear
#define br_host_cache_contains checked_cache_contains
#define br_host_cache_add checked_cache_add
#define br_http_basic_auth checked_basic
#define br_http_send checked_send
#define br_http_release checked_release
#define br_json_first_document checked_json
#define br_json_each_member checked_members
#undef snprintf
#define snprintf checked_snprintf
#define JIRA_BEFORE_RELEASE(result) note_before_release(result)
#define br_result_set_verification_error checked_setter
#define br_finding_key_bytes checked_finding
#define br_results_push checked_push
#define br_jiratoken_v1_init observed_v1_init
#define br_jiratoken_v2_init observed_v2_init
#include "../../src/detectors/jiratoken.c"
#undef br_captures_find
#undef br_endpoints_collect
#undef br_jiratoken_endpoint_host
#undef br_jiratoken_target_init
#undef br_jiratoken_target_clear
#undef br_host_cache_contains
#undef br_host_cache_add
#undef br_http_basic_auth
#undef br_http_send
#undef br_http_release
#undef br_json_first_document
#undef br_json_each_member
#undef snprintf
#undef JIRA_BEFORE_RELEASE
#undef br_result_set_verification_error
#undef br_finding_key_bytes
#undef br_results_push
#undef br_jiratoken_v1_init
#undef br_jiratoken_v2_init

static const char token_a[] = "Z7VoIYJ0K4rFWLBfkhOsLAWX";
static const char token_b[] = "0123456789ABCDEFGHIJKLMN";
static const char token_hyphen[] = "Z7VoIYJ0K4rF-LBfkhOsLAWX";
static const char token_v2[] = "ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC";
static const char email_a[] = "xfkf_bz7@grum.com";
static const char host_a[] = "hereisavalidsubdomain.atlassian.net";
static const char host_foreign[] = "hereisavalidsubdomain.heresalongdomain.com";
static const char cloud_host[] = "api.atlassian.com";
static const char query_body[] = "{\"query\":\"query verify { me { user { name } } }\"}";
static const char rotation[] = "https://howtorotate.com/docs/tutorials/atlassian/";
typedef enum { NONE, FIND, ENDPOINTS, HOST, TARGET, CACHE_READ, CACHE_WRITE, BASIC, JSON, MEMBERS, SETTER, FINDING, PUSH } fault_site;
static fault_site fault;
static size_t nth, setter_calls, cache_reads, cache_writes;
static bool fault_hit, force_flag;
static const char *force_cause, *live_url, *fail_format_on, *expect_token;
static bool sent_this, released_this, null_do, released_unverified, setter_null_cause, token_matched;
static bool record_basic;
static unsigned char basic_user[64];
static size_t basic_user_len;
static int fail_format;
static size_t expect_token_len;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE;
    fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!sent_this && !released_this && !live_url);
    fault = NONE;
    nth = 0;
    fault_hit = force_flag = null_do = released_unverified = setter_null_cause = token_matched = false;
    force_cause = fail_format_on = expect_token = NULL;
    fail_format = 0;
    expect_token_len = setter_calls = cache_reads = cache_writes = 0;
}

static int checked_find(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(FIND)) { *error = strdup("synthetic capture failure"); CHECK(*error); return 1; }
    return rc;
}

static int checked_endpoints(const br_endpoints *settings, const char *cloud, const br_captures *found,
                             br_endpoint_list *out, char **error)
{
    if (hit(ENDPOINTS)) { *error = strdup("synthetic endpoint failure"); CHECK(*error); return -1; }
    return br_endpoints_collect(settings, cloud, found, out, error);
}

static int checked_endpoint_host(br_slice endpoint, br_bytes *host, char **error)
{
    if (hit(HOST)) { *error = strdup("synthetic endpoint host failure"); CHECK(*error); return -1; }
    return br_jiratoken_endpoint_host(endpoint, host, error);
}

static int checked_target_init(br_slice host, bool present, br_jiratoken_target *out, char **error)
{
    if (hit(TARGET)) { *error = strdup("synthetic target failure"); CHECK(*error); return -1; }
    int rc = br_jiratoken_target_init(host, present, out, error);
    if (rc == 0 && force_cause) {
        free(out->cause);
        out->cause = strdup(force_cause);
        CHECK(out->cause);
    }
    if (rc == 0 && force_flag) out->error_url_has_no_host = true;
    return rc;
}

static void checked_target_clear(br_jiratoken_target *target)
{
    if (sent_this) CHECK(released_this && target && target->url && target->url == live_url);
    else CHECK(!released_this);
    br_jiratoken_target_clear(target);
    sent_this = released_this = false;
    live_url = NULL;
}

static int checked_cache_contains(br_host_cache *cache, const char *host, bool *found)
{
    ++cache_reads;
    if (hit(CACHE_READ)) return -1;
    return br_host_cache_contains(cache, host, found);
}

static int checked_cache_add(br_host_cache *cache, const char *host)
{
    ++cache_writes;
    if (hit(CACHE_WRITE)) return -1;
    return br_host_cache_add(cache, host);
}

static int checked_basic(br_slice user, br_slice password, char **out, char **error)
{
    if (record_basic) {
        CHECK(user.data && user.len <= sizeof(basic_user));
        memcpy(basic_user, user.data, user.len);
        basic_user_len = user.len;
        record_basic = false;
    }
    if (hit(BASIC)) { *error = strdup("synthetic basic auth failure"); CHECK(*error); return 1; }
    return br_http_basic_auth(user, password, out, error);
}

static int checked_snprintf(char *out, size_t cap, const char *format, ...)
{
    if (fail_format && format && fail_format_on && !strcmp(format, fail_format_on)) {
        int mode = fail_format;
        fail_format = 0;
        if (mode < 0) return -1;
        return (int)cap;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, cap, format, args);
    va_end(args);
    return rc;
}

static int checked_members(br_slice object, br_json_member_fn callback, void *user)
{
    if (hit(MEMBERS)) return 1;
    return br_json_each_member(object, callback, user);
}

static void note_before_release(const br_result *result)
{
    CHECK(result && !result->verified);
    released_unverified = true;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!sent_this && request && request->url);
    live_url = request->url;
    sent_this = true;
    if (null_do) {
        null_do = false;
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return br_http_send(ctx, request, response, error);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(sent_this && !released_this && live_url && *live_url);
    br_http_release(ctx, response);
    CHECK(live_url && *live_url);
    released_this = true;
}

static int checked_json(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (hit(JSON)) { *cause = strdup("synthetic decode failure"); CHECK(*cause); return -1; }
    return br_json_first_document(body, read_error, out, end, cause);
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_null_cause = !cause;
    if (expect_token) {
        token_matched = count == 1 && secrets && secrets[0].data && secrets[0].len == expect_token_len &&
                        !memcmp(secrets[0].data, expect_token, expect_token_len);
        CHECK(token_matched);
    }
    if (hit(SETTER)) return 1;
    return br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    if (hit(FINDING)) return -1;
    return br_finding_key_bytes(result, type, key, part);
}

static int checked_push(br_results *out, br_result *result)
{
    if (hit(PUSH)) return 1;
    return br_results_push(out, result);
}

static const char *json_text(const br_json *object, const char *name)
{
    br_json *value = NULL;
    CHECK(object && json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void expect_result(const br_result *result, const char *email, const char *token, const char *host,
                          int version, bool verified, const char *verification_error)
{
    char raw_v2[512];
    snprintf(raw_v2, sizeof(raw_v2), "%s:%s:%s", email, token, host);
    CHECK(result->detector_type == 120 && !result->detector_name && !result->redacted && !result->structured_data);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    CHECK(!strcmp(json_text(result->secret_parts, "token"), token));
    CHECK(!strcmp(json_text(result->secret_parts, "domain"), host));
    CHECK(!strcmp(json_text(result->secret_parts, "email"), email));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 2);
    CHECK(!strcmp(json_text(result->extra_data, "rotation_guide"), rotation));
    CHECK(!strcmp(json_text(result->extra_data, "version"), version == 1 ? "1" : "2"));
    CHECK(result->verified == verified);
    CHECK(verification_error ? result->verification_error && !strcmp(result->verification_error, verification_error)
                             : !result->verification_error);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **), int version)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    const char *description = version == 1
        ? "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate and interact with Jira's API."
        : "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate API requests.";
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid JiraToken detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 120 && d->version == version && !strcmp(d->name, "JiraToken") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(d->nkeywords == 3 && !strcmp(d->keywords[0], "atlassian") && !strcmp(d->keywords[1], "confluence"));
    CHECK(!strcmp(d->keywords[2], "jira") && !strcmp(d->cloud_endpoint, "https://api.atlassian.com"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && d->validate_endpoints == br_endpoints_validate_configured);
    CHECK(!d->clean && !d->clean_always && !d->false_positive);
    return d;
}

static void scan_nov(const br_detector *d, const br_scan_ctx *ctx, const char *input, size_t expect)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx local = ctx ? *ctx : (br_scan_ctx){0};
    if (!local.transport) local.transport = &transport;
    br_results out = test_scan(d, &local, false, input, strlen(input));
    CHECK(out.len == expect && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void grammar(const br_detector *d, int version)
{
    char input[800];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    if (version == 1) {
        snprintf(input, sizeof(input), "jira %s\njira %s\njira %s\njira Xfkf_bz7@Grum.COM", token_a, host_a, email_a);
        br_results out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1 && !http.calls);
        expect_result(&out.items[0], email_a, token_a, host_a, 1, false, NULL);
        br_results_clear(&out);
        snprintf(input, sizeof(input), "jira %s\njira %s\njira %s", token_a, host_foreign, email_a);
        out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1);
        expect_result(&out.items[0], email_a, token_a, cloud_host, 1, false, NULL);
        br_results_clear(&out);
        snprintf(input, sizeof(input), "jira keyword is not close to the real key in the data\n = '%s' domain = '%s' email = '%s'",
                 token_a, host_a, email_a);
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "jira key = '%s' domain = '%s' email = '%s'", "Z7VoI?J0K4rF#LBfkhO&LAWX",
                 "?y4r3fs1ewqec12v1e3tl.5Hcsrcehic89saXd.ro@", "xfKF_BZq7/grum.com");
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "ATLASSIAN %s\nconfluence %s\nJira %s", token_hyphen, host_a, email_a);
        out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1);
        expect_result(&out.items[0], email_a, token_hyphen, host_a, 1, false, NULL);
        br_results_clear(&out);
        snprintf(input, sizeof(input), "jira %s\njira %s\njira %s", "Z7VoIYJ0K4rF.LBfkhOsLAWX", host_a, email_a);
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "jira %s %s\njira %s\njira %s", token_a, token_b, host_a, email_a);
        out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1);
        expect_result(&out.items[0], email_a, token_a, host_a, 1, false, NULL);
        br_results_clear(&out);
    } else {
        snprintf(input, sizeof(input), "%s %s https://example.atlassian.net/rest/api/2/issue/fake454", token_v2, email_a);
        br_results out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1 && !http.calls);
        expect_result(&out.items[0], email_a, token_v2, "example.atlassian.net", 2, false, NULL);
        br_results_clear(&out);
        snprintf(input, sizeof(input), "%s %s", token_v2, "trufflesecurity@example.com");
        out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1);
        expect_result(&out.items[0], "trufflesecurity@example.com", token_v2, cloud_host, 2, false, NULL);
        br_results_clear(&out);
        snprintf(input, sizeof(input), "https://example.atlassian.net/ %s", token_v2);
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "%s https://example.atlassian.net/", "trufflesecurity@example.com");
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "ATATTA9nsCA?a7812Z7VoI%%YJ0K4rFWLBfk91rhOsLAW=Yx3ssoNC %s example.atlassian.net", email_a);
        scan_nov(d, &ctx, input, 0);
        snprintf(input, sizeof(input), "ATATTX=abcdefgh %s a.jira.com", email_a);
        out = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(out.len == 1);
        expect_result(&out.items[0], email_a, "ATATTX=abcdefgh", "a.jira.com", 2, false, NULL);
        br_results_clear(&out);
        scan_nov(d, &ctx, "ATATT=abcdefgh user@example.com a.jira.com", 0);
    }
}

static void host_policy(const br_detector *d, int version)
{
    char input[600];
    const char *token = version == 1 ? token_a : token_v2;
    const char *prefix = version == 1 ? "jira " : "";
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s%s\n%sz.atlassian.net\n%sa.jira.com\n%s%s\n%sB@Example.COM",
             prefix, token, prefix, prefix, prefix, email_a, prefix);
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 4 && !http.calls);
    expect_result(&out.items[0], email_a, token, "a.jira.com", version, false, NULL);
    expect_result(&out.items[1], email_a, token, "z.atlassian.net", version, false, NULL);
    expect_result(&out.items[2], "b@example.com", token, "a.jira.com", version, false, NULL);
    expect_result(&out.items[3], "b@example.com", token, "z.atlassian.net", version, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s%s\n%sEXAMPLE.Atlassian.Net.\n%s%s", prefix, token, prefix, prefix, email_a);
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_result(&out.items[0], email_a, token, "EXAMPLE.Atlassian.Net", version, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s%s\n%sapi.atlassian.com\n%stenant.atlassian.net\n%s%s",
             prefix, token, prefix, prefix, prefix, email_a);
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_result(&out.items[0], email_a, token, cloud_host, version, false, NULL);
    expect_result(&out.items[1], email_a, token, "tenant.atlassian.net", version, false, NULL);
    br_results_clear(&out);
    const char *configured[] = {"https://jira.example.com:8443/", "https://api.atlassian.com",
                                "tenant.atlassian.net", "https://tenant.atlassian.net", ""};
    br_endpoints settings = {.configured = configured, .nconfigured = 5, .use_cloud = true, .use_found = true};
    ctx.endpoints = &settings;
    snprintf(input, sizeof(input), "%s%s\n%stenant.atlassian.net\n%s%s", prefix, token, prefix, prefix, email_a);
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_result(&out.items[0], email_a, token, "jira.example.com:8443", version, false, NULL);
    expect_result(&out.items[1], email_a, token, "tenant.atlassian.net", version, false, NULL);
    br_results_clear(&out);
    settings.use_found = false;
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_result(&out.items[0], email_a, token, "jira.example.com:8443", version, false, NULL);
    expect_result(&out.items[1], email_a, token, "tenant.atlassian.net", version, false, NULL);
    br_results_clear(&out);
    br_endpoints cloud_only = {.use_cloud = true};
    ctx.endpoints = &cloud_only;
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    br_endpoints none = {0};
    ctx.endpoints = &none;
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

typedef struct {
    const char *host, *email, *token, *agent;
    const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_auth, *borrowed_accept;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user;
    char *authorization = NULL;
    br_slice email = {(const unsigned char *)script->email, strlen(script->email)};
    br_slice token = {(const unsigned char *)script->token, strlen(script->token)};
    char url[256];
    snprintf(url, sizeof(url), "https://%s/gateway/api/graphql", script->host);
    CHECK(ctx == script->ctx && !strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_LOCAL && request->profile != BR_HTTP_SANE);
    CHECK(request->profile != BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 120);
    CHECK(request->body.len == sizeof(query_body) - 1 && !memcmp(request->body.data, query_body, request->body.len));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization"));
    CHECK(br_http_basic_auth(email, token, &authorization, NULL) == 0);
    CHECK(!strcmp(request->headers[2].value, authorization));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, script->agent));
    script->borrowed_url = request->url;
    script->borrowed_accept = request->headers[0].value;
    script->borrowed_auth = request->headers[2].value;
    free(authorization);
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    request_script *script = http->user;
    if (script && script->borrowed_url) {
        char url[256];
        snprintf(url, sizeof(url), "https://%s/gateway/api/graphql", script->host);
        CHECK(!strcmp(script->borrowed_url, url));
        CHECK(script->borrowed_accept && !strcmp(script->borrowed_accept, "application/json"));
        CHECK(script->borrowed_auth && !strncmp(script->borrowed_auth, "Basic ", 6));
        script->borrowed_url = script->borrowed_accept = script->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static void verify_policy(const br_detector *d, int version)
{
    char input[240];
    const char *token = version == 1 ? token_a : token_v2;
    const char *prefix = version == 1 ? "jira " : "";
    snprintf(input, sizeof(input), "%s%s\n%stenant.atlassian.net\n%s%s", prefix, token, prefix, prefix, email_a);
    request_script script = {.host = "tenant.atlassian.net", .email = email_a, .token = token, .agent = "TruffleHog"};
    test_http http = {.user = &script, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    script.ctx = &ctx;
    static const unsigned char junk[] = {0xff, 0, '{'};
    const struct { int status; const char *body; const char *read_error; bool verified; const char *error; } cases[] = {
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Jira User\"}}}}", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}},\"Data\":[]}", NULL, false, NULL},
        {200, "{\"DATA\":{\"ME\":{\"USER\":{\"NAME\":\"Briar\"}}}}", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"\"}}},\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}}}", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\",\"name\":null}}}}", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}},\"data\":null}", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\",\"name\":\"\"}}}}", NULL, false, NULL},
        {200, "{\"data\":[],\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}}}", NULL, false, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\",\"name\":1}}}}", "read failed", false, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}}} trailing", NULL, true, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"\"}}}}", "ignored", false, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":null}}}}", NULL, false, NULL},
        {200, "{\"method\":\"POST\"}", NULL, false, NULL},
        {200, "{", NULL, false, NULL},
        {200, "{\"data\":{\"me\":{\"user\":{\"name\":\"Jira User\"}}}}", "read failed", true, NULL},
        {401, "{\"data\":{\"me\":{\"user\":{\"name\":\"Jira User\"}}}}", NULL, false, NULL},
        {403, "{\"code\":403}", "", false, NULL},
        {202, "{\"status\":\"accepted\"}", NULL, false, NULL},
        {302, "{\"location\":\"elsewhere\"}", NULL, false, NULL},
        {404, "{\"code\":404}", NULL, false, NULL},
        {429, "{\"code\":429}", "ignored", false, "unexpected status code: 429"},
        {500, "{\"code\":500}", NULL, false, "unexpected status code: 500"},
        {503, "", NULL, false, "unexpected status code: 503"},
        {499, "", NULL, false, NULL},
        {0, (const char *)junk, "ignored", false, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, cases[i].body ? strlen(cases[i].body) : 0},
            .body_error = cases[i].read_error,
        };
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !script.borrowed_url);
        expect_result(&out.items[0], email_a, token, "tenant.atlassian.net", version, cases[i].verified, cases[i].error);
        br_results_clear(&out);
    }
    char leaked[160];
    snprintf(leaked, sizeof(leaked), "bad %s and %s", token, email_a);
    reset_observation();
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = leaked;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"ignored", 7}};
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(out.items[0].verification_error && strstr(out.items[0].verification_error, "[REDACTED]"));
    CHECK(strstr(out.items[0].verification_error, email_a) && !strstr(out.items[0].verification_error, token));
    CHECK(!out.items[0].verified);
    br_results_clear(&out);
    reset_observation();
    http.calls = http.releases = 0;
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    expect_result(&out.items[0], email_a, token, "tenant.atlassian.net", version, false, "net/http: nil Context");
    br_results_clear(&out);
    out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    br_results_clear(&out);
    const char *stops[] = {"https://first.atlassian.net", "https://second.jira.com"};
    br_endpoints settings = {.configured = stops, .nconfigured = 2};
    ctx.endpoints = &settings;
    script.host = "first.atlassian.net";
    http.calls = http.releases = 0;
    http.send_rc = 0;
    http.send_error = NULL;
    const char verified_body[] = "{\"data\":{\"me\":{\"user\":{\"name\":\"Jira User\"}}}}";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)verified_body, sizeof(verified_body) - 1}};
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_result(&out.items[0], email_a, token, "first.atlassian.net", version, true, NULL);
    br_results_clear(&out);
}

static void cache_sequence(const br_detector *v1, const br_detector *v2)
{
    char input[240];
    snprintf(input, sizeof(input), "jira %s\njira zz-missing.jira.com\njira %s", token_a, email_a);
    request_script script = {.host = "zz-missing.jira.com", .email = email_a, .token = token_a, .agent = "TruffleHog"};
    test_http http = {.user = &script, .inspect = inspect, .send_rc = 1, .send_error = "lookup zz-missing.jira.com: no such host"};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    script.ctx = &ctx;
    char v2_input[240];
    snprintf(v2_input, sizeof(v2_input), "%s %s zz-missing.jira.com", token_v2, email_a);
    request_script v2_script = {.host = "zz-missing.jira.com", .email = email_a, .token = token_v2, .agent = "TruffleHog", .ctx = &ctx};
    http.user = &v2_script;
    br_results out = test_scan(v2, &ctx, true, v2_input, strlen(v2_input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_result(&out.items[0], email_a, token_v2, "zz-missing.jira.com", 2, false, "no such host");
    br_results_clear(&out);
    http.user = &script;
    out = test_scan(v1, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1);
    expect_result(&out.items[0], email_a, token_a, "zz-missing.jira.com", 1, false, NULL);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_result(&out.items[0], email_a, token_a, "zz-missing.jira.com", 1, false, "no such host");
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, false, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    http.user = &v2_script;
    out = test_scan(v2, &ctx, false, v2_input, strlen(v2_input));
    CHECK(out.len == 1 && !http.calls);
    expect_result(&out.items[0], email_a, token_v2, "zz-missing.jira.com", 2, false, NULL);
    br_results_clear(&out);
}

static void owned_failure(const br_detector *d, fault_site site, size_t occurrence, const char *message,
                          bool verify, size_t attempts)
{
    char input[180];
    snprintf(input, sizeof(input), "jira %s\njira tenant.atlassian.net\njira %s", token_a, email_a);
    br_results out = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    /* Only the cache-write fault may classify as no such host; earlier faults must not cache it. */
    test_http http = {.send_rc = site == JSON ? 0 : 1,
                      .send_error = site == CACHE_WRITE ? "lookup tenant.atlassian.net: no such host" : "timeout",
                      .response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    fault = site;
    nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) != 0);
    CHECK(error && !strcmp(error, message));
    free(error);
    CHECK(fault_hit && !sent_this && !live_url && out.len == 1);
    CHECK(!memcmp(&out.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
    CHECK(http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void observed_safety(const br_detector *v1, const br_detector *v2)
{
    char input[180];
    snprintf(input, sizeof(input), "jira %s\njira tenant.atlassian.net\njira %s", token_a, email_a);
    test_http http = {.response = {.status = 401, .body = {(const unsigned char *)"{}", 2}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    br_results out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !setter_calls && cache_reads == 1 && !cache_writes);
    expect_result(&out.items[0], email_a, token_a, "tenant.atlassian.net", 1, false, NULL);
    br_results_clear(&out);
    const char named[] = "{\"data\":{\"me\":{\"user\":{\"name\":\"Jira User\"}}}}";
    reset_observation();
    force_flag = true;
    http.send_rc = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)named, sizeof(named) - 1}};
    out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !setter_calls && !cache_writes && out.items[0].verified);
    br_results_clear(&out);
    char v2_input[180];
    snprintf(v2_input, sizeof(v2_input), "%s %s tenant.atlassian.net", token_v2, email_a);
    reset_observation();
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 401, .body = {(const unsigned char *)"{}", 2}};
    out = test_scan(v2, &ctx, true, v2_input, strlen(v2_input));
    CHECK(out.len == 1 && setter_calls == 1 && !cache_reads && !cache_writes);
    expect_result(&out.items[0], email_a, token_v2, "tenant.atlassian.net", 2, false, NULL);
    br_results_clear(&out);
    const char *flagged[] = {"https://flagged.jira.com"};
    br_endpoints flagged_settings = {.configured = flagged, .nconfigured = 1};
    ctx.endpoints = &flagged_settings;
    char flagged_input[160];
    snprintf(flagged_input, sizeof(flagged_input), "jira %s\njira %s", token_a, email_a);
    reset_observation();
    force_flag = true;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, true, flagged_input, strlen(flagged_input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && cache_writes == 1);
    expect_result(&out.items[0], email_a, token_a, "flagged.jira.com", 1, false, "no such host");
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, false, flagged_input, strlen(flagged_input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    const char *v2_flagged_hosts[] = {"https://v2flag.jira.com"};
    br_endpoints v2_flagged = {.configured = v2_flagged_hosts, .nconfigured = 1};
    ctx.endpoints = &v2_flagged;
    char v2_flagged_input[180];
    snprintf(v2_flagged_input, sizeof(v2_flagged_input), "%s %s", token_v2, email_a);
    reset_observation();
    force_flag = true;
    http.calls = http.releases = 0;
    out = test_scan(v2, &ctx, true, v2_flagged_input, strlen(v2_flagged_input));
    CHECK(out.len == 1 && http.calls == 1 && !cache_reads && !cache_writes);
    expect_result(&out.items[0], email_a, token_v2, "v2flag.jira.com", 2, false, "no such host");
    br_results_clear(&out);
    snprintf(flagged_input, sizeof(flagged_input), "jira %s\njira %s", token_a, email_a);
    ctx.endpoints = &v2_flagged;
    out = test_scan(v1, &ctx, false, flagged_input, strlen(flagged_input));
    CHECK(out.len == 1 && !cache_writes);
    br_results_clear(&out);
    ctx.endpoints = NULL;
    reset_observation();
    force_cause = "lookup foo: no such host";
    force_flag = true;
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases && !cache_writes);
    expect_result(&out.items[0], email_a, token_a, "tenant.atlassian.net", 1, false, "lookup foo: no such host");
    br_results_clear(&out);
    owned_failure(v1, FIND, 1, "synthetic capture failure", true, 0);
    owned_failure(v1, ENDPOINTS, 1, "synthetic endpoint failure", false, 0);
    owned_failure(v1, HOST, 1, "synthetic endpoint host failure", true, 0);
    owned_failure(v1, FINDING, 1, "cannot create JiraToken result", true, 0);
    owned_failure(v1, TARGET, 1, "synthetic target failure", true, 0);
    owned_failure(v1, BASIC, 1, "synthetic basic auth failure", true, 0);
    owned_failure(v1, JSON, 1, "cannot decode JiraToken response", true, 1);
    owned_failure(v1, SETTER, 1, "cannot record JiraToken verification error", true, 1);
    owned_failure(v1, CACHE_READ, 1, "cannot read JiraToken host cache", false, 0);
    owned_failure(v1, CACHE_WRITE, 1, "cannot cache JiraToken host", true, 1);
    owned_failure(v1, PUSH, 1, "cannot append JiraToken result", false, 0);
    reset_observation();
    br_results empty = {0};
    CHECK(v1->scan(NULL, NULL, false, (br_slice){0}, &empty, NULL) != 0);
    CHECK(v1->scan(v1, NULL, false, (br_slice){NULL, 1}, &empty, NULL) != 0);
    CHECK(v1->scan(v1, NULL, false, (br_slice){0}, NULL, NULL) != 0);
    CHECK(!empty.len);
}

static void keep_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void typed_safety(const br_detector *v1, const br_detector *v2)
{
    char input[180];
    const char archived[] = "{\"data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}},\"Data\":[]}";
    const char later_object[] = "{\"data\":[],\"Data\":{\"me\":{\"user\":{\"name\":\"Briar\"}}}}";
    snprintf(input, sizeof(input), "jira %s\njira tenant.atlassian.net\njira %s", token_a, email_a);
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)archived, sizeof(archived) - 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    br_results out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls && released_unverified);
    expect_result(&out.items[0], email_a, token_a, "tenant.atlassian.net", 1, false, NULL);
    br_results_clear(&out);
    char v2_input[180];
    snprintf(v2_input, sizeof(v2_input), "%s %s tenant.atlassian.net", token_v2, email_a);
    reset_observation();
    expect_token = token_v2;
    expect_token_len = strlen(token_v2);
    http.calls = http.releases = 0;
    out = test_scan(v2, &ctx, true, v2_input, strlen(v2_input));
    CHECK(out.len == 1 && setter_calls == 1 && setter_null_cause && token_matched && !cache_writes);
    expect_result(&out.items[0], email_a, token_v2, "tenant.atlassian.net", 2, false, NULL);
    br_results_clear(&out);
    reset_observation();
    expect_token = token_a;
    expect_token_len = strlen(token_a);
    null_do = true;
    http.calls = http.releases = 0;
    out = test_scan(v1, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && setter_calls == 1 && setter_null_cause);
    CHECK(token_matched && released_unverified && !cache_writes);
    expect_result(&out.items[0], email_a, token_a, "tenant.atlassian.net", 1, false, NULL);
    br_results_clear(&out);
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    reset_observation();
    null_do = true;
    fault = SETTER;
    nth = 1;
    http.calls = http.releases = 0;
    char *error = NULL;
    CHECK(v1->scan(v1, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot record JiraToken verification error"));
    free(error);
    CHECK(fault_hit && setter_calls == 1 && !cache_writes && http.calls == 0 && http.releases == 1);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(!strcmp(prior.verification_error, "caller-owned") && !sent_this && !live_url);
    reset_observation();
    fault = MEMBERS;
    nth = 2;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)later_object, sizeof(later_object) - 1}};
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(v1->scan(v1, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot project JiraToken response"));
    free(error);
    CHECK(fault_hit && !setter_calls && !cache_writes && released_unverified);
    CHECK(http.calls == 1 && http.releases == 1 && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fail_format = -1;
    fail_format_on = "%d";
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(v1->scan(v1, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot format JiraToken version"));
    free(error);
    CHECK(!fail_format && !http.calls && !http.releases && !setter_calls && !released_unverified);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fail_format = 1;
    fail_format_on = "unexpected status code: %d";
    http.response = (br_http_response){.status = 429, .body = {(const unsigned char *)"{}", 2}};
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(v1->scan(v1, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot format JiraToken status"));
    free(error);
    CHECK(!fail_format && !setter_calls && !cache_writes && released_unverified);
    CHECK(http.calls == 1 && http.releases == 1 && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(!strcmp(prior.verification_error, "caller-owned") && !sent_this && !live_url);
    br_results_clear(&kept);
}

static const unsigned char kelvin_email[] = {
    'X', 0xe2, 0x84, 0xaa, 'N', 'a', 'm', 'e', '@', 'g', 'r', 'u', 'm', '.', 'c', 'o', 'm'
};
static const char folded_email[] = "xkname@grum.com";

static size_t put_bytes(char *out, size_t at, size_t cap, const void *bytes, size_t n)
{
    CHECK(n < cap - at);
    memcpy(out + at, bytes, n);
    return at + n;
}

static size_t kelvin_input(char *out, size_t cap, const char *prefix, const char *token, int shape)
{
    size_t at = put_bytes(out, 0, cap, prefix, strlen(prefix));
    at = put_bytes(out, at, cap, token, strlen(token));
    at = put_bytes(out, at, cap, "\n", 1);
    if (shape != 1) {
        at = put_bytes(out, at, cap, prefix, strlen(prefix));
        at = put_bytes(out, at, cap, "XKName@grum.com", 15);
        at = put_bytes(out, at, cap, "\n", 1);
    }
    if (shape != 0) {
        at = put_bytes(out, at, cap, prefix, strlen(prefix));
        at = put_bytes(out, at, cap, kelvin_email, sizeof(kelvin_email));
        if (shape == 2) {
            at = put_bytes(out, at, cap, "\n", 1);
            at = put_bytes(out, at, cap, prefix, strlen(prefix));
            at = put_bytes(out, at, cap, "XKName@grum.com", 15);
        }
    }
    out[at] = '\0';
    return at;
}

static void kelvin_fold(const br_detector *d, int version, const char *token, bool wrapped)
{
    char input[320];
    const char *prefix = version == 1 ? "jira " : "";
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (int shape = 0; shape < 3; ++shape) {
        size_t n = kelvin_input(input, sizeof(input), prefix, token, shape);
        br_results out = test_scan(d, &ctx, false, input, n);
        CHECK(out.len == 1 && !http.calls && !http.releases);
        expect_result(&out.items[0], folded_email, token, cloud_host, version, false, NULL);
        CHECK(out.items[0].raw_v2.len == strlen(folded_email) + 1 + strlen(token) + 1 + strlen(cloud_host));
        CHECK(!memcmp(out.items[0].raw_v2.data, "xkname@grum.com:", 16));
        br_results_clear(&out);
    }
    size_t n = kelvin_input(input, sizeof(input), prefix, token, 2);
    request_script script = {.host = cloud_host, .email = folded_email, .token = token, .agent = "TruffleHog", .ctx = &ctx};
    http.user = &script;
    http.inspect = inspect;
    http.response = (br_http_response){.status = 401};
    record_basic = wrapped;
    basic_user_len = 0;
    br_results out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_result(&out.items[0], folded_email, token, cloud_host, version, false, NULL);
    if (wrapped) {
        CHECK(!record_basic && basic_user_len == 15 && !memcmp(basic_user, folded_email, 15));
        CHECK(!memchr(basic_user, 0xe2, basic_user_len));
    }
    br_results_clear(&out);
    record_basic = false;
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(token_a) == 24 && strlen(token_hyphen) == 24);
    const br_detector *v1 = descriptor(br_jiratoken_v1_init, 1);
    const br_detector *v2 = descriptor(br_jiratoken_v2_init, 2);
    CHECK(strcmp(v1->description, v2->description));
    grammar(v1, 1);
    grammar(v2, 2);
    kelvin_fold(v1, 1, token_a, false);
    kelvin_fold(v2, 2, token_v2, false);
    host_policy(v1, 1);
    host_policy(v2, 2);
    verify_policy(v1, 1);
    verify_policy(v2, 2);
    cache_sequence(v1, v2);
    const br_detector *observed_v1 = descriptor(observed_v1_init, 1);
    const br_detector *observed_v2 = descriptor(observed_v2_init, 2);
    grammar(observed_v1, 1);
    grammar(observed_v2, 2);
    kelvin_fold(observed_v1, 1, token_a, true);
    kelvin_fold(observed_v2, 2, token_v2, true);
    verify_policy(observed_v1, 1);
    observed_safety(observed_v1, observed_v2);
    typed_safety(observed_v1, observed_v2);
    CHECK(!sent_this && !live_url && fault == NONE && !fail_format && !null_do && !record_basic);
    return test_finish("JiraToken");
}
