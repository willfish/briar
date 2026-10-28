/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <malloc.h>

/* Target actual ABI1 allocation/projection sites, not a new transport framework. */
static size_t allocation_size, allocation_after, allocation_failures, duplicate_after;
static const char *duplicate_text, *part_failure;
static bool push_failure, arm_next_raw;
void *malloc(size_t size)
{
    if (allocation_after && size == allocation_size && --allocation_after == 0) {
        ++allocation_failures; return NULL;
    }
    return calloc(1, size);
}
void *realloc(void *old, size_t size)
{
    if (push_failure) { push_failure = false; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, previous < size ? previous : size); free(old); }
    return copy;
}
char *strdup(const char *text)
{
    if (duplicate_after && duplicate_text && !strcmp(text, duplicate_text) && --duplicate_after == 0) {
        ++allocation_failures; return NULL;
    }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}
int json_object_object_add(br_json *map, const char *name, br_json *value)
{
    if (part_failure && !strcmp(name, part_failure)) { part_failure = NULL; ++allocation_failures; return 1; }
    return json_object_object_add_ex(map, name, value, 0);
}
static char ids[2][65], secrets[2][71];
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void input(char *out, size_t size, bool multiple)
{
    int n = snprintf(out, size, "APPLICATION_ID %s\nclient_id %s\napp_id %s\n", ids[0], multiple ? ids[1] : ids[0], ids[0]);
    CHECK(n > 0 && (size_t)n + 1700 < size);
    memset(out + n, ' ', 1600); n += 1600;
    CHECK(snprintf(out + n, size - (size_t)n, "%s\n%s\n%s", secrets[0], multiple ? secrets[1] : secrets[0], secrets[0]) > 0);
}
static void part(br_json *map, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(map, name, &value) && json_object_is_type(value, json_type_string));
    CHECK(json_object_get_string_len(value) == (int)strlen(expected) && !strcmp(json_object_get_string(value), expected));
}
static void result(const br_result *r, size_t id, size_t secret, const char *endpoint, bool verified, const char *cause)
{
    CHECK(r->detector_type == 1050 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == 70 && !memcmp(r->raw.data, secrets[secret], 70));
    CHECK(r->raw_v2.len == 134 + strlen(endpoint));
    CHECK(!memcmp(r->raw_v2.data, ids[id], 64) && !memcmp(r->raw_v2.data + 64, secrets[secret], 70));
    CHECK(!memcmp(r->raw_v2.data + 134, endpoint, strlen(endpoint)));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 3);
    part(r->secret_parts, "client_id", ids[id]); part(r->secret_parts, "client_secret", secrets[secret]); part(r->secret_parts, "endpoint", endpoint);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}
typedef struct { size_t id, secret; const char *endpoint; int status; br_slice body; const char *read_error, *send_error; int send_rc; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx;
    const char *url; br_slice body; char expected_url[12000], expected_body[256];
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at);
    const row *r = &s->rows[at];
    CHECK(request->detector_type == 1050 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(snprintf(s->expected_url, sizeof(s->expected_url), "%s/oauth/token", r->endpoint) > 0);
    CHECK(!strcmp(request->url, s->expected_url));
    int len = snprintf(s->expected_body, sizeof(s->expected_body), "grant_type=client_credentials&client_id=%s&client_secret=%s", ids[r->id], secrets[r->secret]);
    CHECK(len > 0 && request->body.len == (size_t)len && !memcmp(request->body.data, s->expected_body, request->body.len));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog gitlab-offline"));
    s->url = request->url; s->body = request->body;
    http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error};
    http->send_error = r->send_error; http->send_rc = r->send_rc;
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->url && !strcmp(s->url, s->expected_url));
    CHECK(s->body.len == strlen(s->expected_body) && !memcmp(s->body.data, s->expected_body, s->body.len));
    s->url = NULL; s->body = (br_slice){0}; test_http_release(user, response);
    if (arm_next_raw) { arm_next_raw = false; allocation_size = 70; allocation_after = 1; }
}
static br_results run(const br_detector *d, const char *data, const br_endpoints *ep, bool verify, script *s)
{
    test_http http = {.inspect = inspect, .user = s}; br_transport transport = {&http, test_http_send, release};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = ep, .user_agent = "gitlab-offline"}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data, strlen(data));
    CHECK(http.calls == s->count && http.releases == http.calls && !s->url);
    return out;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(br_gitlaboauth2_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_gitlaboauth2_init(&d, &error) == 0 && d && !error);
    CHECK(br_gitlaboauth2_init(&again, &error) == 0 && d == again && !error);
    CHECK(d->type == 1050 && d->version == 0 && !strcmp(d->name, "GitLabOauth2") && !*d->custom_name);
    CHECK(!strcmp(d->description, "GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking, and CI/CD pipeline features. GitLab OAuth application credentials can be used to access GitLab APIs on behalf of users."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gloas-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->scan && d->state && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(d->validate_endpoints && !strcmp(d->cloud_endpoint, "https://gitlab.com"));
    br_endpoints zero = {0}; CHECK(d->validate_endpoints(&zero, &error) != 0 && error); free(error); error = NULL;
    const char *empty[] = {""}; br_endpoints one = {.configured = empty, .nconfigured = 1};
    CHECK(d->validate_endpoints(&one, &error) == 0 && !error);
    return d;
}
static void extract(const br_detector *d)
{
    char data[4096]; input(data, sizeof(data), true); script none = {0};
    br_results out = run(d, data, NULL, false, &none); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) result(&out.items[i], i / 2, i % 2, "https://gitlab.com", false, NULL);
    br_results_clear(&out);
    br_endpoints zero = {0}; out = run(d, data, &zero, true, &none); CHECK(!out.len); br_results_clear(&out);
    const char *eps[] = {"", "HTTPS://bad?query", "", "https://gitlab.com"};
    br_endpoints ep = {.configured = eps, .nconfigured = 4, .use_cloud = true};
    out = run(d, data, &ep, false, &none); CHECK(out.len == 16);
    const char *order[] = {"", "HTTPS://bad?query", "https://gitlab.com", "https://gitlab.com"};
    for (size_t i = 0; i < out.len; ++i) result(&out.items[i], i / 8, (i / 4) % 2, order[i % 4], false, NULL);
    br_results_clear(&out);
    const char *prefixes[] = {"application_id", "CLIENT_ID", "App_Id", "iD", "preidsuffix"};
    for (size_t i = 0; i < 5; ++i) {
        snprintf(data, sizeof(data), "%s %s\n%80s%s", prefixes[i], ids[0], "", secrets[0]);
        out = run(d, data, NULL, false, &none); CHECK(out.len == 1); br_results_clear(&out);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(data, sizeof(data), "id%*s%s\n%80s%s", gap, "", ids[0], "", secrets[0]);
        out = run(d, data, NULL, false, &none); CHECK(out.len == (gap == 40 ? 1u : 0u)); br_results_clear(&out);
    }
    const char *bad[] = {"%s\n%80s%s", "id_%s\n%80s%s", "id %s_\n%80s%s", "id %s\n%80s_%s", "id %s\n%80s%s_"};
    for (size_t i = 0; i < 5; ++i) {
        snprintf(data, sizeof(data), bad[i], ids[0], "", secrets[0]);
        out = run(d, data, NULL, false, &none); CHECK(!out.len); br_results_clear(&out);
    }
    snprintf(data, sizeof(data), "id %s\n%80s%s", ids[0], "", secrets[0]);
    char *start = strstr(data, ids[0]); start[0] = 'A'; out = run(d, data, NULL, false, &none); CHECK(!out.len); br_results_clear(&out);
    start[0] = ids[0][0]; start = strstr(data, secrets[0]); start[0] = 'G'; out = run(d, data, NULL, false, &none); CHECK(!out.len); br_results_clear(&out);
    start[0] = 'g'; start[6] = 'A'; out = run(d, data, NULL, false, &none); CHECK(!out.len); br_results_clear(&out);
    /* Independent regex roles: an ID may be the hex suffix of a secret. */
    snprintf(data, sizeof(data), "id %s", secrets[0]); out = run(d, data, NULL, false, &none); CHECK(out.len == 1);
    CHECK(!memcmp(out.items[0].raw_v2.data, secrets[0] + 6, 64)); br_results_clear(&out);
    snprintf(data, sizeof(data), "id\r\n%s\n%80s%s", ids[0], "", secrets[0]); out = run(d, data, NULL, false, &none); CHECK(out.len == 1); br_results_clear(&out);
}
static void one(const br_detector *d, row r, bool verified, const char *cause)
{
    char data[4096]; input(data, sizeof(data), false); r.endpoint = "https://gitlab.com";
    script s = {.rows = &r, .count = 1}; br_results out = run(d, data, NULL, true, &s);
    CHECK(out.len == 1); result(&out.items[0], 0, 0, r.endpoint, verified, cause); br_results_clear(&out);
}
static void policy(const br_detector *d)
{
    one(d, (row){.status = 400, .body = text("{\"error\":\"invalid_scope\"}")}, true, NULL);
    one(d, (row){.status = 400, .body = text("{\"error\":\"bad\",\"ERROR\":\"invalid_scope\",\"error\":null,\"other\":1e9999}")}, true, NULL);
    one(d, (row){.status = 400, .body = text("{\"error\":\"invalid_scope\",\"error\":\"bad\"}")}, false, "unexpected error in response: bad");
    one(d, (row){.status = 400, .body = text("{\"error\":17,\"error\":\"invalid_scope\"}")}, false, "json: cannot unmarshal number into Go struct field .error of type string");
    one(d, (row){.status = 400, .body = text("{\"error\":false,\"error\":[]}")}, false, "json: cannot unmarshal bool into Go struct field .error of type string");
    one(d, (row){.status = 400, .body = text("[]")}, false, "json: cannot unmarshal array into Go value of type struct { Error string \"json:\\\"error\\\"\" }");
    one(d, (row){.status = 400, .body = text("null")}, false, "unexpected error in response: ");
    one(d, (row){.status = 400, .body = text("{}")}, false, "unexpected error in response: ");
    one(d, (row){.status = 400, .body = text("{\"error\":\"invalid_scope\"} {}")}, false, "invalid character '{' after top-level value");
    one(d, (row){.status = 400, .body = text("")}, false, "unexpected end of JSON input");
    one(d, (row){.status = 400, .body = text("not json"), .read_error = ""}, false, "");
    one(d, (row){.status = 400, .body = text("{\"error\":\"invalid_scope\"}"), .read_error = "read failed"}, false, "read failed");
    one(d, (row){.status = 401, .body = text("not json"), .read_error = "ignored"}, false, NULL);
    one(d, (row){.status = 401, .read_error = ""}, false, NULL);
    one(d, (row){.status = 200, .body = text("{\"error\":\"invalid_scope\"}"), .read_error = "ignored"}, false, "unexpected HTTP response status 200");
    one(d, (row){.status = 422, .read_error = "ignored"}, false, "unexpected HTTP response status 422");
    one(d, (row){.status = 500}, false, "unexpected HTTP response status 500");
    one(d, (row){.send_rc = 1, .send_error = secrets[0]}, false, secrets[0]); /* ZERO redaction args. */
    one(d, (row){.status = 400, .read_error = ids[0]}, false, ids[0]);
    one(d, (row){.status = 400, .body = text("{\"error\":\"caf\\u00e9 雪\"}")}, false, "unexpected error in response: café 雪");
    one(d, (row){.status = 400, .body = text("{\"unknown\\u0000\":1,\"error\":\"invalid_scope\",\"hidden\":\"\\u0000\"}")}, true, NULL);
    char data[4096]; input(data, sizeof(data), false);
    br_results out = test_scan(d, NULL, true, data, strlen(data)); CHECK(out.len == 1);
    result(&out.items[0], 0, 0, "https://gitlab.com", false, "net/http: nil Context"); br_results_clear(&out);
}
static void products(const br_detector *d)
{
    char data[4096]; input(data, sizeof(data), true);
    const char *eps[] = {"http://example.test:000000/path//", "https://other.test/"};
    br_endpoints ep = {.configured = eps, .nconfigured = 2};
    row rows[] = {
        {.id=0,.secret=0,.endpoint=eps[0],.status=401},
        {.id=0,.secret=0,.endpoint=eps[1],.status=400,.body=text("{\"error\":\"invalid_scope\"}")},
        {.id=1,.secret=0,.endpoint=eps[0],.status=401},
        {.id=1,.secret=0,.endpoint=eps[1],.status=401},
        {.id=1,.secret=1,.endpoint=eps[0],.status=400,.body=text("{\"error\":\"invalid_scope\"}")},
    };
    script s = {.rows=rows,.count=5}; br_results out = run(d, data, &ep, true, &s); CHECK(out.len == 5);
    for (size_t i=0;i<5;++i) result(&out.items[i],rows[i].id,rows[i].secret,rows[i].endpoint,i==1||i==4,NULL);
    br_results_clear(&out);
    const char *later[] = {"https://ok.test", "not a URL"}; ep = (br_endpoints){.configured=later,.nconfigured=2};
    row successes[] = {{.endpoint=later[0],.status=400,.body=text("{\"error\":\"invalid_scope\"}")},{.id=1,.endpoint=later[0],.status=400,.body=text("{\"error\":\"invalid_scope\"}")}};
    s = (script){.rows=successes,.count=2}; out = run(d,data,&ep,true,&s); CHECK(out.len==2); br_results_clear(&out);
    /* Full unbounded literal endpoint, including repeated slash and high port. */
    char long_endpoint[10000]; static const char long_prefix[] = "https://-.:999999/";
    memcpy(long_endpoint,long_prefix,sizeof(long_prefix)-1);
    memset(long_endpoint+sizeof(long_prefix)-1,'a',sizeof(long_endpoint)-sizeof(long_prefix)); long_endpoint[sizeof(long_endpoint)-1]=0;
    const char *longs[]={long_endpoint}; ep=(br_endpoints){.configured=longs,.nconfigured=1};
    input(data,sizeof(data),false); row r={.endpoint=long_endpoint,.status=401}; s=(script){.rows=&r,.count=1};
    out=run(d,data,&ep,true,&s); CHECK(out.len==1); result(&out.items[0],0,0,long_endpoint,false,NULL); br_results_clear(&out);
}
static void fatal(const br_detector *d, const char *data, const br_endpoints *ep, row *r, bool verify, size_t sends)
{
    script s={.rows=r,.count=sends}; test_http http={.inspect=inspect,.user=&s}; br_transport transport={&http,test_http_send,release};
    br_scan_ctx ctx={.transport=&transport,.endpoints=ep,.user_agent="gitlab-offline"}; s.ctx=&ctx;
    size_t saved_allocation=allocation_after, saved_duplicate=duplicate_after;
    const char *saved_part=part_failure; allocation_after=duplicate_after=0; part_failure=NULL;
    br_results out={0}; br_result seed={0}; CHECK(br_finding_key(&seed,7,"caller-preserved","key")==0);
    CHECK(br_results_push(&out,&seed)==0); unsigned char *original=out.items[0].raw.data;
    allocation_after=saved_allocation; duplicate_after=saved_duplicate; part_failure=saved_part;
    char *error=NULL; int rc=d->scan(d,&ctx,verify,text(data),&out,&error);
    CHECK(rc==-1 && error && out.len==1 && out.items[0].raw.data==original);
    CHECK(http.calls==sends && http.releases==sends); free(error); br_results_clear(&out);
}
static void guards_and_resources(const br_detector *d)
{
    char data[4096]; input(data,sizeof(data),false);
    const char *bad[]={"", "HTTPS://a", "https://a?x", "https://a#x", "https://u@a", "https://[::1]", "https://a:", "https://a:x", "https://a/a%20b", "https://a/雪"};
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);++i) {
        br_endpoints ep={.configured=&bad[i],.nconfigured=1}; fatal(d,data,&ep,NULL,true,0);
        script none={0}; br_results out=run(d,data,&ep,false,&none); CHECK(out.len==1); br_results_clear(&out);
    }
    const char *later_bad[]={"https://gitlab.com","https://bad.test?query"};
    br_endpoints later_ep={.configured=later_bad,.nconfigured=2};
    row rejected={.endpoint=later_bad[0],.status=401}; fatal(d,data,&later_ep,&rejected,true,1);
    row r={.endpoint="https://gitlab.com",.status=400,.body=text("{\"error\":\"invalid_scope\\u0000\"}")}; fatal(d,data,NULL,&r,true,1);
    r.body=(br_slice){(const unsigned char *)"{}",(size_t)INT_MAX+1}; fatal(d,data,NULL,&r,true,1);
    /* Capture, raw, V2, URL and complete body resources precede ordinary policy. */
    const size_t sizes[]={65,71,70,152,31,190};
    for(size_t i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        allocation_size=sizes[i]; allocation_after=1;
        fatal(d,data,NULL,NULL,true,0); CHECK(!allocation_after);
    }
    const char *parts[]={"client_secret","client_id","endpoint"};
    for(size_t i=0;i<3;++i) { part_failure=parts[i]; fatal(d,data,NULL,NULL,false,0); CHECK(!part_failure); }
    duplicate_text="net/http: nil Context"; duplicate_after=1;
    br_results out={0}; char *error=NULL; CHECK(d->scan(d,NULL,true,text(data),&out,&error)==-1 && error && !out.len); free(error); br_results_clear(&out); CHECK(!duplicate_after);
    r=(row){.endpoint="https://gitlab.com",.status=400,.read_error="read-cause"};
    duplicate_text="read-cause"; duplicate_after=1; fatal(d,data,NULL,&r,true,1); CHECK(!duplicate_after);
    duplicate_after=2; fatal(d,data,NULL,&r,true,1); CHECK(!duplicate_after); /* Setter, not classification. */
    duplicate_text=NULL;
    /* Roll back an earlier appended product, preserving preexisting caller data. */
    input(data,sizeof(data),true); r=(row){.endpoint="https://gitlab.com",.status=401}; arm_next_raw=true;
    fatal(d,data,NULL,&r,true,1); CHECK(!arm_next_raw && !allocation_after);
    /* An actual push growth failure, with no transport or source-side skip. */
    input(data,sizeof(data),false); out=(br_results){0}; push_failure=true; error=NULL;
    CHECK(d->scan(d,NULL,false,text(data),&out,&error)==-1 && error && !out.len && !push_failure); free(error); br_results_clear(&out);
    CHECK(allocation_failures>=14);
}
int main(void)
{
    for(size_t i=0;i<64;++i) { ids[0][i]="0123456789abcdef"[i%16]; ids[1][i]="fedcba9876543210"[i%16]; }
    for(size_t s=0;s<2;++s) { memcpy(secrets[s],"gloas-",6); for(size_t i=0;i<64;++i) secrets[s][i+6]="abcdef0123456789"[(i+s)%16]; }
    const br_detector *d=descriptor(); extract(d); policy(d); products(d); guards_and_resources(d);
    return test_finish("gitlaboauth2");
}
