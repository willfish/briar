/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"
#include "../support/detector_test.h"
#include <curl/curl.h>

int br_getemail_init(const br_detector **out, char **error);
static const char key[] = "Ab3d-Ef6Gh9Jk2Lm5Nq8";
static const char key2[] = "Zy8x-Wv5Ut2Sr9Qp6Nm3";
static size_t fail_size, fail_after, fail_part;
static bool fail_agent;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *k, bool verified)
{
    test_key_result(r, 326, k, "key");
    CHECK(r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 21 && sizeof(key2) == 21);
    CHECK(br_getemail_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_getemail_init(NULL, NULL) != 0);
    CHECK(!br_getemail_init(&d, &error) && d && !error);
    CHECK(!br_getemail_init(&again, NULL) && again == d);
    CHECK(d->type == 326 && !d->version && !strcmp(d->name, "GetEmail") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "GetEmail is a service used to find email addresses based on names and domains. GetEmail API keys can be used to access and retrieve email addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "getemail"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extraction(const br_detector *d)
{
    const struct { const char *input, *capture; } cases[] = {
        {"GETEMAIL Ab3d-Ef6Gh9Jk2Lm5Nq8", key},
        {"preGeTeMaIlpost\r\nAb3d-Ef6Gh9Jk2Lm5Nq8", key},
        {"getemail A------------------Z", "A------------------Z"},
        {"getemail 00000000000000000000", "00000000000000000000"},
        {"getemail abcdefghijklmnopqrst", "abcdefghijklmnopqrst"},
        {"getemail ABCDEFGHIJKLMNOPQRST", "ABCDEFGHIJKLMNOPQRST"},
        {"getemail --------------------", NULL},
        {"getemail -Ab3d-Ef6Gh9Jk2Lm5Nq", NULL},
        {"getemail Ab3d-Ef6Gh9Jk2Lm5Nq-", NULL},
        {"getemail _Ab3d-Ef6Gh9Jk2Lm5Nq8", NULL},
        {"getemail Ab3d-Ef6Gh9Jk2Lm5Nq8_", NULL},
        {"getemail Ab3d-Ef6Gh9Jk2Lm5Nq8X", NULL},
        {"getemail Ab3d-Ef6Gh9Jk2Lm5Nq", NULL},
        {"Ab3d-Ef6Gh9Jk2Lm5Nq8", NULL},
    };
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport=&t};
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        br_results r = test_scan(d, &ctx, false, cases[i].input, strlen(cases[i].input));
        CHECK(r.len == (cases[i].capture ? 1u : 0u) && !http.calls && !http.releases);
        if (r.len) result_is(&r.items[0], cases[i].capture, false);
        br_results_clear(&r);
    }
    unsigned char input[512];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "getemail", 8); memset(input + 8, '.', gap); memcpy(input + 8 + gap, key, 20);
        br_results r = test_scan(d, NULL, false, input, 28 + gap);
        CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    int n = sprintf((char *)input, "getemail %s\ngetemail %s\ngetemail %s", key, key2, key);
    br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 3);
    result_is(&r.items[0], key, false); result_is(&r.items[1], key2, false); result_is(&r.items[2], key, false); br_results_clear(&r);
    n = sprintf((char *)input, "getemail %s %s", key, key2);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); br_results_clear(&r);
    r = test_scan(d, NULL, false, NULL, 0); CHECK(!r.len); br_results_clear(&r);
}

typedef struct { char url[160]; const char *borrowed; } expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected *e = http->user; CHECK(ctx && !ctx->deadline_monotonic_ms);
    CHECK(!strcmp(req->method, "GET") && !strcmp(req->url, e->url));
    CHECK(req->profile == BR_HTTP_SANE && req->timeout_ms == 5000 && req->detector_type == 326);
    CHECK(req->nheaders == 1 && !strcmp(req->headers[0].name, "User-Agent") && !strcmp(req->headers[0].value, "TruffleHog getemail-offline"));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    e->borrowed = req->url;
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    if (e && e->borrowed) { CHECK(!strcmp(e->borrowed, e->url)); e->borrowed = NULL; }
    test_http_release(user, response);
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification(const br_detector *d)
{
    char input[256]; int n = sprintf(input, "getemail %s", key);
    expected e = {0}; sprintf(e.url, "https://api.getemail.io/v1/find-mail?firstname=Larry&lastname=Page&domain=google.com&api_key=%s", key);
    static const unsigned char binary[] = "before\0after\"code\":\"USER_NOT_EXIST\"tail";
    const br_slice bodies[] = {{0}, text("malformed"),
        text("junk\"code\":\"USER_NOT_EXIST\"tail"),
        {binary,sizeof(binary)-1},
        text("{\"code\": \"USER_NOT_EXIST\"}"),
        text("{\"code\":\"user_not_exist\"}"),
        text("USER_NOT_EXIST")};
    const int statuses[] = {0,199,200,201,204,206,299,300,301,400,401,403,429,500};
    for (size_t s = 0; s < sizeof(statuses)/sizeof(*statuses); ++s)
        for (size_t b = 0; b < sizeof(bodies)/sizeof(*bodies); ++b)
            for (int read_error = 0; read_error < 3; ++read_error) {
                test_http http = {.response={.status=statuses[s],.body=bodies[b],.body_error=read_error == 1 ? "synthetic read failure" : read_error == 2 ? "" : NULL},.inspect=inspect,.user=&e};
                br_transport t = {&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t,.user_agent="getemail-offline"};
                br_results r = test_scan(d,&ctx,true,input,(size_t)n);
                CHECK(r.len == (read_error ? 0u : 1u) && http.calls == 1 && http.releases == 1 && !e.borrowed);
                if (r.len) result_is(&r.items[0],key,statuses[s] >= 200 && statuses[s] < 300 && b != 2 && b != 3);
                br_results_clear(&r);
            }
    const int errors[] = {-1,1,7};
    for (size_t i = 0; i < sizeof(errors)/sizeof(*errors); ++i) {
        test_http http = {.response={.status=200,.body_error=""},.send_rc=errors[i],.send_error=i ? key : NULL,.inspect=inspect,.user=&e};
        br_transport t = {&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t,.user_agent="getemail-offline"};
        br_results r = test_scan(d,&ctx,true,input,(size_t)n); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0],key,false); br_results_clear(&r);
    }
    test_http http = {0}; br_transport t = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0},{.transport=&t,.cancelled=cancelled,.cancel_user=&cancellations},{.transport=&t,.deadline_monotonic_ms=1},{.transport=&t,.user_agent="bad\r\nagent"},{.transport=&t}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent = true;
        br_results r = test_scan(d,&contexts[i],true,input,(size_t)n); CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent);
        result_is(&r.items[0],key,false); br_results_clear(&r);
    }
    CHECK(cancellations == 1);
    br_results r = test_scan(d,NULL,true,input,(size_t)n); CHECK(!r.len); br_results_clear(&r);
    n += sprintf(input + n,"\ngetemail %s",key);
    http = (test_http){.response={.status=200},.inspect=inspect,.user=&e};
    t = (br_transport){&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t,.user_agent="getemail-offline"};
    r = test_scan(d,&ctx,true,input,(size_t)n); CHECK(r.len == 2 && http.calls == 2 && http.releases == 2);
    result_is(&r.items[0],key,true); result_is(&r.items[1],key,true); br_results_clear(&r);
}
static void guard_backend_destroy(void *user)
{
    test_http *http = user;
    bool *destroyed = http->user;
    CHECK(destroyed && !*destroyed && !http->calls && !http->releases);
    *destroyed = true;
}
static void guards(const br_detector *d)
{
    char input[80]; int n = sprintf(input,"getemail %s",key); char *error = NULL;
    const br_transport *raw = br_curl_transport_init(&error); CHECK(raw && !error);
    br_transport copied = *raw;
    const br_transport *transports[] = {raw,&copied};
    for (size_t i = 0; i < 2; ++i) {
        br_scan_ctx ctx = {.transport=transports[i]}; br_results r = test_scan(d,&ctx,true,input,(size_t)n);
        CHECK(r.len == 1); result_is(&r.items[0],key,false); br_results_clear(&r);
    }
    test_http http = {0};
    for (int local = 0; local < 2; ++local) {
        br_http_client *owned = NULL;
        bool destroyed = false;
        http.user = &destroyed;
        br_http_owned_backend backend = {.transport=test_transport(&http),.destroy=guard_backend_destroy};
        CHECK(!br_http_client_init(&owned,backend,local ? BR_HTTP_DETECTOR_LOCAL : BR_HTTP_SANE,&error) && owned && !error);
        copied = *br_http_client_transport(owned);
        br_scan_ctx ctx = {.transport=&copied}; br_results r = test_scan(d,&ctx,true,input,(size_t)n);
        CHECK(r.len == 1 && !http.calls && !http.releases); result_is(&r.items[0],key,false); br_results_clear(&r);
        br_http_client_destroy(owned); CHECK(destroyed);
    }
    curl_global_cleanup();
}
static void resources(const br_detector *d)
{
    char input[128]; int n = sprintf(input,"getemail %s\ngetemail %s",key,key2);
    br_result prior = {.detector_type=12345,.verified=true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data,"keep",4); prior.raw.len = 4;
    br_results r = {0}; CHECK(!br_results_push(&r,&prior)); unsigned char *original = r.items[0].raw.data; char *error = NULL;
    for (int mode = 0; mode < 3; ++mode) for (size_t part = 1; part <= 2; ++part) {
        test_http http = {.response={.status=200,.body_error=""}}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport=&t};
        fail_part = part;
        CHECK(d->scan(d,mode == 1 ? NULL : &ctx,mode != 0,text(input),&r,&error) != 0 && !fail_part && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original && r.items[0].verified && !memcmp(original,"keep",4)); free(error); error = NULL;
    }
    const size_t sizes[] = {21,20};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        fail_size = sizes[i]; fail_after = 1;
        CHECK(d->scan(d,NULL,true,(br_slice){(const unsigned char *)input,(size_t)n},&r,&error) != 0 && !fail_after && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    }
    size_t cap = r.cap; r.cap = 0;
    CHECK(d->scan(d,NULL,false,text(input),&r,&error) != 0 && error);
    r.cap = cap; CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL,NULL,false,text(""),NULL,NULL) != 0);
    r = test_scan(d,NULL,false,input,(size_t)n); CHECK(r.len == 2); br_results_clear(&r);
}
int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); verification(d); guards(d); resources(d);
    return test_finish("GetEmail grammar/occurrences/metadata/default-transport byte boundary/body-drop/error-keep/guards/rollback");
}
