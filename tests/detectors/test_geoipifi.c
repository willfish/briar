/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[33], b[33];
static size_t fail_size, fail_after, fail_part_after, failed_allocations;
static const char prefix[] = "https://geo.ipify.org/api/v2/country?apiKey=";
static const char suffix[] = "&ipAddress=8.8.8.8";

/* Exercise existing allocation/JSON boundaries, not provider-specific seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_geoipifi_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_geoipifi_init(NULL, NULL) != 0);
    fail_size = sizeof("(?i:ipifi)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_geoipifi_init(&d, &error) != 0 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_geoipifi_init(&d, &error) == 0 && d && !error);
    CHECK(br_geoipifi_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 286 && !d->version && !strcmp(d->name, "GeoIpifi") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GeoIpifi is a service that provides geolocation information. GeoIpifi API keys can be used to retrieve geolocation data based on IP addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ipifi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 286, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[400], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"ipifi '%s'",true}, {"IpIfI=%s",true}, {"preIPIFIsuffix:%s",true}, {"geoipifi %s",true},
        {"ipify %s",false}, {"geoipify %s",false}, {"ipifi\r\n%s",true}, {"%s",false}, {"%s ipifi",false},
        {"ipifi%s",false}, {"ipifi x%s",false}, {"ipifi _%s",false}, {"ipifi %s_",false}, {"ipifi %s9",false},
        {"ipifi %.31s",false}, {"ipifi +%s=",true}, {"ipifi \xc3\xa9%s\xc3\xa9",true},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a); extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) for (size_t rune = 0; rune < 2; ++rune) {
        size_t at = 5; memcpy(input, "ipifi", at);
        for (size_t i = 0; i < gap; ++i) {
            if (rune) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = i % 2 ? '\r' : '\n';
        }
        memcpy(input + at, a, 32); at += 32; extract_case(d, input, at, gap == 40 ? a : NULL);
    }
    const char invalid[] = "- /+.=";
    for (size_t i = 0; i < sizeof(invalid)-1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "ipifi %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    const char *valid[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "________________________________", "00000000000000000000000000000000"};
    for (size_t i = 0; i < sizeof(valid)/sizeof(*valid); ++i) {
        snprintf(input, sizeof(input), "ipifi %s", valid[i]); extract_case(d, input, strlen(input), valid[i]);
    }
    snprintf(input, sizeof(input), "ipifi %s %s", a, b); extract_case(d, input, strlen(input), a);
    int n = snprintf(input, sizeof(input), "ipifi%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent;
    const char *borrowed_url, *borrowed_key;
} expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !e->borrowed_url);
    CHECK(req->detector_type == 286 && req->profile == BR_HTTP_SANE && req->timeout_ms == 5000);
    CHECK(!strcmp(req->method, "GET") && strlen(req->url) == sizeof(prefix) - 1 + 32 + sizeof(suffix) - 1);
    CHECK(!memcmp(req->url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(req->url + sizeof(prefix) - 1, e->keys[at], 32));
    CHECK(!strcmp(req->url + sizeof(prefix) - 1 + 32, suffix));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    CHECK(req->nheaders == 1 && !strcmp(req->headers[0].name, "User-Agent") && !strcmp(req->headers[0].value, e->agent));
    /* Only provider-owned URL is borrowed. The effective request and synthesized
     * headers/UA are not valid after send returns on ordinary ABI1. */
    e->borrowed_url = req->url; e->borrowed_key = e->keys[at];
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    CHECK(e->borrowed_url && !memcmp(e->borrowed_url, prefix, sizeof(prefix)-1));
    CHECK(!memcmp(e->borrowed_url + sizeof(prefix)-1, e->borrowed_key, 32));
    CHECK(!strcmp(e->borrowed_url + sizeof(prefix)-1 + 32, suffix));
    e->borrowed_url = e->borrowed_key = NULL; test_http_release(user, response);
}
static void occurrences_nilskip(const br_detector *d)
{
    char input[200]; snprintf(input, sizeof(input), "ipifi %s\nIPIFI %s\nipifi %s", a, b, a);
    const char *keys[] = {a,b,a}; expected e = {.keys=keys,.count=3,.agent="TruffleHog geoipifi-offline"};
    test_http http = {.inspect=inspect,.user=&e,.response={.status=200,.body_error="ignored"}};
    br_transport t = {&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t,.user_agent="geoipifi-offline"}; e.ctx = &ctx;
    br_results out = test_scan(d,&ctx,false,input,strlen(input)); CHECK(out.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i],keys[i],false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    for (size_t pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; out = test_scan(d,&ctx,true,input,strlen(input));
        CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i],keys[i],true);
        br_results_clear(&out);
    }
    out = test_scan(d,NULL,true,input,strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d,NULL,false,input,strlen(input)); CHECK(out.len == 3); br_results_clear(&out);
}
static void status_body_errors(const br_detector *d)
{
    char input[60]; snprintf(input,sizeof(input),"ipifi %s",a);
    const char *keys[] = {a}; expected e = {.keys=keys,.count=1,.agent="TruffleHog"};
    test_http http = {.inspect=inspect,.user=&e}; br_transport t = {&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t}; e.ctx = &ctx;
    const int statuses[] = {0,199,200,201,204,250,299,300,301,400,401,403,429,500};
    static const unsigned char body[] = {0,0xff,'{','!'};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status=statuses[i],.body={body,sizeof(body)},.body_error=i % 2 ? "ignored read failure" : NULL};
        br_results out = test_scan(d,&ctx,true,input,strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0],a,statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1,"synthetic timeout"},{-7,"synthetic cancellation"},{7,"out of memory constructing HTTP headers"},
        {1,"net/http: nil Context"},{1,"cannot create GeoIpifi result"},{-1,NULL},{1,a},
    };
    http.response.status = 200;
    for (size_t i = 0; i < sizeof(failures)/sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results out = test_scan(d,&ctx,true,input,strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0],a,false); br_results_clear(&out);
    }
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool fail_agent(void *user) { (void)user; fail_size = sizeof("TruffleHog"); fail_after = 1; return false; }
static void shared_setup(const br_detector *d)
{
    char input[60]; snprintf(input,sizeof(input),"ipifi %s",a);
    test_http http = {0}; br_transport t = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0},{.transport=&t,.cancelled=cancelled,.cancel_user=&cancellations},
        {.transport=&t,.deadline_monotonic_ms=1},{.transport=&t,.user_agent="bad\r\nagent"},
        {.transport=&t,.cancelled=fail_headers},{.transport=&t,.cancelled=fail_agent}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d,&contexts[i],true,input,strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && failed_allocations == before + (i >= 4 ? 1u : 0u));
        result(&out.items[0],a,false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void prior_is(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(prior->raw.data,"prior",5));
    CHECK(out->items[0].secret_parts == prior->secret_parts && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error,"caller-owned"));
}
static void rollback(const br_detector *d)
{
    char input[120]; snprintf(input,sizeof(input),"ipifi %s\nipifi %s",a,b);
    const char *keys[] = {a,b}; expected e = {.keys=keys,.count=2,.agent="TruffleHog"};
    test_http http = {.inspect=inspect,.user=&e,.response={.status=200}};
    br_transport t = {&http,test_http_send,release}; br_scan_ctx ctx = {.transport=&t}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior,777,"prior","key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out,&prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        /* Regex span allocation then each finding's Raw are 32 bytes. */
        if (failure < 3) { fail_size = 32; fail_after = failure + 1; }
        else fail_part_after = 2;
        const br_scan_ctx *scanctx = failure == 1 || failure == 3 ? NULL : &ctx;
        CHECK(d->scan(d,scanctx,true,(br_slice){(const unsigned char *)input,strlen(input)},&out,&error) != 0);
        CHECK(error && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure == 2 || failure == 4 ? 1u : 0u) && http.releases == http.calls && !e.borrowed_url);
        prior_is(&out,&prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* A positive JSON failure remains fatal even after a suppressed Do error. */
    http.send_rc = 7; http.send_error = "synthetic setup/Do failure"; fail_part_after = 2;
    CHECK(d->scan(d,&ctx,true,(br_slice){(const unsigned char *)input,strlen(input)},&out,&error) != 0 && error && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1); prior_is(&out,&prior); free(error); error = NULL;
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL;
    size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d,&ctx,true,(br_slice){(const unsigned char *)input,strlen(input)},&out,&error) != 0 && error && !strcmp(error,"cannot append GeoIpifi result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); prior_is(&out,&prior); free(error);
    fail_part_after = 1;
    CHECK(d->scan(d,NULL,true,(br_slice){(const unsigned char *)input,strlen(input)},&out,NULL) != 0 && !fail_part_after);
    prior_is(&out,&prior); br_results_clear(&out);
    CHECK(d->scan(NULL,NULL,false,(br_slice){0},NULL,NULL) != 0);
    out = test_scan(d,NULL,false,input,strlen(input)); CHECK(out.len == 2); br_results_clear(&out);
}
int main(void)
{
    test_secret(a,32,0); test_secret(b,32,11); a[0] = 'Q'; a[16] = '_'; b[2] = 'Z'; b[31] = '_';
    const br_detector *d = descriptor(); grammar(d); occurrences_nilskip(d); status_body_errors(d); shared_setup(d); rollback(d);
    CHECK(!fail_after && !fail_part_after);
    return test_finish("GeoIpifi grammar/occurrences/request/status/errors/rollback");
}
