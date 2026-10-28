/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[41], key2[41], id[16], id2[31];
static size_t fail_size, fail_after, fail_part;
static bool fail_agent, fail_headers;

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
    int rc = json_object_object_add_ex(o, name, v, 0);
    if (!rc && fail_headers) {
        fail_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *k, bool verified)
{
    test_key_result(r, 633, k, "key");
    CHECK(r->verified == verified && !r->verification_error);
    br_json *hidden = NULL;
    CHECK(!json_object_object_get_ex(r->secret_parts, "id", &hidden));
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_getsandbox_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_getsandbox_init(NULL, NULL) != 0);
    CHECK(br_getsandbox_init(&d, &error) == 0 && d && !error);
    CHECK(br_getsandbox_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 633 && !d->version && !strcmp(d->name, "GetSandbox"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GetSandbox is a service for creating and managing sandboxes. GetSandbox API keys can be used to access and control these sandboxes."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "getsandbox"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction(const br_detector *d)
{
    char input[512], upper[41];
    const char *formats[] = {"getsandbox %s", "%s", "getsandbox _%s", "getsandbox %s_", "getsandbox X%s", "getsandbox %sX"};
    for (size_t f = 0; f < sizeof(formats)/sizeof(*formats); ++f) {
        int n = sprintf(input, formats[f], key);
        n += sprintf(input + n, "\ngetsandbox %s", id);
        br_results r = test_scan(d, NULL, false, input, (size_t)n);
        CHECK(r.len == (f == 0 ? 1u : 0u));
        if (r.len) result_is(&r.items[0], key, false);
        br_results_clear(&r);
    }
    const char *missing[] = {"", "getsandbox", key, id, id2};
    for (size_t i = 0; i < sizeof(missing)/sizeof(*missing); ++i) {
        int n = sprintf(input, "getsandbox %s", missing[i]);
        br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    memcpy(upper, key, sizeof(upper)); upper[12] = 'Q';
    int n = sprintf(input, "getsandbox %s\ngetsandbox %s", upper, id);
    br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    const char *bad_ids[] = {"abcdefghijklmNop", "abcdefghijklmn", "abcdefghijklmnopqrstuvwxyz12345", "_abcdefghijklmno", "abcdefghijklmno_"};
    for (size_t i = 0; i < sizeof(bad_ids)/sizeof(*bad_ids); ++i) {
        n = sprintf(input, "getsandbox %s\ngetsandbox %s", key, bad_ids[i]);
        r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    n = sprintf(input, "preGeTsAnDbOxSuffix\r\n%s\nGETSANDBOX\r%s", key, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], key, false); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) for (int role = 0; role < 2; ++role) {
        n = sprintf(input, "getsandbox %s\ngetsandbox", role ? key : id);
        memset(input + n, '.', gap); n += (int)gap;
        n += sprintf(input + n, "%s", role ? id : key);
        r = test_scan(d, NULL, false, input, (size_t)n);
        CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    n = sprintf(input, "getsandbox %s", key); input[n++] = 0;
    n += sprintf(input + n, "getsandbox %s", id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); br_results_clear(&r);
    r = test_scan(d, NULL, false, NULL, 0); CHECK(!r.len); br_results_clear(&r);
}

typedef struct {
    const char *const *keys, *const *ids;
    size_t nids;
    const char *borrowed_key, *borrowed_url;
} expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected *e = http->user; size_t index = http->calls - 1;
    char url[128]; sprintf(url, "https://getsandbox.com/api/1/sandboxes/%s", e->ids[index % e->nids]);
    CHECK(ctx && !strcmp(req->method, "GET") && !strcmp(req->url, url));
    CHECK(req->profile == BR_HTTP_SANE && req->timeout_ms == 5000 && req->detector_type == 633);
    CHECK(req->nheaders == 2);
    CHECK(!strcmp(req->headers[0].name, "Api-Key") && !strcmp(req->headers[0].value, e->keys[index / e->nids]));
    CHECK(!strcmp(req->headers[1].name, "User-Agent") && !strcmp(req->headers[1].value, ctx->user_agent ? "TruffleHog synthetic" : "TruffleHog"));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    /* Only source values are retained: ordinary effective headers/UA expire
     * at send return, while provider URL and captures survive release. */
    e->borrowed_key = req->headers[0].value; e->borrowed_url = req->url;
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    if (e && e->borrowed_key) {
        size_t index = http->calls - 1; char url[128];
        sprintf(url, "https://getsandbox.com/api/1/sandboxes/%s", e->ids[index % e->nids]);
        CHECK(!strcmp(e->borrowed_key, e->keys[index / e->nids]));
        CHECK(!strcmp(e->borrowed_url, url));
        e->borrowed_key = e->borrowed_url = NULL;
    }
    test_http_release(user, response);
}

static void products(const br_detector *d)
{
    char input[4096];
    int n = sprintf(input, "getsandbox %s\ngetsandbox %s\ngetsandbox %s\n", key, key2, key);
    memset(input + n, '.', 1800); n += 1800;
    n += sprintf(input + n, "\ngetsandbox %s\ngetsandbox %s\ngetsandbox %s", id, id2, id);
    const char *keys[] = {key, key2, key}, *ids[] = {id, id2, id};
    expected e = {.keys=keys, .ids=ids, .nids=3};
    test_http http = {.response={.status=200}, .inspect=inspect, .user=&e};
    br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport=&t};
    br_results r = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(r.len == 9 && !http.calls && !http.releases);
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) result_is(&r.items[k * 3 + i], keys[k], false);
    br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(r.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) result_is(&r.items[k * 3 + i], keys[k], true);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
}

static void hyphens(const br_detector *d)
{
    char overlap[41], backtracked[27], input[256];
    memset(overlap, 'a', 25); overlap[25] = '-'; memset(overlap + 26, 'b', 14); overlap[40] = 0;
    memcpy(backtracked, overlap, 26); backtracked[26] = 0;
    const char *keys[] = {overlap}, *ids[] = {backtracked};
    expected e = {.keys=keys, .ids=ids, .nids=1};
    test_http http = {.response={.status=204}, .inspect=inspect, .user=&e};
    br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport=&t};
    int n = sprintf(input, "getsandbox %s", overlap);
    br_results r = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); result_is(&r.items[0], overlap, true); br_results_clear(&r);
    char leading[41], trailing[41]; leading[0] = '-'; memset(leading + 1, 'a', 39); leading[40] = 0;
    memset(trailing, 'b', 39); trailing[39] = '-'; trailing[40] = 0;
    n = sprintf(input, "getsandboxX%s\ngetsandbox %s", leading, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], leading, false); br_results_clear(&r);
    n = sprintf(input, "getsandbox %sX\ngetsandbox %s", trailing, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], trailing, false); br_results_clear(&r);
    n = sprintf(input, "getsandbox -%s\ngetsandbox %s", key, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], key, false); br_results_clear(&r);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification(const br_detector *d)
{
    char input[256]; int n = sprintf(input, "getsandbox %s\ngetsandbox %s", key, id);
    const char *keys[] = {key}, *ids[] = {id}; expected e = {.keys=keys, .ids=ids, .nids=1};
    const struct { int status, rc; const char *cause; } cases[] = {
        {199,0,NULL},{200,0,NULL},{204,0,NULL},{299,0,NULL},{300,0,NULL},
        {401,0,NULL},{500,0,NULL},{200,1,"synthetic timeout"},{200,-1,key},{200,7,NULL},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        test_http http = {.response={.status=cases[i].status, .body=text("not JSON"), .body_error="ignored read error"},
            .send_rc=cases[i].rc, .send_error=cases[i].cause, .inspect=inspect, .user=&e};
        br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport=&t,.user_agent=i == 1 ? "synthetic" : NULL};
        br_results r = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], key, !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300); br_results_clear(&r);
    }
    size_t cancellations = 0; test_http http = {0}; br_transport t = test_transport(&http);
    br_scan_ctx contexts[] = {{0},{.transport=&t,.cancelled=cancelled,.cancel_user=&cancellations},
        {.transport=&t,.deadline_monotonic_ms=1},{.transport=&t,.user_agent="bad\r\nagent"}, {.transport=&t}, {.transport=&t}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        if (i == 4) fail_agent = true;
        if (i == 5) fail_headers = true;
        br_results r = test_scan(d, &contexts[i], true, input, (size_t)n);
        CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_agent && !fail_headers && !fail_after); result_is(&r.items[0], key, false); br_results_clear(&r);
    }
    CHECK(cancellations == 1);
}

static void rollback(const br_detector *d)
{
    char input[256]; int n = sprintf(input, "getsandbox %s\ngetsandbox %s\ngetsandbox %s", key, id, id);
    br_result prior = {.detector_type=12345,.verified=true}; prior.raw.data = malloc(4); CHECK(prior.raw.data);
    memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    br_results r = {0}; CHECK(br_results_push(&r, &prior) == 0); unsigned char *original = r.items[0].raw.data;
    char *error = NULL;
    for (size_t part = 1; part <= 2; ++part) {
        fail_part = part;
        CHECK(d->scan(d, NULL, part == 1, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error && !fail_part);
        CHECK(r.len == 1 && r.items[0].raw.data == original && r.items[0].verified); free(error); error = NULL;
    }
    const size_t sizes[] = {41,16,40};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        fail_size = sizes[i]; fail_after = 1;
        CHECK(d->scan(d, NULL, true, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error && !fail_after);
        CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    }
    /* Own finding failure outranks shared setup/Do suppression. */
    fail_part = 2; test_http http = {.send_rc=1}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport=&t};
    CHECK(d->scan(d, &ctx, true, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error && !fail_part);
    CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); free(error); error = NULL;
    size_t cap = r.cap; r.cap = 0;
    CHECK(d->scan(d, NULL, false, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error);
    r.cap = cap; CHECK(r.len == 1 && r.items[0].raw.data == original && !memcmp(original,"keep",4)); free(error);
    br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 2); br_results_clear(&r);
}

int main(void)
{
    test_secret(key,40,0); test_secret(key2,40,9); test_secret(id,15,4); test_secret(id2,30,13);
    const br_detector *d = descriptor();
    extraction(d); products(d); hyphens(d); verification(d); rollback(d);
    return test_finish("getsandbox");
}
