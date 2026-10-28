/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[27], key2[27], id[19], id2[19];
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
    /* Arm only after finding construction: json-c also allocates this size. */
    if (!rc && fail_headers) {
        fail_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *k, bool verified)
{
    test_key_result(r, 327, k, "key");
    CHECK(r->verified == verified && !r->verification_error);
    br_json *hidden = NULL;
    CHECK(!json_object_object_get_ex(r->secret_parts, "id", &hidden));
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_getemails_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_getemails_init(NULL, NULL) != 0);
    CHECK(br_getemails_init(&d, &error) == 0 && d && !error);
    CHECK(br_getemails_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 327 && !d->version && !strcmp(d->name, "GetEmails"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GetEmails is a service used to find email addresses of website visitors. The API keys can be used to access and manage contact data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "getemails"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction(const br_detector *d)
{
    char input[512], upper[27];
    const char *formats[] = {"getemails %s", "%s", "getemails _%s", "getemails %s_", "getemails X%s", "getemails %sX"};
    for (size_t f = 0; f < sizeof(formats)/sizeof(*formats); ++f) {
        int n = sprintf(input, formats[f], key);
        n += sprintf(input + n, "\ngetemails %s", id);
        br_results r = test_scan(d, NULL, false, input, (size_t)n);
        CHECK(r.len == (f == 0 ? 1u : 0u));
        if (r.len) result_is(&r.items[0], key, false);
        br_results_clear(&r);
    }
    const char *missing[] = {"", "getemails", key, id};
    for (size_t i = 0; i < sizeof(missing)/sizeof(*missing); ++i) {
        int n = sprintf(input, "getemails %s", missing[i]);
        br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    memcpy(upper, key, sizeof(upper)); upper[12] = 'Q';
    int n = sprintf(input, "GeTeMaIlS %s\ngetemails %s", upper, id);
    br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    char upper_id[19]; memcpy(upper_id, id, sizeof(upper_id)); upper_id[9] = 'Q';
    n = sprintf(input, "getemails %s\ngetemails %s", key, upper_id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    n = sprintf(input, "preGeTeMaIlSsuffix\r\n%s\nGETEMAILS\r%s", key, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], key, false); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int role = 0; role < 2; ++role) {
            n = sprintf(input, "getemails %s\ngetemails", role ? key : id);
            memset(input + n, '.', gap); n += (int)gap;
            n += sprintf(input + n, "%s", role ? id : key);
            r = test_scan(d, NULL, false, input, (size_t)n);
            CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
        }
    }
    r = test_scan(d, NULL, false, NULL, 0); CHECK(!r.len); br_results_clear(&r);
}

typedef struct {
    const char *const *keys, *const *ids;
    size_t nids;
    const char *borrowed_key, *borrowed_id;
} expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected *e = http->user; size_t index = http->calls - 1;
    CHECK(ctx && !strcmp(req->method, "GET"));
    CHECK(!strcmp(req->url, "https://api.getemails.com/api/v1/contacts"));
    CHECK(req->profile == BR_HTTP_SANE && req->timeout_ms == 5000 && req->detector_type == 327);
    CHECK(req->nheaders == 3);
    CHECK(!strcmp(req->headers[0].name, "Api-Key") && !strcmp(req->headers[0].value, e->keys[index / e->nids]));
    CHECK(!strcmp(req->headers[1].name, "Api-Id") && !strcmp(req->headers[1].value, e->ids[index % e->nids]));
    CHECK(!strcmp(req->headers[2].name, "User-Agent") && !strcmp(req->headers[2].value, "TruffleHog"));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    /* Retain only source capture values, never the ordinary effective request,
     * synthesized header array or UA, whose lifetime ends at send return. */
    e->borrowed_key = req->headers[0].value; e->borrowed_id = req->headers[1].value;
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    if (e && e->borrowed_key) {
        size_t index = http->calls - 1;
        CHECK(!strcmp(e->borrowed_key, e->keys[index / e->nids]));
        CHECK(!strcmp(e->borrowed_id, e->ids[index % e->nids]));
        e->borrowed_key = e->borrowed_id = NULL;
    }
    test_http_release(user, response);
}

static void products(const br_detector *d)
{
    char input[4096];
    int n = sprintf(input, "getemails %s\ngetemails %s\ngetemails %s\n", key, key2, key);
    memset(input + n, '.', 1800); n += 1800;
    n += sprintf(input + n, "\ngetemails %s\ngetemails %s\ngetemails %s", id, id2, id);
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

static void hyphen_boundaries(const br_detector *d)
{
    char overlap[27], input[512];
    memset(overlap, 'a', 18); overlap[18] = '-'; memset(overlap + 19, 'b', 7); overlap[26] = 0;
    const char *keys[] = {overlap}, *ids[] = {"aaaaaaaaaaaaaaaaaa"};
    expected e = {.keys=keys, .ids=ids, .nids=1};
    test_http http = {.response={.status=204}, .inspect=inspect, .user=&e};
    br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport=&t};
    int n = sprintf(input, "getemails %s", overlap);
    br_results r = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); result_is(&r.items[0], overlap, true); br_results_clear(&r);
    /* Boundary is word/nonword, not a ban on leading/trailing hyphens. */
    char leading[27], trailing[27]; leading[0] = '-'; memset(leading + 1, 'a', 25); leading[26] = 0;
    memset(trailing, 'b', 25); trailing[25] = '-'; trailing[26] = 0;
    n = sprintf(input, "getemailsX%s\ngetemails %s", leading, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], leading, false); br_results_clear(&r);
    n = sprintf(input, "getemails %sX\ngetemails %s", trailing, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], trailing, false); br_results_clear(&r);
    n = sprintf(input, "getemails -%s\ngetemails %s", key, id);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], key, false); br_results_clear(&r);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification(const br_detector *d)
{
    char input[256]; int n = sprintf(input, "getemails %s\ngetemails %s", key, id);
    const char *keys[] = {key}, *ids[] = {id}; expected e = {.keys=keys, .ids=ids, .nids=1};
    const struct { int status, rc; const char *cause; } cases[] = {
        {199,0,NULL},{200,0,NULL},{201,0,NULL},{204,0,NULL},{299,0,NULL},{300,0,NULL},
        {401,0,NULL},{403,0,NULL},{500,0,NULL},{200,1,"synthetic timeout"},
        {200,-1,"synthetic cancellation"},{200,7,"synthetic allocation failure"},{200,1,NULL},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        test_http http = {.response={.status=cases[i].status, .body=text("not JSON"), .body_error="ignored read error"},
            .send_rc=cases[i].rc, .send_error=cases[i].cause, .inspect=inspect, .user=&e};
        br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport=&t};
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
    char input[256]; int n = sprintf(input, "getemails %s\ngetemails %s\ngetemails %s", key, id, id);
    br_result prior = {.detector_type=12345,.verified=true}; prior.raw.data = malloc(4); CHECK(prior.raw.data);
    memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    br_results r = {0}; CHECK(br_results_push(&r, &prior) == 0); unsigned char *original = r.items[0].raw.data;
    char *error = NULL;
    for (size_t part = 1; part <= 2; ++part) {
        fail_part = part;
        CHECK(d->scan(d, NULL, part == 1, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error && !fail_part);
        CHECK(r.len == 1 && r.items[0].raw.data == original && r.items[0].verified); free(error); error = NULL;
    }
    const size_t sizes[] = {27,19,26};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        fail_size = sizes[i]; fail_after = 1;
        CHECK(d->scan(d, NULL, true, (br_slice){(unsigned char *)input,(size_t)n}, &r, &error) != 0 && error && !fail_after);
        CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    }
    /* Own finding failure outranks shared setup suppression as well. */
    fail_part = 2; test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport=&t};
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
    test_secret(key,26,0); test_secret(key2,26,9); test_secret(id,18,4); test_secret(id2,18,13);
    const br_detector *d = descriptor();
    extraction(d); products(d); hyphen_boundaries(d); verification(d); rollback(d);
    return test_finish("getemails");
}
