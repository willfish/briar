/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[40], key2[40];
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

static void result_is(const br_result *r, br_slice k, br_slice s, bool verified)
{
    CHECK(r->detector_type == 407 && !r->detector_name);
    CHECK(r->raw.len == k.len && !memcmp(r->raw.data, k.data, k.len));
    CHECK(r->raw_v2.len == k.len + s.len && !memcmp(r->raw_v2.data, k.data, k.len));
    CHECK(!memcmp(r->raw_v2.data + k.len, s.data, s.len));
    CHECK(!r->redacted && !r->extra_data && !r->structured_data);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == k.len);
    CHECK(!memcmp(json_object_get_string(part), k.data, k.len));
    CHECK(json_object_object_get_ex(r->secret_parts, "search_engine", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == s.len);
    CHECK(!memcmp(json_object_get_string(part), s.data, s.len));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->chunk_offset && !r->chunk_offset_set);
}

static size_t fixture(unsigned char *input, const char *prefix, br_slice search)
{
    int n = sprintf((char *)input, "geocod %s\n%s", key, prefix);
    memcpy(input + n, search.data, search.len);
    return (size_t)n + search.len;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_geocodio_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_geocodio_init(NULL, NULL) != 0);
    CHECK(br_geocodio_init(&d, &error) == 0 && d && !error);
    CHECK(br_geocodio_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 407 && !d->version && !strcmp(d->name, "Geocodio") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Geocodio is a service that provides geocoding and reverse geocoding. Geocodio API keys can be used to convert addresses into geographic coordinates and vice versa."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "geocod"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->scan && d->state && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction(const br_detector *d)
{
    unsigned char input[4096];
    const struct { const char *search; size_t count; } cases[] = {
        {"AbCdEfG", 1}, {"AbCdEf", 0}, {"AbCdEfGhIjKlMnOpQrStUvWxYz1234", 1},
        {"AbCdEfGhIjKlMnOpQrStUvWxYz12345", 0},
        {"abc_def", 1}, {"ab?c&=D", 1}, {"abc\vdef", 1}, {"abc\tdef", 0},
        {"abc\ndef", 0}, {"abc\fdef", 0}, {"abc\rdef", 0}, {"abc def", 0},
        {"ab\xc3\xa9" "cdef", 1},
    };
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        size_t n = fixture(input, "GeOcOd ", text(cases[i].search));
        br_results r = test_scan(d, &ctx, false, input, n);
        CHECK(r.len == cases[i].count && !http.calls && !http.releases);
        if (r.len) result_is(&r.items[0], text(key), text(cases[i].search), false);
        br_results_clear(&r);
    }
    const char *formats[] = {"%s\ngeocod AbCdEfG", "geocod X%s\ngeocod AbCdEfG", "geocod %sX\ngeocod AbCdEfG", "geocod _%s\ngeocod AbCdEfG"};
    for (size_t i = 0; i < sizeof(formats)/sizeof(*formats); ++i) {
        int n = sprintf((char *)input, formats[i], key);
        br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    }
    char upper[40]; memcpy(upper, key, 40); upper[12] = 'Q';
    int n = sprintf((char *)input, "geocod %s\ngeocod AbCdEfG", upper);
    br_results r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "geocod", 6); size_t at = 6;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = '.';
            }
            memcpy(input + at, key, 39); at += 39;
            memcpy(input + at, "\ngeocod AbCdEfG", 15); at += 15;
            r = test_scan(d, NULL, false, input, at); CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
        }
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)sprintf((char *)input, "geocod %s\ngeocod", key);
        memset(input + at, '.', gap); at += gap;
        memcpy(input + at, "AbCdEfG", 7); at += 7;
        r = test_scan(d, NULL, false, input, at); CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    n = sprintf((char *)input, "preGeOcOdsuffix\r\n%s\ngeocod AbCdEfG", key);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], text(key), text("AbCdEfG"), false); br_results_clear(&r);
    /* ASCII word boundaries reject underscore-adjacent keys. */
    n = sprintf((char *)input, "geocod_%s", key);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(!r.len); br_results_clear(&r);
    /* A plain 39-word key cannot satisfy the search's 30-rune end boundary. */
    n = sprintf((char *)input, "geocod:%s\ngeocod AbCdEfG", key);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], text(key), text("AbCdEfG"), false); br_results_clear(&r);
    r = test_scan(d, NULL, false, NULL, 0); CHECK(!r.len); br_results_clear(&r);
}

static void products_and_trim(const br_detector *d)
{
    unsigned char input[8192];
    int n = sprintf((char *)input, "geocod %s\ngeocod %s\ngeocod %s\n", key, key2, key);
    memset(input + n, '.', 1800); n += 1800;
    n += sprintf((char *)input + n, "\ngeocod AbCdEfG\ngeocod HiJkLmN\ngeocod AbCdEfG");
    br_results r = test_scan(d, NULL, false, input, (size_t)n);
    const char *keys[] = {key, key2, key}; const char *searches[] = {"AbCdEfG", "HiJkLmN", "AbCdEfG"};
    CHECK(r.len == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s)
        result_is(&r.items[k * 3 + s], text(keys[k]), text(searches[s]), false);
    br_results_clear(&r);
    const char *spaces[] = {"\v", "\xc2\x85", "\xc2\xa0", "\xe2\x80\x80", "\xe3\x80\x80"};
    for (size_t i = 0; i < sizeof(spaces)/sizeof(*spaces); ++i) {
        char prefix[32]; sprintf(prefix, "geocod%s", spaces[i]);
        size_t len = fixture(input, prefix, text("AbCdEfG"));
        r = test_scan(d, NULL, false, input, len); CHECK(r.len == 1); result_is(&r.items[0], text(key), text("AbCdEfG"), false); br_results_clear(&r);
        unsigned char token[128]; memset(token, 'A', 29); size_t bytes = strlen(spaces[i]);
        memcpy(token + 29, spaces[i], bytes); token[29 + bytes] = 'Z';
        len = fixture(input, "geocod ", (br_slice){token, 30 + bytes});
        r = test_scan(d, NULL, false, input, len); CHECK(r.len == 1); result_is(&r.items[0], text(key), (br_slice){token, 29}, false); br_results_clear(&r);
    }
    size_t len = fixture(input, "geocod ", text("ab\xe2\x80\x8b" "cdef"));
    r = test_scan(d, NULL, false, input, len); CHECK(r.len == 1); result_is(&r.items[0], text(key), text("ab\xe2\x80\x8b" "cdef"), false); br_results_clear(&r);
    unsigned char only_space[31]; memset(only_space, '\v', 30); only_space[30] = 'Z';
    len = fixture(input, "geocod", (br_slice){only_space, sizeof(only_space)});
    r = test_scan(d, NULL, false, input, len); CHECK(r.len == 1); result_is(&r.items[0], text(key), text(""), false); br_results_clear(&r);
    /* Search can capture a prefix of the SAME key match's whole regex span:
     * key's lazy gap skips this short token to reach the 39-byte key. */
    n = sprintf((char *)input, "geocod AbCdEfG %s", key);
    r = test_scan(d, NULL, false, input, (size_t)n); CHECK(r.len == 1); result_is(&r.items[0], text(key), text("AbCdEfG"), false); br_results_clear(&r);
}

typedef struct { const char *url, *borrowed; size_t len; } expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected *e = http->user; CHECK(ctx);
    CHECK(!strcmp(req->method, "GET") && !strcmp(req->url, e->url));
    CHECK(req->profile == BR_HTTP_SANE && req->timeout_ms == 5000 && req->detector_type == 407);
    CHECK(req->nheaders == 1 && !strcmp(req->headers[0].name, "User-Agent") && !strcmp(req->headers[0].value, "TruffleHog geocodio-offline"));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    e->borrowed = req->url; e->len = strlen(req->url);
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    if (e && e->borrowed) { CHECK(strlen(e->borrowed) == e->len && !strcmp(e->borrowed, e->url)); e->borrowed = NULL; }
    test_http_release(user, response);
}

static void url_case(const br_detector *d, br_slice search, const char *projected, bool keep)
{
    unsigned char input[512]; size_t n = fixture(input, "geocod ", search);
    char url[1024]; sprintf(url, "https://api.geocod.io/v1.6/geocode?q=%s&api_key=%s", projected, key);
    expected e = {.url = url}; test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect, .user = &e};
    br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &t, .user_agent = "geocodio-offline"};
    br_results r = test_scan(d, &ctx, false, input, n); CHECK(r.len == 1); result_is(&r.items[0], text(key), search, false); br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, n); CHECK(r.len == (keep ? 1u : 0u) && http.calls == (keep ? 1u : 0u) && http.releases == http.calls);
    if (keep) result_is(&r.items[0], text(key), search, true);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, n); CHECK(!r.len); br_results_clear(&r);
}

static void urls(const br_detector *d)
{
    /* Parent's Go 1.26.8 constructor-only observations, constrained by the
     * pinned 1.26.7 source/table. These are NOT pinned-runtime/wire evidence. */
    url_case(d, text("NewYork"), "NewYork", true);
    static const unsigned char parent_nul_query[] = "abc\0defgh";
    static const unsigned char parent_nul_fragment[] = "abc#de\0fgh";
    url_case(d, (br_slice){parent_nul_query, sizeof(parent_nul_query) - 1}, "", false);
    url_case(d, (br_slice){parent_nul_fragment, sizeof(parent_nul_fragment) - 1}, "abc#de%00fgh", true);
    url_case(d, text("abc#def%2fghi"), "abc#def%2fghi", true);
    url_case(d, text("abc#def%xxghi"), "", false);
    url_case(d, text("abc#d\xc3\xa9" "f'ghi"), "abc#d%C3%A9f%27ghi", true);
    url_case(d, text("abc#d\xc3\xa9" "f%2fghi"), "abc#d%C3%A9f/ghi", true);
    url_case(d, text("Ab?x=Y&z=Q"), "Ab?x=Y&z=Q", true);
    url_case(d, text("Ab%zzCd"), "Ab%zzCd", true); /* Query percent not parsed. */
    url_case(d, text("Ab[Q]c'D"), "Ab[Q]c'D", true); /* Query untouched. */
    url_case(d, text("Ab#c%2fD"), "Ab#c%2fD", true); /* Valid RawFragment retains lowercase hex. */
    url_case(d, text("Ab#c[Q]'D"), "Ab#c[Q]'D", true); /* validEncoded exceptions. */
    url_case(d, text("Ab#c%zzD"), "", false);
    url_case(d, text("Ab#c%2D"), "Ab#c%2D", true);
    url_case(d, text("Ab#c%2D%D"), "", false);
    url_case(d, text("Ab#c\"%2fD"), "Ab#c%22/D", true); /* Whole-fragment fallback unescapes first. */
    url_case(d, text("Ab#c'[Q]\"D"), "Ab#c%27%5BQ%5D%22D", true);
    url_case(d, text("Ab#c#deF"), "Ab#c%23deF", true); /* FIRST hash only. */
    url_case(d, text("Ab#c\xc3\xa9" "deF"), "Ab#c%C3%A9deF", true);
    const unsigned char nul_before[] = {'A','b',0,'c','d','e','F'};
    const unsigned char nul_after[] = {'A','b','#','c',0,'d','e','F'};
    url_case(d, (br_slice){nul_before, sizeof(nul_before)}, "", false);
    url_case(d, (br_slice){nul_after, sizeof(nul_after)}, "Ab#c%00deF", true);
    url_case(d, text("Ab\vcdEF"), "", false);
    url_case(d, text("Ab#c\vdeF"), "Ab#c%0BdeF", true);
    url_case(d, text("Ab\177cdEF"), "", false);
    url_case(d, text("Ab#c\177deF"), "Ab#c%7FdeF", true);
    /* 30 runes with 28 four-byte interior runes proves byte/rune sizing;
     * fragment fallback expands each Unicode byte, including joined key. */
    unsigned char token[128]; char escaped[512]; size_t at = 0, out = 0;
    token[at++] = 'A'; token[at++] = '#'; memcpy(escaped, "A#", 2); out = 2;
    for (size_t i = 0; i < 27; ++i) { memcpy(token + at, "\xf0\x9f\x98\x80", 4); at += 4; memcpy(escaped + out, "%F0%9F%98%80", 12); out += 12; }
    token[at++] = 'Z'; escaped[out++] = 'Z'; escaped[out] = 0;
    url_case(d, (br_slice){token, at}, escaped, true);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification(const br_detector *d)
{
    unsigned char input[256]; size_t n = fixture(input, "geocod ", text("AbCdEfG"));
    char url[256]; sprintf(url, "https://api.geocod.io/v1.6/geocode?q=AbCdEfG&api_key=%s", key);
    expected e = {.url = url};
    const struct { int status, rc; const char *cause; } cases[] = {
        {199,0,NULL},{200,0,NULL},{204,0,NULL},{299,0,NULL},{300,0,NULL},{401,0,NULL},{403,0,NULL},{500,0,NULL},
        {200,1,"synthetic timeout"},{200,-1,"synthetic cancellation"},{200,7,"out of memory constructing HTTP headers"},{200,1,NULL},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = text("not JSON"), .body_error = "ignored body read failure"}, .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect, .user = &e};
        br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &t, .user_agent = "geocodio-offline"};
        br_results r = test_scan(d, &ctx, true, input, n); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], text(key), text("AbCdEfG"), !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300); br_results_clear(&r);
    }
    test_http http = {0}; br_transport t = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport=&t,.cancelled=cancelled,.cancel_user=&cancellations}, {.transport=&t,.deadline_monotonic_ms=1}, {.transport=&t,.user_agent="bad\r\nagent"}, {.transport=&t}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent = true;
        br_results r = test_scan(d, &contexts[i], true, input, n); CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent);
        result_is(&r.items[0], text(key), text("AbCdEfG"), false); br_results_clear(&r);
    }
    CHECK(cancellations == 1);
    /* No break on verified and no dedup/cache: every duplicate product sends. */
    n += (size_t)sprintf((char *)input + n, "\ngeocod AbCdEfG");
    http = (test_http){.response={.status=200}}; br_scan_ctx ctx = {.transport=&t};
    br_results r = test_scan(d, &ctx, true, input, n); CHECK(r.len == 2 && http.calls == 2 && http.releases == 2); br_results_clear(&r);
}

static void resources(const br_detector *d)
{
    unsigned char input[256]; size_t n = fixture(input, "geocod ", text("AbCdEfG\ngeocod AbCdEfG"));
    br_result prior = {.detector_type=12345, .verified=true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    br_results r = {0}; CHECK(br_results_push(&r, &prior) == 0); unsigned char *original = r.items[0].raw.data;
    char *error = NULL;
    for (size_t part = 1; part <= 4; ++part) {
        fail_part = part;
        CHECK(d->scan(d, NULL, part < 3, (br_slice){input,n}, &r, &error) != 0 && !fail_part && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original && r.items[0].verified && !memcmp(original,"keep",4)); free(error); error = NULL;
    }
    /* Own capture and finding allocations are fatal BEFORE nilctx skip. */
    const size_t sizes[] = {40, 8, 39, 46};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(*sizes); ++i) {
        fail_size = sizes[i]; fail_after = 1;
        CHECK(d->scan(d, NULL, true, (br_slice){input,n}, &r, &error) != 0 && !fail_after && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    }
    /* Own finding failure must also outrank an otherwise skipped URL. */
    const unsigned char bad_query[] = "abc\0defgh";
    size_t bad_n = fixture(input, "geocod ", (br_slice){bad_query, sizeof(bad_query) - 1});
    fail_part = 1;
    CHECK(d->scan(d, &(br_scan_ctx){0}, true, (br_slice){input,bad_n}, &r, &error) != 0 && !fail_part && error);
    CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    n = fixture(input, "geocod ", text("AbCdEfG\ngeocod AbCdEfG"));
    size_t cap = r.cap; r.cap = 0;
    CHECK(d->scan(d, NULL, false, (br_slice){input,n}, &r, &error) != 0 && error);
    r.cap = cap; CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    r = test_scan(d, NULL, false, input, n); CHECK(r.len == 2); br_results_clear(&r);
}

int main(void)
{
    test_secret(key, 39, 0); test_secret(key2, 39, 9);
    const br_detector *d = descriptor();
    extraction(d); products_and_trim(d); urls(d); verification(d); resources(d);
    return test_finish("Geocodio grammar/products/Go trim/URL constructor/lifetime/status/resource rollback");
}
