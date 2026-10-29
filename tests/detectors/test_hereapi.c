/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[44], key2[44];
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
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}

static const char url_prefix[] =
    "https://weather.ls.hereapi.com/weather/1.0/report.json?product=alerts&name=Argentina&apiKey=";
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static size_t fixture(unsigned char *input, const char *prefix, br_slice token, const char *suffix)
{
    size_t n = strlen(prefix), end = strlen(suffix);
    memcpy(input, prefix, n);
    memcpy(input + n, token.data, token.len);
    memcpy(input + n + token.len, suffix, end);
    return n + token.len + end;
}

static void result_is(const br_result *r, br_slice expected, bool verified)
{
    CHECK(r->detector_type == 408 && !r->detector_name);
    CHECK(r->raw.data && r->raw.len == expected.len);
    CHECK(!expected.len || !memcmp(r->raw.data, expected.data, expected.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted);
    CHECK(!r->extra_data && !r->structured_data);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(part), expected.data, expected.len));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->chunk_offset && !r->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_hereapi_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_hereapi_init(NULL, NULL) != 0);
    CHECK(br_hereapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_hereapi_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 408 && d->version == 0 && !strcmp(d->name, "HereAPI"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "HereAPI provides access to a wide range of location-based services including maps, geocoding, and traffic information. HereAPI keys can be used to authenticate and access these services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "hereapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction(const br_detector *d)
{
    unsigned char input[1024], token[192];
    test_http http = {0}; br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t};
    const char *formats[] = {"%s", "hereapi %s", "HeReApI %s", "preHEREAPIsuffix\r\n%s", "hereapi_%s", "hereapi %s_", "hereapi X%s", "hereapi %sX"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(*formats); ++i) {
        int n = sprintf((char *)input, formats[i], key);
        br_results r = test_scan(d, &ctx, false, input, (size_t)n);
        CHECK(r.len == (i >= 1 && i <= 3 ? 1u : 0u));
        if (r.len) result_is(&r.items[0], text(key), false);
        br_results_clear(&r);
    }
    for (size_t len = 42; len <= 44; ++len) {
        memset(token, 'A', len);
        size_t n = fixture(input, "hereapi ", (br_slice){token, len}, "");
        br_results r = test_scan(d, &ctx, false, input, n);
        CHECK(r.len == (len == 43 ? 1u : 0u)); br_results_clear(&r);
    }
    const unsigned char excluded[] = {'\t', '\n', '\f', '\r', ' '};
    for (size_t i = 0; i < sizeof(excluded); ++i) {
        memcpy(token, key, 43); token[21] = excluded[i];
        size_t n = fixture(input, "hereapi ", (br_slice){token, 43}, "");
        br_results r = test_scan(d, &ctx, false, input, n);
        CHECK(!r.len); br_results_clear(&r);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "hereapi", 7); size_t at = 7;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key, 43); at += 43;
            br_results r = test_scan(d, &ctx, false, input, at);
            CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
        }
    }
    /* ASCII boundaries allow nonword capture edges when context is a word. */
    memset(token, 'A', 43); token[0] = token[42] = '-';
    size_t n = fixture(input, "hereapi", (br_slice){token, 43}, "Z");
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1); result_is(&r.items[0], (br_slice){token, 43}, false); br_results_clear(&r);
    n = fixture(input, "hereapi \xc3\xa9", text(key), "\xc3\xa9");
    r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1); result_is(&r.items[0], text(key), false); br_results_clear(&r);
    /* The class includes VT, Unicode whitespace, punctuation and binary NUL. */
    const unsigned char admitted[] = {'\v', 0, '+', '/', '=', '_', 'Q'};
    for (size_t i = 0; i < sizeof(admitted); ++i) {
        memcpy(token, key, 43); token[21] = admitted[i];
        n = fixture(input, "hereapi ", (br_slice){token, 43}, "");
        r = test_scan(d, &ctx, false, input, n);
        CHECK(r.len == 1); result_is(&r.items[0], (br_slice){token, 43}, false); br_results_clear(&r);
    }
    memset(token, 'A', 20); memcpy(token + 20, "\xe3\x80\x80", 3); memset(token + 23, 'Z', 22);
    n = fixture(input, "hereapi ", (br_slice){token, 45}, "");
    r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1); result_is(&r.items[0], (br_slice){token, 45}, false); br_results_clear(&r);
    /* All 43 four-byte runes are admitted: 172 bytes is a grammar bound. */
    for (size_t i = 0; i < 43; ++i) memcpy(token + i * 4, "\xf0\x9f\x98\x80", 4);
    n = fixture(input, "hereapi", (br_slice){token, 172}, "Z");
    r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1); result_is(&r.items[0], (br_slice){token, 172}, false); br_results_clear(&r);
    int len = sprintf((char *)input, "hereapi %s\nhereapi %s\nhereapi %s", key, key2, key);
    r = test_scan(d, &ctx, false, input, (size_t)len);
    CHECK(r.len == 3);
    result_is(&r.items[0], text(key), false); result_is(&r.items[1], text(key2), false); result_is(&r.items[2], text(key), false);
    br_results_clear(&r);
    r = test_scan(d, &ctx, false, NULL, 0); CHECK(!r.len); br_results_clear(&r);
    CHECK(!http.calls && !http.releases);
}

typedef struct { const char *url, *borrowed; } expected_request;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *req)
{
    expected_request *e = http->user;
    CHECK(ctx && !strcmp(req->method, "GET") && !strcmp(req->url, e->url));
    CHECK(req->profile == BR_HTTP_SANE && req->timeout_ms == 5000 && req->detector_type == 408);
    CHECK(req->nheaders == 1 && !strcmp(req->headers[0].name, "User-Agent"));
    CHECK(!strcmp(req->headers[0].value, "TruffleHog hereapi-offline"));
    CHECK(!req->body.data && !req->body.len && !req->dedup_key.data && !req->dedup_key.len);
    e->borrowed = req->url; /* Only provider-owned URL storage, never prepared headers/UA. */
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user;
    expected_request *e = http->user;
    if (e && e->borrowed) { CHECK(!strcmp(e->borrowed, e->url)); e->borrowed = NULL; }
    test_http_release(user, response);
}

static void trimming(const br_detector *d)
{
    const char *spaces[] = {"\v", "\xc2\x85", "\xe2\x80\x80", "\xe3\x80\x80"};
    unsigned char token[128], input[256]; char trimmed[42], url[256];
    memset(trimmed, 'A', 41); trimmed[41] = 0;
    sprintf(url, "%s%s", url_prefix, trimmed);
    expected_request e = {.url = url};
    test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &e};
    br_transport t = {&http, test_http_send, release};
    br_scan_ctx ctx = {.transport = &t, .user_agent = "hereapi-offline"};
    for (size_t i = 0; i < sizeof(spaces) / sizeof(*spaces); ++i) {
        size_t width = strlen(spaces[i]);
        memcpy(token, spaces[i], width); memset(token + width, 'A', 41); memcpy(token + width + 41, spaces[i], width);
        size_t n = fixture(input, "hereapi", (br_slice){token, 41 + 2 * width}, "Z");
        br_results r = test_scan(d, &ctx, false, input, n);
        CHECK(r.len == 1 && http.calls == i && http.releases == i);
        result_is(&r.items[0], text(trimmed), false); br_results_clear(&r);
        r = test_scan(d, &ctx, true, input, n);
        CHECK(r.len == 1 && http.calls == i + 1 && http.releases == http.calls);
        result_is(&r.items[0], text(trimmed), true); br_results_clear(&r);
    }
    memset(token, '\v', 43);
    size_t n = fixture(input, "hereapi", (br_slice){token, 43}, "Z");
    e.url = url_prefix;
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1 && http.calls == 4); result_is(&r.items[0], text(""), false); br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, n);
    CHECK(r.len == 1 && http.calls == 5 && http.releases == 5);
    result_is(&r.items[0], text(""), true); br_results_clear(&r);
    r = test_scan(d, NULL, true, input, n); CHECK(!r.len); br_results_clear(&r);
}

static bool ascii_word(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static void url_case(const br_detector *d, br_slice token, const char *projected, bool keep)
{
    unsigned char input[512]; char url[1024];
    size_t n = fixture(input, "hereapi ", token, ascii_word(token.data[token.len - 1]) ? "" : "Z");
    sprintf(url, "%s%s", url_prefix, projected);
    expected_request e = {.url = url};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect, .user = &e};
    br_transport t = {&http, test_http_send, release};
    br_scan_ctx ctx = {.transport = &t, .user_agent = "hereapi-offline"};
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == 1 && !http.calls && !http.releases);
    result_is(&r.items[0], token, false); br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, n);
    CHECK(r.len == (keep ? 1u : 0u) && http.calls == (keep ? 1u : 0u) && http.releases == http.calls);
    if (keep) result_is(&r.items[0], token, true);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, n); CHECK(!r.len); br_results_clear(&r);
}

static void url_tail(const br_detector *d, br_slice tail, const char *projected, bool keep)
{
    unsigned char token[43]; char output[512];
    CHECK(tail.len < sizeof(token));
    size_t pad = sizeof(token) - tail.len;
    memset(token, 'A', pad); memcpy(token + pad, tail.data, tail.len);
    memset(output, 'A', pad); strcpy(output + pad, projected);
    url_case(d, (br_slice){token, sizeof(token)}, output, keep);
}

static void urls(const br_detector *d)
{
    /* Source-derived URL.String projection, not a Go runtime or wire oracle. */
    url_case(d, text(key), key, true);
    url_tail(d, text("?x=Y&z=Q"), "?x=Y&z=Q", true);
    url_tail(d, text("%zzZ"), "%zzZ", true); /* RawQuery escapes are not parsed. */
    url_tail(d, text("%'[Q]Z"), "%'[Q]Z", true);
    url_tail(d, (br_slice){(const unsigned char *)"\0Z", 2}, "", false);
    url_tail(d, text("\vZ"), "", false);
    url_tail(d, text("\x1fZ"), "", false);
    url_tail(d, text("\177Z"), "", false);
    url_tail(d, text("#"), "", true); /* EMPTY terminal fragment drops the '#'. */
    url_tail(d, text("#%2fZ"), "#%2fZ", true);
    url_tail(d, text("#'[Q]Z"), "#'[Q]Z", true); /* validEncoded exceptions. */
    url_tail(d, text("#%00Z"), "#%00Z", true);
    url_tail(d, text("#%xxZ"), "", false);
    url_tail(d, text("#%Z"), "", false);
    url_tail(d, text("#%41%Z"), "", false); /* Validate every escape. */
    url_tail(d, (br_slice){(const unsigned char *)"#\0%zzZ", 6}, "", false);
    url_tail(d, (br_slice){(const unsigned char *)"#%41'\0", 6}, "#A%27%00", true);
    url_tail(d, text("#%41'[Q]\"Z"), "#A%27%5BQ%5D%22Z", true);
    url_tail(d, text("#%2f\"Z"), "#/%22Z", true); /* Whole-fragment fallback. */
    url_tail(d, text("#c#Z"), "#c%23Z", true); /* FIRST hash only. */
    url_tail(d, text("#+\vZ"), "#+%0BZ", true); /* Fragment '+' is not space. */
    url_tail(d, text("#\x1fZ"), "#%1FZ", true);
    url_tail(d, text("#\177Z"), "#%7FZ", true);
    unsigned char token[172]; char projected[600]; size_t at = 0, out = 0;
    token[at++] = 'A'; token[at++] = '#'; memcpy(projected, "A#", 2); out = 2;
    for (size_t i = 0; i < 40; ++i) {
        memcpy(token + at, "\xf0\x9f\x98\x80", 4); at += 4;
        memcpy(projected + out, "%F0%9F%98%80", 12); out += 12;
    }
    token[at++] = 'Z'; projected[out++] = 'Z'; projected[out] = 0;
    url_case(d, (br_slice){token, at}, projected, true);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification(const br_detector *d)
{
    unsigned char input[512]; size_t n = fixture(input, "hereapi ", text(key), "");
    char url[256]; sprintf(url, "%s%s", url_prefix, key);
    expected_request e = {.url = url};
    const struct { int status, rc; const char *cause; } cases[] = {
        {199,0,NULL}, {200,0,NULL}, {201,0,NULL}, {204,0,NULL}, {299,0,NULL},
        {300,0,NULL}, {401,0,NULL}, {403,0,NULL}, {500,0,NULL},
        {200,1,"synthetic timeout"}, {200,-1,"synthetic cancellation"},
        {200,7,"out of memory constructing HTTP headers"}, {200,1,NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = text("not JSON"), .body_error = "ignored body read error"}, .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect, .user = &e};
        br_transport t = {&http, test_http_send, release};
        br_scan_ctx ctx = {.transport = &t, .user_agent = "hereapi-offline"};
        br_results r = test_scan(d, &ctx, true, input, n);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], text(key), !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&r);
    }
    test_http http = {0}; br_transport t = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport=&t,.cancelled=cancelled,.cancel_user=&cancellations}, {.transport=&t,.deadline_monotonic_ms=1}, {.transport=&t,.user_agent="bad\r\nagent"}, {.transport=&t}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        if (i == 4) fail_agent = true;
        br_results r = test_scan(d, &contexts[i], true, input, n);
        CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent);
        result_is(&r.items[0], text(key), false); br_results_clear(&r);
    }
    CHECK(cancellations == 1);
    n += fixture(input + n, "\nhereapi ", text(key), "");
    http = (test_http){.response = {.status = 200}, .inspect = inspect, .user = &e};
    t = (br_transport){&http, test_http_send, release};
    br_scan_ctx ctx = {.transport=&t, .user_agent="hereapi-offline"};
    br_results r = test_scan(d, &ctx, true, input, n);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2); /* No dedup or early success break. */
    result_is(&r.items[0], text(key), true); result_is(&r.items[1], text(key), true); br_results_clear(&r);
}

static void resources(const br_detector *d)
{
    unsigned char input[256];
    int n = sprintf((char *)input, "hereapi %s\nhereapi %s", key, key2);
    br_result prior = {.detector_type=12345, .verified=true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    br_results r = {0}; CHECK(br_results_push(&r, &prior) == 0);
    unsigned char *original = r.items[0].raw.data; char *error = NULL;
    for (size_t part = 1; part <= 2; ++part) {
        fail_part = part;
        CHECK(d->scan(d, NULL, part == 1, (br_slice){input,(size_t)n}, &r, &error) != 0 && !fail_part && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original && r.items[0].verified && !memcmp(original, "keep", 4));
        free(error); error = NULL;
    }
    const size_t sizes[] = {44, 43}; /* Owned capture/finding failures precede nil-context drop. */
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        fail_size = sizes[i]; fail_after = 1;
        CHECK(d->scan(d, NULL, true, (br_slice){input,(size_t)n}, &r, &error) != 0 && !fail_after && error);
        CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    }
    unsigned char binary[43]; memcpy(binary, key, 43); binary[20] = 0;
    size_t bad_n = fixture(input, "hereapi ", (br_slice){binary,43}, "");
    fail_part = 1;
    CHECK(d->scan(d, &(br_scan_ctx){0}, true, (br_slice){input,bad_n}, &r, &error) != 0 && !fail_part && error);
    CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    memset(binary, '\v', 43); bad_n = fixture(input, "hereapi", (br_slice){binary,43}, "Z");
    fail_size = 1; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){input,bad_n}, &r, &error) != 0 && !fail_after && error);
    CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); error = NULL;
    size_t len = fixture(input, "hereapi ", text(key), "");
    size_t cap = r.cap; r.cap = 0;
    CHECK(d->scan(d, NULL, false, (br_slice){input,len}, &r, &error) != 0 && error);
    r.cap = cap; CHECK(r.len == 1 && r.items[0].raw.data == original); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    r = test_scan(d, NULL, false, input, len); CHECK(r.len == 1); br_results_clear(&r);
}

int main(void)
{
    test_secret(key, 43, 0); test_secret(key2, 43, 9);
    const br_detector *d = descriptor();
    extraction(d); trimming(d); urls(d); verification(d); resources(d);
    return test_finish("HereAPI grammar/occurrences/Go trim/URL projection/lifetime/status/resource rollback");
}
