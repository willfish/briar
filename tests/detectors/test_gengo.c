/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char a[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char b[] = "[]-(){}|_^@$=~BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
static time_t tick = 1700000000;
static size_t clocks, signs, fail_clock_at, fail_sign_at, fail_part_after, fail_json_after;

int clock_gettime(clockid_t which, struct timespec *out)
{
    if (which != CLOCK_REALTIME) return (int)syscall(SYS_clock_gettime, which, out);
    if (++clocks == fail_clock_at) { errno = EIO; return -1; }
    *out = (struct timespec){tick, 999999999}; return 0;
}

unsigned char *EVP_Q_mac(OSSL_LIB_CTX *ctx, const char *name, const char *propq,
                        const char *subalg, const OSSL_PARAM *params, const void *key,
                        size_t keylen, const unsigned char *data, size_t datalen,
                        unsigned char *out, size_t outsize, size_t *outlen)
{
    if (++signs == fail_sign_at) return NULL;
    unsigned char *(*real_mac)(OSSL_LIB_CTX *, const char *, const char *, const char *,
        const OSSL_PARAM *, const void *, size_t, const unsigned char *, size_t, unsigned char *, size_t, size_t *);
    void *symbol = dlsym(RTLD_NEXT, "EVP_Q_mac"); CHECK(symbol); memcpy(&real_mac, &symbol, sizeof(real_mac));
    return real_mac(ctx, name, propq, subalg, params, key, keylen, data, datalen, out, outsize, outlen);
}

int json_object_object_add(br_json *object, const char *name, br_json *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

struct json_tokener *json_tokener_new_ex(int depth)
{
    if (fail_json_after && --fail_json_after == 0) return NULL;
    struct json_tokener *(*real_new)(int);
    void *symbol = dlsym(RTLD_NEXT, "json_tokener_new_ex"); CHECK(symbol); memcpy(&real_new, &symbol, sizeof(real_new));
    return real_new(depth);
}

static void reset(void)
{
    clocks = signs = fail_clock_at = fail_sign_at = fail_part_after = fail_json_after = 0;
    tick = 1700000000;
}

static void finding(const br_result *r, const char *key, const char *secret, bool verified)
{
    CHECK(r->detector_type == 426 && !r->detector_name && r->verified == verified && !r->verification_error);
    CHECK(r->raw.len == 64 && !memcmp(r->raw.data, secret, 64));
    CHECK(r->raw_v2.len == 128 && !memcmp(r->raw_v2.data, key, 64) && !memcmp(r->raw_v2.data + 64, secret, 64));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(r->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), secret));
    CHECK(!r->redacted && !r->extra_data && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(strlen(a) == 64 && strlen(b) == 64 && BR_ABI_REVISION == 1);
    CHECK(br_gengo_init(NULL, &error) == -1 && error); free(error);
    CHECK(!br_gengo_init(&d, &error) && d && !error);
    CHECK(!br_gengo_init(&again, NULL) && again == d);
    CHECK(d->type == 426 && d->version == 0 && !strcmp(d->name, "Gengo") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Gengo is a platform for professional human translation services. Gengo API keys can be used to access and manage translation projects and resources."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gengo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->cloud_endpoint && !d->validate_endpoints);
    return d;
}

static void extraction(const br_detector *d)
{
    const char *suffixes[] = {" ", "\r", "\n", "\t", ""};
    char input[256];
    for (size_t i = 0; i < 5; ++i) {
        snprintf(input, sizeof(input), "GeNgO %s%s", b, suffixes[i]);
        br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == (i < 3 ? 1u : 0u));
        if (r.len) finding(&r.items[0], b, b, false);
        br_results_clear(&r);
    }
    /* First match consumes the ONLY 'gengo' prefix of the next would-be match.
     * No overlapping/restarted matching and no lookbehind delimiter emulation. */
    snprintf(input, sizeof(input), "gengogengo%s %s ", a, b);
    br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 1); finding(&r.items[0], a, a, false); br_results_clear(&r);
    snprintf(input, sizeof(input), "gengo%s gengo%s\rgengo%s\n", a, b, a);
    r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 9);
    const char *values[] = {a, b, a};
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) finding(&r.items[k * 3 + s], values[k], values[s], false);
    br_results_clear(&r); CHECK(!clocks && !signs);
    char far[2048]; memset(far, '!', sizeof(far));
    memcpy(far, "gengo", 5); memcpy(far + 5, a, 64); far[69] = '\n';
    memcpy(far + 1800, "gengo", 5); memcpy(far + 1805, b, 64); far[1869] = '\r';
    r = test_scan(d, NULL, false, far, sizeof(far)); CHECK(r.len == 4); finding(&r.items[1], a, b, false); br_results_clear(&r);
}

typedef struct { const char *const *values; size_t count; const char *ts; const char *const *signatures; int arm; const char *live_url; char copy[256]; } inspection;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    inspection *i = http->user; size_t at = http->calls - 1;
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 426 && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog offline"));
    if (i->values) {
        char expected[256]; snprintf(expected, sizeof(expected), "https://api.gengo.com/v2/account/me?ts=%s&api_key=%s&api_sig=%s", i->ts, i->values[at / i->count], i->signatures[at % i->count]);
        CHECK(!strcmp(request->url, expected));
    }
    i->live_url = request->url; strcpy(i->copy, request->url);
    if (http->calls == 2 && i->arm == 1) fail_json_after = 4; /* After sticky type error, fail next projected name. */
    if (http->calls == 1 && i->arm == 2) fail_part_after = 1;
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; inspection *i = http->user;
    CHECK(i->live_url && !strcmp(i->live_url, i->copy));
    test_http_release(user, response);
}

static void verification(const br_detector *d)
{
    const char *values[] = {a, b};
    const char *gold[] = {"602b744b069b2f83ac503c72b01011a3c650a62c", "1e192b2f51423c37760f57a3fdbb2ca6a1586045"};
    inspection i = {.values = values, .count = 2, .ts = "1700000000", .signatures = gold};
    test_http http = {.response = {.status = 299, .body = {(const unsigned char *)"{\"opstat\":\"ok\"}", 15}}, .inspect = inspect, .user = &i};
    br_transport t = test_transport(&http); t.release = release; br_scan_ctx ctx = {.transport = &t, .user_agent = "offline"};
    char input[256]; snprintf(input, sizeof(input), "gengo%s\ngengo%s ", a, b);
    br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 4 && http.calls == 4 && http.releases == 4 && clocks == 4 && signs == 4);
    for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) finding(&r.items[k * 2 + s], values[k], values[s], true);
    br_results_clear(&r);
    /* Signed seconds, including the maximum-width negative decimal. */
    const time_t times[] = {-1, INT64_MIN}; const char *texts[] = {"-1", "-9223372036854775808"};
    const char *negative[] = {"08b74057f2651c8ec4e3eab8f96e984c7e793a31", "ebec238dd8a59d4336fa31929971a0e17833826e"};
    snprintf(input, sizeof(input), "gengo%s ", a); i.count = 1;
    for (size_t n = 0; n < 2; ++n) {
        reset(); tick = times[n]; i.ts = texts[n]; i.signatures = &negative[n]; http.calls = http.releases = 0;
        r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); finding(&r.items[0], a, a, true); br_results_clear(&r);
    }
}

static void response_policies(const br_detector *d)
{
    struct { const char *body; int status; const char *read_error; int send_rc; size_t count; bool verified; } cases[] = {
        {"{\"opstat\":\"ok\"}",200,NULL,0,1,true}, {"{\"opstat\":\"ok\"}",300,NULL,0,1,false},
        {"{\"opstat\":\"ok\"}",199,NULL,0,1,false}, {"{\"opstat\":\"OK\"}",200,NULL,0,1,false},
        {"{\"opstat\":\"ok\\u0000\"}",200,NULL,0,1,false},
        {"{\"OPSTAT\":\"ok\",\"opstat\":null}",200,NULL,0,1,true},
        {"{\"op\\u017ftat\":\"ok\",\"unknown\":1e9999}",200,NULL,0,1,true},
        {"{\"opstat\":\"ok\",\"opstat\":\"bad\"}",200,NULL,0,1,false},
        {"{\"opstat\":7,\"opstat\":\"ok\"}",200,NULL,0,0,false},
        {"{\"opstat\":{},\"opstat\":null}",503,NULL,0,0,false},
        {"null",200,NULL,0,1,false}, {"{}",200,NULL,0,1,false}, {"[]",503,NULL,0,0,false},
        {"{\"opstat\":\"ok\"} {}",200,NULL,0,0,false}, {"{",503,NULL,0,0,false},
        {"{",503,"read failure",0,1,false}, {"{\"opstat\":\"ok\"}",200,"read failure",0,1,false},
        {"{",200,NULL,1,1,false}, {"{",503,"read failure",1,1,false},
    };
    char input[128]; snprintf(input, sizeof(input), "gengo%s ", a);
    for (size_t n = 0; n < sizeof(cases) / sizeof(cases[0]); ++n) {
        reset(); inspection i = {0}; test_http http = {.response = {.status = cases[n].status, .body = {(const unsigned char *)cases[n].body, strlen(cases[n].body)}, .body_error = cases[n].read_error}, .send_rc = cases[n].send_rc, .send_error = cases[n].send_rc ? "mixed adapter failure" : NULL, .inspect = inspect, .user = &i};
        br_transport t = test_transport(&http); t.release = release; br_scan_ctx ctx = {.transport = &t, .user_agent = "offline"};
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == cases[n].count && http.calls == 1 && http.releases == 1);
        if (r.len) finding(&r.items[0], a, a, cases[n].verified);
        br_results_clear(&r);
    }
}

static void fatal_and_nil(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "gengo%s\ngengo%s ", a, b);
    reset(); br_results r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && clocks == 4 && signs == 4); br_results_clear(&r);
    for (int mode = 0; mode < 4; ++mode) {
        reset();
        br_result prior = {0}; CHECK(!br_finding_key(&prior, 999, "caller-owned-synthetic", "key"));
        CHECK(!br_results_push(&r, &prior)); unsigned char *original = r.items[0].raw.data;
        inspection i = {.arm = mode == 2 ? 1 : mode == 3 ? 2 : 0};
        const char *body = mode == 2 ? "{\"opstat\":7,\"x\":0}" : "{\"opstat\":\"ok\"}";
        test_http http = {.response = {.status = 503, .body = {(const unsigned char *)body, strlen(body)}}, .inspect = inspect, .user = &i};
        br_transport t = test_transport(&http); t.release = release; br_scan_ctx ctx = {.transport = &t, .user_agent = "offline"};
        if (mode == 0) fail_clock_at = 2;
        if (mode == 1) fail_sign_at = 2;
        char *error = NULL; int rc = d->scan(d, mode < 2 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == -1 && error && r.len == 1 && r.items[0].raw.data == original);
        CHECK(!memcmp(original, "caller-owned-synthetic", r.items[0].raw.len));
        if (mode == 2) CHECK(http.calls == 2 && http.releases == 2 && !fail_json_after);
        if (mode == 3) CHECK(http.calls == 1 && http.releases == 1 && !fail_part_after);
        free(error); br_results_clear(&r);
    }
    reset();
}

int main(void)
{
    const br_detector *d = descriptor(); reset(); extraction(d); verification(d); response_policies(d); fatal_and_nil(d);
    return test_finish("gengo");
}
