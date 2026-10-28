/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_http_send gumroad_real_send
#define br_http_release gumroad_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

static bool fail_growth;
static void *gumroad_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc gumroad_realloc
#include "../../src/result.c"
#undef realloc

static char key1[44], key2[44];
static size_t fail_size, fail_after, fail_parts, allocation_failures;
static size_t sends, releases, expected_count;
static const char *const *expected_keys;
static const char *original_url;
static br_slice original_body;
static bool native_attempt;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, n);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_parts && --fail_parts == 0) return 1;
    return json_object_object_add_ex(o, name, v, 0);
}

static void check_body(br_slice body, const char *key)
{
    CHECK(body.data && body.len == 56);
    CHECK(!memcmp(body.data, "access_token=", 13) && !memcmp(body.data + 13, key, 43));
}
static void check_request(const br_http_request *r, const char *key, bool effective)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.gumroad.com/v2/products"));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 792);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/x-www-form-urlencoded"));
    if (effective) {
        CHECK(!strcmp(r->headers[1].name, "User-Agent"));
        CHECK(!strcmp(r->headers[1].value, "TruffleHog gumroad-offline") || !strcmp(r->headers[1].value, "TruffleHog"));
    }
    check_body(r->body, key);
}
int br_http_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(!original_url && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    /* Retain only original provider values, never the effective request,
     * synthesized UA, or either request's header array. */
    original_url = r->url; original_body = r->body; ++sends;
    int rc = gumroad_real_send(ctx, r, response, error);
    if (native_attempt) {
        CHECK(rc != 0 && error && *error);
        CHECK(!strcmp(*error, "unsupported: curl adapter supports bodyless GET or POST"));
        CHECK(!response->status && !response->body.data);
    }
    return rc;
}
void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_url && !strcmp(original_url, "https://api.gumroad.com/v2/products"));
    check_body(original_body, expected_keys[releases]);
    gumroad_real_release(ctx, response);
    original_url = NULL; original_body = (br_slice){0}; ++releases;
}
static void expect(const char *const *keys, size_t n)
{
    CHECK(!original_url && !original_body.data && sends == releases);
    expected_keys = keys; expected_count = n; sends = releases = 0;
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)ctx;
    CHECK(http->calls == http->releases + 1);
    check_request(r, expected_keys[sends - 1], true);
}
static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 792, key, "key");
    CHECK(r->raw.len == 43 && r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gumroad_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(!br_gumroad_init(&d, &error) && d && !error);
    CHECK(!br_gumroad_init(&again, NULL) && again == d);
    CHECK(d->type == 792 && !d->version && !strcmp(d->name, "Gumroad") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Gumroad is an online platform that facilitates the sale of products by creators. Gumroad API keys can be used to access and manage these products."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gumroad"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extraction_case(const br_detector *d, const void *input, size_t n, const char *key)
{
    expect(NULL, 0);
    br_results r = test_scan(d, NULL, false, input, n);
    CHECK(r.len == (key ? 1u : 0u) && !sends && !releases);
    if (key) check_result(&r.items[0], key, false);
    br_results_clear(&r);
}
static void grammar(const br_detector *d)
{
    char input[256], changed[44];
    const struct { const char *format; bool match; } cases[] = {
        {"gumroad '%s'", true}, {"GuMrOaD=%s", true}, {"pregumroadsuffix:%s", true},
        {"gumroad\r\n%s", true}, {"gumroad\r%s", true}, {"gumroad\n%s", true},
        {"%s", false}, {"%s gumroad", false}, {"gum road %s", false},
        {"gumroad%s", false}, {"gumroad x%s", false}, {"gumroad _%s", false},
        {"gumroad %s_", false}, {"gumroad %s9", false}, {"gumroad %.42s", false},
        {"gumroad -%s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(d, input, strlen(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, 44); changed[0] = '-';
    snprintf(input, sizeof(input), "gumroad %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "gumroad _%s", changed); extraction_case(d, input, strlen(input), changed);
    changed[42] = '-';
    snprintf(input, sizeof(input), "gumroad _%sx", changed); extraction_case(d, input, strlen(input), changed);
    memcpy(changed, key1, 44); changed[42] = '-';
    snprintf(input, sizeof(input), "gumroad %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "gumroad %sx", changed); extraction_case(d, input, strlen(input), changed);
    memset(changed, '-', 43); changed[43] = 0;
    snprintf(input, sizeof(input), "gumroad _%sx", changed); extraction_case(d, input, strlen(input), changed);
    memset(changed, 'a', 43);
    snprintf(input, sizeof(input), "gumroad %s", changed); extraction_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gumroad", 7); memset(input + 7, '.', gap); memcpy(input + 7 + gap, key1, 43);
        extraction_case(d, input, 50 + gap, gap == 40 ? key1 : NULL);
    }
    snprintf(input, sizeof(input), "gumroad %s %s", key1, key2);
    extraction_case(d, input, strlen(input), key1);
    int n = snprintf(input, sizeof(input), "gumroad%c%s", 0, key1);
    extraction_case(d, input, (size_t)n, key1);
    extraction_case(d, NULL, 0, NULL);
}
static void occurrences(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "gumroad %s\nGUMROAD %s\ngumroad %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int mode = 0; mode < 3; ++mode) {
        expect(keys, mode == 2 ? 3 : 0);
        br_results r = test_scan(d, mode == 1 ? NULL : &ctx, mode != 0, input, strlen(input));
        CHECK(r.len == (mode == 1 ? 0u : 3u));
        CHECK(sends == expected_count && releases == sends);
        CHECK(http.calls == (mode == 2 ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], mode == 2);
        if (r.len) CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts);
        br_results_clear(&r);
    }
    CHECK(http.calls == 3 && http.releases == 3);
}
static void verification(const br_detector *d)
{
    static const unsigned char bytes[] = "\0\xff ignored non-JSON";
    const struct { int status, rc; const char *read_error, *send_error; } cases[] = {
        {199, 0, NULL, NULL}, {200, 0, NULL, NULL}, {201, 0, "ignored read error", NULL},
        {299, 0, "", NULL}, {300, 0, NULL, NULL}, {401, 0, NULL, NULL}, {500, 0, NULL, NULL},
        {200, 1, NULL, "synthetic send failure"}, {200, -1, NULL, "cannot create Gumroad result"},
        {299, -1, NULL, NULL},
    };
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "gumroad-offline"};
    char input[64]; snprintf(input, sizeof(input), "gumroad %s", key1); const char *keys[] = {key1};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expect(keys, 1);
        http.response = (br_http_response){.status = cases[i].status, .body = {bytes, sizeof(bytes) - 1}, .body_error = cases[i].read_error};
        http.send_rc = cases[i].rc; http.send_error = cases[i].send_error;
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && http.calls == i + 1 && http.releases == i + 1);
        check_result(&r.items[0], key1, !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&r);
    }
}
static bool cancelled(void *unused) { (void)unused; return true; }
static bool fail_headers(void *unused) { (void)unused; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool fail_agent(void *unused) { (void)unused; fail_size = sizeof("TruffleHog ") + strlen("gumroad-offline"); fail_after = 1; return false; }
static void setup_failures(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "gumroad %s", key1); const char *keys[] = {key1};
    for (int mode = 0; mode < 6; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : mode == 3 ? fail_agent : NULL, .deadline_monotonic_ms = mode == 4 ? 1 : 0, .user_agent = mode == 5 ? "bad\nagent" : "gumroad-offline"};
        size_t before = allocation_failures; expect(keys, 1);
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 || mode == 3 ? 1u : 0u));
        check_result(&r.items[0], key1, false); br_results_clear(&r);
    }
}
static void check_prior(const br_results *r, const br_result *prior)
{
    CHECK(r->len == 1 && r->items[0].raw.data == prior->raw.data && r->items[0].secret_parts == prior->secret_parts);
    CHECK(r->items[0].raw.len == 5 && !memcmp(r->items[0].raw.data, "prior", 5));
    CHECK(r->items[0].verified && r->items[0].detector_type == 777 && r->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(r->items[0].verification_error, "caller-owned"));
}
static void resources(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "gumroad %s\ngumroad %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results r = {0}; br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&r, &prior)); prior = r.items[0];
    char *error = NULL; expect(NULL, 0); fail_size = 44; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture")); check_prior(&r, &prior); free(error); error = NULL;
    fail_size = 43; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot create Gumroad result")); check_prior(&r, &prior); free(error); error = NULL;
    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const char *keys[] = {key1, key2};
    for (int mode = 0; mode < 3; ++mode) {
        expect(keys, mode == 2 ? 1 : 0); fail_parts = 2;
        CHECK(d->scan(d, mode == 1 ? NULL : &ctx, mode != 0, data, &r, &error) == -1 && error && !fail_parts);
        CHECK(!strcmp(error, "cannot create Gumroad result") && sends == expected_count && releases == sends);
        check_prior(&r, &prior); free(error); error = NULL;
    }
    /* Fail actual vector growth after one successful append and two releases. */
    size_t cap = r.cap; r.cap = 2; expect(keys, 2); fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Gumroad result") && sends == 2 && releases == 2);
    check_prior(&r, &prior); r.cap = cap; free(error); br_results_clear(&r);
}
static void native_guard(const br_detector *d)
{
    char *error = NULL; const br_transport *native = br_curl_transport_init(&error); CHECK(native && !error);
    br_scan_ctx ctx = {.transport = native}; const char *keys[] = {key1}; expect(keys, 1);
    char input[64]; snprintf(input, sizeof(input), "gumroad %s", key1); native_attempt = true;
    br_results r = test_scan(d, &ctx, true, input, strlen(input)); native_attempt = false;
    CHECK(r.len == 1 && sends == 1 && releases == 1); check_result(&r.items[0], key1, false);
    br_results_clear(&r); curl_global_cleanup();
}
int main(void)
{
    test_secret(key1, 43, 0); key1[3] = 'Z'; key1[12] = '-'; test_secret(key2, 43, 7); key2[7] = 'Q';
    const br_detector *d = descriptor();
    grammar(d); occurrences(d); verification(d); setup_failures(d); resources(d); native_guard(d);
    return test_finish("Gumroad grammar/hyphens/duplicates/metadata/GET body/status/read/setup/guard/resources/rollback");
}
