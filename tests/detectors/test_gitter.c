/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Inspect provider values without changing the key or bypassing the guard. */
#define br_http_send gitter_real_send
#define br_http_release gitter_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

/* Fail the real result-vector growth allocation, not a fabricated push result. */
static bool fail_growth;
static void *gitter_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc gitter_realloc
#include "../../src/result.c"
#undef realloc

static char key1[41], key2[41];
static size_t fail_size, fail_after, fail_part_after, sends, releases;
static const br_http_request *provider_request;
static br_slice provider_key;
static const char *const *expected_keys;
static size_t expected_count;
static bool backend_destroyed;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(o, name, v, 0);
}

static void check_request(const br_http_request *r, const char *key, bool effective)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.gitter.im/v1/user/me"));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 555);
    CHECK(effective ? r->timeout_ms > 0 && r->timeout_ms <= 5000 : !r->timeout_ms);
    CHECK(!r->body.data && !r->body.len && r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Authorization"));
    CHECK(strlen(r->headers[0].value) == 47 && !memcmp(r->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(r->headers[0].value + 7, key, 41));
    CHECK(r->dedup_key.len == 44 && !memcmp(r->dedup_key.data, "555:", 4));
    CHECK(!memcmp(r->dedup_key.data + 4, key, 40));
    if (effective) {
        CHECK(!strcmp(r->headers[1].name, "User-Agent"));
        CHECK(!strcmp(r->headers[1].value, "TruffleHog gitter-offline"));
    }
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(!provider_request && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    provider_request = r;
    provider_key = (br_slice){(const unsigned char *)expected_keys[sends++], 40};
    int rc = gitter_real_send(ctx, r, response, error);
    if (!br_http_client_is_owned(ctx->transport)) {
        CHECK(rc != 0 && error && *error);
        CHECK(!strcmp(*error, ctx->transport ? "unsupported HTTP request coalescing" : "HTTP transport not installed"));
        CHECK(!response->status && !response->body.data && !response->body_error);
    }
    return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && provider_key.len == 40);
    /* Only the original provider request is retained. Ordinary effective
     * headers/UA expire at send return and are never borrowed here. */
    check_request(provider_request, (const char *)provider_key.data, false);
    gitter_real_release(ctx, response);
    provider_request = NULL; provider_key = (br_slice){0}; ++releases;
}

static void expect(const char *const *keys, size_t n)
{
    CHECK(!provider_request && !provider_key.data);
    expected_keys = keys; expected_count = n; sends = releases = 0;
}

static void forbidden(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; (void)ctx; (void)r;
    CHECK(!"Borrowed keyed transport must be rejected before callback");
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 555, key, "key");
    CHECK(r->raw.len == 40 && r->verified == verified && !r->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gitter_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(!br_gitter_init(&d, &error) && d && !error);
    CHECK(!br_gitter_init(&again, NULL) && again == d);
    CHECK(d->type == 555 && !d->version && !strcmp(d->name, "Gitter"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Gitter is a chat and networking platform. Gitter API keys can be used to access and interact with Gitter services and data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gitter"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction_case(const br_detector *d, const void *text, size_t n, const char *key)
{
    expect(NULL, 0);
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == (key ? 1u : 0u) && !sends && !releases);
    if (key) check_result(&r.items[0], key, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[256], changed[41];
    const struct { const char *format; bool match; } cases[] = {
        {"gitter '%s'", true}, {"GiTtEr=%s", true}, {"pregittersuffix:%s", true},
        {"gitter\r\n%s", true}, {"gitter\r%s", true}, {"gitter\n%s", true},
        {"%s", false}, {"%s gitter", false}, {"git ter %s", false},
        {"gitter%s", false}, {"gitter x%s", false}, {"gitter _%s", false},
        {"gitter %s_", false}, {"gitter %s9", false}, {"gitter %.39s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(d, input, strlen(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, 41); changed[12] = '-';
    snprintf(input, sizeof(input), "gitter %s", changed); extraction_case(d, input, strlen(input), changed);
    changed[12] = 'A'; snprintf(input, sizeof(input), "gitter %s", changed); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'a', 40); changed[40] = 0;
    snprintf(input, sizeof(input), "gitter %s", changed); extraction_case(d, input, strlen(input), changed);
    memcpy(changed, key1, 41); changed[0] = '-';
    snprintf(input, sizeof(input), "gitter %s", changed); extraction_case(d, input, strlen(input), NULL);
    /* A leading hyphen can start at a word boundary after an underscore. */
    snprintf(input, sizeof(input), "gitter _%s", changed); extraction_case(d, input, strlen(input), changed);
    memcpy(changed, key1, 41); changed[39] = '-';
    snprintf(input, sizeof(input), "gitter %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "gitter %sx", changed); extraction_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gitter", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, key1, 40);
        extraction_case(d, input, 6 + gap + 40, gap == 40 ? key1 : NULL);
    }
    snprintf(input, sizeof(input), "gitter %s %s", key1, key2);
    extraction_case(d, input, strlen(input), key1);
    int n = snprintf(input, sizeof(input), "gitter%c%s", 0, key1);
    extraction_case(d, input, (size_t)n, key1); extraction_case(d, NULL, 0, NULL);
}

static void occurrences(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "gitter %s\nGITTER %s\ngitter %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.inspect = forbidden}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (int mode = 0; mode < 4; ++mode) {
        bool verify = mode != 0; const br_scan_ctx *context = mode == 2 ? NULL : &ctx;
        expect(keys, mode == 1 || mode == 3 ? 3 : 0);
        br_results r = test_scan(d, context, verify, input, strlen(input));
        CHECK(r.len == (mode == 2 ? 0u : 3u));
        CHECK(sends == expected_count && releases == sends && !http.calls);
        for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], false);
        if (r.len) CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts);
        br_results_clear(&r);
        if (mode == 1) CHECK(http.releases == 3);
        if (mode == 2) ctx.transport = NULL;
    }
}

static const br_http_request *raw_owned_request;
static void inspect_owned(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http;
    CHECK(!ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > 0);
    check_request(r, key1, true);
    /* This is the actual owned raw backend, whose prepared storage, unlike
     * ordinary effective request storage, survives raw backend release. */
    CHECK(!raw_owned_request); raw_owned_request = r;
}

static void release_owned(void *user, br_http_response *r)
{
    CHECK(raw_owned_request); check_request(raw_owned_request, key1, true);
    raw_owned_request = NULL; test_http_release(user, r);
}

static void destroy_backend(void *user)
{
    test_http *http = user;
    CHECK(!raw_owned_request && http->calls == http->releases);
    backend_destroyed = true; /* Stack storage is not freed and is still live. */
}

static void owned(const br_detector *d)
{
    static const unsigned char bytes[] = "ignored\0arbitrary response";
    const struct { int status, rc; const char *read_error, *send_error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {199, 0, NULL, NULL, false}, {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false},
        {500, 0, NULL, NULL, false}, {200, 1, NULL, "synthetic send error", false},
        {200, 0, "synthetic read failure", NULL, false}, {299, 0, "", NULL, false},
    };
    test_http http = {.inspect = inspect_owned};
    br_http_owned_backend backend = {.transport = {&http, test_http_send, release_owned}, .destroy = destroy_backend};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "gitter-offline"};
    char input[64]; snprintf(input, sizeof(input), "gitter %s", key1); const char *keys[] = {key1};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.response = (br_http_response){.status = cases[i].status, .body = {bytes, sizeof(bytes) - 1}, .body_error = cases[i].read_error};
        http.send_rc = cases[i].rc; http.send_error = cases[i].send_error; expect(keys, 1);
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && http.calls == i + 1 && http.releases == i + 1);
        check_result(&r.items[0], key1, cases[i].verified); br_results_clear(&r);
    }
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); CHECK(backend_destroyed);
}

static void check_prior(const br_results *r, const br_result *prior)
{
    CHECK(r->len == 1 && r->items[0].raw.data == prior->raw.data && r->items[0].raw.len == 5);
    CHECK(r->items[0].verified && r->items[0].detector_type == 777 && !memcmp(r->items[0].raw.data, "prior", 5));
    CHECK(r->items[0].verification_error == prior->verification_error && !strcmp(r->items[0].verification_error, "caller-owned"));
}

static void resources(const br_detector *d)
{
    char input[112]; snprintf(input, sizeof(input), "gitter %s\ngitter %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results r = {0}; br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(5); CHECK(prior.raw.data); memcpy(prior.raw.data, "prior", 5); prior.raw.len = 5;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&r, &prior)); prior = r.items[0];
    char *error = NULL;
    expect(NULL, 0); fail_size = 41; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture")); check_prior(&r, &prior); free(error); error = NULL;
    fail_size = 40; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot create Gitter result")); check_prior(&r, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Gitter result")); check_prior(&r, &prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; test_http http = {.inspect = forbidden};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect(keys, 2); fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Gitter result") && sends == 1 && releases == 1);
    check_prior(&r, &prior); free(error); error = NULL;
    /* Real realloc failure after one new finding: preserve caller's vector and
     * roll back only this invocation's earlier appended result. */
    size_t cap = r.cap; r.cap = 2; expect(keys, 2); fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Gitter result") && sends == 2 && releases == 2);
    check_prior(&r, &prior); r.cap = cap; free(error); br_results_clear(&r);
}

int main(void)
{
    test_secret(key1, 40, 0); test_secret(key2, 40, 7);
    const br_detector *d = descriptor();
    grammar(d); occurrences(d); owned(d); resources(d);
    return test_finish("Gitter grammar/metadata/guard/owned status/read promotion/resources");
}
