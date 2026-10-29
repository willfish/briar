/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <pthread.h>

/* Observe original provider storage, then use the unchanged shared adapter. */
#define br_http_send holidayapi_real_send
#define br_http_release holidayapi_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

static bool fail_growth;
static void *holidayapi_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc holidayapi_realloc
#include "../../src/result.c"
#undef realloc

static char key1[37], key2[37];
static size_t fail_size, fail_after, fail_part_after, sends, releases;
static bool fail_guard_copy, fail_shared_headers;
static const br_http_request *provider_request;
static const char *const *expected_keys;
static size_t expected_count;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

char *strdup(const char *text)
{
    if (fail_guard_copy && !strcmp(text, "unsupported HTTP request coalescing")) {
        fail_guard_copy = false;
        return NULL;
    }
    size_t n = strlen(text) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, text, n);
    return copy;
}

int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(o, name, v, 0);
}

static void check_request(const br_http_request *r, const char *key, bool effective)
{
    static const char base[] = "https://holidayapi.com/v1/holidays?key=";
    CHECK(!strcmp(r->method, "GET") && strlen(r->url) == 96);
    CHECK(!memcmp(r->url, base, sizeof(base) - 1));
    CHECK(!memcmp(r->url + sizeof(base) - 1, key, 36));
    CHECK(!strcmp(r->url + sizeof(base) - 1 + 36, "&country=PH&year=2020"));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 361);
    CHECK(effective ? r->timeout_ms > 0 && r->timeout_ms <= 5000 : !r->timeout_ms);
    CHECK(!r->body.data && !r->body.len);
    CHECK(r->dedup_key.len == 40 && !memcmp(r->dedup_key.data, "361:", 4));
    CHECK(!memcmp(r->dedup_key.data + 4, key, 36));
    if (effective) {
        CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "User-Agent"));
        CHECK(!strcmp(r->headers[0].value, "TruffleHog holidayapi-offline"));
    } else {
        CHECK(!r->headers && !r->nheaders && r->dedup_key.data[40] == '\0');
    }
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r,
                 br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    provider_request = r;
    ++sends;
    if (fail_shared_headers) {
        fail_shared_headers = false;
        fail_size = sizeof(br_header); fail_after = 1;
    }
    int rc = holidayapi_real_send(ctx, r, response, error);
    if (!br_http_client_is_owned(ctx->transport)) {
        CHECK(rc != 0 && error);
        if (*error) CHECK(!strcmp(*error, ctx->transport ? "unsupported HTTP request coalescing" : "HTTP transport not installed"));
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && sends == releases + 1);
    /* Retain only provider-owned values. Ordinary synthesized headers/UA end
     * at send return; only the owned raw backend has the stronger lifetime. */
    check_request(provider_request, expected_keys[releases], false);
    holidayapi_real_release(ctx, response);
    provider_request = NULL;
    ++releases;
}

static void expect(const char *const *keys, size_t n)
{
    CHECK(!provider_request);
    expected_keys = keys; expected_count = n; sends = releases = 0;
}

static void forbidden(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; (void)ctx; (void)r;
    CHECK(!"borrowed keyed transport must be rejected before raw backend I/O");
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 361, key, "key");
    CHECK(r->raw.len == 36 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 36);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_holidayapi_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid HolidayAPI detector output")); free(error); error = NULL;
    CHECK(br_holidayapi_init(NULL, NULL) == -1);
    CHECK(!br_holidayapi_init(&d, &error) && d && !error);
    CHECK(!br_holidayapi_init(&again, NULL) && again == d);
    CHECK(d->type == 361 && !d->version && !strcmp(d->name, "HolidayAPI"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "HolidayAPI keys are used to access holiday data for various countries and years. These keys can be used to query and retrieve holiday information programmatically."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "holidayapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction_case(const br_detector *d, const void *input, size_t n, const char *key)
{
    test_http http = {.inspect = forbidden}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; expect(NULL, 0);
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == (key ? 1u : 0u) && !sends && !releases && !http.calls && !http.releases);
    if (key) check_result(&r.items[0], key, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[256], changed[37];
    const struct { const char *format; bool match; } cases[] = {
        {"holidayapi '%s'", true}, {"HoLiDaYaPi=%s", true}, {"preholidayapisuffix:%s", true},
        {"holidayapi\r\n%s", true}, {"holidayapi\r%s", true}, {"holidayapi\n%s", true},
        {"%s", false}, {"%s holidayapi", false}, {"holiday api %s", false},
        {"holidayapi%s", false}, {"holidayapi x%s", false}, {"holidayapi _%s", false},
        {"holidayapi %s_", false}, {"holidayapi %s9", false}, {"holidayapi %.35s", false},
        {"holidayapi %s-", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(d, input, strlen(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, sizeof(changed)); changed[12] = '-';
    snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), changed);
    changed[12] = 'A'; snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), NULL);
    changed[12] = '_'; snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'z', 36); changed[36] = '\0';
    snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), changed); /* Not UUID or hex; no entropy filter. */
    memcpy(changed, key1, sizeof(changed)); changed[0] = '-';
    snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "holidayapi _%s", changed); extraction_case(d, input, strlen(input), changed);
    memcpy(changed, key1, sizeof(changed)); changed[35] = '-';
    snprintf(input, sizeof(input), "holidayapi %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "holidayapi %sx", changed); extraction_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "holidayapi", 10); memset(input + 10, '.', gap); memcpy(input + 10 + gap, key1, 36);
        extraction_case(d, input, 10 + gap + 36, gap == 40 ? key1 : NULL);
    }
    snprintf(input, sizeof(input), "holidayapi %s %s", key1, key2);
    extraction_case(d, input, strlen(input), key1); /* FindAll consumes the prefix with its first capture. */
    int n = snprintf(input, sizeof(input), "holidayapi%c%s", 0, key1);
    extraction_case(d, input, (size_t)n, key1); extraction_case(d, NULL, 0, NULL);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void occurrences_and_guard(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "holidayapi %s\nHOLIDAYAPI %s\nholidayapi %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200, .body_error = "unreachable"}, .inspect = forbidden};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect(NULL, 0);
    br_results r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases && !http.calls && !http.releases);
    for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], false);
    CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts);
    br_results_clear(&r);
    for (int pass = 0; pass < 2; ++pass) {
        expect(keys, 3); http.releases = 0;
        r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 3 && sends == 3 && releases == 3 && !http.calls && http.releases == 3);
        for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], false);
        br_results_clear(&r);
    }
    expect(NULL, 0); http.releases = 0;
    r = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!r.len && !sends && !releases && !http.calls && !http.releases); br_results_clear(&r);
    r = test_scan(d, NULL, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases);
    for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], false);
    br_results_clear(&r);
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    snprintf(input, sizeof(input), "holidayapi %s", key1);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        expect(keys, 1); http.releases = 0; if (i == 4) fail_guard_copy = true;
        r = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_guard_copy);
        check_result(&r.items[0], key1, false); br_results_clear(&r);
    }
    CHECK(!cancellations); /* The borrowed keyed guard precedes shared preparation. */
}

typedef struct {
    pthread_mutex_t mutex;
    test_http http;
    const br_http_request *raw_request;
    bool destroyed;
} owned_fixture;

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *r,
                       br_http_response *response, char **error)
{
    owned_fixture *f = user;
    CHECK(!pthread_mutex_lock(&f->mutex));
    CHECK(!f->destroyed && !f->raw_request && !ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > 0);
    check_request(r, key1, true);
    f->raw_request = r;
    int rc;
    if (monotonic_ms() >= ctx->deadline_monotonic_ms) {
        ++f->http.calls; *error = strdup("context deadline exceeded"); CHECK(*error); rc = 1;
    } else rc = test_http_send(&f->http, ctx, r, response, error);
    CHECK(!pthread_mutex_unlock(&f->mutex));
    return rc;
}

static void owned_release(void *user, br_http_response *response)
{
    owned_fixture *f = user;
    CHECK(!pthread_mutex_lock(&f->mutex));
    CHECK(f->raw_request);
    /* Only this actual owned raw snapshot retains synthesized request storage
     * through its backend release. Never infer this for borrowed transports. */
    check_request(f->raw_request, key1, true);
    f->raw_request = NULL; test_http_release(&f->http, response);
    CHECK(!pthread_mutex_unlock(&f->mutex));
}

static void owned_destroy(void *user)
{
    owned_fixture *f = user;
    CHECK(!pthread_mutex_lock(&f->mutex));
    CHECK(!f->destroyed && !f->raw_request && f->http.calls == f->http.releases);
    f->destroyed = true;
    CHECK(!pthread_mutex_unlock(&f->mutex));
}

static void owned_verification(const br_detector *d)
{
    static const unsigned char body[] = "not JSON\0ignored arbitrary body";
    const struct { int status, rc; const char *read_error, *send_error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {204, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {199, 0, NULL, NULL, false}, {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, 1, NULL, "synthetic timeout", false}, {299, -1, NULL, "out of memory in shared Do", false},
        {200, 1, NULL, NULL, false}, {200, 0, "synthetic partial read", NULL, false}, {299, 0, "", NULL, false},
    };
    owned_fixture f = {0}; CHECK(!pthread_mutex_init(&f.mutex, NULL));
    br_http_owned_backend backend = {.transport = {&f, owned_send, owned_release}, .destroy = owned_destroy};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "holidayapi-offline"};
    char input[64]; snprintf(input, sizeof(input), "holidayapi %s", key1); const char *keys[] = {key1};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        f.http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body) - 1}, .body_error = cases[i].read_error};
        f.http.send_rc = cases[i].rc; f.http.send_error = cases[i].send_error;
        expect(keys, 1);
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && f.http.calls == i + 1 && f.http.releases == i + 1);
        check_result(&r.items[0], key1, cases[i].verified); br_results_clear(&r);
    }
    size_t calls = f.http.calls;
    ctx.user_agent = "invalid\r\nagent"; expect(keys, 1);
    br_results r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && sends == 1 && releases == 1 && f.http.calls == calls && f.http.releases == calls);
    check_result(&r.items[0], key1, false); br_results_clear(&r);
    ctx.user_agent = "holidayapi-offline"; expect(keys, 1); fail_shared_headers = true;
    r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && sends == 1 && releases == 1 && !fail_after && !fail_shared_headers && f.http.calls == calls && f.http.releases == calls);
    check_result(&r.items[0], key1, false); br_results_clear(&r);
    /* A provider-owned failure after a verified first occurrence must roll back
     * this invocation too, rather than treating success as resource recovery. */
    snprintf(input, sizeof(input), "holidayapi %s", key1);
    char twice[128]; snprintf(twice, sizeof(twice), "%s\n%s", input, input);
    const char *duplicates[] = {key1, key1}; expect(duplicates, 2);
    f.http.response = (br_http_response){.status = 200}; f.http.send_rc = 0; f.http.send_error = NULL;
    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)twice, strlen(twice)}, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create HolidayAPI result") && !r.len && sends == 1 && releases == 1 && f.http.calls == calls + 1 && f.http.releases == calls + 1);
    free(error); error = NULL; br_results_clear(&r);
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); /* Destroy before the stack-backed fixture expires. */
    CHECK(f.destroyed && !pthread_mutex_destroy(&f.mutex));
}

static void check_prior(const br_results *r, const br_result *prior)
{
    CHECK(r->len == 1 && r->items[0].raw.data == prior->raw.data && r->items[0].raw.len == 5);
    CHECK(r->items[0].verified && r->items[0].detector_type == 777 && !memcmp(r->items[0].raw.data, "prior", 5));
    CHECK(r->items[0].verification_error == prior->verification_error && !strcmp(r->items[0].verification_error, "caller-owned"));
}

static void resources(const br_detector *d)
{
    char input[112]; snprintf(input, sizeof(input), "holidayapi %s\nholidayapi %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results r = {0}; br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(5); CHECK(prior.raw.data); memcpy(prior.raw.data, "prior", 5); prior.raw.len = 5;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&r, &prior)); prior = r.items[0]; char *error = NULL;
    expect(NULL, 0); fail_size = 37; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture")); check_prior(&r, &prior); free(error); error = NULL;
    fail_size = 2 * sizeof(br_span); fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, NULL) == -1 && !fail_after); check_prior(&r, &prior);
    fail_size = 36; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot create HolidayAPI result")); check_prior(&r, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create HolidayAPI result")); check_prior(&r, &prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; test_http http = {.inspect = forbidden};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect(keys, 2); fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create HolidayAPI result") && sends == 1 && releases == 1 && !http.calls && http.releases == 1);
    check_prior(&r, &prior); free(error); error = NULL;
    size_t cap = r.cap; r.cap = 2; expect(keys, 2); fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append HolidayAPI result") && sends == 2 && releases == 2 && !http.calls && http.releases == 3);
    check_prior(&r, &prior); r.cap = cap; free(error); br_results_clear(&r);
}

int main(void)
{
    test_secret(key1, 36, 0); test_secret(key2, 36, 7);
    const br_detector *d = descriptor();
    grammar(d); occurrences_and_guard(d); owned_verification(d); resources(d);
    return test_finish("HolidayAPI grammar/metadata/full-key guard/owned status/read promotion/resources");
}
