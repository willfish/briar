/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_peopledatalabs_init(const br_detector **out, char **error);

static char key_a[65], key_b[65];
static const char url[] =
    "https://api.peopledatalabs.com/v5/person/enrich?min_likelihood=6&profile=https://linkedin.com/in/williamhgates";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, fail_any, setter_calls;
static size_t alloc_64, alloc_65;
static bool fail_growth;
static char *last_65;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error pdl_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_any && --fail_any == 0) return NULL;
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == 64) ++alloc_64;
    if (n == 65) ++alloc_65;
    void *p = calloc(1, n);
    if (p && n == 65) last_65 = p;
    return p;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    (void)result; (void)cause; (void)secrets; (void)count;
    ++setter_calls;
    return pdl_real_setter(result, cause, secrets, count);
}

static void fill_key(char *out, char a, char b)
{
    for (int i = 0; i < 64; i += 2) {
        out[i] = a;
        out[i + 1] = b;
    }
    out[64] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    br_results empty = {0};
    CHECK(BR_ABI_REVISION == 1);
    fail_any = 1;
    CHECK(br_peopledatalabs_init(&d, &error) == -1 && error && !fail_any);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_peopledatalabs_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_peopledatalabs_init(NULL, NULL) == -1);
    if (br_peopledatalabs_init(&d, &error) != 0) {
        fprintf(stderr, "init error: %s\n", error ? error : "(null)");
        CHECK(0);
    }
    CHECK(d && !error);
    CHECK(br_peopledatalabs_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 658 && d->version == 0 && !strcmp(d->name, "PeopleDataLabs"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PeopleDataLabs provides access to person and company data through their API. The API keys can be used to enrich profiles with additional data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "peopledatalabs"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &empty, &error) == -1 && error);
    free(error);
    br_results_clear(&empty);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 658, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
}

static void expect_raw(const br_detector *d, const void *text, size_t n,
                       const char *const *raws, size_t count)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count && !setter_calls);
    for (size_t i = 0; i < count; ++i) {
        check_result(&r.items[i], raws[i], false);
        if (i) CHECK(r.items[i].raw.data != r.items[0].raw.data);
    }
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[220], bad[80];
    expect_raw(d, key_a, 64, NULL, 0);
    expect_raw(d, "peopledatalabs", 14, NULL, 0);
    int n = snprintf(input, sizeof(input), "peopledatalabs %s", key_a);
    CHECK(n > 0);
    const char *one[] = {key_a};
    expect_raw(d, input, (size_t)n, one, 1);
    n = snprintf(input, sizeof(input), "PeopleDataLabs %s", key_a);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, one, 1);
    n = snprintf(input, sizeof(input), "PEOPLEDATALABS %s", key_a);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, one, 1);
    memcpy(input, "peopledatalabs", 14);
    memset(input + 14, '.', 40);
    memcpy(input + 54, key_a, 64);
    expect_raw(d, input, 118, one, 1);
    memset(input + 14, '.', 41);
    memcpy(input + 55, key_a, 64);
    expect_raw(d, input, 119, NULL, 0);
    n = snprintf(input, sizeof(input), "peopledatalabs %s peopledatalabs %s", key_a, key_a);
    CHECK(n > 0);
    const char *dups[] = {key_a, key_a};
    expect_raw(d, input, (size_t)n, dups, 2);
    memset(bad, 'a', 63); bad[63] = '\0';
    n = snprintf(input, sizeof(input), "peopledatalabs %s", bad);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, NULL, 0);
    memset(bad, 'a', 65); bad[65] = '\0';
    n = snprintf(input, sizeof(input), "peopledatalabs %s", bad);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, NULL, 0);
    memset(bad, 'A', 64); bad[64] = '\0';
    n = snprintf(input, sizeof(input), "peopledatalabs %s", bad);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, NULL, 0);
    n = snprintf(input, sizeof(input), "peopledatalabs x%s", key_a);
    CHECK(n > 0);
    expect_raw(d, input, (size_t)n, NULL, 0);
    expect_raw(d, NULL, 0, NULL, 0);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *live[2];
    br_header markers[2];
    int statuses[2];
    const char *body_errors[2];
    int send_rc[2];
    size_t released_ids[2];
    size_t release_lengths[2];
    size_t sends_at_release[2];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != request->headers[0].value && !strcmp(e->live[i], e->keys[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 658);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(strcmp(request->headers[0].name, "X-API-Key") && strcmp(request->headers[0].name, "x-api-key"));
    CHECK(request->headers[0].value == last_65);
    CHECK(!strcmp(request->headers[0].value, e->keys[at]));
    CHECK(strlen(request->headers[0].value) == 64);
    CHECK(strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(strcmp(request->headers[1].name, "Accept") && strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog peopledatalabs-offline"));
    e->live[at] = request->headers[0].value;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_rc[at] ? "synthetic send error" : NULL;
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->keys[id]));
        e->live[id] = NULL;
        e->released_ids[http->releases] = id;
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = http->calls;
    } else {
        CHECK(response && !response->headers && e->out && last_65 && !strcmp(last_65, e->keys[0]));
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = 0;
    }
    test_http_release(user, response);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].verified && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static br_results scan_ok(const br_detector *d, const br_scan_ctx *ctx, const void *data,
                          size_t n, expected *e)
{
    br_results out = {0};
    e->out = &out;
    char *error = NULL;
    int rc = d->scan(d, ctx, true, (br_slice){data, n}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error && !setter_calls);
    return out;
}

static void verification(const br_detector *d)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "peopledatalabs %s", key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key_a};
    expected e = {.keys = keys, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "peopledatalabs-offline"};
    e.ctx = &ctx;
    const struct { int status, rc; const char *body_error; bool verified; } cases[] = {
        {200, 0, NULL, true},
        {201, 0, "synthetic read failure", true},
        {299, 0, "", true},
        {199, 0, NULL, false},
        {300, 0, "", false},
        {401, 0, "read", false},
        {404, 0, NULL, false},
        {0, 0, NULL, false},
        {200, 4, "read", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        memset(e.live, 0, sizeof(e.live));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], key_a, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "peopledatalabs-offline"};
    br_results unpublished = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0] && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&unpublished.items[0], key_a, false);
    br_results_clear(&unpublished);
}

static void order_and_nil(const br_detector *d)
{
    char input[180];
    int n = snprintf(input, sizeof(input), "peopledatalabs %s peopledatalabs %s", key_a, key_b);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key_a, key_b};
    expected e = {.keys = keys, .count = 2, .statuses = {200, 401}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "peopledatalabs-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live[i] && e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
    }
    check_result(&r.items[0], key_a, true);
    check_result(&r.items[1], key_b, false);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    expected mixed_e = {.keys = keys, .count = 2, .statuses = {200, 201}, .send_rc = {5, 0}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed_e};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "peopledatalabs-offline"};
    mixed_e.ctx = &mixed_ctx;
    setter_calls = 0;
    br_results mixed = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed_e);
    CHECK(mixed.len == 2 && mixed_http.calls == 2 && mixed_http.releases == 2 && !setter_calls);
    CHECK(mixed_e.released_ids[0] == 0 && mixed_e.release_lengths[0] == 0 && mixed_e.sends_at_release[0] == 1);
    CHECK(mixed_e.released_ids[1] == 1 && mixed_e.release_lengths[1] == 2 && mixed_e.sends_at_release[1] == 2);
    check_result(&mixed.items[0], key_a, false);
    check_result(&mixed.items[1], key_b, true);
    br_results_clear(&mixed);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases;
    size_t raw_before = alloc_64, copy_before = alloc_65;
    br_results quiet = test_scan(d, NULL, false, input, (size_t)n);
    size_t raw_quiet = alloc_64 - raw_before, copy_quiet = alloc_65 - copy_before;
    CHECK(quiet.len == 2);
    br_results_clear(&quiet);
    raw_before = alloc_64;
    copy_before = alloc_65;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(alloc_64 - raw_before == raw_quiet && alloc_65 - copy_before == copy_quiet);
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char one[96], two[180];
    int one_n = snprintf(one, sizeof(one), "peopledatalabs %s", key_a);
    int two_n = snprintf(two, sizeof(two), "peopledatalabs %s peopledatalabs %s", key_a, key_b);
    CHECK(one_n > 0 && two_n > 0);
    const char *keys[] = {key_a, key_b};
    expected e = {.keys = keys, .count = 2, .statuses = {200, 201}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "peopledatalabs-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)two, (size_t)two_n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    e.out = &out;
    char *error = NULL;
    setter_calls = 0;

    size_t before = alloc_65;
    br_results quiet = test_scan(d, NULL, false, one, (size_t)one_n);
    size_t baseline = alloc_65 - before;
    CHECK(quiet.len == 1 && baseline > 0);
    br_results_clear(&quiet);
    fail_size = 65;
    fail_after = baseline + 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate PeopleDataLabs key"));
    CHECK(!http.calls && !http.releases && !setter_calls);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_size = 65; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create PeopleDataLabs result"));
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append PeopleDataLabs result"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain PeopleDataLabs response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    fill_key(key_a, 'a', '0');
    fill_key(key_b, 'b', '1');
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    order_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !fail_any && !setter_calls);
    return test_finish("PeopleDataLabs");
}
