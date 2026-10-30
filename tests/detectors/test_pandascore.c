/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pandascore_init(const br_detector **out, char **error);

enum { key_len = 51 };
static char key1[key_len + 1], key2[key_len + 1], mixed[key_len + 1];
static const char url[] = "https://api.pandascore.co/videogames";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls, alloc_auth;
static bool fail_growth;
static const size_t auth_size = sizeof("Bearer ") + key_len;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error pandascore_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == auth_size) ++alloc_auth;
    return calloc(1, n);
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
    return pandascore_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_pandascore_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_pandascore_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:pandascore)(?s:.){0,40}?");
    fail_after = 1;
    CHECK(br_pandascore_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_pandascore_init(&d, &error) == 0 && d && !error);
    CHECK(br_pandascore_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 731 && d->version == 0 && !strcmp(d->name, "PandaScore"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PandaScore is an esports data provider offering a wide range of statistics and live data for various video games. PandaScore API keys can be used to access and retrieve this data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "pandascore"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 731, key, "key");
    CHECK(r->raw.len == key_len && r->verified == verified && !r->extra_data && !r->verification_error);
}

static void expect_n(const br_detector *d, const void *text, size_t n, size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count && !setter_calls);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[220], changed[key_len + 1], near[120], far[130];
    int n = snprintf(input, sizeof(input), "pandascore %s\n", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "PANDASCORE %s ", mixed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, mixed);
    n = snprintf(input, sizeof(input), "pandascore\r%s ", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "pandascore%s ", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "pandascore %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "pandascore %s\t", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    expect_n(d, key1, key_len, 0, NULL);
    n = snprintf(input, sizeof(input), "pandascore %s pandascore %s\n", key1, key1);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2 && !setter_calls);
    check_result(&both.items[0], key1, false);
    check_result(&both.items[1], key1, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    memcpy(near, "pandascore", 10);
    memset(near + 10, '.', 40);
    memcpy(near + 50, key1, key_len);
    near[101] = ' ';
    expect_n(d, near, 102, 1, key1);
    memcpy(far, "pandascore", 10);
    memset(far + 10, '.', 41);
    memcpy(far + 51, key1, key_len);
    far[102] = '\n';
    expect_n(d, far, 103, 0, NULL);
    memcpy(changed, key1, key_len + 1); changed[15] = '.';
    n = snprintf(input, sizeof(input), "pandascore %s\n", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    memcpy(changed, key1, key_len - 1); changed[key_len - 1] = '\0';
    n = snprintf(input, sizeof(input), "pandascore.%s ", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    expect_n(d, "pandascore", 10, 0, NULL);
    expect_n(d, NULL, 0, 0, NULL);
}

typedef struct {
    const char *const *keys;
    const char *const *bearers;
    size_t count;
    const char *live[3];
    br_header markers[3];
    int statuses[3];
    const char *body_errors[3];
    int send_rc[3];
    const char *send_errors[3];
    size_t released_ids[3];
    size_t release_lengths[3];
    size_t sends_at_release[3];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void bearer_for(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "Bearer %s", key);
    CHECK(wrote == 7 + key_len && (size_t)wrote < n);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != request->headers[1].value && !strcmp(e->live[i], e->bearers[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 731);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, e->bearers[at]));
    CHECK(request->headers[1].value[7 + key_len - 1] != ' ');
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog pandascore-offline"));
    e->live[at] = request->headers[1].value;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_errors[at];
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->bearers[id]));
        e->live[id] = NULL;
        e->released_ids[http->releases] = id;
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = http->calls;
    } else {
        CHECK(response && !response->headers && e->out);
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
    char input[90], bearer[64];
    int n = snprintf(input, sizeof(input), "pandascore %s\n", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    bearer_for(bearer, sizeof(bearer), key1);
    const char *keys[] = {key1};
    const char *bearers[] = {bearer};
    expected e = {.keys = keys, .bearers = bearers, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pandascore-offline"};
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
        e.send_errors[0] = cases[i].rc ? "synthetic send error" : NULL;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], key1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));
    size_t built = alloc_auth;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "pandascore-offline"};
    br_results unpublished = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0] && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    CHECK(alloc_auth == built + 1);
    check_result(&unpublished.items[0], key1, false);
    br_results_clear(&unpublished);
}

static void order_and_nil(const br_detector *d)
{
    char input[180], bearer1[64], bearer2[64];
    int n = snprintf(input, sizeof(input), "pandascore %s\npandascore %s ", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    bearer_for(bearer1, sizeof(bearer1), key1);
    bearer_for(bearer2, sizeof(bearer2), key2);
    const char *keys[] = {key1, key2};
    const char *bearers[] = {bearer1, bearer2};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 299}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pandascore-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live[i] && e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
    }
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key2, true);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    expected mixed_e = {.keys = keys, .bearers = bearers, .count = 2,
                        .statuses = {200, 201}, .send_rc = {5, 0}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed_e};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "pandascore-offline"};
    mixed_e.ctx = &mixed_ctx;
    setter_calls = 0;
    br_results mixed = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed_e);
    CHECK(mixed.len == 2 && mixed_http.calls == 2 && mixed_http.releases == 2 && !setter_calls);
    CHECK(mixed_e.released_ids[0] == 0 && mixed_e.release_lengths[0] == 0 && mixed_e.sends_at_release[0] == 1);
    CHECK(mixed_e.released_ids[1] == 1 && mixed_e.release_lengths[1] == 2 && mixed_e.sends_at_release[1] == 2);
    check_result(&mixed.items[0], key1, false);
    check_result(&mixed.items[1], key2, true);
    br_results_clear(&mixed);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char one[80];
    int one_n = snprintf(one, sizeof(one), "pandascore %s\n", key1);
    CHECK(one_n > 0);
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases, built = alloc_auth;
    fail_size = auth_size;
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == 0 && !error);
    CHECK(fail_after == 1 && alloc_auth == built && !setter_calls);
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    fail_after = 0;

    fail_size = auth_size;
    fail_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate PandaScore authorization"));
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[180], bearer1[64], bearer2[64];
    int n = snprintf(input, sizeof(input), "pandascore %s\npandascore %s ", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    bearer_for(bearer1, sizeof(bearer1), key1);
    bearer_for(bearer2, sizeof(bearer2), key2);
    const char *keys[] = {key1, key2};
    const char *bearers[] = {bearer1, bearer2};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 201}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pandascore-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
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

    fail_size = 54; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create PandaScore result"));
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
    CHECK(!strcmp(error, "cannot append PandaScore result"));
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
    CHECK(!strcmp(error, "cannot retain PandaScore response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    test_secret(key1, key_len, 0);
    test_secret(key2, key_len, 13);
    memcpy(mixed, key1, key_len + 1);
    mixed[0] = 'A';
    mixed[10] = '-';
    mixed[20] = '_';
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    order_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !setter_calls);
    return test_finish("PandaScore");
}
