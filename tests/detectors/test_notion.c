/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_notion_init(const br_detector **out, char **error);

static char key1[51], key2[51];
static const char url[] = "https://api.notion.com/v1/users";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls, auth_allocs;
static bool fail_growth, fail_setter, setter_null;
static char setter_cause[256];
static const size_t auth_size = sizeof("Bearer ") + 50;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error notion_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == auth_size) ++auth_allocs;
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
    ++setter_calls;
    setter_null = !cause;
    setter_cause[0] = '\0';
    if (cause) snprintf(setter_cause, sizeof(setter_cause), "%s", cause);
    CHECK(count == 1 && secrets && secrets[0].len == 50 && secrets[0].data);
    if (fail_setter) return 1;
    return notion_real_setter(result, cause, secrets, count);
}

static void make_key(char *out, size_t shift)
{
    memcpy(out, "secret_", 7);
    test_secret(out + 7, 43, shift);
    CHECK(strlen(out) == 50);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_notion_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_notion_init(NULL, NULL) == -1);
    CHECK(br_notion_init(&d, &error) == 0 && d && !error);
    CHECK(br_notion_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 134 && d->version == 0 && !strcmp(d->name, "Notion"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Notion is a productivity tool that provides an all-in-one workspace for note-taking, project management, and collaboration. Notion API keys can be used to access and modify data within a user's Notion workspace."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "notion"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified, const char *cause)
{
    test_key_result(r, 134, key, "key");
    CHECK(r->raw.len == 50 && r->verified == verified && !r->extra_data);
    if (cause) CHECK(r->verification_error && !strcmp(r->verification_error, cause));
    else CHECK(!r->verification_error);
}

static void expect_n(const br_detector *d, const void *text, size_t n, size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, false, NULL);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[220], changed[51], far[160];
    expect_n(d, key1, 50, 1, key1);
    int n = snprintf(input, sizeof(input), "notion %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "%s notion %s", key1, key1);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], key1, false, NULL);
    check_result(&both.items[1], key1, false, NULL);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    memcpy(far, "notion", 6);
    memset(far + 6, '.', 80);
    memcpy(far + 86, key1, 50);
    expect_n(d, far, 136, 1, key1);
    memcpy(changed, key1, 51); changed[7] = 'A';
    n = snprintf(input, sizeof(input), "%s.", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, changed);
    memcpy(changed, key1, 51); changed[0] = 'S';
    n = snprintf(input, sizeof(input), "%s", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "x%s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "%sx", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "%s.", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    memcpy(changed, key1, 49); changed[49] = '\0';
    n = snprintf(input, sizeof(input), "%s.", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    memcpy(changed, key1, 50); changed[20] = '-'; changed[50] = '\0';
    n = snprintf(input, sizeof(input), "%s", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    expect_n(d, "notion", 6, 0, NULL);
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
    size_t setter_at_release[3];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void bearer_for(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "Bearer %s", key);
    CHECK(wrote == 57 && (size_t)wrote < n);
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
    CHECK(request->detector_type == 134);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Notion-Version"));
    CHECK(!strcmp(request->headers[0].value, "2022-06-28"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, e->bearers[at]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog notion-offline"));
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
        e->setter_at_release[http->releases] = setter_calls;
    } else {
        CHECK(response && !response->headers && e->out);
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = 0;
        e->setter_at_release[http->releases] = setter_calls;
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
    CHECK(rc == 0 && !error);
    return out;
}

static void verification(const br_detector *d)
{
    char input[80], bearer[64];
    int n = snprintf(input, sizeof(input), "%s", key1);
    CHECK(n == 50);
    bearer_for(bearer, sizeof(bearer), key1);
    const char *keys[] = {key1};
    const char *bearers[] = {bearer};
    expected e = {.keys = keys, .bearers = bearers, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "notion-offline"};
    e.ctx = &ctx;
    const struct {
        int status, rc; const char *body_error, *send_error, *cause; bool verified;
    } cases[] = {
        {200, 0, NULL, NULL, NULL, true},
        {201, 0, "synthetic read failure", NULL, NULL, true},
        {299, 0, "", NULL, NULL, true},
        {403, 0, "", NULL, NULL, true},
        {403, 0, "synthetic read failure", NULL, NULL, true},
        {401, 0, NULL, NULL, NULL, false},
        {199, 0, NULL, NULL, NULL, false},
        {300, 0, NULL, NULL, NULL, false},
        {404, 0, "read", NULL, NULL, false},
        {0, 0, NULL, NULL, NULL, false},
        {200, 1, "read", "synthetic send error", "synthetic send error", false},
        {500, 7, NULL, key1, "[REDACTED]", false},
        {200, 4, NULL, NULL, "HTTP transport failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        setter_calls = 0;
        setter_null = false;
        memset(e.live, 0, sizeof(e.live));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, 50, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0]);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.setter_at_release[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        CHECK(setter_calls == (cases[i].rc == 0 ? 0u : 1u) && !setter_null);
        check_result(&r.items[0], key1, cases[i].verified, cases[i].cause);
        br_results_clear(&r);
    }
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));
    size_t built = auth_allocs;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "notion-offline"};
    br_results unpublished = scan_ok(d, &missing, input, 50, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0]);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0 && e.setter_at_release[0] == 0);
    CHECK(setter_calls == 1 && !setter_null);
    CHECK(auth_allocs == built + 1);
    check_result(&unpublished.items[0], key1, false, "HTTP transport not installed");
    br_results_clear(&unpublished);
}

static void order_and_nil(const br_detector *d)
{
    char input[120], bearer1[64], bearer2[64];
    int n = snprintf(input, sizeof(input), "%s %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    bearer_for(bearer1, sizeof(bearer1), key1);
    bearer_for(bearer2, sizeof(bearer2), key2);
    const char *keys[] = {key1, key2};
    const char *bearers[] = {bearer1, bearer2};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 403}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "notion-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live[i]);
        CHECK(e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
        CHECK(e.setter_at_release[i] == 0);
    }
    check_result(&r.items[0], key1, true, NULL);
    check_result(&r.items[1], key2, true, NULL);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    expected failed_send = {.keys = keys, .bearers = bearers, .count = 2,
                            .statuses = {200, 201}, .send_rc = {4, 0},
                            .send_errors = {"synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "notion-offline"};
    failed_send.ctx = &failed_ctx;
    setter_calls = 0;
    br_results mixed = scan_ok(d, &failed_ctx, input, (size_t)n, &failed_send);
    CHECK(mixed.len == 2 && failed_http.calls == 2 && failed_http.releases == 2 && setter_calls == 1);
    CHECK(failed_send.released_ids[0] == 0 && failed_send.sends_at_release[0] == 1);
    CHECK(failed_send.release_lengths[0] == 0 && failed_send.setter_at_release[0] == 0);
    CHECK(failed_send.released_ids[1] == 1 && failed_send.sends_at_release[1] == 2);
    CHECK(failed_send.release_lengths[1] == 2 && failed_send.setter_at_release[1] == 1);
    check_result(&mixed.items[0], key1, false, "synthetic send error");
    check_result(&mixed.items[1], key2, true, NULL);
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
    size_t calls = http.calls, releases = http.releases, setters = setter_calls, built = auth_allocs;
    fail_size = auth_size;
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(fail_after == 1 && auth_allocs == built);
    CHECK(http.calls == calls && http.releases == releases && setter_calls == setters);
    check_prior(&kept, &prior);
    fail_after = 0;

    fail_size = auth_size;
    fail_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)key1, 50}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate Notion authorization"));
    CHECK(http.calls == calls && http.releases == releases && setter_calls == setters);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[120], bearer1[64], bearer2[64];
    int n = snprintf(input, sizeof(input), "%s %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    bearer_for(bearer1, sizeof(bearer1), key1);
    bearer_for(bearer2, sizeof(bearer2), key2);
    const char *keys[] = {key1, key2};
    const char *bearers[] = {bearer1, bearer2};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 403}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "notion-offline"};
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

    fail_size = 51; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    setter_calls = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Notion result"));
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    setter_calls = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Notion result"));
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
    setter_calls = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain Notion response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    e.count = 1;
    e.send_rc[0] = 3;
    e.send_errors[0] = "synthetic send error";
    setter_calls = 0;
    fail_setter = true;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)key1, 50}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot record Notion verification error"));
    CHECK(setter_calls == 1 && http.calls == 1 && http.releases == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.setter_at_release[0] == 0);
    CHECK(!strcmp(setter_cause, "synthetic send error"));
    check_prior(&out, &prior);
    fail_setter = false;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    make_key(key1, 0);
    make_key(key2, 9);
    key1[10] = 'Z';
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    order_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !fail_setter);
    return test_finish("Notion");
}
