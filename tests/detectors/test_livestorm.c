/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_livestorm_init(const br_detector **out, char **error);

enum { raw_len = 243, capture_len = 244 };
static char token_a[raw_len + 1], token_b[raw_len + 1];
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls, alloc_auth;
static bool fail_growth;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error livestorm_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (n == (size_t)raw_len + 1) ++alloc_auth;
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
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
    return livestorm_real_setter(result, cause, secrets, count);
}

static void make_token(char *out, char mid, char sig)
{
    static const char head[] = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi";
    CHECK(strlen(head) == 65);
    memcpy(out, head, 65);
    memset(out + 65, mid, 134);
    out[199] = '.';
    memset(out + 200, sig, 43);
    out[raw_len] = '\0';
    CHECK(strlen(out) == raw_len);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_livestorm_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_livestorm_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:livestorm)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_livestorm_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_livestorm_init(&d, &error) == 0 && d && !error);
    CHECK(br_livestorm_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 735 && d->version == 0 && !strcmp(d->name, "Livestorm"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Livestorm is a video communication platform for webinars, meetings, and virtual events. Livestorm API keys can be used to interact with Livestorm services programmatically."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "livestorm"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 735, token, "key");
    CHECK(r->raw.len == raw_len && r->verified == verified && !r->verification_error);
    CHECK(r->raw.data[r->raw.len - 1] != ' ' && r->raw.data[r->raw.len - 1] != '\r');
    CHECK(r->raw.data[r->raw.len - 1] != '\n');
}

static void extract(const br_detector *d, const void *text, size_t n, const char *token)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == (token ? 1u : 0u));
    if (token) check_result(&r.items[0], token, false);
    br_results_clear(&r);
}

static size_t with_tail(char *out, size_t cap, const char *prefix, const char *token, int tail)
{
    size_t pn = strlen(prefix), tn = strlen(token);
    CHECK(pn + tn + 2 < cap);
    memcpy(out, prefix, pn);
    memcpy(out + pn, token, tn);
    size_t n = pn + tn;
    if (tail >= 0) out[n++] = (char)tail;
    out[n] = '\0';
    return n;
}

static void grammar(const br_detector *d)
{
    char input[800], changed[raw_len + 1];
    size_t n = with_tail(input, sizeof(input), "livestorm ", token_a, ' ');
    extract(d, input, n, token_a);
    n = with_tail(input, sizeof(input), "LiVeStOrM=", token_a, '\n');
    extract(d, input, n, token_a);
    n = with_tail(input, sizeof(input), "livestorm ", token_a, '\r');
    extract(d, input, n, token_a);
    n = with_tail(input, sizeof(input), "livestorm ", token_a, ' ');
    input[n] = ' '; input[n + 1] = '\0';
    extract(d, input, n + 1, token_a);
    for (int tail = 0; tail < 3; ++tail) {
        char bad = tail == 0 ? '\t' : tail == 1 ? '\v' : '\f';
        n = with_tail(input, sizeof(input), "livestorm ", token_a, bad);
        extract(d, input, n, NULL);
    }
    n = with_tail(input, sizeof(input), "livestorm ", token_a, -1);
    extract(d, input, n, NULL);
    n = with_tail(input, sizeof(input), "livestorm", token_a, ' ');
    extract(d, input, n, NULL);
    extract(d, token_a, raw_len, NULL);
    memcpy(changed, token_a, sizeof(changed));
    changed[0] = 'x';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, NULL);
    memcpy(changed, token_a, sizeof(changed));
    changed[65] = '-';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, changed);
    memcpy(changed, token_a, sizeof(changed));
    changed[65] = '_';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, NULL);
    memcpy(changed, token_a, sizeof(changed));
    changed[200] = '_';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, changed);
    memcpy(changed, token_a, sizeof(changed));
    changed[200] = '-';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, changed);
    memcpy(changed, token_a, sizeof(changed));
    changed[200] = '+';
    n = with_tail(input, sizeof(input), "livestorm ", changed, ' ');
    extract(d, input, n, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "livestorm", 9);
        memset(input + 9, '.', gap);
        memcpy(input + 9 + gap, token_a, raw_len);
        input[9 + gap + raw_len] = ' ';
        extract(d, input, 9 + gap + capture_len, gap == 40 ? token_a : NULL);
    }
    n = with_tail(input, sizeof(input), "livestorm ", token_a, ' ');
    input[n++] = '\n';
    memcpy(input + n, "LIVESTORM ", 10);
    memcpy(input + n + 10, token_b, raw_len);
    input[n + 10 + raw_len] = '\n';
    br_results both = test_scan(d, NULL, false, input, n + 10 + capture_len);
    CHECK(both.len == 2);
    check_result(&both.items[0], token_a, false);
    check_result(&both.items[1], token_b, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *live_auths[3];
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

static void expect_auth(const char *value, const char *key)
{
    CHECK(value && strlen(value) == raw_len && !strcmp(value, key));
    CHECK(strncmp(value, "Bearer ", 7) != 0 && value[raw_len - 1] != ' ');
    CHECK(value[raw_len - 1] != '\r' && value[raw_len - 1] != '\n');
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live_auths[i]) { ++failed; continue; }
        CHECK(e->live_auths[i] != request->headers[0].value);
        expect_auth(e->live_auths[i], e->keys[i]);
    }
    CHECK(http->releases == failed && !setter_calls);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->url && !strcmp(request->url, "https://api.livestorm.co/v1/ping"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 735);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    expect_auth(request->headers[0].value, e->keys[at]);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog livestorm-offline"));
    e->live_auths[at] = request->headers[0].value;
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
    CHECK(!setter_calls);
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live_auths[id]);
        expect_auth(e->live_auths[id], e->keys[id]);
        e->live_auths[id] = NULL;
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
    CHECK(rc == 0 && !error);
    return out;
}

static void verification(const br_detector *d)
{
    expected e = {0};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "livestorm-offline"};
    e.ctx = &ctx;
    const struct { int tail, status, rc; const char *body_error, *send_error; bool verified; } cases[] = {
        {' ', 200, 0, NULL, NULL, true}, {'\r', 201, 0, NULL, NULL, true},
        {'\n', 299, 0, "", NULL, true}, {' ', 200, 0, "synthetic read failure", NULL, true},
        {' ', 199, 0, NULL, NULL, false}, {' ', 300, 0, "read", NULL, false},
        {' ', 200, 1, NULL, "synthetic send error", false},
        {' ', 204, 7, "read", token_a, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char input[320];
        size_t n = with_tail(input, sizeof(input), "livestorm ", token_a, cases[i].tail);
        const char *keys[] = {token_a};
        http.calls = http.releases = 0;
        setter_calls = 0;
        memset(e.live_auths, 0, sizeof(e.live_auths));
        e.keys = keys;
        e.count = 1;
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live_auths[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], token_a, cases[i].verified);
        br_results_clear(&r);
    }
    char input[320];
    size_t n = with_tail(input, sizeof(input), "livestorm ", token_a, ' ');
    const char *keys[] = {token_a};
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live_auths, 0, sizeof(e.live_auths));
    e.keys = keys;
    e.count = 1;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "livestorm-offline"};
    br_results dropped = scan_ok(d, &missing, input, n, &e);
    CHECK(dropped.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&dropped.items[0], token_a, false);
    br_results_clear(&dropped);

    alloc_auth = 0;
    char *error = NULL;
    br_results nil = {0};
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, n}, &nil, &error) == 0 && !error);
    size_t nil_alloc = alloc_auth;
    CHECK(nil.len == 0 && !setter_calls);
    br_results_clear(&nil);
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live_auths, 0, sizeof(e.live_auths));
    e.statuses[0] = 200;
    e.body_errors[0] = NULL;
    e.send_rc[0] = 0;
    e.send_errors[0] = NULL;
    alloc_auth = 0;
    br_results sent = scan_ok(d, &ctx, input, n, &e);
    CHECK(nil_alloc == 0 && sent.len == 1 && alloc_auth == 1 && !setter_calls);
    br_results_clear(&sent);
}

static size_t append_capture(char *out, size_t at, size_t cap, const char *token, int tail)
{
    CHECK(at + 10 + raw_len + 2 < cap);
    memcpy(out + at, "livestorm ", 10);
    memcpy(out + at + 10, token, raw_len);
    at += 10 + raw_len;
    out[at++] = (char)tail;
    out[at] = '\0';
    return at;
}

static void duplicates_and_nil(const br_detector *d)
{
    char input[900];
    size_t total = append_capture(input, 0, sizeof(input), token_a, ' ');
    total = append_capture(input, total, sizeof(input), token_b, '\n');
    total = append_capture(input, total, sizeof(input), token_a, '\r');
    const char *keys[] = {token_a, token_b, token_a};
    expected e = {.keys = keys, .count = 3, .statuses = {200, 204, 299}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "livestorm-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, total, &e);
    CHECK(r.len == 3 && http.calls == 3 && http.releases == 3 && !setter_calls);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(!e.live_auths[i]);
        CHECK(e.released_ids[i] == 2 - i);
        CHECK(e.release_lengths[i] == 3 && e.sends_at_release[i] == 3);
    }
    check_result(&r.items[0], token_a, true);
    check_result(&r.items[1], token_b, true);
    check_result(&r.items[2], token_a, true);
    CHECK(r.items[0].raw.data != r.items[2].raw.data);
    br_results_clear(&r);

    expected failed_send = {.keys = keys, .count = 3, .statuses = {200, 403, 201},
                            .send_rc = {0, 4, 0}, .send_errors = {NULL, "synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "livestorm-offline"};
    failed_send.ctx = &failed_ctx;
    setter_calls = 0;
    br_results mixed_fail = scan_ok(d, &failed_ctx, input, total, &failed_send);
    CHECK(mixed_fail.len == 3 && failed_http.calls == 3 && failed_http.releases == 3 && !setter_calls);
    CHECK(failed_send.released_ids[0] == 1 && failed_send.sends_at_release[0] == 2);
    CHECK(failed_send.release_lengths[0] == 1);
    CHECK(failed_send.released_ids[1] == 2 && failed_send.released_ids[2] == 0);
    CHECK(failed_send.sends_at_release[1] == 3 && failed_send.sends_at_release[2] == 3);
    CHECK(failed_send.release_lengths[1] == 3 && failed_send.release_lengths[2] == 3);
    check_result(&mixed_fail.items[0], token_a, true);
    check_result(&mixed_fail.items[1], token_b, false);
    check_result(&mixed_fail.items[2], token_a, true);
    br_results_clear(&mixed_fail);

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
    alloc_auth = 0;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, total}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[700];
    size_t total = append_capture(input, 0, sizeof(input), token_a, ' ');
    total = append_capture(input, total, sizeof(input), token_b, ' ');
    const char *keys[] = {token_a, token_b};
    expected e = {.keys = keys, .count = 2, .statuses = {200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "livestorm-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, total};
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

    fail_size = (size_t)capture_len + 1; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live_auths[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_size = (size_t)raw_len + 1; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate Livestorm authorization"));
    CHECK(!http.calls && !http.releases && !e.live_auths[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Livestorm result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live_auths[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_auths, 0, sizeof(e.live_auths));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Livestorm result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_auths[0] && !e.live_auths[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_auths, 0, sizeof(e.live_auths));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain Livestorm response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_auths[0] && !e.live_auths[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    make_token(token_a, 'A', 'a');
    make_token(token_b, 'B', 'b');
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    duplicates_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !setter_calls);
    return test_finish("Livestorm");
}
