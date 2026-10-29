/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_lendflow_init(const br_detector **out, char **error);

static char key1[957], key2[957];
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc;
static bool fail_growth;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#include "../../src/result.c"
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void fill_key(char *out, char base)
{
    static const struct { size_t n; char sep; } segs[] = {
        {36, '.'}, {235, '.'}, {32, '-'}, {47, '-'}, {162, '-'},
        {42, '-'}, {40, '-'}, {66, '-'}, {59, '-'}, {7, '-'}, {220, 0},
    };
    size_t at = 0;
    for (size_t s = 0; s < sizeof(segs) / sizeof(segs[0]); ++s) {
        memset(out + at, base, segs[s].n);
        at += segs[s].n;
        if (segs[s].sep) out[at++] = segs[s].sep;
    }
    out[at] = '\0';
    CHECK(at == 956);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_lendflow_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_lendflow_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:lendflow)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_lendflow_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_lendflow_init(&d, &error) == 0 && d && !error);
    CHECK(br_lendflow_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 668 && d->version == 0 && !strcmp(d->name, "Lendflow"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Lendflow is a platform for accessing financial data and services. Lendflow API keys can be used to access and manipulate this financial data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lendflow"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 668, key, "key");
    CHECK(r->raw.len == 956 && r->verified == verified && !r->verification_error);
}

static void extract(const br_detector *d, const void *text, size_t n, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == (key ? 1u : 0u));
    if (key) check_result(&r.items[0], key, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[2400], changed[957];
    int n = snprintf(input, sizeof(input), "lendflow %s", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "LeNdFlOw=%s", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "mylendflow %s", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    extract(d, key1, 956, NULL);
    n = snprintf(input, sizeof(input), "%s lendflow", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    memcpy(input, "lendflow", 8); memcpy(input + 8, key1, 956);
    extract(d, input, 8 + 956, NULL);
    memcpy(changed, key1, 957); changed[0] = '_';
    n = snprintf(input, sizeof(input), "lendflow %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    memcpy(changed, key1, 957); changed[354] = '_';
    n = snprintf(input, sizeof(input), "lendflow %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, changed);
    memcpy(changed, key1, 957); changed[36] = 'x';
    n = snprintf(input, sizeof(input), "lendflow %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    memcpy(input, "lendflow ", 9); memcpy(input + 9, key1, 956); input[9 + 956] = 'x';
    extract(d, input, 9 + 956 + 1, NULL);
    memcpy(input, "lendflow ", 9); memcpy(input + 9, key1, 956); input[9 + 956] = '.';
    extract(d, input, 9 + 956 + 1, key1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "lendflow", 8);
        memset(input + 8, '.', gap);
        memcpy(input + 8 + gap, key1, 956);
        extract(d, input, 8 + gap + 956, gap == 40 ? key1 : NULL);
    }
    memset(input, 'z', 200);
    memcpy(input + 200, "lendflow ", 9);
    memcpy(input + 209, key1, 956);
    CHECK(209 + 956 > 1024);
    extract(d, input, 209 + 956, key1);
    n = snprintf(input, sizeof(input), "lendflow %s\nlendflow %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], key1, false);
    check_result(&both.items[1], key2, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *auths[4];
    br_header markers[4];
    int statuses[4];
    const char *read_errors[4];
    int send_rc[4];
    const char *causes[4];
    size_t released_ids[4];
    size_t release_lengths[4];
    size_t sends_at_release[4];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void check_auth(const char *auth, const char *key)
{
    CHECK(auth && strlen(auth) == 7 + 956);
    CHECK(!memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, key, 956));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    const char *key = e->keys[at];
    CHECK(at < e->count && ctx == e->ctx);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->auths[i]) { ++failed; continue; }
        CHECK(e->auths[i] != request->headers[1].value);
        check_auth(e->auths[i], e->keys[i]);
    }
    /* A failed send has already released. Successful Bearers stay live. */
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->url && !strcmp(request->url, "https://app.lendflow.io/api/v1/deals"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(request->detector_type == 668);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    check_auth(request->headers[1].value, key);
    CHECK(!strcmp(request->headers[2].name, "Accept"));
    CHECK(!strcmp(request->headers[2].value, "application/json"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    CHECK(!strcmp(request->headers[3].value, "TruffleHog lendflow-offline"));
    e->auths[at] = request->headers[1].value;
    e->markers[at] = (br_header){"synthetic-attempt", key};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->read_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->causes[at];
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out);
        check_auth(e->auths[id], e->keys[id]);
        e->auths[id] = NULL;
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
    char input[1100];
    int n = snprintf(input, sizeof(input), "lendflow %s", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1};
    expected e = {.keys = keys, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lendflow-offline"};
    e.ctx = &ctx;
    const struct { int status, rc; const char *body_error, *send_error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {199, 0, NULL, NULL, false}, {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false},
        {200, 0, "synthetic read failure", NULL, true}, {299, 0, "", NULL, true},
        {200, 1, NULL, "synthetic send error", false}, {200, 7, "read", key1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        memset(e.auths, 0, sizeof(e.auths));
        e.statuses[0] = cases[i].status;
        e.read_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.causes[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.auths[0]);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        /* Successful Do is published before its deferred release. A failed send
         * releases immediately, before append. */
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], key1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = 0;
    memset(e.auths, 0, sizeof(e.auths));
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "lendflow-offline"};
    br_results prepared = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(prepared.len == 1 && !http.calls && http.releases == 1 && !e.auths[0]);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&prepared.items[0], key1, false);
    br_results_clear(&prepared);
}

static void duplicates_and_nil(const br_detector *d)
{
    char input[3200];
    int n = snprintf(input, sizeof(input), "lendflow %s\nLENDFLOW %s\nlendflow %s", key1, key2, key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key2, key1};
    expected e = {.keys = keys, .count = 3, .statuses = {204, 204, 204}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lendflow-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 3 && http.calls == 3 && http.releases == 3);
    CHECK(!e.auths[0] && !e.auths[1] && !e.auths[2]);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(e.released_ids[i] == 2 - i);
        CHECK(e.release_lengths[i] == 3 && e.sends_at_release[i] == 3);
    }
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key2, true);
    check_result(&r.items[2], key1, true);
    CHECK(r.items[0].raw.data != r.items[2].raw.data);
    br_results_clear(&r);

    /* The middle Do fails immediately and is absent from the deferred LIFO set. */
    expected mixed = {.keys = keys, .count = 3, .statuses = {200, 500, 201},
                      .send_rc = {0, 4, 0}, .causes = {NULL, "synthetic send error", NULL}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "lendflow-offline"};
    mixed.ctx = &mixed_ctx;
    br_results published = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed);
    CHECK(published.len == 3 && mixed_http.calls == 3 && mixed_http.releases == 3);
    CHECK(mixed.released_ids[0] == 1 && mixed.sends_at_release[0] == 2 && mixed.release_lengths[0] == 1);
    CHECK(mixed.released_ids[1] == 2 && mixed.released_ids[2] == 0);
    CHECK(mixed.sends_at_release[1] == 3 && mixed.sends_at_release[2] == 3);
    CHECK(mixed.release_lengths[1] == 3 && mixed.release_lengths[2] == 3);
    check_result(&published.items[0], key1, true);
    check_result(&published.items[1], key2, false);
    check_result(&published.items[2], key1, true);
    br_results_clear(&published);

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
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[2100];
    int n = snprintf(input, sizeof(input), "lendflow %s\nlendflow %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key2};
    expected e = {.keys = keys, .count = 2, .statuses = {200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lendflow-offline"};
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

    fail_size = 957; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.auths[0] && !e.auths[1]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Lendflow result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.auths[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.auths, 0, sizeof(e.auths));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Lendflow result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.auths[0] && !e.auths[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.auths, 0, sizeof(e.auths));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain Lendflow response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.auths[0] && !e.auths[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    fill_key(key1, 'a');
    fill_key(key2, 'b');
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    duplicates_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc);
    return test_finish("Lendflow");
}
