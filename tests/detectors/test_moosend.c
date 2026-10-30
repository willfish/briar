/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_moosend_init(const br_detector **out, char **error);

static char key1[37], key2[37];
static const char prefix[] = "https://api.moosend.com/v3/lists.json?apikey=";
static const char suffix[] = "&format=json";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, url_allocs, url_size;
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
    if (url_size && n == url_size) ++url_allocs;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void fill_key(char *out, char base)
{
    static const int widths[] = {8, 4, 4, 4, 12};
    size_t at = 0;
    for (size_t s = 0; s < sizeof(widths) / sizeof(widths[0]); ++s) {
        if (s) out[at++] = '-';
        memset(out + at, base, (size_t)widths[s]);
        at += (size_t)widths[s];
    }
    out[at] = '\0';
    CHECK(at == 36);
}

static void expect_url(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "%s%s%s", prefix, key, suffix);
    CHECK(wrote > 0 && (size_t)wrote < n);
    CHECK(strstr(out, "%") == NULL);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_moosend_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_moosend_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:moosend)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_moosend_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_moosend_init(&d, &error) == 0 && d && !error);
    CHECK(br_moosend_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 261 && d->version == 0 && !strcmp(d->name, "Moosend"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Moosend is an email marketing service provider. Moosend API keys can be used to access and manage email marketing campaigns, subscriber lists, and other related data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "moosend"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 261, key, "key");
    CHECK(r->raw.len == 36 && r->verified == verified && !r->verification_error && !r->extra_data);
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
    char input[220], changed[37];
    int n = snprintf(input, sizeof(input), "moosend %s", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    CHECK(key1[0] == 'A');
    n = snprintf(input, sizeof(input), "MoOsEnD=%s", key2);
    CHECK(n > 0); extract(d, input, (size_t)n, key2);
    extract(d, key1, 36, NULL);
    memcpy(input, "moosend", 7); memcpy(input + 7, key1, 36);
    extract(d, input, 43, NULL);
    memcpy(changed, key1, 37); changed[0] = 'B';
    n = snprintf(input, sizeof(input), "moosend %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    memcpy(changed, key2, 37); changed[9] = 'A';
    n = snprintf(input, sizeof(input), "moosend %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    memcpy(changed, key2, 37); changed[35] = 'F';
    n = snprintf(input, sizeof(input), "moosend %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "moosend %s.", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "moosend %sx", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "moosend", 7);
        memset(input + 7, '.', gap);
        memcpy(input + 7 + gap, key1, 36);
        extract(d, input, 7 + gap + 36, gap == 40 ? key1 : NULL);
    }
    n = snprintf(input, sizeof(input), "moosend %s\nMOOSEND %s", key1, key2);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], key1, false);
    check_result(&both.items[1], key2, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    CHECK(memchr(both.items[0].raw.data, 'A', 36));
    br_results_clear(&both);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *urls;
    size_t count;
    const char *live_urls[3];
    br_header markers[3];
    int statuses[3];
    br_slice bodies[3];
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

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->url);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live_urls[i]) { ++failed; continue; }
        CHECK(e->live_urls[i] != request->url && !strcmp(e->live_urls[i], e->urls[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, e->urls[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 261);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog moosend-offline"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(strstr(request->url, "%") == NULL);
    CHECK(strstr(request->url, prefix) == request->url);
    CHECK(!strcmp(request->url + strlen(prefix) + 36, suffix));
    e->live_urls[at] = request->url;
    e->markers[at] = (br_header){"synthetic-attempt", e->urls[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body = e->bodies[at], .body_error = e->body_errors[at],
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
        CHECK(id < e->count && e->out && e->live_urls[id] && !strcmp(e->live_urls[id], e->urls[id]));
        e->live_urls[id] = NULL;
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

static br_slice body_of(const char *text)
{
    return text ? (br_slice){(const unsigned char *)text, strlen(text)} : (br_slice){0};
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
    char input[64], url1[128];
    int n = snprintf(input, sizeof(input), "moosend %s", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_url(url1, sizeof(url1), key1);
    const char *urls[] = {url1};
    expected e = {.urls = urls, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "moosend-offline"};
    e.ctx = &ctx;
    const struct {
        int status, rc; const char *text, *body_error, *send_error; bool kept, verified;
    } cases[] = {
        {200, 0, "CreatedOn", NULL, NULL, true, true},
        {401, 0, "{\"CreatedOn\":1}", NULL, NULL, true, true},
        {500, 0, "xxCreatedOnyy", NULL, NULL, true, true},
        {0, 0, "CreatedOn", NULL, NULL, true, true},
        {200, 0, "createdon", NULL, NULL, true, false},
        {204, 0, "", NULL, NULL, true, false},
        {200, 0, NULL, NULL, NULL, true, false},
        {200, 0, "CreatedOn", "", NULL, false, false},
        {201, 0, "CreatedOn", "synthetic read failure", NULL, false, false},
        {200, 1, "CreatedOn", "read", "synthetic send error", true, false},
        {500, 7, "CreatedOn", NULL, key1, true, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        memset(e.live_urls, 0, sizeof(e.live_urls));
        e.statuses[0] = cases[i].status;
        e.bodies[0] = body_of(cases[i].text);
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 && cases[i].kept ? 1u : 0u));
        CHECK(r.len == (cases[i].kept ? 1u : 0u));
        if (cases[i].kept) check_result(&r.items[0], key1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));
    size_t built = url_allocs;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "moosend-offline"};
    br_results unpublished = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live_urls[0]);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    CHECK(url_allocs == built + 1);
    check_result(&unpublished.items[0], key1, false);
    br_results_clear(&unpublished);
}

static void duplicates_and_nil(const br_detector *d)
{
    char input[120], url1[128], url2[128];
    int n = snprintf(input, sizeof(input), "moosend %s\nmoosend %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_url(url1, sizeof(url1), key1);
    expect_url(url2, sizeof(url2), key2);
    const char *urls[] = {url1, url2};
    expected e = {.urls = urls, .count = 2, .statuses = {404, 500},
                  .bodies = {body_of("CreatedOn"), body_of("CreatedOn")}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "moosend-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live_urls[i]);
        CHECK(e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
    }
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key2, true);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    /* ReadAll failure is deferred and is not searched, even when the unread
     * body would otherwise contain the needle or be an invalid pointer. */
    expected unread = {.urls = urls, .count = 2, .statuses = {200, 200},
                       .bodies = {{NULL, 8}, body_of("CreatedOn")},
                       .body_errors = {"", NULL}};
    test_http unread_http = {.inspect = inspect, .user = &unread};
    br_transport unread_transport = {&unread_http, test_http_send, release_response};
    br_scan_ctx unread_ctx = {.transport = &unread_transport, .user_agent = "moosend-offline"};
    unread.ctx = &unread_ctx;
    br_results dropped_read = scan_ok(d, &unread_ctx, input, (size_t)n, &unread);
    CHECK(dropped_read.len == 1 && unread_http.calls == 2 && unread_http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!unread.live_urls[i]);
        CHECK(unread.released_ids[i] == 1 - i);
        CHECK(unread.release_lengths[i] == 1 && unread.sends_at_release[i] == 2);
    }
    check_result(&dropped_read.items[0], key2, true);
    br_results_clear(&dropped_read);

    expected failed_send = {.urls = urls, .count = 2, .statuses = {200, 201},
                            .bodies = {body_of("CreatedOn"), body_of("CreatedOn")},
                            .send_rc = {4, 0},
                            .send_errors = {"synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "moosend-offline"};
    failed_send.ctx = &failed_ctx;
    br_results mixed_fail = scan_ok(d, &failed_ctx, input, (size_t)n, &failed_send);
    CHECK(mixed_fail.len == 2 && failed_http.calls == 2 && failed_http.releases == 2);
    CHECK(failed_send.released_ids[0] == 0 && failed_send.sends_at_release[0] == 1);
    CHECK(failed_send.release_lengths[0] == 0);
    CHECK(failed_send.released_ids[1] == 1 && failed_send.sends_at_release[1] == 2);
    CHECK(failed_send.release_lengths[1] == 2);
    check_result(&mixed_fail.items[0], key1, false);
    check_result(&mixed_fail.items[1], key2, true);
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
    size_t calls = http.calls, releases = http.releases, built = url_allocs;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases);
    CHECK(url_allocs == built + 2);
    check_prior(&kept, &prior);

    /* Allocation is the first owned step after finding creation. Failing it on
     * a nil context proves the URL was requested before the constructor drop. */
    fail_size = url_size;
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate Moosend URL"));
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[120], url1[128], url2[128];
    int n = snprintf(input, sizeof(input), "moosend %s\nmoosend %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_url(url1, sizeof(url1), key1);
    expect_url(url2, sizeof(url2), key2);
    const char *urls[] = {url1, url2};
    expected e = {.urls = urls, .count = 2, .statuses = {200, 200},
                  .bodies = {body_of("CreatedOn"), body_of("CreatedOn")}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "moosend-offline"};
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

    fail_size = 37; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live_urls[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Moosend result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Moosend result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_urls[0] && !e.live_urls[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain Moosend response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_urls[0] && !e.live_urls[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    e.count = 1;
    e.bodies[0] = (br_slice){NULL, 8};
    e.body_errors[0] = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, 8 + 36}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Moosend response body"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    url_size = sizeof(prefix) - 1 + 36 + sizeof(suffix);
    fill_key(key1, 'a');
    key1[0] = 'A';
    fill_key(key2, 'b');
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    duplicates_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc);
    return test_finish("Moosend");
}
