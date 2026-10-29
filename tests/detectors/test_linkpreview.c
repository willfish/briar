/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_linkpreview_init(const br_detector **out, char **error);

static char key1[33], key2[33], mixed[33];
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls;
static bool fail_growth;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error linkpreview_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
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

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return linkpreview_real_setter(result, cause, secrets, count);
}

static void url_for(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "https://api.linkpreview.net/?key=%s&q=https://google.com", key);
    CHECK(wrote > 0 && (size_t)wrote + 1 == n);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_linkpreview_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_linkpreview_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:linkpreview)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_linkpreview_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_linkpreview_init(&d, &error) == 0 && d && !error);
    CHECK(br_linkpreview_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 438 && d->version == 0 && !strcmp(d->name, "LinkPreview"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "LinkPreview is a service that provides information about a web page when given a URL. LinkPreview API keys can be used to access this service and retrieve metadata about web pages."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "linkpreview"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 438, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
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
    char input[320];
    const struct { const char *fmt; bool match; } cases[] = {
        {"linkpreview token = '%s'", true}, {"LiNkPrEvIeW=%s", true},
        {"mylinkpreview %s", true}, {"linkpreviewing:%s", true},
        {"%s", false}, {"%s linkpreview", false}, {"link preview %s", false},
        {"linkpreview%s", false}, {"linkpreview _%s", false}, {"linkpreview %s_", false},
        {"linkpreview %.31s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].fmt, key1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        extract(d, input, (size_t)n, cases[i].match ? key1 : NULL);
    }
    int n = snprintf(input, sizeof(input), "linkpreview %s", mixed);
    CHECK(n > 0); extract(d, input, (size_t)n, mixed);
    char longer[34]; memcpy(longer, key1, 32); longer[32] = 'a'; longer[33] = 0;
    n = snprintf(input, sizeof(input), "linkpreview %s", longer);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "linkpreview %sx", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "linkpreview %s.", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "linkpreview", 11);
        memset(input + 11, '.', gap);
        memcpy(input + 11 + gap, key1, 32);
        extract(d, input, 11 + gap + 32, gap == 40 ? key1 : NULL);
        memcpy(input, "linkpreview", 11);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 11 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 11 + 4 * gap, key1, 32);
        extract(d, input, 11 + 4 * gap + 32, gap == 40 ? key1 : NULL);
    }
    memcpy(input, "linkpreview\0", 12); memcpy(input + 12, key1, 32);
    extract(d, input, 44, key1);
    n = snprintf(input, sizeof(input), "linkpreview\r\n%s", key1);
    CHECK(n > 0); extract(d, input, (size_t)n, key1);
    extract(d, NULL, 0, NULL);
    n = snprintf(input, sizeof(input), "linkpreview %s linkpreview %s", key1, key2);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], key1, false);
    check_result(&both.items[1], key2, false);
    br_results_clear(&both);
}

typedef struct {
    const char *const *urls;
    size_t count;
    const char *live_urls[3];
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
    CHECK(request->detector_type == 438);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog linkpreview-offline"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(strstr(request->url, "%") == NULL);
    CHECK(strstr(request->url, "https://api.linkpreview.net/?key=") == request->url);
    CHECK(!strcmp(request->url + strlen("https://api.linkpreview.net/?key=") + 32, "&q=https://google.com"));
    e->live_urls[at] = request->url;
    e->markers[at] = (br_header){"synthetic-attempt", e->urls[at]};
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
    char input[80], url[87];
    int n = snprintf(input, sizeof(input), "linkpreview %s", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    url_for(url, sizeof(url), key1);
    const char *urls[] = {url};
    expected e = {.urls = urls, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "linkpreview-offline"};
    e.ctx = &ctx;
    const struct { int status, rc; const char *body_error, *send_error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {199, 0, NULL, NULL, false}, {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false},
        {500, 0, NULL, NULL, false}, {0, 0, NULL, NULL, false},
        {200, 0, "synthetic read failure", NULL, true}, {200, 0, "", NULL, true},
        {200, 1, NULL, "synthetic send error", false}, {299, 7, NULL, key1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        setter_calls = 0;
        memset(e.live_urls, 0, sizeof(e.live_urls));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live_urls[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], key1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "linkpreview-offline"};
    br_results dropped = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(dropped.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&dropped.items[0], key1, false);
    br_results_clear(&dropped);
}

static void duplicates_and_nil(const br_detector *d)
{
    char input[180], url1[87], url2[87];
    int n = snprintf(input, sizeof(input), "linkpreview %s\nLINKPREVIEW %s\nlinkpreview %s", key1, key2, key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    url_for(url1, sizeof(url1), key1);
    url_for(url2, sizeof(url2), key2);
    const char *urls[] = {url1, url2, url1};
    expected e = {.urls = urls, .count = 3, .statuses = {204, 204, 204}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "linkpreview-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 3 && http.calls == 3 && http.releases == 3 && !setter_calls);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(!e.live_urls[i]);
        CHECK(e.released_ids[i] == 2 - i);
        CHECK(e.release_lengths[i] == 3 && e.sends_at_release[i] == 3);
    }
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key2, true);
    check_result(&r.items[2], key1, true);
    CHECK(r.items[0].raw.data != r.items[2].raw.data);
    CHECK(r.items[0].secret_parts != r.items[2].secret_parts);
    br_results_clear(&r);

    expected failed_send = {.urls = urls, .count = 3, .statuses = {200, 403, 201},
                            .send_rc = {0, 4, 0}, .send_errors = {NULL, "synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "linkpreview-offline"};
    failed_send.ctx = &failed_ctx;
    setter_calls = 0;
    br_results mixed_fail = scan_ok(d, &failed_ctx, input, (size_t)n, &failed_send);
    CHECK(mixed_fail.len == 3 && failed_http.calls == 3 && failed_http.releases == 3 && !setter_calls);
    CHECK(failed_send.released_ids[0] == 1 && failed_send.sends_at_release[0] == 2);
    CHECK(failed_send.release_lengths[0] == 1);
    CHECK(failed_send.released_ids[1] == 2 && failed_send.released_ids[2] == 0);
    CHECK(failed_send.sends_at_release[1] == 3 && failed_send.sends_at_release[2] == 3);
    CHECK(failed_send.release_lengths[1] == 3 && failed_send.release_lengths[2] == 3);
    check_result(&mixed_fail.items[0], key1, true);
    check_result(&mixed_fail.items[1], key2, false);
    check_result(&mixed_fail.items[2], key1, true);
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
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);

    fail_size = strlen("https://api.linkpreview.net/?key=") + 32 + sizeof("&q=https://google.com");
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate LinkPreview URL"));
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[120], url1[87], url2[87];
    int n = snprintf(input, sizeof(input), "linkpreview %s\nlinkpreview %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    url_for(url1, sizeof(url1), key1);
    url_for(url2, sizeof(url2), key2);
    const char *urls[] = {url1, url2};
    expected e = {.urls = urls, .count = 2, .statuses = {200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "linkpreview-offline"};
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

    fail_size = 33; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live_urls[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create LinkPreview result"));
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
    CHECK(!strcmp(error, "cannot append LinkPreview result"));
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
    CHECK(!strcmp(error, "cannot retain LinkPreview response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_urls[0] && !e.live_urls[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    test_secret(key1, 32, 0);
    test_secret(key2, 32, 5);
    test_secret(mixed, 32, 9);
    mixed[0] = 'A'; mixed[10] = 'Z'; mixed[31] = 'Q';
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    duplicates_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !setter_calls);
    return test_finish("LinkPreview");
}
