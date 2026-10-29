/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_lessannoyingcrm_init(const br_detector **out, char **error);

static char plain[58], split[58], doubled[58], other[58];
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

static void user_code_plain(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "[%s]", key);
    CHECK(wrote == 59 && (size_t)wrote < n);
}

static void user_code_split(char *out, size_t n, const char *key)
{
    char left[21], right[37];
    memcpy(left, key, 20); left[20] = 0;
    memcpy(right, key + 21, 36); right[36] = 0;
    int wrote = snprintf(out, n, "[%s %s]", left, right);
    CHECK(wrote == 59 && (size_t)wrote < n && strchr(out, ' ') && !strchr(out, '-'));
}

static void user_code_empty(char *out, size_t n, const char *key)
{
    char left[21], right[36];
    memcpy(left, key, 20); left[20] = 0;
    memcpy(right, key + 22, 35); right[35] = 0;
    int wrote = snprintf(out, n, "[%s  %s]", left, right);
    CHECK(wrote == 59 && (size_t)wrote < n);
}

static void expect_url(char *out, size_t n, const char *usercode, const char *key)
{
    int wrote = snprintf(out, n,
        "https://api.lessannoyingcrm.com?UserCode=%s&APIToken=%s&Function=GetUserInfo",
        usercode, key);
    CHECK(wrote > 0 && (size_t)wrote < n);
    CHECK(strstr(out, "%20") == NULL && strstr(out, "%5B") == NULL && strstr(out, "%5b") == NULL);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_lessannoyingcrm_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_lessannoyingcrm_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:less)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_lessannoyingcrm_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_lessannoyingcrm_init(&d, &error) == 0 && d && !error);
    CHECK(br_lessannoyingcrm_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 267 && d->version == 0 && !strcmp(d->name, "LessAnnoyingCRM"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Less Annoying CRM is a customer relationship management system. The API token can be used to access and manage customer data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lessannoyingcrm"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 267, key, "key");
    CHECK(r->raw.len == 57 && r->verified == verified && !r->verification_error);
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
    char input[256], changed[58];
    int n = snprintf(input, sizeof(input), "less %s", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, plain);
    n = snprintf(input, sizeof(input), "LeSs=%s", split);
    CHECK(n > 0); extract(d, input, (size_t)n, split);
    n = snprintf(input, sizeof(input), "lessannoyingcrm %s", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, plain);
    n = snprintf(input, sizeof(input), "preless %s", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, plain);
    n = snprintf(input, sizeof(input), "annoyingcrm %s", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    extract(d, plain, 57, NULL);
    memcpy(input, "less", 4); memcpy(input + 4, plain, 57);
    extract(d, input, 61, NULL);
    memcpy(changed, plain, 58); changed[10] = '_';
    n = snprintf(input, sizeof(input), "less %s", changed);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "less %.56s", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "less %sx", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    n = snprintf(input, sizeof(input), "less %s.", plain);
    CHECK(n > 0); extract(d, input, (size_t)n, plain);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "less", 4);
        memset(input + 4, '.', gap);
        memcpy(input + 4 + gap, plain, 57);
        extract(d, input, 4 + gap + 57, gap == 40 ? plain : NULL);
    }
    n = snprintf(input, sizeof(input), "less %s\nLESS %s", plain, other);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], plain, false);
    check_result(&both.items[1], other, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *urls;
    size_t count;
    const char *live[4];
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

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->url);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != request->url && !strcmp(e->live[i], e->urls[i]));
    }
    /* A failed send has already released. Successful URLs stay live. */
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, e->urls[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 267);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.lessannoyingcrm+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog lacrm-offline"));
    CHECK(strstr(request->url, "UserCode=[") && strstr(request->url, "]&APIToken="));
    CHECK(strstr(request->url, "&Function=GetUserInfo"));
    CHECK(strstr(request->url, "%20") == NULL && strstr(request->url, "%5B") == NULL);
    e->live[at] = request->url;
    e->markers[at] = (br_header){"synthetic-attempt", e->urls[at]};
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
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->urls[id]));
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
    CHECK(rc == 0 && !error);
    return out;
}

static void one_verify(const br_detector *d, test_http *http, br_scan_ctx *ctx, expected *e,
                       const char *key, const char *url, int status, int rc,
                       const char *body_error, const char *send_error, bool verified)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "less %s", key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *urls[] = {url};
    e->urls = urls; e->count = 1;
    memset(e->live, 0, sizeof(e->live));
    e->statuses[0] = status;
    e->read_errors[0] = body_error;
    e->send_rc[0] = rc;
    e->causes[0] = send_error;
    http->calls = http->releases = 0;
    br_results r = scan_ok(d, ctx, input, (size_t)n, e);
    CHECK(r.len == 1 && http->calls == 1 && http->releases == 1 && !e->live[0]);
    CHECK(e->sends_at_release[0] == 1 && e->released_ids[0] == 0);
    /* Successful Do is published before its deferred release. A failed send
     * releases immediately, before append. */
    CHECK(e->release_lengths[0] == (rc == 0 ? 1u : 0u));
    check_result(&r.items[0], key, verified);
    br_results_clear(&r);
}

static void verification(const br_detector *d)
{
    char plain_code[64], split_code[64], empty_code[64];
    char plain_url[256], split_url[256], empty_url[256];
    user_code_plain(plain_code, sizeof(plain_code), plain);
    user_code_split(split_code, sizeof(split_code), split);
    user_code_empty(empty_code, sizeof(empty_code), doubled);
    expect_url(plain_url, sizeof(plain_url), plain_code, plain);
    expect_url(split_url, sizeof(split_url), split_code, split);
    expect_url(empty_url, sizeof(empty_url), empty_code, doubled);
    CHECK(strlen(plain_url) == strlen(split_url) && strlen(plain_url) == strlen(empty_url));
    expected e = {0};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lacrm-offline"};
    e.ctx = &ctx;
    one_verify(d, &http, &ctx, &e, plain, plain_url, 200, 0, NULL, NULL, true);
    one_verify(d, &http, &ctx, &e, split, split_url, 201, 0, NULL, NULL, true);
    one_verify(d, &http, &ctx, &e, doubled, empty_url, 299, 0, "", NULL, true);
    one_verify(d, &http, &ctx, &e, plain, plain_url, 200, 0, "synthetic read failure", NULL, true);
    one_verify(d, &http, &ctx, &e, plain, plain_url, 199, 0, NULL, NULL, false);
    one_verify(d, &http, &ctx, &e, plain, plain_url, 300, 0, "read", NULL, false);
    one_verify(d, &http, &ctx, &e, plain, plain_url, 200, 1, NULL, "synthetic send error", false);
    one_verify(d, &http, &ctx, &e, plain, plain_url, 204, 7, "read", plain, false);
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));
    const char *missing_urls[] = {plain_url};
    e.urls = missing_urls; e.count = 1;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "lacrm-offline"};
    char input[80];
    int n = snprintf(input, sizeof(input), "less %s", plain);
    CHECK(n > 0);
    br_results prepared = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(prepared.len == 1 && !http.calls && http.releases == 1 && !e.live[0]);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&prepared.items[0], plain, false);
    br_results_clear(&prepared);
}

static void duplicates_and_nil(const br_detector *d)
{
    char input[256], code[64], url[256];
    int n = snprintf(input, sizeof(input), "less %s\nless %s\nless %s", plain, other, plain);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    user_code_plain(code, sizeof(code), plain);
    expect_url(url, sizeof(url), code, plain);
    char other_code[64], other_url[256];
    user_code_plain(other_code, sizeof(other_code), other);
    expect_url(other_url, sizeof(other_url), other_code, other);
    const char *urls[] = {url, other_url, url};
    expected e = {.urls = urls, .count = 3, .statuses = {200, 200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lacrm-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 3 && http.calls == 3 && http.releases == 3);
    CHECK(!e.live[0] && !e.live[1] && !e.live[2]);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(e.released_ids[i] == 2 - i);
        CHECK(e.release_lengths[i] == 3 && e.sends_at_release[i] == 3);
    }
    check_result(&r.items[0], plain, true);
    check_result(&r.items[1], other, true);
    check_result(&r.items[2], plain, true);
    CHECK(r.items[0].raw.data != r.items[2].raw.data);
    br_results_clear(&r);

    expected mixed = {.urls = urls, .count = 3, .statuses = {200, 500, 201},
                      .send_rc = {0, 4, 0}, .causes = {NULL, "synthetic send error", NULL}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "lacrm-offline"};
    mixed.ctx = &mixed_ctx;
    br_results published = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed);
    CHECK(published.len == 3 && mixed_http.calls == 3 && mixed_http.releases == 3);
    CHECK(mixed.released_ids[0] == 1 && mixed.sends_at_release[0] == 2 && mixed.release_lengths[0] == 1);
    CHECK(mixed.released_ids[1] == 2 && mixed.released_ids[2] == 0);
    CHECK(mixed.sends_at_release[1] == 3 && mixed.sends_at_release[2] == 3);
    CHECK(mixed.release_lengths[1] == 3 && mixed.release_lengths[2] == 3);
    check_result(&published.items[0], plain, true);
    check_result(&published.items[1], other, false);
    check_result(&published.items[2], plain, true);
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

    /* URL allocation is the first owned step after finding creation. Failing it
     * on a nil context proves formatting ran before the constructor drop. */
    fail_size = strlen(url) + 1; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot format LessAnnoyingCRM URL"));
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[180];
    int n = snprintf(input, sizeof(input), "less %s\nless %s", plain, other);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char code[64], url[256], other_code[64], other_url[256];
    user_code_plain(code, sizeof(code), plain);
    expect_url(url, sizeof(url), code, plain);
    user_code_plain(other_code, sizeof(other_code), other);
    expect_url(other_url, sizeof(other_url), other_code, other);
    const char *urls[] = {url, other_url};
    expected e = {.urls = urls, .count = 2, .statuses = {200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lacrm-offline"};
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

    fail_size = 58; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live[0] && !e.live[1]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create LessAnnoyingCRM result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append LessAnnoyingCRM result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live[0] && !e.live[1]);
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
    CHECK(!strcmp(error, "cannot retain LessAnnoyingCRM response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live[0] && !e.live[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    test_secret(plain, 57, 0);
    test_secret(split, 57, 3);
    split[20] = '-';
    test_secret(doubled, 57, 9);
    doubled[20] = '-'; doubled[21] = '-';
    test_secret(other, 57, 11);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    duplicates_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc);
    return test_finish("LessAnnoyingCRM");
}
