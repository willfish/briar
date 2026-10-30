/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pagerdutyapikey_init(const br_detector **out, char **error);

static char key1[21], key2[21], mixed[21];
static const char url[] = "https://api.pagerduty.com/users";
static size_t fail_size, fail_after, fail_part_after, setter_calls, sized_allocs;
static bool fail_growth, fail_setter, setter_null;
static char setter_cause[256];
static const size_t auth_size = sizeof("Token ") + 20;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error pager_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == auth_size) ++sized_allocs;
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
    CHECK(count == 1 && secrets && secrets[0].len == 20 && secrets[0].data);
    if (fail_setter) return 1;
    return pager_real_setter(result, cause, secrets, count);
}

static void make_key(char *out, size_t shift)
{
    memcpy(out, "u+", 2);
    test_secret(out + 2, 18, shift);
    CHECK(strlen(out) == 20);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    static const char *order[] = {"pagerduty", "pager_duty", "pd_", "pd-"};
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_pagerdutyapikey_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_pagerdutyapikey_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:pagerduty|pager_duty|pd_|pd-)(?s:.){0,40}?");
    fail_after = 1;
    CHECK(br_pagerdutyapikey_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_pagerdutyapikey_init(&d, &error) == 0 && d && !error);
    CHECK(br_pagerdutyapikey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 32 && d->version == 0 && !strcmp(d->name, "PagerDutyApiKey"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PagerDuty is an incident management platform that provides reliable notifications, automatic escalations, on-call scheduling, and other functionality to help teams detect and fix infrastructure problems quickly. PagerDuty API keys can be used to access and manage these functionalities."));
    CHECK(d->nkeywords == 4);
    for (size_t i = 0; i < 4; ++i) CHECK(!strcmp(d->keywords[i], order[i]));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified, const char *cause)
{
    test_key_result(r, 32, key, "key");
    CHECK(r->raw.len == 20 && r->verified == verified && !r->extra_data);
    if (cause) CHECK(r->verification_error && !strcmp(r->verification_error, cause));
    else CHECK(!r->verification_error);
}

static void expect_n(const br_detector *d, const void *text, size_t n, size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count && !setter_calls);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, false, NULL);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[240], changed[21], near[80], far[90];
    int n = snprintf(input, sizeof(input), "pagerduty %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "PAGERDUTY %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "pager_duty %s", mixed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, mixed);
    n = snprintf(input, sizeof(input), "pd_ %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "pd-%s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "PD-%s", key2);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key2);
    n = snprintf(input, sizeof(input), "pd_%s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "pd %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "pagerduty%s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    expect_n(d, key1, 20, 0, NULL);
    n = snprintf(input, sizeof(input), "pagerduty %s pagerduty %s", key1, key1);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2 && !setter_calls);
    check_result(&both.items[0], key1, false, NULL);
    check_result(&both.items[1], key1, false, NULL);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    memcpy(near, "pagerduty", 9);
    memset(near + 9, '.', 40);
    memcpy(near + 49, key1, 20);
    expect_n(d, near, 69, 1, key1);
    memcpy(far, "pagerduty", 9);
    memset(far + 9, '.', 41);
    memcpy(far + 50, key1, 20);
    expect_n(d, far, 70, 0, NULL);
    memcpy(changed, key1, 21); changed[0] = 'U';
    n = snprintf(input, sizeof(input), "pagerduty %s", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    memcpy(changed, key1, 21); changed[8] = '.';
    n = snprintf(input, sizeof(input), "pagerduty %s", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    memcpy(changed, key1, 19); changed[19] = '\0';
    n = snprintf(input, sizeof(input), "pagerduty %s.", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "pagerduty %sa", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "pagerduty %s.", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    expect_n(d, "pagerduty", 9, 0, NULL);
    expect_n(d, NULL, 0, 0, NULL);
}

typedef struct {
    const char *const *keys;
    const char *const *tokens;
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
} expected;

static void token_for(char *out, size_t n, const char *key)
{
    int wrote = snprintf(out, n, "Token %s", key);
    CHECK(wrote == 26 && (size_t)wrote < n);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    for (size_t i = 0; i < at; ++i) CHECK(!e->live[i]);
    CHECK(http->releases == at);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 32);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.pagerduty+json;version=2"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].value, e->tokens[at]));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    CHECK(!strcmp(request->headers[3].value, "TruffleHog pagerduty-offline"));
    e->live[at] = request->headers[2].value;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_errors[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->tokens[id]));
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
    char input[80], token[32];
    int n = snprintf(input, sizeof(input), "pagerduty %s", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    token_for(token, sizeof(token), key1);
    const char *keys[] = {key1};
    const char *tokens[] = {token};
    expected e = {.keys = keys, .tokens = tokens, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pagerduty-offline"};
    e.ctx = &ctx;
    const struct {
        int status, rc; const char *body_error, *send_error, *cause; bool verified, null_cause;
    } cases[] = {
        {200, 0, NULL, NULL, NULL, true, true},
        {200, 0, "", NULL, NULL, true, true},
        {200, 0, "synthetic read failure", NULL, NULL, true, true},
        {403, 0, "", NULL, NULL, true, true},
        {402, 0, "synthetic read failure", NULL, NULL, true, true},
        {401, 0, "read", NULL, NULL, false, true},
        {400, 0, NULL, NULL, NULL, false, true},
        {404, 0, "", NULL, NULL, false, true},
        {429, 0, "", NULL, "PagerDuty rate limit reached", false, false},
        {429, 0, "synthetic read failure", NULL, "PagerDuty rate limit reached", false, false},
        {201, 0, NULL, NULL, "unexpected HTTP response status 201", false, false},
        {299, 0, "read", NULL, "unexpected HTTP response status 299", false, false},
        {500, 0, NULL, NULL, "unexpected HTTP response status 500", false, false},
        {0, 0, NULL, NULL, "unexpected HTTP response status 0", false, false},
        {-1, 0, NULL, NULL, "unexpected HTTP response status -1", false, false},
        {200, 4, "read", "synthetic send error", "synthetic send error", false, false},
        {403, 7, NULL, key1, "[REDACTED]", false, false},
        {200, 1, NULL, NULL, "HTTP transport failed", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        setter_null = false;
        memset(e.live, 0, sizeof(e.live));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].send_error;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0]);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == 0 && e.setter_at_release[0] == 0);
        CHECK(setter_calls == 1 && setter_null == cases[i].null_cause);
        check_result(&r.items[0], key1, cases[i].verified, cases[i].cause);
        br_results_clear(&r);
    }
    http.calls = http.releases = setter_calls = 0;
    setter_null = false;
    memset(e.live, 0, sizeof(e.live));
    size_t before = sized_allocs;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "pagerduty-offline"};
    br_results unpublished = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0]);
    CHECK(e.release_lengths[0] == 0 && e.setter_at_release[0] == 0 && setter_calls == 1 && !setter_null);
    CHECK(sized_allocs > before);
    check_result(&unpublished.items[0], key1, false, "HTTP transport not installed");
    br_results_clear(&unpublished);
}

static void immediate_and_nil(const br_detector *d)
{
    char input[120], token1[32], token2[32];
    int n = snprintf(input, sizeof(input), "pagerduty %s pd- %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    token_for(token1, sizeof(token1), key1);
    token_for(token2, sizeof(token2), key2);
    const char *keys[] = {key1, key2};
    const char *tokens[] = {token1, token2};
    expected e = {.keys = keys, .tokens = tokens, .count = 2, .statuses = {200, 403}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pagerduty-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && setter_calls == 2 && setter_null);
    CHECK(e.released_ids[0] == 0 && e.sends_at_release[0] == 1 && e.release_lengths[0] == 0);
    CHECK(e.setter_at_release[0] == 0);
    CHECK(e.released_ids[1] == 1 && e.sends_at_release[1] == 2 && e.release_lengths[1] == 1);
    CHECK(e.setter_at_release[1] == 1);
    check_result(&r.items[0], key1, true, NULL);
    check_result(&r.items[1], key2, true, NULL);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    char one[64];
    int one_n = snprintf(one, sizeof(one), "pagerduty %s", key1);
    CHECK(one_n > 0);
    size_t before = sized_allocs, setters = setter_calls;
    br_results quiet = test_scan(d, NULL, false, one, (size_t)one_n);
    size_t baseline = sized_allocs - before;
    CHECK(quiet.len == 1 && setter_calls == setters);
    br_results_clear(&quiet);

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
    setter_calls = 0;
    setter_null = false;
    before = sized_allocs;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == 0 && !error);
    CHECK(sized_allocs - before == baseline);
    CHECK(http.calls == calls && http.releases == releases);
    CHECK(setter_calls == 1 && !setter_null && !strcmp(setter_cause, "net/http: nil Context"));
    CHECK(kept.len == 2 && kept.items[0].raw.data == prior.raw.data);
    check_result(&kept.items[1], key1, false, "net/http: nil Context");
    br_result_clear(&kept.items[--kept.len]);

    fail_setter = true;
    setter_calls = 0;
    before = sized_allocs;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot record PagerDutyApiKey verification error"));
    CHECK(sized_allocs - before == baseline && setter_calls == 1 && !setter_null);
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    fail_setter = false;
    free(error); error = NULL;

    fail_size = auth_size;
    fail_after = baseline + 1;
    setter_calls = 0;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate PagerDutyApiKey authorization"));
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[120], token1[32], token2[32];
    int n = snprintf(input, sizeof(input), "pagerduty %s pd- %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    token_for(token1, sizeof(token1), key1);
    token_for(token2, sizeof(token2), key2);
    const char *keys[] = {key1, key2};
    const char *tokens[] = {token1, token2};
    expected e = {.keys = keys, .tokens = tokens, .count = 2, .statuses = {200, 429}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pagerduty-offline"};
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

    fail_size = 21; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create PagerDutyApiKey result"));
    CHECK(http.calls == 1 && http.releases == 1 && setter_calls == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.setter_at_release[0] == 0);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append PagerDutyApiKey result"));
    CHECK(http.calls == 2 && http.releases == 2 && setter_calls == 2);
    CHECK(e.released_ids[0] == 0 && e.released_ids[1] == 1);
    CHECK(e.release_lengths[0] == 1 && e.release_lengths[1] == 2);
    CHECK(e.setter_at_release[0] == 0 && e.setter_at_release[1] == 1);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));

    e.count = 1;
    e.statuses[0] = 200;
    fail_setter = true;
    setter_calls = 0;
    char one[64];
    int one_n = snprintf(one, sizeof(one), "pagerduty %s", key1);
    CHECK(one_n > 0);
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot record PagerDutyApiKey verification error"));
    CHECK(setter_calls == 1 && setter_null && http.calls == 1 && http.releases == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.setter_at_release[0] == 0);
    check_prior(&out, &prior);
    fail_setter = false;
    free(error); error = NULL;
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));

    e.send_rc[0] = 3;
    e.send_errors[0] = "synthetic send error";
    fail_setter = true;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot record PagerDutyApiKey verification error"));
    CHECK(setter_calls == 1 && !setter_null && !strcmp(setter_cause, "synthetic send error"));
    CHECK(http.calls == 1 && http.releases == 1 && e.setter_at_release[0] == 0);
    check_prior(&out, &prior);
    fail_setter = false;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    make_key(key1, 0);
    make_key(key2, 7);
    memcpy(mixed, "u+Ab9_+-zzzzzzzzzzzz", 21);
    CHECK(strlen(mixed) == 20);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    immediate_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_setter);
    return test_finish("PagerDutyApiKey");
}
