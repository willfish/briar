/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char ida[] = "Ab7Cd9Ef2Gh5Jk6Lm", idb[] = "Zy8Xw6Vu4Ts2Rq0Pn";
static const char ka[] = "ghijklmnopqrstuvwxyz0123456789ab", kb[] = "zyxwvutsrqponmlkjihgfedcba987654";
static const char *const urls[] = {
    "https://app.hive.com/api/v1/testcredentials?user_id=Ab7Cd9Ef2Gh5Jk6Lm&api_key=ghijklmnopqrstuvwxyz0123456789ab",
    "https://app.hive.com/api/v1/testcredentials?user_id=Ab7Cd9Ef2Gh5Jk6Lm&api_key=zyxwvutsrqponmlkjihgfedcba987654",
    "https://app.hive.com/api/v1/testcredentials?user_id=Zy8Xw6Vu4Ts2Rq0Pn&api_key=ghijklmnopqrstuvwxyz0123456789ab",
    "https://app.hive.com/api/v1/testcredentials?user_id=Zy8Xw6Vu4Ts2Rq0Pn&api_key=zyxwvutsrqponmlkjihgfedcba987654",
};
static size_t fail_size, fail_after, failed_allocations, fail_part_after, url_attempts;
static bool fail_agent, watch_captures;
static const char *first_id, *first_key, *last_url;
#define URL_SIZE (sizeof("https://app.hive.com/api/v1/testcredentials?user_id=") - 1 + 17 + sizeof("&api_key=") - 1 + 32 + 1)

/* Existing native resource boundaries, not replacement detector/HTTP helpers. */
void *malloc(size_t size)
{
    if (size == URL_SIZE) { ++url_attempts; last_url = NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (size == URL_SIZE) last_url = value;
    if (watch_captures && size == 18 && !first_id) first_id = value;
    if (watch_captures && size == 33 && !first_key) first_key = value;
    return value;
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *copy = malloc(n); if (copy) memcpy(copy, s, n); return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
static void watch(void)
{
    watch_captures = true; first_id = first_key = last_url = NULL;
}
static void unwatch(void)
{
    watch_captures = false; first_id = first_key = last_url = NULL;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(ida) == 17 && strlen(idb) == 17 && strlen(ka) == 32 && strlen(kb) == 32);
    CHECK(br_hive_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_hive_init(NULL, NULL) != 0);
    for (size_t at = 1; at <= 2; ++at) {
        fail_size = sizeof("(?i:hive)(?s:.){0,40}?"); fail_after = at;
        CHECK(br_hive_init(&d, &error) != 0 && !d && error && !fail_after);
        CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    }
    CHECK(br_hive_init(&d, &error) == 0 && d && !error);
    CHECK(br_hive_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 571 && d->version == 0 && !strcmp(d->name, "Hive") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Hive is a project management and collaboration tool. Hive API keys can be used to access and manage projects, tasks, and other data within a Hive workspace."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "hive"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *id, bool verified)
{
    test_key_result(r, 571, id, "key");
    CHECK(r->raw.len == 17 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 17);
}
static size_t pair(char *input, size_t size, const char *id, const char *key)
{
    int n = snprintf(input, size, "HiVe %s\nhIvE %s", id, key);
    CHECK(n > 0 && (size_t)n < size); return (size_t)n;
}
static void extract(const br_detector *d, const void *input, size_t len, const char *id)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = url_attempts; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (id ? 1u : 0u) && !http.calls && !http.releases && url_attempts == before);
    if (id) result(&out.items[0], id, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[1800]; size_t n = pair(input, sizeof(input), ida, ka); extract(d, input, n, ida);
    const char *bad_ids[] = {"Ab7Cd9Ef2Gh5Jk6L", "Ab7Cd9Ef2Gh5Jk6Lmn", "_Ab7Cd9Ef2Gh5Jk6Lm", "Ab7Cd9Ef2Gh5Jk6Lm_", "Ab7Cd9Ef2Gh5Jk6L-"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); ++i) {
        n = pair(input, sizeof(input), bad_ids[i], ka); extract(d, input, n, NULL);
    }
    char changed[34]; memcpy(changed, ka, sizeof(ka)); changed[0] = 'G';
    n = pair(input, sizeof(input), ida, changed); extract(d, input, n, NULL);
    memcpy(changed, ka, sizeof(ka)); changed[31] = '\0'; n = pair(input, sizeof(input), ida, changed); extract(d, input, n, NULL);
    snprintf(changed, sizeof(changed), "%s_", ka); n = pair(input, sizeof(input), ida, changed); extract(d, input, n, NULL);
    snprintf(changed, sizeof(changed), "_%s", ka); n = pair(input, sizeof(input), ida, changed); extract(d, input, n, NULL);
    snprintf(changed, sizeof(changed), "%sa", ka); n = pair(input, sizeof(input), ida, changed); extract(d, input, n, NULL);
    n = pair(input, sizeof(input), "AAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); extract(d, input, n, "AAAAAAAAAAAAAAAAA");
    n = (size_t)snprintf(input, sizeof(input), "hive %s", ida); extract(d, input, n, NULL);
    n = (size_t)snprintf(input, sizeof(input), "hive %s", ka); extract(d, input, n, NULL);
    n = (size_t)snprintf(input, sizeof(input), "%s %s", ida, ka); extract(d, input, n, NULL);
    n = (size_t)snprintf(input, sizeof(input), "archive %s %s", ida, ka); extract(d, input, n, ida); /* No keyword word boundary. */
    n = (size_t)snprintf(input, sizeof(input), "hive %s %s", ka, ida); extract(d, input, n, ida);
    n = (size_t)snprintf(input, sizeof(input), "hive %s %s\nhive %s %s", ida, idb, ka, kb);
    extract(d, input, n, ida); /* FindAll consumes whole prefix+capture; cannot reuse that prefix. */
    n = (size_t)snprintf(input, sizeof(input), "hive\r\n-%s-\nhive\n\r%s", ida, ka); extract(d, input, n, ida);
    n = (size_t)snprintf(input, sizeof(input), "hive 💡%s💡\nhive %s", ida, ka); extract(d, input, n, ida);
    for (size_t side = 0; side < 2; ++side) {
        const char *first = side ? ka : ida, *second = side ? ida : ka;
        for (size_t gap = 40; gap <= 41; ++gap) {
            memcpy(input, "hive", 4); memset(input + 4, ':', gap); n = 4 + gap;
            memcpy(input + n, first, strlen(first)); n += strlen(first); memset(input + n, '!', 100); n += 100;
            n += (size_t)snprintf(input + n, sizeof(input) - n, "hive %s", second);
            extract(d, input, n, gap == 40 ? ida : NULL);
            memcpy(input, "hive", 4); for (size_t i = 0; i < gap; ++i) memcpy(input + 4 + 4 * i, "💡", 4);
            n = 4 + 4 * gap; memcpy(input + n, first, strlen(first)); n += strlen(first);
            memset(input + n, '!', 100); n += 100; n += (size_t)snprintf(input + n, sizeof(input) - n, "hive %s", second);
            extract(d, input, n, gap == 40 ? ida : NULL);
        }
    }
    memcpy(input, "hive\0", 5); memcpy(input + 5, ida, 17); n = 22;
    n += (size_t)snprintf(input + n, sizeof(input) - n, "\nhive %s", ka); extract(d, input, n, ida);
    n = (size_t)snprintf(input, sizeof(input), "hive %s", ida); memset(input + n, '!', 1200); n += 1200;
    n += (size_t)snprintf(input + n, sizeof(input) - n, "hive %s", ka); extract(d, input, n, ida); /* Span is an engine hint, not a local cap. */
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *urls;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_url;
} expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !e->borrowed_url);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 571);
    CHECK(!strcmp(request->method, "GET") && request->url == last_url && !strcmp(request->url, e->urls[at]));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, e->agent));
    e->borrowed_url = request->url; /* Never retain synthesized request/headers/UA. */
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    CHECK(last_url && !strcmp(last_url, e->urls[http->calls ? http->calls - 1 : 0]));
    if (e->borrowed_url) CHECK(e->borrowed_url == last_url);
    else CHECK(!http->calls && !response->status && !response->body.data && !response->body.len && !response->body_error);
    CHECK(first_id && !memcmp(first_id, ida, sizeof(ida)) && first_key && !memcmp(first_key, ka, sizeof(ka)));
    e->borrowed_url = NULL; test_http_release(user, response);
}
static void occurrences_and_requests(const br_detector *d)
{
    char input[400]; int n = snprintf(input, sizeof(input), "hive %s\nhive %s\nhive %s\nhive %s\nhive %s\nhive %s", ida, idb, ida, ka, kb, ka);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *order[] = {urls[0], urls[1], urls[0], urls[2], urls[3], urls[2], urls[0], urls[1], urls[0]};
    expected e = {.urls = order, .count = 9, .agent = "TruffleHog hive-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "hive-offline"}; e.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        watch(); size_t before = url_attempts; br_results out = test_scan(d, &ctx, pass != 0, input, (size_t)n);
        CHECK(out.len == 9 && http.calls == (pass ? 9u : 0u) && http.releases == http.calls && url_attempts == before + (pass ? 9u : 0u));
        for (size_t i = 0; i < 9; ++i) result(&out.items[i], i / 3 == 1 ? idb : ida, pass != 0);
        CHECK(out.items[0].raw.data != out.items[6].raw.data && out.items[0].secret_parts != out.items[6].secret_parts);
        br_results_clear(&out); unwatch();
    }
    size_t len = pair(input, sizeof(input), ida, ka), before = url_attempts;
    br_results out = test_scan(d, NULL, true, input, len); CHECK(!out.len && url_attempts == before + 1); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, len); CHECK(out.len == 1 && url_attempts == before + 1); result(&out.items[0], ida, false); br_results_clear(&out); unwatch();
}
static bool arm_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification_outcomes(const br_detector *d)
{
    char input[100]; size_t len = pair(input, sizeof(input), ida, ka);
    expected e = {.urls = urls, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "ignored" : ""};
        watch(); br_results out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result(&out.items[0], ida, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out); unwatch();
    }
    const struct { int rc; const char *cause; } failures[] = {
        {7, "timeout"}, {-7, "cannot create Hive result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, ka}, {7, ""},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        watch(); br_results out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result(&out.items[0], ida, false); br_results_clear(&out); unwatch();
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = arm_headers}, {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; size_t before = failed_allocations;
        watch(); br_results out = test_scan(d, &contexts[i], true, input, len);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !e.borrowed_url);
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
        result(&out.items[0], ida, false); br_results_clear(&out); unwatch();
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5) && !strcmp(prior->verification_error, "caller-owned"));
}
static void owned_failures_and_rollback(const br_detector *d)
{
    char input[200]; size_t len = pair(input, sizeof(input), ida, ka);
    len += (size_t)snprintf(input + len, sizeof(input) - len, "\nhive %s", kb);
    expected e = {.urls = urls, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 18; fail_after = 1; } /* ID capture. */
        if (failure == 1) { fail_size = 33; fail_after = 2; } /* Second hidden key capture, before any send. */
        if (failure == 2) { fail_size = 17; fail_after = 2; } /* Second finding Raw. */
        if (failure == 3) fail_part_after = 2; /* Positive JSON insertion failure. */
        if (failure == 4) { fail_size = URL_SIZE; fail_after = 2; } /* Second full URL. */
        watch(); CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !e.borrowed_url);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0; unwatch();
    }
    /* Finding and URL allocation failures precede nil-context ordinary DROP. */
    fail_size = 17; fail_after = 1; size_t before = url_attempts;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, len}, &out, &error) != 0 && error && !fail_after && url_attempts == before);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_size = URL_SIZE; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, len}, &out, &error) != 0 && error && !fail_after && url_attempts == before + 1);
    CHECK(!strcmp(error, "cannot allocate Hive URL")); check_prior(&out, &prior); free(error); error = NULL;
    /* NoV never enters URL assembly, even with that allocation armed. */
    fail_after = 1; br_results nov = test_scan(d, NULL, false, input, len);
    CHECK(nov.len == 2 && fail_after == 1 && url_attempts == before + 1); fail_after = 0; br_results_clear(&nov);
    /* Push failure is fatal after success AND after suppressed Do failure. */
    for (size_t pass = 0; pass < 2; ++pass) {
        http.send_rc = pass ? 7 : 0; http.send_error = pass ? "cannot allocate Hive URL" : NULL;
        size_t cap = out.cap; out.cap = 0; watch();
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, &error) != 0 && error && !strcmp(error, "cannot append Hive result"));
        out.cap = cap; CHECK(http.calls == 1 && http.releases == 1 && !e.borrowed_url); check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0; unwatch();
    }
    br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); occurrences_and_requests(d);
    verification_outcomes(d); owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !watch_captures && !first_id && !first_key && !last_url);
    return test_finish("Hive");
}
