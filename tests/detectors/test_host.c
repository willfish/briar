/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char ka[] = "ghijklmnopq123", kb[] = "zyxwvutsrq9876";
static const char *const urls[] = {
    "https://host.io/api/domains/ip/8.8.8.8?token=ghijklmnopq123",
    "https://host.io/api/domains/ip/8.8.8.8?token=zyxwvutsrq9876",
};
#define URL_SIZE (sizeof("https://host.io/api/domains/ip/8.8.8.8?token=") + 14)
static size_t fail_size, fail_after, failed_allocations, fail_part_after, url_attempts;
static int part_failure;
static bool fail_agent, watch_captures;
static const char *first_capture, *last_url;

/* Reuse the existing native allocation/JSON boundaries, not replacement
 * detector or transport helpers. Only explicitly armed operations fail. */
void *malloc(size_t size)
{
    if (size == URL_SIZE) { ++url_attempts; last_url = NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (size == URL_SIZE) last_url = value;
    if (watch_captures && size == 15 && !first_capture) first_capture = value;
    return value;
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *copy = malloc(n); if (copy) memcpy(copy, s, n); return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return part_failure;
    return json_object_object_add_ex(object, name, value, 0);
}
static void watch(void) { watch_captures = true; first_capture = last_url = NULL; }
static void unwatch(void) { watch_captures = false; first_capture = last_url = NULL; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(ka) == 14 && strlen(kb) == 14);
    CHECK(br_host_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_host_init(NULL, NULL) != 0);
    fail_size = sizeof("(?i:host)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_host_init(&d, &error) != 0 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_host_init(&d, &error) == 0 && d && !error);
    CHECK(br_host_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 556 && d->version == 0 && !strcmp(d->name, "Host") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Host.io provides domain data and related services. Host.io tokens can be used to access and manage domain information."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "host.io")); /* Literal dispatch keyword, not a regex. */
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 556, key, "key");
    CHECK(r->raw.len == 14 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 14);
}
static void extract(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = url_attempts; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases && url_attempts == before);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[300]; int n = snprintf(input, sizeof(input), "HoSt [%s]", ka);
    CHECK(n > 0 && (size_t)n < sizeof(input)); extract(d, input, (size_t)n, ka);
    const char *bad[] = {
        "ghijklmnopq12", "ghijklmnopq1234", "Ghijklmnopq123", "ABCDEFGHIJKLMN",
        "_ghijklmnopq123", "ghijklmnopq123_", "ghijklmnopq12-3",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        n = snprintf(input, sizeof(input), "host %s", bad[i]); CHECK(n > 0 && (size_t)n < sizeof(input));
        extract(d, input, (size_t)n, NULL);
    }
    const char *unfiltered[] = {"aaaaaaaaaaaaaa", "00000000000000", "abcdefghijklmn", "zzzzzzzzzzzzzz"};
    for (size_t i = 0; i < sizeof(unfiltered) / sizeof(unfiltered[0]); ++i) {
        n = snprintf(input, sizeof(input), "host %s", unfiltered[i]); CHECK(n > 0 && (size_t)n < sizeof(input));
        extract(d, input, (size_t)n, unfiltered[i]);
    }
    const char *prefixes[] = {"host.io ", "HOST.IO ", "ghost ", "hostXio ", "host\r\n", "host-"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        n = snprintf(input, sizeof(input), "%s%s", prefixes[i], ka); CHECK(n > 0 && (size_t)n < sizeof(input));
        extract(d, input, (size_t)n, ka); /* Direct extraction is broader than dispatch. */
    }
    n = snprintf(input, sizeof(input), "host%s", ka); CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    extract(d, ka, strlen(ka), NULL);
    n = snprintf(input, sizeof(input), "host %s %s", ka, kb); CHECK(n > 0);
    extract(d, input, (size_t)n, ka); /* FindAll consumes prefix+capture; it cannot reuse that prefix. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "host", 4); memset(input + 4, ':', gap); memcpy(input + 4 + gap, ka, 14);
        extract(d, input, 4 + gap + 14, gap == 40 ? ka : NULL);
        memcpy(input, "host", 4);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 4 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 4 + 4 * gap, ka, 14);
        extract(d, input, 4 + 4 * gap + 14, gap == 40 ? ka : NULL);
    }
    for (size_t gap = 37; gap <= 38; ++gap) {
        memcpy(input, "host.io", 7); memset(input + 7, ':', gap); memcpy(input + 7 + gap, ka, 14);
        extract(d, input, 7 + gap + 14, gap == 37 ? ka : NULL); /* .io consumes three of forty. */
    }
    memcpy(input, "host\0", 5); memcpy(input + 5, ka, 14); extract(d, input, 19, ka);
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
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 556);
    CHECK(!strcmp(request->method, "GET") && request->url == last_url && !strcmp(request->url, e->urls[at]));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, e->agent));
    e->borrowed_url = request->url; /* Keep only the provider-original URL, never prepared storage. */
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    CHECK(last_url && !strcmp(last_url, e->urls[http->calls ? http->calls - 1 : 0]));
    if (e->borrowed_url) CHECK(e->borrowed_url == last_url);
    else CHECK(!http->calls && !response->status && !response->body.data && !response->body.len && !response->body_error);
    CHECK(first_capture && !memcmp(first_capture, ka, sizeof(ka)));
    e->borrowed_url = NULL; test_http_release(user, response);
}
static void occurrences_and_nil(const br_detector *d)
{
    char input[120]; int n = snprintf(input, sizeof(input), "host.io %s\nhost %s\nhost %s", ka, kb, ka);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *order[] = {urls[0], urls[1], urls[0]};
    expected e = {.urls = order, .count = 3, .agent = "TruffleHog host-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "host-offline"}; e.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        watch(); size_t before = url_attempts; br_results out = test_scan(d, &ctx, pass != 0, input, (size_t)n);
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls && url_attempts == before + (pass ? 3u : 0u));
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], i == 1 ? kb : ka, pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out); unwatch();
    }
    size_t before = url_attempts;
    br_results out = test_scan(d, NULL, true, input, (size_t)n); CHECK(!out.len && url_attempts == before + 3); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, (size_t)n); CHECK(out.len == 3 && url_attempts == before + 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], i == 1 ? kb : ka, false);
    br_results_clear(&out); unwatch();
}
static bool arm_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification_outcomes(const br_detector *d)
{
    char input[40]; int n = snprintf(input, sizeof(input), "host %s", ka); CHECK(n > 0 && (size_t)n < sizeof(input));
    expected e = {.urls = urls, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "" : "ignored read error"};
        watch(); br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result(&out.items[0], ka, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out); unwatch();
    }
    const struct { int rc; const char *cause; } failures[] = {
        {7, "timeout"}, {-7, "cannot create Host result"}, {1, "out of memory constructing HTTP headers"},
        {-1, NULL}, {1, ka}, {7, ""}, {-1, "cannot allocate Host URL"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        watch(); br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result(&out.items[0], ka, false); br_results_clear(&out); unwatch();
    }
    size_t cancellations = 0;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_send}, {.transport = &transport, .cancelled = arm_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; size_t before = failed_allocations;
        watch(); br_results out = test_scan(d, &contexts[i], true, input, (size_t)n);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !e.borrowed_url);
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 2 || i == 3 ? 1u : 0u));
        result(&out.items[0], ka, false); br_results_clear(&out); unwatch();
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
    char input[80]; int n = snprintf(input, sizeof(input), "host %s\nhost %s", ka, kb); CHECK(n > 0 && (size_t)n < sizeof(input));
    expected e = {.urls = urls, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 15; fail_after = 2; } /* Collect all captures before I/O. */
        if (failure == 1) { fail_size = 14; fail_after = 2; } /* Second finding Raw. */
        if (failure == 2 || failure == 3) { fail_part_after = 2; part_failure = failure == 2 ? 7 : -7; }
        if (failure == 4) { fail_size = URL_SIZE; fail_after = 2; }
        watch(); CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure ? 1u : 0u) && http.releases == http.calls && !e.borrowed_url);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0; unwatch();
    }
    /* Finding and full URL failures remain fatal before nil-constructor DROP. */
    fail_size = 14; fail_after = 1; size_t before = url_attempts;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) != 0 && error && !fail_after && url_attempts == before);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_size = URL_SIZE; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) != 0 && error && !fail_after && url_attempts == before + 1);
    CHECK(!strcmp(error, "cannot allocate Host URL")); check_prior(&out, &prior); free(error); error = NULL;
    fail_after = 1; br_results nov = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(nov.len == 2 && fail_after == 1 && url_attempts == before + 1); fail_after = 0; br_results_clear(&nov);
    /* Push is fatal in NoV, after success and after suppressed Do failure. */
    for (size_t pass = 0; pass < 3; ++pass) {
        http.send_rc = pass == 2 ? 7 : 0; http.send_error = pass == 2 ? "cannot append Host result" : NULL;
        size_t cap = out.cap; out.cap = 0; watch();
        CHECK(d->scan(d, &ctx, pass != 0, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) != 0 && error && !strcmp(error, "cannot append Host result"));
        out.cap = cap; CHECK(http.calls == (pass ? 1u : 0u) && http.releases == http.calls && !e.borrowed_url); check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0; unwatch();
    }
    br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); occurrences_and_nil(d);
    verification_outcomes(d); owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !watch_captures && !first_capture && !last_url);
    return test_finish("Host");
}
