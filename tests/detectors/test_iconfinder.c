/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Observe ordinary attempts/releases while retaining the real shared setup. */
#define br_http_send iconfinder_real_send
#define br_http_release iconfinder_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

/* Exercise the real result-vector growth failure after an earlier append. */
static bool fail_growth;
static void *iconfinder_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc iconfinder_realloc
#include "../../src/result.c"
#undef realloc

static char key1[65], key2[65];
static size_t fail_size, fail_after, fail_part_after, sends, releases;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_context;
static const char *const *expected_keys;
static const char *expected_agent;
static size_t expected_count;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static void check_request(const br_http_request *r, const char *key, bool effective)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.iconfinder.com/v4/iconsets"));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 487);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Authorization"));
    CHECK(strlen(r->headers[0].value) == 71 && !memcmp(r->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(r->headers[0].value + 7, key, 65));
    if (effective) {
        CHECK(!strcmp(r->headers[1].name, "User-Agent"));
        CHECK(!strcmp(r->headers[1].value, expected_agent));
    }
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r,
                 br_http_response *response, char **error)
{
    CHECK(!provider_request && sends == releases && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    provider_request = r; provider_context = ctx; ++sends;
    return iconfinder_real_send(ctx, r, response, error);
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_context && sends == releases + 1);
    /* Only the original provider request/auth are borrowed. Synthesized
     * effective request/header-array/UA storage is never retained here. */
    check_request(provider_request, expected_keys[releases], false);
    iconfinder_real_release(ctx, response);
    check_request(provider_request, expected_keys[releases], false);
    provider_request = NULL; provider_context = NULL; ++releases;
}

static void expect(const char *const *keys, size_t count, const char *agent)
{
    CHECK(!provider_request && !provider_context && sends == releases);
    expected_keys = keys; expected_count = count; expected_agent = agent;
    sends = releases = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    CHECK(provider_request && ctx == provider_context && http->calls == sends);
    CHECK(http->releases == releases && sends <= expected_count);
    check_request(r, expected_keys[sends - 1], true);
    CHECK(r->headers[0].value == provider_request->headers[0].value);
}

static void result_is(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 487, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_iconfinder_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_iconfinder_init(NULL, NULL) != 0);
    CHECK(!br_iconfinder_init(&d, &error) && d && !error);
    CHECK(!br_iconfinder_init(&again, NULL) && again == d);
    CHECK(d->type == 487 && !d->version && !strcmp(d->name, "IconFinder"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "IconFinder is a platform that provides a large collection of icons. IconFinder API keys can be used to access and retrieve icons from the platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "iconfinder"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default/native integration belongs to the parent. */
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {.inspect = inspect}; br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t}; expect(NULL, 0, NULL);
    br_results r = test_scan(d, &ctx, false, input, len);
    CHECK(r.len == (key ? 1u : 0u) && !sends && !releases && !http.calls && !http.releases);
    if (key) result_is(&r.items[0], key, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[65];
    const struct { const char *format; bool match; } cases[] = {
        {"iconfinder '%s'", true}, {"IcOnFiNdEr:%s", true}, {"preiconfindersuffix:%s", true},
        {"iconfinder\r\n%s", true}, {"iconfinder\r%s", true}, {"iconfinder\n%s", true},
        {"%s", false}, {"%s iconfinder", false}, {"icon finder %s", false},
        {"iconfinder%s", false}, {"iconfinder x%s", false}, {"iconfinder _%s", false},
        {"iconfinder %s_", false}, {"iconfinder %s9", false}, {"iconfinder %.63s", false},
        {"iconfinder -%s", true}, {"iconfinder %s-", true}, {"iconfinder %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1, key2);
        extract_case(d, input, strlen(input), cases[i].match ? key1 : NULL);
    }
    const char invalid[] = "_-=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[12] = invalid[i];
        snprintf(input, sizeof(input), "iconfinder %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "Aa0"; /* No provider-local randomness/FP filtering. */
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 64); changed[64] = '\0';
        snprintf(input, sizeof(input), "iconfinder %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "iconfinder", 10); memset(input + 10, '.', gap);
        memcpy(input + 10 + gap, key1, 64);
        extract_case(d, input, 74 + gap, gap == 40 ? key1 : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 10 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 10 + 2 * gap, key1, 64);
        extract_case(d, input, 74 + 2 * gap, gap == 40 ? key1 : NULL);
    }
    int n = snprintf(input, sizeof(input), "iconfinder%c%s", 0, key1);
    extract_case(d, input, (size_t)n, key1); extract_case(d, NULL, 0, NULL);
}

static void occurrences(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "iconfinder %s\nICONFINDER %s\niconfinder %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.inspect = inspect, .response = {.status = 204, .body_error = "ignored"}};
    br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t, .user_agent = "iconfinder-offline"};
    expect(NULL, 0, NULL);
    br_results r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts);
    br_results_clear(&r);
    expect(keys, 3, "TruffleHog iconfinder-offline");
    r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 3 && sends == 3 && releases == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], true);
    br_results_clear(&r);
    expect(NULL, 0, NULL);
    r = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!r.len && !sends && !releases); br_results_clear(&r);
    r = test_scan(d, NULL, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    br_results_clear(&r);
}

static void verification(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "iconfinder %s", key1);
    const char *keys[] = {key1};
    test_http http = {.inspect = inspect}; br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t};
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '!', '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i == 4 ? "" : i % 2 ? "ignored read failure" : NULL};
        expect(keys, 1, "TruffleHog");
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], key1, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&r);
    }
    const struct { int rc; const char *message; } failures[] = {
        {1, "context canceled"}, {-7, "cannot create IconFinder result"},
        {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {7, key1},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].message;
        http.response = i ? (br_http_response){.status = 200} : (br_http_response){0};
        expect(keys, 1, "TruffleHog");
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], key1, false); br_results_clear(&r);
    }
}

static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void shared_setup(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "iconfinder %s", key1);
    const char *keys[] = {key1}; size_t calls = 0;
    test_http http = {.inspect = inspect}; br_transport t = test_transport(&http);
    br_scan_ctx contexts[] = {
        {0}, {.transport = &t, .cancelled = fail_headers},
        {.transport = &t, .cancelled = cancelled, .cancel_user = &calls},
        {.transport = &t, .deadline_monotonic_ms = 1},
        {.transport = &t, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; expect(keys, 1, NULL);
        br_results r = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && !http.calls && !fail_after);
        CHECK(http.releases == (i ? 1u : 0u));
        result_is(&r.items[0], key1, false); br_results_clear(&r);
    }
    CHECK(calls == 1);
}

static void check_prior(const br_results *r, const br_result *prior)
{
    CHECK(r->len == 1 && r->items[0].raw.data == prior->raw.data && r->items[0].raw.len == 5);
    CHECK(r->items[0].secret_parts == prior->secret_parts && r->items[0].detector_type == 777);
    CHECK(r->items[0].verified && !memcmp(r->items[0].raw.data, "prior", 5));
    CHECK(r->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}

static void resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "iconfinder %s\niconfinder %s", key1, key2);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r = {0}; CHECK(!br_results_push(&r, &prior)); prior = r.items[0]; char *error = NULL;
    const char *keys[] = {key1, key2};
    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    const struct {
        size_t size, after, part, attempts;
        bool nil;
        int send_rc;
        const char *message;
    } failures[] = {
        {64, 1, 0, 0, false, 0, "out of memory collecting detector captures"},
        {65, 2, 0, 0, true, 0, "out of memory copying detector capture"},
        /* Two capture arrays allocate 64 bytes before the findings' Raw. */
        {64, 3, 0, 0, true, 0, "cannot create IconFinder result"},
        {64, 4, 0, 1, false, 0, "cannot create IconFinder result"},
        {0, 0, 1, 0, true, 0, "cannot create IconFinder result"},
        {0, 0, 2, 1, false, 0, "cannot create IconFinder result"},
        {0, 0, 2, 1, false, 7, "cannot create IconFinder result"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        fail_size = failures[i].size; fail_after = failures[i].after; fail_part_after = failures[i].part;
        http.calls = http.releases = 0; http.send_rc = failures[i].send_rc;
        http.send_error = failures[i].send_rc ? "cannot create IconFinder result" : NULL;
        expect(keys, 2, "TruffleHog");
        CHECK(d->scan(d, failures[i].nil ? NULL : &ctx, true, text(input), &r, &error) != 0);
        CHECK(error && !strcmp(error, failures[i].message) && !fail_after && !fail_part_after);
        CHECK(sends == failures[i].attempts && releases == sends && http.calls == sends && http.releases == sends);
        check_prior(&r, &prior); free(error); error = NULL;
    }
    size_t cap = r.cap; r.cap = 2; fail_growth = true;
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL;
    expect(keys, 2, "TruffleHog");
    CHECK(d->scan(d, &ctx, true, text(input), &r, &error) != 0 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append IconFinder result") && sends == 2 && releases == 2);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&r, &prior);
    r.cap = cap; free(error); error = NULL;
    r.cap = 0; expect(NULL, 0, NULL); /* Actual positive push-validation failure. */
    CHECK(d->scan(d, NULL, false, text(input), &r, &error) != 0 && error);
    CHECK(!strcmp(error, "cannot append IconFinder result") && !sends && !releases);
    r.cap = cap; check_prior(&r, &prior); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
}

int main(void)
{
    test_secret(key1, 64, 0); key1[13] = 'Q'; test_secret(key2, 64, 7); key2[18] = 'Z';
    const br_detector *d = descriptor();
    extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !provider_request && !provider_context);
    return test_finish("IconFinder grammar/prefix/boundaries/duplicates/metadata/nil/request/status/ignored-body/send/setup/resources/rollback");
}
