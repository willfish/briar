/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

#define br_result_set_verification_error insightly_real_setter
#define br_results_push insightly_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

static const char key[] = "g1h2j3k4-m5n6-p7q8-r9s0-t1u2v3w4x5y6";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7k6j5h4g3f2";
/* Independent standard Base64 goldens for the complete 37-byte KEY + ':'. */
static const char *const goldens[] = {
    "Basic ZzFoMmozazQtbTVuNi1wN3E4LXI5czAtdDF1MnYzdzR4NXk2Og==",
    "Basic ejl5OHg3dzZ2NXU0dDNzMnIxcTBwOW44bTdrNmo1aDRnM2YyOg==",
};
static size_t fail_size, fail_after, fail_key_after, fail_push_after;
static size_t failed_allocations, basic_allocations, setter_calls;
static bool track_basic, fail_agent;

/* Reuse the existing named-test allocation seam with the real Basic helper.
 * Failure of its 59-byte allocation returns +1, not a replacement encoder. */
void *malloc(size_t size)
{
    if (track_basic && size == 59) ++basic_allocations;
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return insightly_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 7;
    return insightly_real_push(out, owned);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_insightly_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Insightly detector output")); free(error); error = NULL;
    CHECK(br_insightly_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:insightly)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_insightly_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_insightly_init(&d, &error) == 0 && d && !error);
    CHECK(br_insightly_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 271 && d->version == 0 && !strcmp(d->name, "Insightly") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Insightly is a customer relationship management (CRM) platform. Insightly API keys can be used to access and manage CRM data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "insightly"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 271, expected, "key");
    CHECK(r->raw.len == 36 && r->verified == verified && !r->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = basic_allocations;
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && basic_allocations == before);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[37];
    const char *good[] = {"insightly '%s'", "InSiGhTlY\r\n%s", "myINSIGHTLYsuffix:%s", "insightly-%s", "insightly %s-"};
    const char *bad[] = {"%s", "insight-ly %s", "insightly%s", "insightly %.35s", "insightly %sX", "insightly X%s", "insightly %s_", "insightly _%s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extract_case(d, input, strlen(input), key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(d, input, strlen(input), NULL);
    }
    const char disallowed[] = "A_+/. ";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[18] = disallowed[i];
        snprintf(input, sizeof(input), "insightly %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    /* Nonword hyphen edges need contextual word bytes, not UUID validation. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "insightly%s", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "insightly %s", changed); extract_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[35] = '-';
    snprintf(input, sizeof(input), "insightly %sX", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "insightly %s", changed); extract_case(d, input, strlen(input), NULL);
    memset(changed, '-', 36); changed[36] = '\0';
    snprintf(input, sizeof(input), "insightly%sX", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "insightly %s", changed); extract_case(d, input, strlen(input), NULL);
    memset(changed, 'z', 36);
    snprintf(input, sizeof(input), "insightly %s", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "insightly %sz", changed); extract_case(d, input, strlen(input), NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "insightly", 9); memset(input + 9, ':', gap); memcpy(input + 9 + gap, key, 36);
        extract_case(d, input, 9 + gap + 36, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 9 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 9 + 2 * gap, key, 36);
        extract_case(d, input, 9 + 2 * gap + 36, gap == 40 ? key : NULL);
    }
    memcpy(input, "insightly\0", 10); memcpy(input + 10, key, 36); extract_case(d, input, 46, key);
    extract_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "insightly %s %s", key, other); extract_case(d, input, strlen(input), key);
}

typedef struct {
    const char *keys[3], *agent;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth, *borrowed_url;
    char saved_auth[59];
    bool arm_raw_failure;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && at < 3 && ctx == s->ctx && http->releases == at && !s->borrowed_auth);
    CHECK(request->detector_type == 271 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.na1.insightly.com/v3.1/Contacts?top=2"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->agent));
    const char *auth = request->headers[0].value;
    CHECK(auth && strlen(auth) == 58 && !memcmp(auth, "Basic ", 6) && auth[56] == '=' && auth[57] == '=' && !auth[58]);
    unsigned char plain[39];
    CHECK(EVP_DecodeBlock(plain, (const unsigned char *)auth + 6, 52) == 39);
    CHECK(!memcmp(plain, s->keys[at], 36) && plain[36] == ':' && !plain[37] && !plain[38]);
    if (!strcmp(s->keys[at], key)) CHECK(!strcmp(auth, goldens[0]));
    if (!strcmp(s->keys[at], other)) CHECK(!strcmp(auth, goldens[1]));
    /* Retain provider originals only, never effective request/header/UA storage. */
    s->borrowed_auth = auth; s->borrowed_url = request->url;
    memcpy(s->saved_auth, auth, sizeof(s->saved_auth));
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(http->calls == http->releases + 1);
        CHECK(!memcmp(s->borrowed_auth, s->saved_auth, sizeof(s->saved_auth)));
        CHECK(!strcmp(s->borrowed_url, "https://api.na1.insightly.com/v3.1/Contacts?top=2"));
        s->borrowed_auth = s->borrowed_url = NULL;
        if (s->arm_raw_failure) { fail_size = 36; fail_after = 1; s->arm_raw_failure = false; }
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void occurrences_and_constructor_order(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "insightly %s\ninsightly %s\ninsightly %s", key, other, key);
    script s = {.keys = {key, other, key}, .agent = "TruffleHog insightly-offline", .count = 3};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "insightly-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        size_t before = basic_allocations;
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        CHECK(basic_allocations == before + (pass ? 3u : 0u));
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], s.keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    size_t before = basic_allocations;
    fail_size = 59; fail_after = 1;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && basic_allocations == before && fail_after == 1); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && basic_allocations == before && fail_after == 1); br_results_clear(&out); fail_after = 0;
    char edge[37]; memset(edge, '-', 36); edge[36] = '\0';
    snprintf(input, sizeof(input), "insightly%sX", edge);
    s.keys[0] = edge; s.count = 1; http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], edge, true); br_results_clear(&out);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void verification_and_shared_errors(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "insightly %s", key);
    script s = {.keys = {key}, .agent = "TruffleHog", .count = 1};
    test_http http = {.user = &s, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored partial read"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {1, "out of memory constructing Basic authentication"}, {-1, "cannot create Insightly finding"},
        {1, "out of memory constructing HTTP headers"}, {-1, key}, {1, ""}, {1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_transport missing_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i >= 5 ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !setter_calls && !s.borrowed_auth && !s.borrowed_url);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "insightly %s\ninsightly %s", key, other);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    script s = {.keys = {key, other}, .agent = "TruffleHog", .count = 2};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    char *error = NULL;
    const struct { const char *cause; size_t calls; } cases[] = {
        {"out of memory copying detector capture", 0}, {"out of memory iterating regex", 0},
        {"cannot create Insightly finding", 0}, {"cannot create Insightly finding", 1},
        {"out of memory constructing Basic authentication", 1}, {"cannot append Insightly finding", 2},
        {"cannot create Insightly finding", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        http.calls = http.releases = 0;
        if (i == 0) { fail_size = 37; fail_after = 2; }
        if (i == 1) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (i == 2) fail_key_after = 1;
        if (i == 3) fail_key_after = 2;
        if (i == 4) { fail_size = 59; fail_after = 2; }
        if (i == 5) fail_push_after = 2;
        if (i == 6) s.arm_raw_failure = true;
        size_t before = basic_allocations;
        /* Owned capture/finding failures precede even a nil-context drop. */
        const br_scan_ctx *scan_ctx = i <= 2 ? NULL : &ctx;
        CHECK(d->scan(d, scan_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].cause)); free(error); error = NULL;
        CHECK(!fail_after && !fail_key_after && !fail_push_after && !s.arm_raw_failure);
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !s.borrowed_auth && !s.borrowed_url);
        CHECK(basic_allocations == before + (i == 4 ? 2u : cases[i].calls));
        prior_unchanged(&out, &prior);
    }
    /* A later owned +1 Basic failure beats a retained ordinary Do failure. */
    http.calls = http.releases = 0; http.send_rc = 1; http.send_error = "cannot create Insightly finding";
    fail_size = 59; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication")); free(error);
    CHECK(!fail_after && http.calls == 1 && http.releases == 1); prior_unchanged(&out, &prior);
    http.calls = http.releases = 0; fail_size = 59; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1);
    CHECK(!fail_after && !http.calls && !http.releases); prior_unchanged(&out, &prior);
    fail_push_after = 2; error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Insightly finding") && !fail_push_after); free(error);
    CHECK(!http.calls && !http.releases); prior_unchanged(&out, &prior);
    br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
}

int main(void)
{
    const br_detector *d = descriptor();
    track_basic = true;
    extraction(d);
    occurrences_and_constructor_order(d);
    verification_and_shared_errors(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_key_after && !fail_push_after && !fail_agent && !setter_calls);
    return test_finish("Insightly grammar/occurrences/metadata/Basic/status/errors/release/rollback");
}
