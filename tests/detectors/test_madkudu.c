/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Main owns the shared factory declaration and registry integration. */
int br_madkudu_init(const br_detector **out, char **error);

#define br_result_set_verification_error madkudu_real_setter
#define br_results_push madkudu_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push
#define br_finding_key_bytes madkudu_real_finding
#include "../../src/detectors/findings.c"
#undef br_finding_key_bytes

static const char key[] = "0123456789abcdef0123456789abcdef";
static const char other[] = "fedcba9876543210fedcba9876543210";
static const char *const auth_values[] = {
    "Basic MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY6",
    "Basic ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA6",
};
static size_t fail_size, fail_after, failed_allocations, basic_allocations;
static size_t fail_finding_after, fail_part_after, fail_push_after, setter_calls;
static bool track_basic, fail_agent;

/* Reuse the named-detector allocation seam with the real Basic encoder:
 * KEY32 + ':' is 33 bytes, 44 Base64 bytes, then "Basic " and NUL, total 51. */
void *malloc(size_t size)
{
    if (track_basic && size == 51) ++basic_allocations;
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
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_finding_key_bytes(br_result *result, int32_t type, br_slice value, const char *part)
{
    int rc = madkudu_real_finding(result, type, value, part);
    if (rc == 0 && fail_finding_after && --fail_finding_after == 0) return 1;
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return madkudu_real_push(out, owned);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return madkudu_real_setter(r, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_madkudu_init(NULL, &error) == -1 && error && !strcmp(error, "invalid MadKudu detector output"));
    free(error); error = NULL;
    CHECK(br_madkudu_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:madkudu)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_madkudu_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_madkudu_init(&d, &error) == 0 && d && !error);
    CHECK(br_madkudu_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 715 && d->version == 0 && !strcmp(d->name, "MadKudu") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "MadKudu is a predictive lead scoring service that helps B2B companies identify the best-fit leads based on data. MadKudu API keys can be used to access and manipulate lead scoring data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "madkudu"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 715, expected, "key");
    CHECK(r->verified == verified && !r->verification_error);
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
    char input[256], changed[34];
    const char *good[] = {"madkudu '%s'", "MaDkUdU=-%s-", "prefixMADKUDUsuffix\r\n%s", "madkudu\r%s", "madkudu\n%s", "madkudu \t%s\t ", "madkudu é%sé"};
    const char *bad[] = {"%s", "mad kudu %s", "%s madkudu", "madkudu%s", "madkudu _%s", "madkudu %s_", "madkudu %sa", "madkudu %.31s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extract_case(d, input, strlen(input), key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = "Ag_- /";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "madkudu %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, '0', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "madkudu %s", changed); extract_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "madkudu", 7); memset(input + 7, ':', gap); memcpy(input + 7 + gap, key, 32);
        extract_case(d, input, 39 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 7 + 4 * i, "💡", 4);
        memcpy(input + 7 + 4 * gap, key, 32);
        extract_case(d, input, 39 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "madkudu\0", 8); memcpy(input + 8, key, 32); extract_case(d, input, 40, key);
    snprintf(input, sizeof(input), "madkudu %s %s", key, other); extract_case(d, input, strlen(input), key);
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *keys[3], *agent;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth, *borrowed_url;
    char saved_auth[51];
    bool arm_raw_failure;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && at < 3 && ctx == s->ctx && http->releases == at && !s->borrowed_auth);
    CHECK(request->detector_type == 715 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.madkudu.com/v1/ping"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->agent));
    const char *auth = request->headers[0].value;
    CHECK(auth && strlen(auth) == 50 && !strchr(auth + 6, '='));
    CHECK(!strcmp(auth, auth_values[!strcmp(s->keys[at], key) ? 0 : 1]));
    /* Borrow only provider-original values, not synthesized headers or UA. */
    s->borrowed_auth = auth; s->borrowed_url = request->url;
    memcpy(s->saved_auth, auth, sizeof(s->saved_auth));
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(http->calls == http->releases + 1);
        CHECK(!memcmp(s->borrowed_auth, s->saved_auth, sizeof(s->saved_auth)));
        CHECK(!strcmp(s->borrowed_url, "https://api.madkudu.com/v1/ping"));
        s->borrowed_auth = s->borrowed_url = NULL;
        if (s->arm_raw_failure) { fail_size = 32; fail_after = 1; s->arm_raw_failure = false; }
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void occurrences_and_constructor_order(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "madkudu %s\nmadkudu %s\nmadkudu %s", key, other, key);
    script s = {.keys = {key, other, key}, .count = 3, .agent = "TruffleHog madkudu-offline"};
    test_http http = {.inspect = inspect, .user = &s, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "madkudu-offline"}; s.ctx = &ctx;
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
    fail_size = 51; fail_after = 1;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && basic_allocations == before && fail_after == 1); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && basic_allocations == before && fail_after == 1);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], s.keys[i], false);
    br_results_clear(&out); fail_after = 0;
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void verification_and_shared_errors(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "madkudu %s", key);
    script s = {.keys = {key}, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &s};
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
        {1, "out of memory constructing Basic authentication"}, {-1, "cannot create MadKudu finding"},
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
        br_results out = test_scan(d, &contexts[i], false, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && !http.releases); result_is(&out.items[0], key, false); br_results_clear(&out);
        out = test_scan(d, &contexts[i], true, input, strlen(input));
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
    char input[128]; snprintf(input, sizeof(input), "madkudu %s\nmadkudu %s", key, other);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    script s = {.keys = {key, other}, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &s, .send_rc = -7, .send_error = "synthetic Do failure", .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    char *error = NULL;
    const struct { const char *cause; size_t calls; } cases[] = {
        {"out of memory copying detector capture", 0}, {"out of memory iterating regex", 0},
        {"cannot create MadKudu finding", 0}, {"cannot create MadKudu finding", 1},
        {"out of memory constructing Basic authentication", 1}, {"cannot append MadKudu finding", 2},
        {"cannot create MadKudu finding", 1}, {"cannot create MadKudu finding", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        http.calls = http.releases = 0;
        if (i == 0) { fail_size = 33; fail_after = 2; }
        if (i == 1) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (i == 2) fail_finding_after = 1;
        if (i == 3) fail_finding_after = 2;
        if (i == 4) { fail_size = 51; fail_after = 2; }
        if (i == 5) fail_push_after = 2;
        if (i == 6) s.arm_raw_failure = true;
        if (i == 7) fail_part_after = 2;
        if (i == 5) { http.send_rc = 0; http.send_error = NULL; }
        else { http.send_rc = -7; http.send_error = "synthetic Do failure"; }
        size_t before = basic_allocations;
        const br_scan_ctx *scan_ctx = i <= 2 ? NULL : &ctx;
        CHECK(d->scan(d, scan_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].cause)); free(error); error = NULL;
        CHECK(!fail_after && !fail_finding_after && !fail_part_after && !fail_push_after && !s.arm_raw_failure);
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !s.borrowed_auth && !s.borrowed_url);
        CHECK(basic_allocations == before + (i == 4 ? 2u : cases[i].calls));
        prior_unchanged(&out, &prior);
    }
    fail_finding_after = 2;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && !fail_finding_after);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error);
    free(error); error = NULL; prior_unchanged(&out, &prior);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error);
    free(error); prior_unchanged(&out, &prior);
    CHECK(!setter_calls);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor(); track_basic = true;
    extraction(d);
    occurrences_and_constructor_order(d);
    verification_and_shared_errors(d);
    owned_failures_and_rollback(d);
    CHECK(!setter_calls && !fail_after && !fail_finding_after && !fail_part_after && !fail_push_after && !fail_agent);
    return test_finish("MadKudu");
}
