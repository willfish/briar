/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "0123456789abcdefghijklmnopqrstuvwxyz0123";
static const char other[] = "zyxwvutsrqponmlkjihgfedcba9876543210zyxw";
static const char url_prefix[] = "https://www.humanity.com/api/v2/me?access_token=";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_agent;
static const char *borrowed_url, *expected_key;

/* Existing named-test allocation seam: distinguish provider-owned work from
 * shared request preparation, whose failures Humanity deliberately suppresses. */
void *malloc(size_t size)
{
    if (size == fail_size && fail_after && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, s, n);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other) == 40);
    CHECK(br_humanity_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Humanity detector output"));
    free(error);
    CHECK(br_humanity_init(NULL, NULL) == -1);
    CHECK(br_humanity_init(&d, &error) == 0 && d && !error);
    CHECK(br_humanity_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 508 && d->version == 0 && !strcmp(d->name, "Humanity") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Humanity is a workforce management platform. Humanity API keys can be used to access and manage workforce data and operations."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "humanity"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 508, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[300], changed[42];
    const char *formats[] = {"humanity '%s'", "HUMANITY=-%s-", "prefixHuMaNiTysuffix\r\n%s", "humanity\r%s", "humanity\n%s", "humanity \t%s\t "};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extract_case(d, input, strlen(input), key);
    }
    const char *missing[] = {"%s", "human ity %s", "%s humanity", "humanity%s", "humanity _%s", "humanity %s_", "humanity %sa"};
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key);
        extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = {'A', '_', '-', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = invalid[i];
        snprintf(input, sizeof(input), "humanity %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[39] = '\0';
    snprintf(input, sizeof(input), "humanity %s", changed);
    extract_case(d, input, strlen(input), NULL);
    memset(changed, 'z', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "humanity %s", changed);
    extract_case(d, input, strlen(input), changed); /* Not hex or entropy validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "humanity", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key, 40);
        extract_case(d, input, 48 + gap, gap == 40 ? key : NULL);
        memcpy(input, "humanity", 8);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "💡", 4);
        memcpy(input + 8 + 4 * gap, key, 40);
        extract_case(d, input, 48 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "humanity\0 ", 10); memcpy(input + 10, key, 40);
    extract_case(d, input, 50, key);
    snprintf(input, sizeof(input), "humanity %s %s", key, other);
    extract_case(d, input, strlen(input), key); /* A consumed prefix is not reused. */
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent;
    const br_http_response *responses;
} expected;

static void check_url(const char *url, const char *value)
{
    char full[sizeof(url_prefix) + 40];
    snprintf(full, sizeof(full), "%s%s", url_prefix, value);
    CHECK(url && !strcmp(url, full));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_url);
    CHECK(request->detector_type == 508 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    expected_key = e->keys[at];
    check_url(request->url, expected_key);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, e->agent));
    /* Only the provider-original URL is borrowed through release, not the
     * synthesized request, header array or User-Agent. */
    borrowed_url = request->url;
    if (e->responses) http->response = e->responses[at];
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_url) check_url(borrowed_url, expected_key);
    else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_url = expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences_and_constructor_order(const br_detector *d)
{
    char input[200];
    snprintf(input, sizeof(input), "humanity %s\nhumanity %s\nhumanity %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog humanity-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 500, .body = {(const unsigned char *)"name", 4}}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "humanity-offline"}; e.ctx = &ctx;
    for (int verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    const br_http_response responses[] = {
        {.status = 200, .body_error = ""},
        {.status = 403},
        {.status = 500, .body = {(const unsigned char *)"name", 4}},
    };
    e.responses = responses; http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 3 && http.releases == 3);
    check_result(&out.items[0], other, false); check_result(&out.items[1], key, true);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && http.calls == 3 && http.releases == 3);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void body_send_and_setup(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "humanity %s", key);
    const char *keys[] = {key};
    expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, 'n', 'a', 'm', 'e', 0};
    const struct { int status; br_slice body; const char *read_error; bool keep, verified; } cases[] = {
        {200, {(const unsigned char *)"name", 4}, NULL, true, true},
        {401, {(const unsigned char *)"name", 4}, NULL, true, true},
        {500, {binary, sizeof(binary)}, NULL, true, true},
        {204, {(const unsigned char *)"not JSON: renamed!", 18}, NULL, true, true},
        {302, {(const unsigned char *)"username", 8}, NULL, true, true},
        {200, {(const unsigned char *)"{\"Name\":\"NAME\"}", 15}, NULL, true, false},
        {500, {(const unsigned char *)"{\"n\\u0061me\":1}", 15}, NULL, true, false},
        {403, {0}, NULL, true, false},
        {200, {(const unsigned char *)"name", 4}, "", false, false},
        {500, {binary, sizeof(binary)}, "synthetic read failure", false, false},
        {401, {0}, "read failed", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == (cases[i].keep ? 1u : 0u) && http.calls == 1 && http.releases == 1);
        if (out.len) check_result(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Humanity result"},
        {1, "cannot construct Humanity URL"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {binary, sizeof(binary)}, .body_error = "ignored after Do error"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "humanity %s\nhumanity %s", key, other);
    const char *keys[] = {key, other};
    expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Positive regex/capture error. */
        if (failure == 1) { fail_size = 41; fail_after = 2; } /* Collect all captures before sending. */
        if (failure == 2) { fail_size = 40; fail_after = 2; } /* Second finding Raw. */
        if (failure == 3) fail_part_after = 2; /* Positive secret-part insertion error. */
        /* json-c's 40-byte string allocation has the same size as the URL:
         * string, URL, string, URL. Target assembly, not finding construction. */
        if (failure == 4) { fail_size = sizeof(url_prefix) + 40; fail_after = 4; }
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        if (failure == 4) CHECK(!strcmp(error, "cannot construct Humanity URL"));
        check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned failures beat the nil-constructor drop. */
    fail_size = sizeof(url_prefix) + 40; fail_after = 2;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot construct Humanity URL") && !fail_after);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot create Humanity result") && !fail_part_after);
    check_prior(&out, &prior); free(error); error = NULL;
    /* A positive push failure is fatal even after a successful marker check. */
    size_t cap = out.cap; out.cap = 0; http.send_rc = 0; http.send_error = NULL;
    http.response = (br_http_response){.status = 500, .body = {(const unsigned char *)"name", 4}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Humanity result") && http.calls == 1 && http.releases == 1);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 40; fail_after = 1;
    CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && !fail_after);
    check_prior(&out, &prior);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_constructor_order(d);
    body_send_and_setup(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !borrowed_url && !expected_key);
    return test_finish("Humanity");
}
