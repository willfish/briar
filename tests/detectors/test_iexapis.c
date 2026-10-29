/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Existing named-test seams exercise real owned failures and catch even a
 * forbidden NULL-cause setter call, without replacing shared HTTP policy. */
#define br_result_set_verification_error iexapis_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const char key[] = "sk_0123456789abcdefghijklmnopqrstuv";
static const char other[] = "sk_zyxwvutsrqponmlkjihgfedcba987654";
static const char url_prefix[] = "https://cloud.iexapis.com/stable/stock/aapl/quote?token=";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, setter_calls;
static bool fail_agent;
static const char *borrowed_url, *expected_key;

void *malloc(size_t size)
{
    if (size == fail_size && fail_after && --fail_after == 0) {
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
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return iexapis_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 35 && strlen(other) == 35);
    CHECK(br_iexapis_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Iexapis detector output"));
    free(error);
    CHECK(br_iexapis_init(NULL, NULL) != 0);
    CHECK(br_iexapis_init(&d, &error) == 0 && d && !error);
    CHECK(br_iexapis_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 813 && d->version == 0 && !strcmp(d->name, "Iexapis") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "IEX Cloud provides data services for financial markets. IEX Cloud API keys can be used to access and retrieve financial data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "iexapis"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 813, value, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *value)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (value ? 1u : 0u) && !http.calls && !http.releases);
    if (value) check_result(&out.items[0], value, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[300], changed[37];
    const char *formats[] = {
        "iexapis '%s'", "IEXAPIS=-%s-", "prefixIeXaPiSsuffix\r\n%s",
        "iexapis\r%s", "iexapis\n%s", "iexapis \t%s\t ",
        "iexapis %s-extra", "iexapis extra-%s",
    };
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extract_case(d, input, strlen(input), key);
    }
    const char *missing[] = {
        "%s", "iexcloud %s", "iex apis %s", "%s iexapis", "iexapis%s",
        "iexapis _%s", "iexapis x%s", "iexapis %s_", "iexapis %sa", "iexapis %sA",
    };
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key);
        extract_case(d, input, strlen(input), NULL);
    }
    const struct { size_t at; char byte; } invalid[] = {
        {0, 'S'}, {1, 'K'}, {1, 'g'}, {2, '-'},
        {15, 'A'}, {15, '_'}, {15, '-'}, {15, ' '},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memcpy(changed, key, sizeof(key)); changed[invalid[i].at] = invalid[i].byte;
        snprintf(input, sizeof(input), "iexapis %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[34] = '\0';
    snprintf(input, sizeof(input), "iexapis %s", changed);
    extract_case(d, input, strlen(input), NULL);
    memcpy(changed, "sk_", 3); memset(changed + 3, 'z', 32); changed[35] = '\0';
    snprintf(input, sizeof(input), "iexapis %s", changed);
    extract_case(d, input, strlen(input), changed); /* Not hex/entropy filtering. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "iexapis", 7); memset(input + 7, ':', gap); memcpy(input + 7 + gap, key, 35);
        extract_case(d, input, 42 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 7 + 4 * i, "💡", 4);
        memcpy(input + 7 + 4 * gap, key, 35);
        extract_case(d, input, 42 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "iexapis\0 ", 9); memcpy(input + 9, key, 35);
    extract_case(d, input, 44, key);
    snprintf(input, sizeof(input), "iexapis %s %s", key, other);
    extract_case(d, input, strlen(input), key); /* The consumed prefix is not reused. */
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
    char full[sizeof(url_prefix) + 35];
    snprintf(full, sizeof(full), "%s%s", url_prefix, value);
    CHECK(url && !strcmp(url, full));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_url);
    CHECK(request->detector_type == 813 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    expected_key = e->keys[at];
    check_url(request->url, expected_key);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, e->agent));
    /* Only the provider-original URL is borrowed through release, never the
     * prepared request, synthesized header array or User-Agent. */
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

static void occurrences_and_nil_constructor(const br_detector *d)
{
    char input[180];
    snprintf(input, sizeof(input), "iexapis %s\niexapis %s\niexapis %s", key, other, key);
    const char *keys[] = {key, other, key};
    const br_http_response responses[] = {
        {.status = 200, .body_error = ""}, {.status = 401, .body_error = "ignored read failure"}, {.status = 299},
    };
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog iexapis-offline", .responses = responses};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "iexapis-offline"}; e.ctx = &ctx;
    for (int verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify && i != 1);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, strlen(input));
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

static void status_body_and_shared_failures(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "iexapis %s", key);
    const char *keys[] = {key};
    expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, '{', ']', 0};
    const struct { int status; br_slice body; const char *read_error; bool verified; } cases[] = {
        {199, {binary, sizeof(binary)}, "ignored read failure", false},
        {200, {0}, NULL, true},
        {201, {binary, sizeof(binary)}, "", true},
        {204, {binary, sizeof(binary)}, "ignored read failure", true},
        {299, {(const unsigned char *)"not JSON", 8}, "ignored read failure", true},
        {300, {0}, NULL, false}, {401, {0}, "", false},
        {429, {binary, sizeof(binary)}, "ignored read failure", false},
        {500, {binary, sizeof(binary)}, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Iexapis result"}, {7, "cannot construct Iexapis URL"},
        {-1, NULL}, {1, key}, {7, "net/http: nil Context"}, {1, "context canceled"},
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
    br_transport no_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_send},
        {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 2 || i == 3 ? 1u : 0u));
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
    char input[120]; snprintf(input, sizeof(input), "iexapis %s\niexapis %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
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
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Positive regex error. */
        if (failure == 1) { fail_size = 36; fail_after = 2; } /* Second capture, before any send. */
        if (failure == 2) { fail_size = 35; fail_after = 2; } /* Second finding Raw. */
        if (failure == 3) fail_part_after = 2; /* Positive JSON insertion error. */
        if (failure == 4) { fail_size = sizeof(url_prefix) + 35; fail_after = 2; } /* Second URL. */
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        if (failure == 4) CHECK(!strcmp(error, "cannot construct Iexapis URL"));
        check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned errors precede both nil-constructor drop and NoV success. */
    fail_size = sizeof(url_prefix) + 35; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "cannot construct Iexapis URL"));
    check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Iexapis result"));
    check_prior(&out, &prior); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error);
    check_prior(&out, &prior);
    /* A positive shared push error is fatal even after verified success. */
    size_t cap = out.cap; out.cap = 0; http.send_rc = 0; http.send_error = NULL;
    http.response = (br_http_response){.status = 204, .body_error = "ignored"};
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Iexapis result") && http.calls == 1 && http.releases == 1);
    check_prior(&out, &prior); free(error);
    fail_size = 35; fail_after = 2;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) != 0 && !fail_after);
    check_prior(&out, &prior);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_nil_constructor(d);
    status_body_and_shared_failures(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !borrowed_url && !expected_key && !setter_calls);
    return test_finish("Iexapis");
}
