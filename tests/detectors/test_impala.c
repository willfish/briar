/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Existing named-test seams: exercise owned failures and forbid error setters. */
#define br_result_set_verification_error impala_real_setter
#define br_results_push impala_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

static const char key[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi_";
static const char other[] = "zyxwvutsrqponmlkjihgfedcba9876543210_ZYXWVUTSR";
static size_t fail_size, fail_after, fail_part_after, fail_push_after;
static size_t failed_allocations, setter_calls;
static bool fail_agent;

void *malloc(size_t size)
{
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
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return impala_real_setter(result, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 7;
    return impala_real_push(out, owned);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 46 && strlen(other) == 46);
    CHECK(br_impala_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Impala detector output")); free(error); error = NULL;
    CHECK(br_impala_init(NULL, NULL) != 0);
    fail_size = sizeof("(?i:impala)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_impala_init(&d, &error) != 0 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_impala_init(&d, &error) == 0 && d && !error);
    CHECK(br_impala_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 509 && d->version == 0 && !strcmp(d->name, "Impala") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Impala is a travel API service used for managing bookings and reservations. Impala API keys can be used to access and modify booking data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "impala"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 509, expected, "key");
    CHECK(r->raw.len == 46 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "invalid\r\nagent"};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[47];
    const struct { const char *format; bool matches; } cases[] = {
        {"impala '%s'", true}, {"ImPaLa=%s", true}, {"preimpalasuffix:%s", true},
        {"impala\r\n%s", true}, {"impala\n\r%s", true}, {"impala -%s-", true},
        {"impala \t%s\t ", true}, {"impala %s.payload.signature", true},
        {"%s", false}, {"%s impala", false}, {"im pala %s", false},
        {"impala%s", false}, {"impala x%s", false}, {"impala _%s", false},
        {"impala %s_", false}, {"impala %s9", false}, {"impala %.45s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        extract(d, input, strlen(input), cases[i].matches ? key : NULL);
    }
    const char invalid[] = {'-', '/', ' ', '+', '='};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "impala %s", changed);
        extract(d, input, strlen(input), NULL);
    }
    const char unfiltered[] = {'a', 'Z', '0', '_'};
    for (size_t i = 0; i < sizeof(unfiltered); ++i) {
        memset(changed, unfiltered[i], 46); changed[46] = '\0';
        snprintf(input, sizeof(input), "impala %s", changed);
        extract(d, input, strlen(input), changed); /* No entropy/semantic filter. */
    }
    memcpy(changed, key, sizeof(key)); changed[0] = '_';
    snprintf(input, sizeof(input), "impala %s", changed);
    extract(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "impala", 6); memset(input + 6, ':', gap);
        memcpy(input + 6 + gap, key, 46);
        extract(d, input, 52 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 6 + 4 * gap, key, 46);
        extract(d, input, 52 + 4 * gap, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "impala%c%s", 0, key);
    extract(d, input, (size_t)n, key);
    snprintf(input, sizeof(input), "impala %s %s", key, other);
    extract(d, input, strlen(input), key); /* Consumed prefixes are not reused. */
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_key, *borrowed_url, *expected_key;
} expected_request;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_request *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !e->borrowed_key);
    CHECK(request->detector_type == 509 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://sandbox.impala.travel/v1/bookings"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, e->keys[at]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Borrow only provider originals, not the synthesized request/headers/UA. */
    e->borrowed_key = request->headers[0].value;
    e->borrowed_url = request->url;
    e->expected_key = e->keys[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected_request *e = http->user;
    if (e->borrowed_key) {
        CHECK(!strcmp(e->borrowed_key, e->expected_key));
        CHECK(!strcmp(e->borrowed_url, "https://sandbox.impala.travel/v1/bookings"));
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    e->borrowed_key = e->borrowed_url = e->expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences_and_constructor(const br_detector *d)
{
    char input[180];
    snprintf(input, sizeof(input), "impala %s\nIMPALA %s\nimpala %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_request e = {.keys = keys, .count = 3, .agent = "TruffleHog impala-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "impala-offline"}; e.ctx = &ctx;
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], verify != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && http.calls == 3 && http.releases == 3); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool arm_headers_failure(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static bool arm_agent_failure(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void status_body_send_and_setup(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "impala %s", key);
    const char *keys[] = {key};
    expected_request e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *body_error; } cases[] = {
        {0, NULL}, {199, "ignored"}, {200, NULL}, {201, "ignored"}, {204, ""},
        {299, "ignored"}, {300, ""}, {401, NULL}, {403, "ignored"}, {429, ""}, {500, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = {ignored, sizeof(ignored)}, .body_error = cases[i].body_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Impala result"}, {1, "out of memory constructing HTTP headers"},
        {-1, NULL}, {1, key}, {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_transport release_only = {.user = &http, .release = release_response};
    br_scan_ctx contexts[] = {
        {.transport = &transport, .cancelled = arm_headers_failure},
        {.transport = &transport, .cancelled = arm_agent_failure},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &release_only}, {0},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i == 6 ? 0u : 1u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i < 2 ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !e.borrowed_key && !e.borrowed_url && !setter_calls);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "impala %s\nimpala %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *keys[] = {key, other};
    expected_request e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Regex returns +1. */
        if (failure == 1) { fail_size = 47; fail_after = 2; } /* All captures precede I/O. */
        if (failure == 2) { fail_size = 46; fail_after = 2; http.send_rc = -7; http.send_error = "suppressed Do error"; }
        if (failure == 3) { fail_part_after = 2; http.send_rc = 0; http.send_error = NULL; } /* JSON returns +7. */
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned failures win before an ordinary nil-constructor drop, and in NoV. */
    fail_size = 46; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 46; fail_after = 2;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) != 0 && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior);
    fail_push_after = 2; /* Positive nonzero must abort after successful verification. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append Impala result"));
    CHECK(!fail_push_after && http.calls == 2 && http.releases == 2); check_prior(&out, &prior);
    free(error); br_results_clear(&out);
    CHECK(!e.borrowed_key && !e.borrowed_url && !setter_calls);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_constructor(d);
    status_body_send_and_setup(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_agent && !setter_calls);
    return test_finish("Impala");
}
