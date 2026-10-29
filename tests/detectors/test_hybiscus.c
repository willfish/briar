/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <malloc.h>

/* Reuse the named-test allocation/JSON seams and count forbidden setters. */
#define br_result_set_verification_error hybiscus_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const char key[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
static const char other[] = "zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUT";
static size_t fail_size, fail_after, fail_part_after, fail_realloc_size;
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

void *realloc(void *pointer, size_t size)
{
    if (fail_realloc_size && size == fail_realloc_size) {
        fail_realloc_size = 0;
        ++failed_allocations;
        return NULL;
    }
    if (!size) { free(pointer); return NULL; }
    size_t previous = pointer ? malloc_usable_size(pointer) : 0;
    void *copy = malloc(size);
    if (copy) {
        if (pointer) memcpy(copy, pointer, previous < size ? previous : size);
        free(pointer);
    }
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
    return hybiscus_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other) == 43);
    CHECK(br_hybiscus_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Hybiscus detector output")); free(error);
    CHECK(br_hybiscus_init(NULL, NULL) != 0);
    CHECK(br_hybiscus_init(&d, &error) == 0 && d && !error);
    CHECK(br_hybiscus_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 773 && d->version == 0 && !strcmp(d->name, "Hybiscus") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Hybiscus is a service that provides API keys to access its resources and perform operations. These keys should be kept secure to prevent unauthorized access."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "hybiscus"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 773, expected, "key");
    CHECK(r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[260], changed[45];
    const struct { const char *format; bool matches; } cases[] = {
        {"hybiscus '%s'", true}, {"HyBiScUs=%s", true}, {"prehybiscussuffix:%s", true},
        {"hybiscus\r\n%s", true}, {"hybiscus\n\r%s", true}, {"hybiscus -%s-", true},
        {"hybiscus \t%s\t ", true}, {"hybiscus %s.payload.signature", true},
        {"%s", false}, {"%s hybiscus", false}, {"hy biscus %s", false},
        {"hybiscus%s", false}, {"hybiscus x%s", false}, {"hybiscus _%s", false},
        {"hybiscus %s_", false}, {"hybiscus %s9", false}, {"hybiscus %.42s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        extract(d, input, strlen(input), cases[i].matches ? key : NULL);
    }
    const char invalid[] = {'_', '-', '/', ' ', '+'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "hybiscus %s", changed);
        extract(d, input, strlen(input), NULL);
    }
    const char unfiltered[] = {'a', 'Z', '0'};
    for (size_t i = 0; i < sizeof(unfiltered); ++i) {
        memset(changed, unfiltered[i], 43); changed[43] = '\0';
        snprintf(input, sizeof(input), "hybiscus %s", changed);
        extract(d, input, strlen(input), changed); /* No entropy/hex validation. */
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "hybiscus", 8); memset(input + 8, ':', gap);
        memcpy(input + 8 + gap, key, 43);
        extract(d, input, 51 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "💡", 4);
        memcpy(input + 8 + 4 * gap, key, 43);
        extract(d, input, 51 + 4 * gap, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "hybiscus%c%s", 0, key);
    extract(d, input, (size_t)n, key);
    snprintf(input, sizeof(input), "hybiscus %s %s", key, other);
    extract(d, input, strlen(input), key); /* Consumed prefixes are not reused. */
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_key, *borrowed_url, *borrowed_accept, *expected_key;
} expected_request;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_request *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !e->borrowed_key);
    CHECK(request->detector_type == 773 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.hybiscus.dev/api/v1/get-remaining-quota"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.hybiscus+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && !strcmp(request->headers[1].value, e->keys[at]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, e->agent));
    /* Borrow provider originals, not synthesized request/header-array/UA. */
    e->borrowed_key = request->headers[1].value;
    e->borrowed_accept = request->headers[0].value;
    e->borrowed_url = request->url;
    e->expected_key = e->keys[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected_request *e = http->user;
    if (e->borrowed_key) {
        CHECK(!strcmp(e->borrowed_key, e->expected_key));
        CHECK(!strcmp(e->borrowed_accept, "application/vnd.hybiscus+json; version=3"));
        CHECK(!strcmp(e->borrowed_url, "https://api.hybiscus.dev/api/v1/get-remaining-quota"));
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    e->borrowed_key = e->borrowed_url = e->borrowed_accept = e->expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences_and_constructor(const br_detector *d)
{
    char input[180];
    snprintf(input, sizeof(input), "hybiscus %s\nHYBISCUS %s\nhybiscus %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_request e = {.keys = keys, .count = 3, .agent = "TruffleHog hybiscus-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hybiscus-offline"}; e.ctx = &ctx;
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], verify != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && http.calls == 3 && http.releases == 3); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool arm_headers_failure(void *user)
{
    (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}
static bool arm_agent_failure(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void status_body_send_and_setup(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "hybiscus %s", key);
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
        result(&out.items[0], key, cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Hybiscus result"}, {1, "out of memory constructing HTTP headers"},
        {-1, NULL}, {1, key}, {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], key, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {.transport = &transport, .cancelled = arm_headers_failure},
        {.transport = &transport, .cancelled = arm_agent_failure},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"}, {0},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i == 5 ? 0u : 1u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i < 2 ? 1u : 0u));
        result(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !e.borrowed_key && !e.borrowed_url && !e.borrowed_accept && !setter_calls);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "hybiscus %s\nhybiscus %s", key, other);
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
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 44; fail_after = 2; } /* All captures precede I/O. */
        if (failure == 2) { fail_size = 43; fail_after = 2; http.send_rc = -7; http.send_error = "suppressed Do error"; }
        if (failure == 3) { fail_part_after = 2; http.send_rc = 0; http.send_error = NULL; } /* JSON returns +7. */
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned failures win before an ordinary nil-constructor drop, and in NoV. */
    fail_size = 43; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 43; fail_after = 2;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) != 0 && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior);
    /* A real realloc failure makes the second successful candidate's push +1. */
    out.cap = 2; fail_realloc_size = 4 * sizeof(br_result);
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append Hybiscus result"));
    CHECK(!fail_realloc_size && http.calls == 2 && http.releases == 2); check_prior(&out, &prior);
    free(error); br_results_clear(&out);
    CHECK(!e.borrowed_key && !e.borrowed_url && !e.borrowed_accept && !setter_calls);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_constructor(d);
    status_body_send_and_setup(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_realloc_size && !fail_agent && !setter_calls);
    return test_finish("Hybiscus");
}
