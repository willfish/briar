/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <malloc.h>

static const char a[] = "aB3dE6gH9jK2mN5pQ8sT1vW4";
static const char b[] = "Z9y8X7w6V5u4T3s2R1q0P9o8";
static size_t fail_size, fail_after, failed, fail_part_after, fail_realloc_size;
static bool fail_agent;
static const char *borrowed_auth, *expected_key;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n); if (p) memcpy(p, s, n); return p;
}
void *realloc(void *p, size_t size)
{
    if (fail_realloc_size && size == fail_realloc_size) { fail_realloc_size = 0; ++failed; return NULL; }
    if (!size) { free(p); return NULL; }
    size_t previous = p ? malloc_usable_size(p) : 0;
    void *copy = malloc(size);
    if (copy) { if (p) memcpy(copy, p, previous < size ? previous : size); free(p); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_happyscribe_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_happyscribe_init(NULL, NULL) != 0);
    CHECK(br_happyscribe_init(&d, &error) == 0 && d && !error);
    CHECK(br_happyscribe_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 507 && !d->version && !strcmp(d->name, "Happyscribe") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Happyscribe is a transcription service that converts audio to text. Happyscribe API keys can be used to access and manage these transcription services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "happyscribe"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 507, key, "key");
    CHECK(r->raw.len == 24 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 24);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[220], changed[25];
    const struct { const char *format; bool matches; } cases[] = {
        {"happyscribe '%s'", true}, {"HaPpYsCrIbE=%s", true}, {"prehappyscribesuffix:%s", true}, {"happyscribe\r\n%s", true},
        {"%s", false}, {"%s happyscribe", false}, {"happy scribe %s", false}, {"happyscribe%s", false},
        {"happyscribe x%s", false}, {"happyscribe _%s", false}, {"happyscribe %s_", false}, {"happyscribe %s9", false},
        {"happyscribe %.23s", false}, {"happyscribe +%s=", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a); extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "happyscribe", 11); memset(input + 11, ':', gap); memcpy(input + 11 + gap, a, 24);
        extract_case(d, input, 35 + gap, gap == 40 ? a : NULL);
    }
    const char invalid[] = "_-+/.=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "happyscribe %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    const char *low_entropy[] = {"aaaaaaaaaaaaaaaaaaaaaaaa", "000000000000000000000000", "ZZZZZZZZZZZZZZZZZZZZZZZZ"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(input, sizeof(input), "happyscribe %s", low_entropy[i]); extract_case(d, input, strlen(input), low_entropy[i]);
    }
    snprintf(input, sizeof(input), "happyscribe %s %s", a, b); extract_case(d, input, strlen(input), a);
    int n = snprintf(input, sizeof(input), "happyscribe%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}
typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 507 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.happyscribe.com/api/v1/transcriptions"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value; expected_key = e->keys[at];
    CHECK(strlen(auth) == 31 && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, expected_key, 24));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    borrowed_auth = auth; /* Never retain effective request/header array or synthesized UA. */
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_auth && expected_key && !memcmp(borrowed_auth, "Bearer ", 7) && !memcmp(borrowed_auth + 7, expected_key, 25));
    borrowed_auth = expected_key = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[150]; snprintf(input, sizeof(input), "happyscribe %s\nHAPPYSCRIBE %s\nhappyscribe %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog happyscribe-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "happyscribe-offline"}; e.ctx = &ctx;
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], true);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3); br_results_clear(&out);
}
static void statuses_and_send(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "happyscribe %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {ignored, sizeof(ignored)}, .body_error = i % 2 ? "ignored" : NULL};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *error; } failures[] = {{1, "net/http: nil Context"}, {-7, "cannot create Happyscribe result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, a}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].error;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, false); br_results_clear(&out);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "happyscribe %s", a);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed == before + (i == 1 || i == 2 ? 1u : 0u));
        result(&out.items[0], a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(out->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}
static void resources(const br_detector *d)
{
    char input[100]; snprintf(input, sizeof(input), "happyscribe %s\nhappyscribe %s", a, b); br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *keys[] = {a, b}; expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 25; fail_after = 2; }
        if (failure == 2) { fail_size = 24; fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0);
        CHECK(error && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !borrowed_auth);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned construction failures win over nil-context constructor skips. */
    for (size_t failure = 0; failure < 3; ++failure) {
        if (failure == 0) { fail_size = 25; fail_after = 1; }
        if (failure == 1) { fail_size = 24; fail_after = 1; }
        if (failure == 2) fail_part_after = 2;
        CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after && !fail_part_after);
        check_prior(&out, &prior); free(error); error = NULL;
    }
    /* A valid full collection reaches real realloc failure on the second push. */
    out.cap = 2; fail_realloc_size = 4 * sizeof(br_result);
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append Happyscribe result"));
    CHECK(!fail_realloc_size && http.calls == 2 && http.releases == 2); check_prior(&out, &prior);
    free(error); br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); occurrences(d); statuses_and_send(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_realloc_size && !fail_agent && !borrowed_auth && !expected_key);
    return test_finish("Happyscribe");
}
