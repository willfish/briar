/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char a[] = "0123456789abcdef0123456789abcdef";
static const char b[] = "fedcba9876543210fedcba9876543210";
/* Independent Python base64.b64encode(KEY + b':') goldens. */
static const char auth_a[] = "Basic MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY6";
static const char auth_b[] = "Basic ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA6";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static size_t encoder_calls, fail_encoder_after;
static bool fail_agent;
static const char *borrowed_auth, *expected_auth;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n); if (p) memcpy(p, s, n); return p;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
/* Interpose the actual library entry, not a production formatter seam. Normal
 * calls use OpenSSL streaming Base64; independent goldens check the wire bytes. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls; CHECK(len == 33 && in[32] == ':');
    CHECK(!memcmp(in, a, 32) || !memcmp(in, b, 32));
    if (fail_encoder_after && --fail_encoder_after == 0) return 1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[64]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 44); out[at] = '\0'; return (int)at;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gtmetrix_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_gtmetrix_init(NULL, NULL) != 0);
    CHECK(br_gtmetrix_init(&d, &error) == 0 && d && !error);
    CHECK(br_gtmetrix_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 763 && !d->version && !strcmp(d->name, "GTMetrix") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GTMetrix provides website performance analytics and monitoring. GTMetrix API keys can be used to access and manage these analytics."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gtmetrix"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 763, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[240], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"gtmetrix '%s'", true}, {"GtMeTrIx=%s", true}, {"pregtmetrixsuffix:%s", true}, {"gtmetrix\r\n%s", true},
        {"%s", false}, {"%s gtmetrix", false}, {"gt metrix %s", false}, {"gtmetrix%s", false},
        {"gtmetrix x%s", false}, {"gtmetrix _%s", false}, {"gtmetrix %s_", false}, {"gtmetrix %s9", false},
        {"gtmetrix %.31s", false}, {"gtmetrix +%s=", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a); extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gtmetrix", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, a, 32);
        extract_case(d, input, 40 + gap, gap == 40 ? a : NULL);
    }
    /* Only the keyword folds case. Lowercase g/z are not hexadecimal. */
    const char invalid[] = "AFgz_-/+.=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "gtmetrix %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "gtmetrix %s", changed); extract_case(d, input, strlen(input), changed);
    memset(changed, '0', 32); snprintf(input, sizeof(input), "gtmetrix %s", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "gtmetrix %s %s", a, b); extract_case(d, input, strlen(input), a);
    int n = snprintf(input, sizeof(input), "gtmetrix%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}

typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 763 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://gtmetrix.com/api/2.0/status"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    expected_auth = !strcmp(e->keys[at], a) ? auth_a : auth_b;
    CHECK(strlen(auth) == 50 && !memcmp(auth, expected_auth, 51) && !strchr(auth, '='));
    unsigned char decoded[34]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 44) == 33);
    CHECK(!memcmp(decoded, e->keys[at], 32) && decoded[32] == ':');
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    borrowed_auth = auth; /* Never retain effective headers, request or synthesized UA. */
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_auth && expected_auth && !memcmp(borrowed_auth, expected_auth, 51));
    borrowed_auth = expected_auth = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "gtmetrix %s\nGTMETRIX %s\ngtmetrix %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog gtmetrix-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "gtmetrix-offline"}; e.ctx = &ctx;
    size_t before = encoder_calls; br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases && encoder_calls == before);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    for (size_t pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; before = encoder_calls; out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && encoder_calls == before + 3);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], true);
        br_results_clear(&out);
    }
    /* Constructor skip must not even reach an armed encoder failure. */
    before = encoder_calls; fail_encoder_after = 1;
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len && encoder_calls == before && fail_encoder_after == 1); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3 && encoder_calls == before && fail_encoder_after == 1); br_results_clear(&out); fail_encoder_after = 0;
}
static void statuses_and_send(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "gtmetrix %s", a);
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
    const struct { int rc; const char *error; } failures[] = {{1, "net/http: nil Context"}, {-7, "cannot create GTMetrix result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, a}};
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
    char input[48]; snprintf(input, sizeof(input), "gtmetrix %s", a);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
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
    char input[100]; snprintf(input, sizeof(input), "gtmetrix %s\ngtmetrix %s", a, b); br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *keys[] = {a, b}; expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 33; fail_after = 2; }
        /* Regex spans, Raw and shared HTTP headers are each 32 bytes. */
        if (failure == 2) { fail_size = 32; fail_after = 4; }
        if (failure == 3) fail_part_after = 2;
        if (failure == 4) fail_encoder_after = 2;
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0);
        CHECK(error && !fail_after && !fail_part_after && !fail_encoder_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !borrowed_auth);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Finding failures precede nil-context skip, which still precedes encoding. */
    size_t before = encoder_calls; fail_encoder_after = 1;
    for (size_t failure = 0; failure < 3; ++failure) {
        if (failure == 0) { fail_size = 33; fail_after = 1; }
        if (failure == 1) { fail_size = 32; fail_after = 2; }
        if (failure == 2) fail_part_after = 2;
        CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after && !fail_part_after);
        CHECK(encoder_calls == before && fail_encoder_after == 1); check_prior(&out, &prior); free(error); error = NULL;
    }
    fail_encoder_after = 0;
    size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append GTMetrix result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error); br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); occurrences(d); statuses_and_send(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_encoder_after && !fail_agent && !borrowed_auth && !expected_auth);
    return test_finish("GTMetrix");
}
