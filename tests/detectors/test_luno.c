/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

int br_luno_init(const br_detector **out, char **error);

#define br_result_set_verification_error luno_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const br_detector *detector;
static char key[44], other[44];
static const char id[] = "abc12def34gh5", other_id[] = "z9y8x7w6v5u4t";
static size_t fail_size, fail_after, fail_key_after, fail_request_after_key, fail_module_alloc_after, setter_calls;
static bool fail_agent;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t original_len, count;
    const char *keys[4], *ids[4], *causes[4], *auth[4];
    int statuses[4], send_rc[4];
    br_header markers[4];
    size_t release_ids[4], release_lengths[4], release_calls[4];
} script;

void *malloc(size_t size)
{
    if ((fail_module_alloc_after && --fail_module_alloc_after == 0) ||
        (size == fail_size && fail_after && --fail_after == 0)) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) { fail_agent = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key") && fail_request_after_key && --fail_request_after_key == 0)
        fail_module_alloc_after = 1;
    return rc;
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return luno_real_setter(result, cause, secrets, count);
}

static void make_keys(void)
{
    test_secret(key, 43, 0); test_secret(other, 43, 9);
    for (size_t i = 0; i < 43; i += 4) { key[i] = (char)('A' + i % 26); other[i] = (char)('Z' - i % 26); }
    key[7] = other[7] = '_'; key[15] = other[15] = '-';
    key[31] = other[31] = '_'; key[39] = other[39] = '-';
    key[42] = 'z'; other[42] = '7';
    CHECK(strlen(key) == 43 && strlen(other) == 43 && strlen(id) == 13 && strlen(other_id) == 13);
}

static void check_result(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 655, value, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void check_auth(const char *authorization, const char *username, const char *password)
{
    char plain[58], expected[83];
    memcpy(plain, username, 13); plain[13] = ':'; memcpy(plain + 14, password, 43); plain[57] = 0;
    memcpy(expected, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)expected + 6, (const unsigned char *)plain, 57) == 76);
    CHECK(authorization && !strcmp(authorization, expected));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && !s->auth[at]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.luno.com/api/1/balance"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 655);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog luno-offline"));
    /* Only the provider-original Basic value survives shared preparation. */
    s->auth[at] = request->headers[0].value; check_auth(s->auth[at], s->ids[at], s->keys[at]);
    s->markers[at] = (br_header){"synthetic-attempt", s->ids[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored read failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    size_t at = 0;
    while (at < s->count && response->headers != &s->markers[at]) ++at;
    CHECK(http->releases < 4 && s->out && !setter_calls);
    if (at < s->count) { check_auth(s->auth[at], s->ids[at], s->keys[at]); s->auth[at] = NULL; }
    else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_ids[http->releases] = at;
    s->release_lengths[http->releases] = s->out->len;
    s->release_calls[http->releases] = http->calls;
    test_http_release(user, response);
}

static void setup(script *s, size_t count, int status)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) { s->keys[i] = key; s->ids[i] = id; s->statuses[i] = status; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "luno-offline"};
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out; s->original_len = out->len;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    s->out = NULL;
    return rc;
}

static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}

static void extract_case(const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && !setter_calls);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void descriptor_and_grammars(void)
{
    make_keys();
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_luno_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Luno detector output")); free(error);
    CHECK(br_luno_init(NULL, NULL) != 0);
    CHECK(br_luno_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_luno_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 655 && detector->version == 0 && !strcmp(detector->name, "Luno") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Luno is a cryptocurrency exchange platform that allows users to buy, sell, and store digital currencies. Luno API keys can be used to access account information and perform transactions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "luno"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    char input[400], changed[44];
    const char *good[] = {"luno %s\nluno %s", "LuNo '%s'\nLUNO %s", "prelunosuffix\r\n%s\nluno %s", "luno\r%s\nluno %s", "luno\n%s\nluno %s", "luno \xc3\xa9%s\xc3\xa9\nluno %s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key, id); extract_case(input, strlen(input), key);
    }
    const char *bad[] = {"%s\nluno %s", "luno%s\nluno %s", "luno x%s\nluno %s", "luno %sx\nluno %s", "luno %.42s\nluno %s", "luno %s\n%s", "luno %s\nluno%s", "luno %s\nluno _%s", "luno %s\nluno %s_", "luno %s\nluno %.12s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key, id); extract_case(input, strlen(input), NULL);
    }
    snprintf(input, sizeof(input), "luno %s", key); extract_case(input, strlen(input), NULL); /* Hidden NoV ID requirement. */
    snprintf(input, sizeof(input), "luno %s", id); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "luno %s\nluno ABC12DEF34GH5", key); extract_case(input, strlen(input), NULL);
    memcpy(changed, key, sizeof(changed)); changed[20] = '/';
    snprintf(input, sizeof(input), "luno %s\nluno %s", changed, id); extract_case(input, strlen(input), NULL);
    memcpy(changed, key, sizeof(changed)); changed[0] = '_'; changed[42] = '_';
    snprintf(input, sizeof(input), "luno %s\nluno %s", changed, id); extract_case(input, strlen(input), changed);
    memcpy(changed, key, sizeof(changed)); changed[0] = '-';
    snprintf(input, sizeof(input), "luno %s\nluno %s", changed, id); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "luno Z%s\nluno %s", changed, id); extract_case(input, strlen(input), changed);
    memcpy(changed, key, sizeof(changed)); changed[42] = '-';
    snprintf(input, sizeof(input), "luno %s\nluno %s", changed, id); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "luno %sa\nluno %s", changed, id); extract_case(input, strlen(input), changed);
    for (size_t which = 0; which < 2; ++which) for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 0;
        if (which) { int n = snprintf(input, sizeof(input), "luno %s\n", key); CHECK(n > 0); at = (size_t)n; }
        memcpy(input + at, "luno", 4); at += 4;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xf0\x9f\x92\xa1", 4); at += 4; }
        const char *value = which ? id : key; size_t len = which ? 13 : 43;
        memcpy(input + at, value, len); at += len;
        if (!which) { int n = snprintf(input + at, sizeof(input) - at, "\nluno %s", id); CHECK(n > 0); at += (size_t)n; }
        extract_case(input, at, gap == 40 ? key : NULL);
    }
    memcpy(input, "luno\0", 5); memcpy(input + 5, key, 43);
    int n = snprintf(input + 48, sizeof(input) - 48, "\nluno %s", id); CHECK(n > 0); extract_case(input, 48 + (size_t)n, key);
    extract_case(NULL, 0, NULL);
    char far[2300]; n = snprintf(far, sizeof(far), "luno %s", key); CHECK(n > 0);
    memset(far + n, ' ', 2048); int end = snprintf(far + n + 2048, sizeof(far) - (size_t)n - 2048, "luno %s", id); CHECK(end > 0);
    extract_case(far, (size_t)n + 2048 + (size_t)end, key);
}

static void product_and_release_order(void)
{
    char input[180]; snprintf(input, sizeof(input), "luno %s\nluno %s\nluno %s\nluno %s", key, other, id, other_id);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        script s; setup(&s, 4, 200);
        s.keys[2] = s.keys[3] = other; s.ids[1] = s.ids[3] = other_id;
        s.statuses[1] = 401; s.statuses[2] = 299; s.statuses[3] = 500;
        if (mixed) { s.send_rc[1] = 7; s.causes[1] = "out of memory constructing Basic authentication"; }
        br_results out = run(&s, NULL, false, input); CHECK(out.len == 4 && !s.http.calls && !s.http.releases);
        for (size_t i = 0; i < 4; ++i) check_result(&out.items[i], s.keys[i], false);
        br_results_clear(&out);
        out = run(&s, &s.ctx, true, input); CHECK(out.len == 4 && s.http.calls == 4 && s.http.releases == 4);
        for (size_t i = 0; i < 4; ++i) {
            check_result(&out.items[i], s.keys[i], i == 0 || i == 2);
            CHECK(!s.auth[i]);
            CHECK(s.release_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 3u : i == 2 ? 2u : 0u) : 3 - i));
            CHECK(s.release_lengths[i] == (mixed && i == 0 ? 1u : 4u));
            CHECK(s.release_calls[i] == (mixed && i == 0 ? 2u : 4u));
        }
        br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "luno %s\nluno %s\nluno %s\nluno %s", key, key, id, id);
    br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&out.items[i], key, false);
    CHECK(out.items[0].raw.data != out.items[3].raw.data && out.items[0].secret_parts != out.items[3].secret_parts); br_results_clear(&out);
    script s; setup(&s, 4, 200);
    out = run(&s, NULL, true, input); CHECK(!out.len && !s.http.calls && !s.http.releases); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void statuses_and_shared_failures(void)
{
    char input[100]; snprintf(input, sizeof(input), "luno %s\nluno %s", key, id);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, 1, statuses[i]);
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        CHECK(s.release_lengths[0] == 1); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Luno result"}, {7, "out of memory constructing Basic authentication"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        script s; setup(&s, 1, 200); s.send_rc[0] = failures[i].rc; s.causes[0] = failures[i].cause;
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, false); CHECK(s.release_lengths[0] == 0); br_results_clear(&out);
    }
    for (size_t i = 0; i < 7; ++i) {
        script s; setup(&s, 1, 200);
        if (i == 0) s.ctx.transport = NULL;
        if (i == 1) s.transport.send = NULL;
        if (i == 2) s.ctx.cancelled = cancelled;
        if (i == 3) s.ctx.deadline_monotonic_ms = 1;
        if (i == 4) s.ctx.user_agent = "bad\r\nagent";
        if (i == 5) s.ctx.cancelled = arm_headers;
        if (i == 6) { s.ctx.cancelled = arm_agent; s.ctx.user_agent = NULL; }
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && !s.http.calls && s.http.releases == (i ? 1u : 0u) && !fail_after && !fail_agent);
        check_result(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(!setter_calls);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->verified && prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_nil_order(void)
{
    char multi[180], one[100];
    snprintf(multi, sizeof(multi), "luno %s\nluno %s\nluno %s\nluno %s", key, other, id, other_id);
    snprintf(one, sizeof(one), "luno %s\nluno %s", key, id);
    br_slice data = {(const unsigned char *)multi, strlen(multi)}, single = {(const unsigned char *)one, strlen(one)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    for (size_t failure = 0; failure < 7; ++failure) {
        script s; setup(&s, 4, 200); s.keys[2] = s.keys[3] = other; s.ids[1] = s.ids[3] = other_id;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 44; fail_after = 2; }
        if (failure == 2) { fail_size = 14; fail_after = 2; }
        if (failure == 3) { fail_size = 43; fail_after = 2; }
        if (failure == 4) fail_key_after = 2;
        if (failure == 5) fail_request_after_key = 2;
        if (failure == 6) { fail_size = 83; fail_after = 2; } /* Actual Basic helper +1. */
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after);
        CHECK(s.http.calls == (failure < 3 ? 0u : 1u) && s.http.releases == s.http.calls);
        if (failure == 6) CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
        if (failure >= 3) CHECK(s.release_lengths[0] == 2);
        for (size_t i = 0; i < s.count; ++i) CHECK(!s.auth[i]);
        check_prior(&out, &prior); free(error);
    }
    /* The ID regex is independently reached even with zero key matches. */
    script s; setup(&s, 1, 200); fail_size = 2 * sizeof(br_span); fail_after = 2; char *error = NULL;
    CHECK(invoke(&s, NULL, false, (br_slice){0}, &out, &error) != 0 && error && !fail_after);
    check_prior(&out, &prior); free(error); error = NULL;
    /* Constructor skip follows the checked finding but precedes request/Basic. */
    fail_size = 83; fail_after = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) == 0 && !error && fail_after == 1);
    fail_after = 0; check_prior(&out, &prior);
    fail_request_after_key = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) == 0 && !error && !fail_request_after_key && fail_module_alloc_after == 1);
    fail_module_alloc_after = 0; check_prior(&out, &prior);
    fail_key_after = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) != 0 && error && !fail_key_after);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 83; fail_after = 1;
    CHECK(invoke(&s, NULL, false, single, &out, &error) == 0 && !error && fail_after == 1);
    fail_after = 0; CHECK(out.len == 2); br_result_clear(&out.items[--out.len]); check_prior(&out, &prior);
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, single, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Luno result") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error);
    fail_key_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_key_after);
    check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_grammars(); product_and_release_order(); statuses_and_shared_failures(); owned_failures_and_nil_order();
    CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after && !fail_agent && !setter_calls);
    return test_finish("Luno");
}
