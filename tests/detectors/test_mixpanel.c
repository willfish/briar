/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

int br_mixpanel_init(const br_detector **out, char **error);

#define br_result_set_verification_error mixpanel_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const br_detector *detector;
static char key[33], other[33];
static size_t fail_size, fail_after, fail_key_after, fail_request_after_key, fail_module_alloc_after, setter_calls;
static bool fail_agent, arm_raw_after_send;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t count;
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
    return mixpanel_real_setter(result, cause, secrets, count);
}

static void result_check(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 371, value, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void check_auth(const char *authorization, const char *id, const char *value)
{
    char plain[74], expected[107];
    int n = snprintf(plain, sizeof(plain), "%s:%s", id, value); CHECK(n >= 63 && n <= 73);
    memcpy(expected, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)expected + 6, (const unsigned char *)plain, n) == 4 * ((n + 2) / 3));
    CHECK(authorization && !strcmp(authorization, expected));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && !s->auth[at]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://mixpanel.com/api/app/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 371);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog mixpanel-offline"));
    s->auth[at] = request->headers[0].value; check_auth(s->auth[at], s->ids[at], s->keys[at]);
    s->markers[at] = (br_header){"synthetic-attempt", s->ids[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored read failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
    if (arm_raw_after_send) { arm_raw_after_send = false; fail_size = 32; fail_after = 1; }
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
    for (size_t i = 0; i < count; ++i) { s->keys[i] = s->ids[i] = key; s->statuses[i] = status; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "mixpanel-offline"};
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out;
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

static void extract_case(const void *input, size_t len, const char *expected, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases && !setter_calls);
    for (size_t i = 0; i < count; ++i) result_check(&out.items[i], expected, false);
    br_results_clear(&out);
}

static void make_id(char *out, size_t len)
{
    test_secret(out, len, 7); out[0] = 'A'; out[5] = '.'; out[20] = '.'; out[len - 1] = 'Z';
}

static void descriptor_and_grammars(void)
{
    test_secret(key, 32, 0); test_secret(other, 32, 9); key[0] = 'Z'; key[15] = '-'; other[1] = 'Q'; other[14] = '-';
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_mixpanel_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Mixpanel detector output")); free(error);
    CHECK(br_mixpanel_init(NULL, NULL) != 0);
    CHECK(br_mixpanel_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_mixpanel_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 371 && detector->version == 0 && !strcmp(detector->name, "Mixpanel") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Mixpanel is an analytics service that tracks user interactions with web and mobile applications. Mixpanel keys can be used to access and analyze user data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mixpanel"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    /* Upstream disabled/default/selector policy is parent-owned, not changed here. */
    char input[400], changed[33];
    const char *good[] = {"mixpanel %s", "MIXpanel '%s'", "premixpanelsuffix\r\n%s", "mixpanel\r%s", "mixpanel\n%s", "mixpanel \xc3\xa9%s\xc3\xa9"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract_case(input, strlen(input), key, 1); } /* Each key is also its own ID. */
    const char *bad[] = {"%s", "%s mixpanel", "mixpanel%s", "mixpanel x%s", "mixpanel %sx", "mixpanel %.31s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract_case(input, strlen(input), NULL, 0); }
    const char invalid[] = {'_', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) { memcpy(changed, key, sizeof(changed)); changed[12] = invalid[i]; snprintf(input, sizeof(input), "mixpanel %s", changed); extract_case(input, strlen(input), NULL, 0); }
    memcpy(changed, key, sizeof(changed)); changed[0] = '-'; snprintf(input, sizeof(input), "mixpanel %s", changed); extract_case(input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "mixpanel Z%s", changed); extract_case(input, strlen(input), changed, 1);
    memcpy(changed, key, sizeof(changed)); changed[31] = '-'; snprintf(input, sizeof(input), "mixpanel %s", changed); extract_case(input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "mixpanel %sa", changed); extract_case(input, strlen(input), changed, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "mixpanel", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key, 32); extract_case(input, 40 + gap, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 8 + 4 * gap, key, 32); extract_case(input, 40 + 4 * gap, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
    }
    memcpy(input, "mixpanel\0", 9); memcpy(input + 9, key, 32); extract_case(input, 41, key, 1);
    memset(changed, 'a', 32); changed[32] = 0; snprintf(input, sizeof(input), "mixpanel %s", changed); extract_case(input, strlen(input), changed, 1);
    extract_case(NULL, 0, NULL, 0);
    char id[42];
    const size_t lengths[] = {29, 30, 31, 32, 33, 40, 41};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
        make_id(id, lengths[i]);
        /* Overlong invalid IDs use only word bytes, preventing a period boundary fallback. */
        if (lengths[i] == 41) memset(id, 'A', 41);
        snprintf(input, sizeof(input), "mixpanel %s\nmixpanel %s", key, id);
        size_t count = lengths[i] >= 30 && lengths[i] <= 40 ? 2 : 1;
        extract_case(input, strlen(input), key, count);
        if (count == 2) {
            script s; setup(&s, 2, 200); s.ids[1] = id;
            br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 2 && s.http.calls == 2 && s.http.releases == 2);
            for (size_t j = 0; j < 2; ++j) result_check(&out.items[j], key, true);
            br_results_clear(&out);
        }
    }
    make_id(id, 30); char far[2300]; int n = snprintf(far, sizeof(far), "mixpanel %s", key); CHECK(n > 0);
    memset(far + n, ' ', 2048); int end = snprintf(far + n + 2048, sizeof(far) - (size_t)n - 2048, "mixpanel %s", id); CHECK(end > 0);
    extract_case(far, (size_t)n + 2048 + (size_t)end, key, 2);
    snprintf(input, sizeof(input), "mixpanel %s", id); extract_case(input, strlen(input), NULL, 0); /* ID without key emits nothing. */
}

static void product_and_source_wide_release(void)
{
    char input[180], extended[40]; snprintf(extended, sizeof(extended), "%s.suffix", key);
    snprintf(input, sizeof(input), "mixpanel %s\nmixpanel %s", extended, other);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        script s; setup(&s, 4, 200);
        s.keys[2] = s.keys[3] = other;
        s.ids[0] = s.ids[2] = extended; s.ids[1] = s.ids[3] = other;
        s.statuses[1] = 401; s.statuses[2] = 299; s.statuses[3] = 500;
        if (mixed) { s.send_rc[1] = 7; s.causes[1] = "out of memory constructing Basic authentication"; }
        br_results out = run(&s, NULL, false, input); CHECK(out.len == 4 && !s.http.calls && !s.http.releases);
        for (size_t i = 0; i < 4; ++i) result_check(&out.items[i], s.keys[i], false);
        br_results_clear(&out);
        out = run(&s, &s.ctx, true, input); CHECK(out.len == 4 && s.http.calls == 4 && s.http.releases == 4);
        for (size_t i = 0; i < 4; ++i) {
            result_check(&out.items[i], s.keys[i], i == 0 || i == 2); CHECK(!s.auth[i]);
            CHECK(s.release_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 3u : i == 2 ? 2u : 0u) : 3 - i));
            CHECK(s.release_lengths[i] == (mixed && i == 0 ? 1u : 4u));
            CHECK(s.release_calls[i] == (mixed && i == 0 ? 2u : 4u));
        }
        br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "mixpanel %s\nmixpanel %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) result_check(&out.items[i], key, false);
    CHECK(out.items[0].raw.data != out.items[3].raw.data && out.items[0].secret_parts != out.items[3].secret_parts); br_results_clear(&out);
    script s; setup(&s, 4, 200);
    out = run(&s, NULL, true, input); CHECK(!out.len && !s.http.calls && !s.http.releases); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void statuses_and_shared_failures(void)
{
    char input[50]; snprintf(input, sizeof(input), "mixpanel %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, 1, statuses[i]); br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 1);
        result_check(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Mixpanel result"}, {7, "out of memory constructing Basic authentication"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        script s; setup(&s, 1, 200); s.send_rc[0] = failures[i].rc; s.causes[0] = failures[i].cause;
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 0);
        result_check(&out.items[0], key, false); br_results_clear(&out);
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
        result_check(&out.items[0], key, false); br_results_clear(&out);
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
    char multi[100], one[50]; snprintf(multi, sizeof(multi), "mixpanel %s\nmixpanel %s", key, other); snprintf(one, sizeof(one), "mixpanel %s", key);
    br_slice data = {(const unsigned char *)multi, strlen(multi)}, single = {(const unsigned char *)one, strlen(one)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    for (size_t failure = 0; failure < 7; ++failure) {
        script s; setup(&s, 4, 200); s.keys[2] = s.keys[3] = other; s.ids[1] = s.ids[3] = other;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 33; fail_after = 2; }
        if (failure == 2) { fail_size = 33; fail_after = 4; } /* Separate ID capture copies. */
        if (failure == 3) arm_raw_after_send = true; /* After regex/header allocations of the same size. */
        if (failure == 4) fail_key_after = 2;
        if (failure == 5) fail_request_after_key = 2;
        if (failure == 6) { fail_size = 95; fail_after = 2; } /* Actual Basic helper +1. */
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after && !arm_raw_after_send);
        CHECK(s.http.calls == (failure < 3 ? 0u : 1u) && s.http.releases == s.http.calls);
        if (failure == 6) CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
        if (failure >= 3) CHECK(s.release_lengths[0] == 2);
        for (size_t i = 0; i < s.count; ++i) CHECK(!s.auth[i]);
        check_prior(&out, &prior); free(error);
    }
    script s; setup(&s, 1, 200); fail_size = 2 * sizeof(br_span); fail_after = 2; char *error = NULL;
    CHECK(invoke(&s, NULL, false, (br_slice){0}, &out, &error) != 0 && error && !fail_after); check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 95; fail_after = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) == 0 && !error && fail_after == 1); fail_after = 0; check_prior(&out, &prior);
    fail_request_after_key = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) == 0 && !error && !fail_request_after_key && fail_module_alloc_after == 1); fail_module_alloc_after = 0; check_prior(&out, &prior);
    fail_key_after = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) != 0 && error && !fail_key_after); check_prior(&out, &prior); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, single, &out, &error) != 0 && error); out.cap = cap;
    CHECK(!strcmp(error, "cannot append Mixpanel result") && s.http.calls == 1 && s.http.releases == 1); check_prior(&out, &prior); free(error);
    fail_key_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_key_after); check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_grammars(); product_and_source_wide_release(); statuses_and_shared_failures(); owned_failures_and_nil_order();
    CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after && !fail_agent && !arm_raw_after_send && !setter_calls);
    return test_finish("Mixpanel independent overlapping Cartesian products");
}
