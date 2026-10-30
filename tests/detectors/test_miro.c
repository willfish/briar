/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_miro_init(const br_detector **out, char **error);

#define br_result_set_verification_error miro_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const br_detector *detector;
static char key[28], other[28];
static size_t fail_size, fail_after, fail_key_after, fail_request_after_key, fail_module_alloc_after, setter_calls;
static bool fail_agent;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t count;
    const char *keys[3], *causes[3], *auth[3];
    int statuses[3], send_rc[3];
    br_header markers[3];
    size_t release_ids[3], release_lengths[3], release_calls[3];
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
    return miro_real_setter(result, cause, secrets, count);
}

static void check_result(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 774, value, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void check_auth(const char *authorization, const char *value)
{
    CHECK(authorization && strlen(authorization) == 34 && !memcmp(authorization, "Bearer ", 7));
    CHECK(!memcmp(authorization + 7, value, 28));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && !s->auth[at]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.miro.com/v1/users/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 774);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog miro-offline"));
    /* Borrow provider auth, not synthesized prepared request/header-array/UA. */
    s->auth[at] = request->headers[1].value; check_auth(s->auth[at], s->keys[at]);
    s->markers[at] = (br_header){"synthetic-attempt", s->keys[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored read failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    size_t at = 0;
    while (at < s->count && response->headers != &s->markers[at]) ++at;
    CHECK(http->releases < 3 && s->out && !setter_calls);
    if (at < s->count) { check_auth(s->auth[at], s->keys[at]); s->auth[at] = NULL; }
    else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_ids[http->releases] = at;
    s->release_lengths[http->releases] = s->out->len;
    s->release_calls[http->releases] = http->calls;
    test_http_release(user, response);
}

static void setup(script *s, size_t count, int status)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) { s->keys[i] = key; s->statuses[i] = status; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "miro-offline"};
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

static void extract_case(const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && !setter_calls);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void descriptor_and_extraction(void)
{
    test_secret(key, 27, 0); test_secret(other, 27, 9); key[0] = 'Z'; key[8] = 'A'; other[1] = 'Q';
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 27 && strlen(other) == 27);
    CHECK(br_miro_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Miro detector output")); free(error);
    CHECK(br_miro_init(NULL, NULL) != 0);
    CHECK(br_miro_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_miro_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 774 && detector->version == 0 && !strcmp(detector->name, "Miro") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Miro is an online collaborative whiteboarding platform. Miro API keys can be used to access and modify data and collaborate on whiteboards."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "miro"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    char input[300], changed[28];
    const char *good[] = {"miro %s", "MiRo '%s'", "preMIROsuffix\r\n%s", "miro\r%s", "miro\n%s", "miro \xc3\xa9%s\xc3\xa9"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extract_case(input, strlen(input), key);
    }
    const char *bad[] = {"%s", "%s miro", "miro%s", "miro _%s", "miro %s_", "miro %sx", "miro %.26s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(input, strlen(input), NULL);
    }
    const char invalid[] = {'_', '-', '/', ' ', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "miro %s", changed); extract_case(input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "miro", 4); memset(input + 4, '-', gap); memcpy(input + 4 + gap, key, 27);
        extract_case(input, 31 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 4 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 4 + 4 * gap, key, 27); extract_case(input, 31 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "miro\0", 5); memcpy(input + 5, key, 27); extract_case(input, 32, key);
    snprintf(input, sizeof(input), "miro %s %s", key, other); extract_case(input, strlen(input), key);
    memset(changed, 'a', 27); changed[27] = 0;
    snprintf(input, sizeof(input), "miro %s", changed); extract_case(input, strlen(input), changed);
    extract_case(NULL, 0, NULL);
}

static void occurrences_and_release_order(void)
{
    char input[120]; snprintf(input, sizeof(input), "miro %s\nmiro %s\nmiro %s", key, other, key);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        script s; setup(&s, 3, 200); s.keys[1] = other; s.statuses[1] = 401; s.statuses[2] = 299;
        if (mixed) { s.send_rc[1] = 7; s.causes[1] = "cannot construct Miro request"; }
        br_results out = run(&s, NULL, false, input); CHECK(out.len == 3 && !s.http.calls && !s.http.releases);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], s.keys[i], false);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
        out = run(&s, &s.ctx, true, input); CHECK(out.len == 3 && s.http.calls == 3 && s.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) {
            check_result(&out.items[i], s.keys[i], i != 1); CHECK(!s.auth[i]);
            CHECK(s.release_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 2u : 0u) : 2 - i));
            CHECK(s.release_lengths[i] == (mixed && i == 0 ? 1u : 3u));
            CHECK(s.release_calls[i] == (mixed && i == 0 ? 2u : 3u));
        }
        br_results_clear(&out);
    }
    script s; setup(&s, 3, 200);
    br_results out = run(&s, NULL, true, input); CHECK(!out.len && !s.http.calls && !s.http.releases); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void statuses_and_shared_failures(void)
{
    char input[40]; snprintf(input, sizeof(input), "miro %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, 1, statuses[i]);
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        CHECK(s.release_lengths[0] == 1); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Miro result"}, {7, "cannot construct Miro request"}, {-1, NULL}, {1, key},
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
    char multi[80], one[40]; snprintf(multi, sizeof(multi), "miro %s\nmiro %s", key, key); snprintf(one, sizeof(one), "miro %s", key);
    br_slice data = {(const unsigned char *)multi, strlen(multi)}, single = {(const unsigned char *)one, strlen(one)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    for (size_t failure = 0; failure < 5; ++failure) {
        script s; setup(&s, 2, 200);
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 28; fail_after = 2; }
        if (failure == 2) { fail_size = 27; fail_after = 2; }
        if (failure == 3) fail_key_after = 2;
        if (failure == 4) fail_request_after_key = 2;
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after);
        CHECK(s.http.calls == (failure < 2 ? 0u : 1u) && s.http.releases == s.http.calls);
        if (failure == 4) CHECK(!strcmp(error, "cannot construct Miro request"));
        if (failure >= 2) CHECK(s.release_lengths[0] == 2);
        for (size_t i = 0; i < s.count; ++i) CHECK(!s.auth[i]);
        check_prior(&out, &prior); free(error);
    }
    script s; setup(&s, 1, 204); char *error = NULL;
    /* No request/header/auth allocation is reached after the nil constructor. */
    fail_request_after_key = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) == 0 && !error && !fail_request_after_key && fail_module_alloc_after == 1);
    fail_module_alloc_after = 0; check_prior(&out, &prior);
    fail_key_after = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) != 0 && error && !fail_key_after);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_request_after_key = 1;
    CHECK(invoke(&s, NULL, false, single, &out, &error) == 0 && !error && !fail_request_after_key && fail_module_alloc_after == 1);
    fail_module_alloc_after = 0; CHECK(out.len == 2); br_result_clear(&out.items[--out.len]); check_prior(&out, &prior);
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, single, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Miro result") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error);
    fail_key_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_key_after);
    check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_extraction(); occurrences_and_release_order(); statuses_and_shared_failures(); owned_failures_and_nil_order();
    CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after && !fail_agent && !setter_calls);
    return test_finish("Miro");
}
