/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"
#include <pthread.h>
#include <time.h>

int br_mixmax_init(const br_detector **out, char **error);

/* Observe provider storage, forwarding unchanged through actual guards/client
 * dispatch. Never wrap a borrowed transport, remove keys or fabricate success. */
#define br_http_send mixmax_real_send
#define br_http_release mixmax_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#define br_result_set_verification_error mixmax_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const br_detector *detector;
static char key[37], other[37];
static size_t fail_size, fail_after, fail_key_after, fail_request_after_key, fail_module_alloc_after, setter_calls;
static bool fail_guard_copy;
/* Module-failure seams never consume shared-client/worker allocations. */
static _Thread_local bool module_scope;

typedef struct {
    pthread_mutex_t mutex;
    const br_http_request *raw_request;
    br_results *out;
    const char *keys[3], *read_errors[3], *causes[3];
    int statuses[3], send_rc[3];
    size_t count, calls, releases, lengths[3];
    unsigned char body[4];
    br_header header;
    bool destroyed;
} owned_fixture;
typedef struct {
    const br_scan_ctx *ctx;
    br_results *out;
    owned_fixture *fixture;
    const char *keys[3];
    const br_http_request *requests[3];
    br_http_response *responses[3];
    int rc[3];
    size_t count, sends, releases, release_ids[3], release_lengths[3];
} script;
static script *active;

void *malloc(size_t size)
{
    if (module_scope && ((fail_module_alloc_after && --fail_module_alloc_after == 0) ||
        (size == fail_size && fail_after && --fail_after == 0))) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_guard_copy && !strcmp(text, "unsupported HTTP request coalescing")) { fail_guard_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (module_scope && !strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && module_scope && !strcmp(name, "key") && fail_request_after_key && --fail_request_after_key == 0)
        fail_module_alloc_after = 1;
    return rc;
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return mixmax_real_setter(result, cause, secrets, count);
}

static void check_request(const br_http_request *request, const char *value, bool effective)
{
    CHECK(request && !strcmp(request->method, "GET") && !strcmp(request->url, "https://api.mixmax.com/v1/users/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 700);
    CHECK(effective ? request->timeout_ms > 0 && request->timeout_ms <= 5000 : !request->timeout_ms);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->dedup_key.len == 40 && !memcmp(request->dedup_key.data, "700:", 4));
    CHECK(!memcmp(request->dedup_key.data + 4, value, 36));
    CHECK(request->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(request->headers[0].name, "X-Api-Token") && !strcmp(request->headers[0].value, value));
    if (effective) CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog mixmax-offline"));
    else CHECK(request->dedup_key.data[40] == 0);
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    script *s = active; CHECK(s && ctx == s->ctx && s->sends < s->count);
    size_t at = s->sends++; check_request(request, s->keys[at], false);
    s->requests[at] = request; s->responses[at] = response;
    bool previous = module_scope; module_scope = false;
    int rc = mixmax_real_send(ctx, request, response, error);
    module_scope = previous; s->rc[at] = rc;
    if (!br_http_client_is_owned(ctx->transport)) {
        CHECK(rc != 0 && !response->status && !response->headers && !response->body.data && !response->body_error);
        if (error && *error) CHECK(!strcmp(*error, ctx->transport ? "unsupported HTTP request coalescing" : "HTTP transport not installed"));
    } else {
        CHECK(!response->body_error);
        if (s->fixture) {
            owned_fixture *f = s->fixture; CHECK(!pthread_mutex_lock(&f->mutex));
            CHECK(f->calls == f->releases && !f->raw_request);
            if (!rc) {
                static const unsigned char original[] = {0xff, 0, '{', ']'};
                CHECK(response->body.data != f->body && response->body.len == sizeof(original));
                CHECK(!memcmp(response->body.data, original, sizeof(original)) && f->body[0] == '!');
                CHECK(response->nheaders == 1 && !strcmp(response->headers[0].name, "X-Synthetic"));
                CHECK(!strcmp(response->headers[0].value, "buffered"));
            }
            CHECK(!pthread_mutex_unlock(&f->mutex));
        }
    }
    return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    script *s = active; CHECK(s && ctx == s->ctx && s->out && !setter_calls);
    size_t at = 0;
    while (at < s->sends && s->responses[at] != response) ++at;
    CHECK(at < s->sends && s->requests[at] && s->releases < 3);
    check_request(s->requests[at], s->keys[at], false);
    s->release_ids[s->releases] = at; s->release_lengths[s->releases++] = s->out->len;
    bool previous = module_scope; module_scope = false;
    mixmax_real_release(ctx, response);
    module_scope = previous;
    s->requests[at] = NULL; s->responses[at] = NULL;
}

static int64_t fixture_now(void)
{
    struct timespec now; CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int fixture_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    owned_fixture *f = user;
    /* Serialize each raw byte transaction through release, including competing
     * workers. Check deadlines after acquiring the transaction mutex. */
    if (pthread_mutex_lock(&f->mutex)) abort();
    size_t at = f->calls++; CHECK(at < f->count && !f->destroyed && !f->raw_request && f->out);
    CHECK(ctx->transport && ctx->transport->user == f && !ctx->cancelled && !ctx->cancel_user);
    CHECK(ctx->deadline_monotonic_ms > 0); check_request(request, f->keys[at], true);
    f->raw_request = request; /* The owned raw snapshot has through-release lifetime. */
    f->body[0] = 0xff; f->body[1] = 0; f->body[2] = '{'; f->body[3] = ']';
    f->header = (br_header){"X-Synthetic", "buffered"};
    *response = (br_http_response){.status = f->statuses[at], .headers = &f->header, .nheaders = 1,
        .body = {f->body, sizeof(f->body)}, .body_error = f->read_errors[at]};
    int rc = f->send_rc[at];
    const char *cause = f->causes[at];
    if (fixture_now() >= ctx->deadline_monotonic_ms) { rc = 1; cause = "synthetic deadline exceeded"; }
    *error = cause ? strdup(cause) : NULL; CHECK(!cause || *error);
    return rc; /* The same raw worker releases and unlocks, even on failure. */
}

static void fixture_release(void *user, br_http_response *response)
{
    owned_fixture *f = user; /* Transaction mutex remains held from send. */
    CHECK(f->raw_request && f->releases < f->calls && response);
    check_request(f->raw_request, f->keys[f->releases], true);
    f->lengths[f->releases++] = f->out->len;
    memset(f->body, '!', sizeof(f->body)); /* Buffer copy must precede raw close. */
    f->raw_request = NULL;
    CHECK(!pthread_mutex_unlock(&f->mutex));
}

static void fixture_destroy(void *user)
{
    owned_fixture *f = user; CHECK(!f->raw_request && f->calls == f->releases);
    f->destroyed = true;
}

static void prepare(script *s, const br_scan_ctx *ctx, size_t count, owned_fixture *fixture)
{
    *s = (script){.ctx = ctx, .count = count, .fixture = fixture};
    for (size_t i = 0; i < count; ++i) s->keys[i] = key;
    if (fixture) {
        CHECK(!pthread_mutex_lock(&fixture->mutex));
        fixture->count = count; fixture->calls = fixture->releases = 0;
        for (size_t i = 0; i < count; ++i) { fixture->keys[i] = key; fixture->statuses[i] = 200; fixture->send_rc[i] = 0; fixture->read_errors[i] = fixture->causes[i] = NULL; }
        CHECK(!pthread_mutex_unlock(&fixture->mutex));
    }
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out; active = s;
    if (s->fixture) { CHECK(!pthread_mutex_lock(&s->fixture->mutex)); s->fixture->out = out; CHECK(!pthread_mutex_unlock(&s->fixture->mutex)); }
    module_scope = true;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    module_scope = false;
    if (s->fixture) { CHECK(!pthread_mutex_lock(&s->fixture->mutex)); s->fixture->out = NULL; CHECK(!pthread_mutex_unlock(&s->fixture->mutex)); }
    s->out = NULL; active = NULL;
    return rc;
}

static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}

static void result_check(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 700, value, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const void *input, size_t len, const char *expected)
{
    br_results out = test_scan(detector, NULL, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u)); if (expected) result_check(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void descriptor_and_grammar(void)
{
    test_secret(key, 36, 0); test_secret(other, 36, 9); key[0] = 'Z'; key[8] = '_'; key[17] = '-'; other[1] = 'Q'; other[9] = '-';
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_mixmax_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Mixmax detector output")); free(error);
    CHECK(br_mixmax_init(NULL, NULL) != 0);
    CHECK(br_mixmax_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_mixmax_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 700 && detector->version == 0 && !strcmp(detector->name, "Mixmax") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Mixmax is a communication platform for email enhancement and automation. Mixmax API tokens can be used to access and manage email communication and automation features."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mixmax"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    char input[300], changed[37];
    const char *good[] = {"mixmax %s", "MIXmax '%s'", "premixmaxsuffix\r\n%s", "mixmax\r%s", "mixmax\n%s", "mixmax \xc3\xa9%s\xc3\xa9"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract_case(input, strlen(input), key); }
    const char *bad[] = {"%s", "%s mixmax", "mixmax%s", "mixmax x%s", "mixmax %sx", "mixmax %.35s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract_case(input, strlen(input), NULL); }
    memcpy(changed, key, sizeof(changed)); changed[12] = '/'; snprintf(input, sizeof(input), "mixmax %s", changed); extract_case(input, strlen(input), NULL);
    memcpy(changed, key, sizeof(changed)); changed[0] = changed[35] = '_'; snprintf(input, sizeof(input), "mixmax %s", changed); extract_case(input, strlen(input), changed);
    changed[0] = '-'; snprintf(input, sizeof(input), "mixmax %s", changed); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mixmax Z%s", changed); extract_case(input, strlen(input), changed);
    memcpy(changed, key, sizeof(changed)); changed[35] = '-'; snprintf(input, sizeof(input), "mixmax %s", changed); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mixmax %sa", changed); extract_case(input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "mixmax", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, key, 36); extract_case(input, 42 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 6 + 4 * gap, key, 36); extract_case(input, 42 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "mixmax\0", 7); memcpy(input + 7, key, 36); extract_case(input, 43, key);
    snprintf(input, sizeof(input), "mixmax %s %s", key, other); extract_case(input, strlen(input), key);
    memset(changed, 'a', 36); changed[36] = 0; snprintf(input, sizeof(input), "mixmax %s", changed); extract_case(input, strlen(input), changed);
    extract_case(NULL, 0, NULL); CHECK(!setter_calls);
}

static void forbidden(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request; CHECK(!"borrowed keyed guard must precede backend invocation");
}

static void borrowed_guard_and_noverifier(void)
{
    char input[160]; snprintf(input, sizeof(input), "mixmax %s\nmixmax %s\nmixmax %s", key, other, key);
    test_http http = {.inspect = forbidden}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mixmax-offline"}; script s;
    prepare(&s, &ctx, 3, NULL); s.keys[1] = other;
    br_results out = run(&s, &ctx, false, input); CHECK(out.len == 3 && !s.sends && !s.releases && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result_check(&out.items[i], s.keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = run(&s, &ctx, true, input); CHECK(out.len == 3 && s.sends == 3 && s.releases == 3 && !http.calls && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_check(&out.items[i], s.keys[i], false);
    br_results_clear(&out);
    prepare(&s, NULL, 0, NULL); out = run(&s, NULL, true, input); CHECK(!out.len && !s.sends && !s.releases); br_results_clear(&out);
    char one[50]; snprintf(one, sizeof(one), "mixmax %s", key);
    prepare(&s, &ctx, 1, NULL); fail_guard_copy = true;
    out = run(&s, &ctx, true, one); CHECK(out.len == 1 && !fail_guard_copy && s.sends == 1 && s.releases == 1 && !http.calls); result_check(&out.items[0], key, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; prepare(&s, &missing, 1, NULL);
    out = run(&s, &missing, true, one); CHECK(out.len == 1 && s.sends == 1 && s.releases == 1); result_check(&out.items[0], key, false); br_results_clear(&out);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->verified && prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void owned_checks(void)
{
    owned_fixture first = {0}, second = {0}; CHECK(!pthread_mutex_init(&first.mutex, NULL) && !pthread_mutex_init(&second.mutex, NULL));
    br_http_owned_backend backends[] = {
        {.transport = {&first, fixture_send, fixture_release}, .destroy = fixture_destroy},
        {.transport = {&second, fixture_send, fixture_release}, .destroy = fixture_destroy},
    };
    br_http_client *clients[2] = {0}; char *error = NULL;
    for (size_t i = 0; i < 2; ++i) CHECK(br_http_client_init(&clients[i], backends[i], BR_HTTP_SANE, &error) == 0 && clients[i] && !error);
    br_scan_ctx contexts[] = {
        {.transport = br_http_client_transport(clients[0]), .user_agent = "mixmax-offline"},
        {.transport = br_http_client_transport(clients[1]), .user_agent = "mixmax-offline"},
    };
    CHECK(contexts[0].transport != contexts[1].transport && br_http_client_is_owned(contexts[0].transport) && br_http_client_is_owned(contexts[1].transport));
    const struct { int status, rc; const char *read_error, *cause; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, 0, "buffered read failed", NULL, false}, {299, 0, "", NULL, false},
        {200, 1, NULL, "cannot create Mixmax result", false}, {200, -7, NULL, key, false}, {200, 1, NULL, NULL, false},
    };
    char one[50]; snprintf(one, sizeof(one), "mixmax %s", key); script s;
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        prepare(&s, &contexts[0], 1, &first); first.statuses[0] = cases[i].status; first.send_rc[0] = cases[i].rc; first.read_errors[0] = cases[i].read_error; first.causes[0] = cases[i].cause;
        br_results out = run(&s, &contexts[0], true, one);
        CHECK(out.len == 1 && s.sends == 1 && s.releases == 1 && first.calls == 1 && first.releases == 1 && first.lengths[0] == 0);
        result_check(&out.items[0], key, cases[i].verified); CHECK(s.release_lengths[0] == (s.rc[0] ? 0u : 1u)); br_results_clear(&out);
    }
    /* A separately selected client reaches only its own backend, with the same full key. */
    prepare(&s, &contexts[1], 1, &second); second.statuses[0] = 401;
    br_results out = run(&s, &contexts[1], true, one); CHECK(second.calls == 1 && second.releases == 1); result_check(&out.items[0], key, false); br_results_clear(&out);
    char input[160]; snprintf(input, sizeof(input), "mixmax %s\nmixmax %s\nmixmax %s", key, other, key);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        prepare(&s, &contexts[0], 3, &first); s.keys[1] = first.keys[1] = other; first.statuses[1] = 401; first.statuses[2] = 299;
        if (mixed) first.read_errors[1] = "";
        out = run(&s, &contexts[0], true, input); CHECK(out.len == 3 && s.sends == 3 && s.releases == 3 && first.calls == 3 && first.releases == 3);
        for (size_t i = 0; i < 3; ++i) {
            result_check(&out.items[i], s.keys[i], i != 1);
            CHECK(first.lengths[i] == i); /* Raw close before each candidate's publication. */
            CHECK(s.release_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 2u : 0u) : 2 - i));
            CHECK(s.release_lengths[i] == (mixed && i == 0 ? 1u : 3u));
        }
        br_results_clear(&out);
    }
    /* Owned shared preparation rejection remains ordinary and makes no raw call. */
    prepare(&s, &contexts[0], 1, &first); contexts[0].user_agent = "bad\r\nagent";
    out = run(&s, &contexts[0], true, one); CHECK(out.len == 1 && !first.calls && !first.releases && s.sends == 1 && s.releases == 1); result_check(&out.items[0], key, false); br_results_clear(&out);
    contexts[0].user_agent = "mixmax-offline";
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    out = (br_results){0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char twice[100]; snprintf(twice, sizeof(twice), "mixmax %s\nmixmax %s", key, key); br_slice data = {(const unsigned char *)twice, strlen(twice)};
    for (size_t failure = 0; failure < 5; ++failure) {
        prepare(&s, &contexts[0], 2, &first);
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 37; fail_after = 2; }
        if (failure == 2) { fail_size = 36; fail_after = 2; }
        if (failure == 3) fail_key_after = 2;
        if (failure == 4) fail_request_after_key = 2;
        CHECK(invoke(&s, &contexts[0], true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after);
        CHECK(s.sends == (failure < 2 ? 0u : 1u) && s.releases == s.sends && first.calls == s.sends && first.releases == first.calls);
        if (failure >= 2) CHECK(s.release_lengths[0] == 2);
        check_prior(&out, &prior); free(error); error = NULL;
    }
    prepare(&s, NULL, 0, NULL); fail_key_after = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) != 0 && error && !fail_key_after); check_prior(&out, &prior); free(error); error = NULL;
    br_slice single = {(const unsigned char *)one, strlen(one)};
    fail_request_after_key = 1;
    CHECK(invoke(&s, NULL, true, single, &out, &error) == 0 && !error && !fail_request_after_key && fail_module_alloc_after == 1); fail_module_alloc_after = 0; check_prior(&out, &prior);
    fail_key_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_key_after); check_prior(&out, &prior);
    prepare(&s, &contexts[0], 1, &first); size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &contexts[0], true, single, &out, &error) != 0 && error); out.cap = cap;
    CHECK(!strcmp(error, "cannot append Mixmax result") && s.sends == 1 && s.releases == 1 && first.calls == 1 && first.releases == 1); check_prior(&out, &prior); free(error); error = NULL; br_results_clear(&out);
    /* Drain ALL selected clients before destroying ANY backend/client. */
    for (size_t i = 0; i < 2; ++i) CHECK(br_http_client_drain(clients[i], &error) == 0 && !error);
    for (size_t i = 0; i < 2; ++i) br_http_client_destroy(clients[i]);
    CHECK(first.destroyed && second.destroyed && !pthread_mutex_destroy(&first.mutex) && !pthread_mutex_destroy(&second.mutex));
}

int main(void)
{
    descriptor_and_grammar(); borrowed_guard_and_noverifier(); owned_checks();
    CHECK(!active && !module_scope && !fail_after && !fail_key_after && !fail_request_after_key && !fail_module_alloc_after && !fail_guard_copy && !setter_calls);
    return test_finish("Mixmax real guard + owned buffered replay");
}
