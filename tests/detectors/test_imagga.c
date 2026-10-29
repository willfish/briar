/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Observe ordinary attempts/releases without replacing shared preparation. */
#define br_http_send imagga_real_send
#define br_http_release imagga_real_release
#define br_http_basic_auth imagga_real_basic_auth
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#undef br_http_basic_auth

#define br_results_push imagga_real_push
#define br_result_set_verification_error imagga_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[73], other[73];
static size_t fail_size, fail_after, fail_part_after, fail_push_after, failed_allocations;
static size_t sends, releases, basic_calls, setter_calls;
static bool fail_agent;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_context;
static const char *const *expected_keys;
static const char *expected_agent;
static size_t expected_count;

/* Reuse the existing named-test allocation and positive-failure seams. */
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

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 7;
    return imagga_real_push(out, owned);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return imagga_real_setter(r, cause, secrets, count);
}

int br_http_basic_auth(br_slice username, br_slice password, char **out, char **error)
{
    ++basic_calls;
    return imagga_real_basic_auth(username, password, out, error);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static void check_request(const br_http_request *r, const char *expected, bool effective)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.imagga.com/v2/usage"));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 349);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (effective ? 3u : 2u));
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!strcmp(r->headers[1].name, "Authorization"));
    CHECK(strlen(r->headers[1].value) == 78 && !memcmp(r->headers[1].value, "Basic ", 6));
    CHECK(!memcmp(r->headers[1].value + 6, expected, 73));
    if (effective) {
        CHECK(!strcmp(r->headers[2].name, "User-Agent"));
        CHECK(!strcmp(r->headers[2].value, expected_agent));
    }
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r,
                 br_http_response *response, char **error)
{
    CHECK(!provider_request && sends == releases && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    provider_request = r; provider_context = ctx; ++sends;
    return imagga_real_send(ctx, r, response, error);
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_context && sends == releases + 1);
    /* Borrow only the provider originals, never synthesized headers/UA. */
    check_request(provider_request, expected_keys[releases], false);
    imagga_real_release(ctx, response);
    check_request(provider_request, expected_keys[releases], false);
    provider_request = NULL; provider_context = NULL; ++releases;
}

static void expect(const char *const *keys, size_t count, const char *agent)
{
    CHECK(!provider_request && !provider_context && sends == releases);
    expected_keys = keys; expected_count = count; expected_agent = agent;
    sends = releases = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    CHECK(provider_request && ctx == provider_context && http->calls == sends && http->releases == releases);
    check_request(r, expected_keys[sends - 1], true);
    CHECK(r->headers[1].value == provider_request->headers[1].value);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 72 && strlen(other) == 72);
    CHECK(br_imagga_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_imagga_init(NULL, NULL) != 0);
    fail_size = sizeof("(?i:imagga)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_imagga_init(&d, &error) != 0 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error);
    CHECK(br_imagga_init(&d, &error) == 0 && d && !error);
    CHECK(br_imagga_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 349 && d->version == 0 && !strcmp(d->name, "Imagga") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Imagga is a cloud-based image recognition and categorization service. Imagga API keys can be used to access and utilize these image processing services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "imagga"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Parent owns registry/default/native integration. */
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 349, expected, "key");
    CHECK(r->raw.len == 72 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_get_string_len(part) == 72);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; expect(NULL, 0, NULL);
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !sends && !releases && !http.calls && !http.releases);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[73], shifted[73];
    const struct { const char *format; bool match; } cases[] = {
        {"imagga '%s'", true}, {"ImAgGa\r\n%s", true}, {"preIMAGGAsuffix:%s", true},
        {"imagga-%s", true}, {"imagga %sX_extra", true}, {"imagga %s==", true},
        {"%s", false}, {"%s imagga", false}, {"ima-gga %s", false},
        {"imagga%s", false}, {"imagga _%s", false}, {"imagga %.71s", false},
        {"imagga %s %s", true}, /* Whole matches consume their keyword prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key, other);
        extract_case(d, input, strlen(input), cases[i].match ? key : NULL);
    }
    const char invalid[] = "_+/-.: ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[36] = invalid[i];
        snprintf(input, sizeof(input), "imagga %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    /* '=' is in the capture alphabet, but a nonword start needs word context. */
    memcpy(changed, key, sizeof(key)); changed[0] = '=';
    snprintf(input, sizeof(input), "imagga%s", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "imagga %s", changed); extract_case(d, input, strlen(input), NULL);
    memcpy(shifted, changed + 1, 71); shifted[71] = 'X'; shifted[72] = '\0';
    snprintf(input, sizeof(input), "imagga %sX", changed); extract_case(d, input, strlen(input), shifted);
    shifted[0] = 'X'; memcpy(shifted + 1, key, 71); shifted[72] = '\0';
    snprintf(input, sizeof(input), "imagga X%s", key); extract_case(d, input, strlen(input), shifted);
    const char repeated[] = "=Aa0";
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 72); changed[72] = '\0';
        snprintf(input, sizeof(input), "imagga%s%s", i ? " " : "", changed);
        extract_case(d, input, strlen(input), changed);
    }
    snprintf(input, sizeof(input), "imagga %s", changed); /* All digits remain allowed. */
    extract_case(d, input, strlen(input), changed);
    memset(changed, '=', 72);
    snprintf(input, sizeof(input), "imagga %s", changed); extract_case(d, input, strlen(input), NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "imagga", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, key, 72);
        extract_case(d, input, 78 + gap, gap == 40 ? key : NULL);
        input[7] = '\r'; input[8] = '\n'; input[9] = '\0';
        extract_case(d, input, 78 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 6 + 2 * gap, key, 72);
        extract_case(d, input, 78 + 2 * gap, gap == 40 ? key : NULL);
    }
    extract_case(d, NULL, 0, NULL);
}

static void occurrences_and_literal_auth(const br_detector *d)
{
    char input[320]; snprintf(input, sizeof(input), "imagga %s\nimagga %s\nimagga %s", key, other, key);
    const char *keys[] = {key, other, key};
    test_http http = {.inspect = inspect, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "imagga-offline"};
    expect(NULL, 0, NULL);
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !sends && !releases && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    expect(keys, 3, "TruffleHog imagga-offline");
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 3 && sends == 3 && releases == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], true);
    br_results_clear(&out);
    expect(NULL, 0, NULL);
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !sends && !releases); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && !sends && !releases); br_results_clear(&out);
    char equals[73]; memset(equals, '=', 72); equals[72] = '\0';
    snprintf(input, sizeof(input), "imagga%s", equals);
    const char *edge[] = {equals}; http.calls = http.releases = 0;
    expect(edge, 1, "TruffleHog imagga-offline");
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], equals, true); br_results_clear(&out);
    CHECK(!basic_calls && !setter_calls);
}

static void verification(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "imagga %s", key);
    const char *keys[] = {key}; test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored read error"};
        expect(keys, 1, "TruffleHog");
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {1, "out of memory constructing HTTP headers"}, {-1, "cannot create Imagga result"},
        {7, key}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        expect(keys, 1, "TruffleHog");
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void shared_setup(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "imagga %s", key);
    const char *keys[] = {key}; size_t cancellations = 0;
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    br_transport no_send = {&http, NULL, test_http_release}, no_release = {&http, test_http_send, NULL};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_release}, {.transport = &no_send},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        expect(keys, 1, NULL);
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && sends == 1 && releases == 1 && !http.calls);
        CHECK(http.releases == (i >= 2 ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i >= 6 ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "imagga %s\nimagga %s", key, other);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    const char *keys[] = {key, other}; test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; char *error = NULL;
    for (size_t failure = 0; failure < 6; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 73; fail_after = 2; }
        if (failure == 2) fail_part_after = 1;
        if (failure == 3) { fail_size = 72; fail_after = 2; }
        if (failure == 4) fail_part_after = 2;
        if (failure == 5) fail_push_after = 2;
        http.calls = http.releases = 0;
        http.send_rc = failure == 4 ? 7 : 0; http.send_error = failure == 4 ? "cannot create Imagga result" : NULL;
        expect(keys, 2, "TruffleHog");
        CHECK(d->scan(d, failure <= 2 ? NULL : &ctx, true, text(input), &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && !fail_push_after);
        size_t attempts = failure <= 2 ? 0 : failure == 5 ? 2 : 1;
        CHECK(sends == attempts && releases == sends && http.calls == sends && http.releases == sends);
        const char *cause = failure == 0 ? "out of memory iterating regex" :
                            failure == 1 ? "out of memory copying detector capture" :
                            failure == 5 ? "cannot append Imagga result" : "cannot create Imagga result";
        CHECK(!strcmp(error, cause)); free(error); error = NULL;
        prior_unchanged(&out, &prior);
    }
    /* Own finding failure remains fatal before the nil-constructor drop, even
     * without a diagnostic output. NoV push failures also roll back this call. */
    expect(NULL, 0, NULL); fail_size = 72; fail_after = 1;
    CHECK(d->scan(d, NULL, true, text(input), &out, NULL) != 0 && !fail_after);
    prior_unchanged(&out, &prior);
    fail_push_after = 2;
    CHECK(d->scan(d, NULL, false, text(input), &out, &error) != 0 && error && !fail_push_after);
    CHECK(!strcmp(error, "cannot append Imagga result") && !sends && !releases); free(error);
    prior_unchanged(&out, &prior); br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
}

int main(void)
{
    test_secret(key, 72, 0); key[0] = 'Q'; key[17] = '='; key[71] = '=';
    test_secret(other, 72, 7); other[0] = 'Z'; other[29] = '=';
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_literal_auth(d); verification(d); shared_setup(d); owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_agent && !basic_calls && !setter_calls);
    CHECK(!provider_request && !provider_context && sends == releases);
    return test_finish("Imagga grammar/occurrences/metadata/literal-auth/status/ignored-body/errors/release/rollback");
}
