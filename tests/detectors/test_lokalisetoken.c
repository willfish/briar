/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_json.h"
#include "../support/detector_test.h"

int br_lokalisetoken_init(const br_detector **out, char **error);

/* Existing named-test seams retain real HTTP preparation and string codecs. */
#define br_result_set_verification_error lokalise_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#define br_gcp_json_text lokalise_real_text
#include "../../src/detectors/gcp_json.c"
#undef br_gcp_json_text

static char key[41], other[41];
static const br_detector *detector;
static size_t fail_size, fail_after, fail_key_after, fail_metadata_after, fail_setter_after, fail_projection_after;
static size_t setter_calls, projection_calls, fail_join_after_setter;
static const char *fail_strdup_text;
static size_t fail_strdup_after;
static bool fail_agent, fail_repair;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t original_len, setters_before;
    const char *borrowed_token, *fixture;
    size_t fixture_len;
    char response_storage[2048];
    bool verified, release_per_finding;
} script;
static script *active;

void *malloc(size_t size)
{
    if (size == fail_size && fail_after && --fail_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if ((fail_agent && !strcmp(text, "TruffleHog")) ||
        (fail_strdup_after && fail_strdup_text && !strcmp(text, fail_strdup_text) && --fail_strdup_after == 0)) {
        fail_agent = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 7;
    if (!strcmp(name, "project creators")) {
        CHECK(active && active->out && active->http.calls == active->http.releases);
        CHECK(setter_calls == active->setters_before + active->http.calls);
        CHECK(active->out->len + 1 == active->original_len + active->http.calls);
        if (fail_metadata_after && --fail_metadata_after == 0) return 7;
    }
    return json_object_object_add_ex(object, name, value, 0);
}

int br_gcp_json_text(br_json *value, br_slice *out, br_bytes *repair, char **error)
{
    ++projection_calls;
    if (fail_projection_after && --fail_projection_after == 0) {
        if (error) *error = strdup("synthetic positive LokaliseToken projection failure");
        return 1;
    }
    if (fail_repair) { fail_repair = false; fail_size = 4; fail_after = 1; }
    return lokalise_real_text(value, out, repair, error);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    CHECK(secrets && count == 1 && secrets[0].len == 40 && !memcmp(secrets[0].data, result->raw.data, 40));
    CHECK(result->extra_data && !json_object_object_length(result->extra_data));
    if (active) {
        size_t expected_releases = active->release_per_finding ? setter_calls - active->setters_before + 1 : 0;
        CHECK(active->http.releases == expected_releases && !active->borrowed_token);
        CHECK(result->verified == active->verified);
        CHECK(active->out && active->out->len == active->original_len + setter_calls - active->setters_before);
    }
    ++setter_calls;
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    int rc = lokalise_real_setter(result, cause, secrets, count);
    if (!rc && fail_join_after_setter && --fail_join_after_setter == 0) {
        fail_size = sizeof("join@example.invalid"); fail_after = 1;
    }
    return rc;
}

static void check_result(const br_result *result, const char *value, bool verified, const char *cause,
                          const void *creators, size_t creators_len)
{
    CHECK(result->detector_type == 129 && result->raw.len == 40 && !memcmp(result->raw.data, value, 40));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set && !result->verification_from_cache);
    br_json *part = NULL, *metadata = NULL;
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 40 && !memcmp(json_object_get_string(part), value, 40));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == (creators ? 1 : 0));
    if (creators) {
        CHECK(json_object_object_get_ex(result->extra_data, "project creators", &metadata) && json_object_is_type(metadata, json_type_string));
        CHECK((size_t)json_object_get_string_len(metadata) == creators_len && !memcmp(json_object_get_string(metadata), creators, creators_len));
    }
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx == &s->ctx && http->calls == http->releases + 1 && !s->borrowed_token);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.lokalise.com/api2/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 129);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Token"));
    CHECK(!strcmp(request->headers[0].value, key) || !strcmp(request->headers[0].value, other));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog lokalise-offline"));
    s->borrowed_token = request->headers[0].value; /* Provider-original storage only. */
    if (s->fixture) {
        CHECK(s->fixture_len < sizeof(s->response_storage));
        memcpy(s->response_storage, s->fixture, s->fixture_len);
        http->response.body = (br_slice){(const unsigned char *)s->response_storage, s->fixture_len};
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_token) {
        CHECK(!strcmp(s->borrowed_token, key) || !strcmp(s->borrowed_token, other));
        s->borrowed_token = NULL;
    } else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    CHECK(s->out && s->out->len == s->original_len + setter_calls - s->setters_before);
    memset(s->response_storage, '!', s->fixture_len); /* Returned creators must already own their strings. */
    test_http_release(user, response);
}

static void setup(script *s, int status, const char *body, const char *read_error, bool verified)
{
    *s = (script){.fixture = body, .fixture_len = body ? strlen(body) : 0, .verified = verified};
    s->http = (test_http){.response = {.status = status, .body_error = read_error}, .inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "lokalise-offline"};
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out; s->original_len = out->len; s->setters_before = setter_calls;
    s->release_per_finding = ctx && ctx->transport && ctx->transport->release;
    active = s;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    active = NULL; s->out = NULL;
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
    size_t before = setter_calls;
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected) check_result(&out.items[0], expected, false, NULL, NULL, 0);
    br_results_clear(&out);
}

static void descriptor_and_extraction(void)
{
    test_secret(key, 40, 0); test_secret(other, 40, 9);
    const br_detector *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strchr(key, 'g') && strlen(key) == 40);
    CHECK(br_lokalisetoken_init(NULL, &error) != 0 && error && !strcmp(error, "invalid LokaliseToken detector output")); free(error);
    CHECK(br_lokalisetoken_init(NULL, NULL) != 0);
    CHECK(br_lokalisetoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_lokalisetoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 129 && detector->version == 0 && !strcmp(detector->name, "LokaliseToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Lokalise is a translation management system that helps teams to manage and automate their localization process. Lokalise tokens can be used to access its API and modify project data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "lokalise"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    char input[400], changed[41];
    const char *good[] = {"lokalise %s", "LoKaLiSe '%s'", "prelokalisesuffix\r\n%s", "lokalise\r%s", "lokalise\n%s", "lokalise \xc3\xa9%s\xc3\xa9"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extract_case(input, strlen(input), key);
    }
    const char *bad[] = {"%s", "%s lokalise", "lokalise%s", "lokalise _%s", "lokalise %s_", "lokalise %sa", "lokalise %.39s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(changed)); changed[13] = 'Z';
    snprintf(input, sizeof(input), "LOKALISE %s", changed); extract_case(input, strlen(input), NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "lokalise", 8); memset(input + 8, '-', gap); memcpy(input + 8 + gap, key, 40);
        extract_case(input, 48 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 8 + 4 * gap, key, 40); extract_case(input, 48 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "lokalise\0", 9); memcpy(input + 9, key, 40); extract_case(input, 49, key);
    snprintf(input, sizeof(input), "lokalise %s %s", key, other); extract_case(input, strlen(input), key);
    extract_case(NULL, 0, NULL);
    snprintf(input, sizeof(input), "lokalise %s\nlokalise %s\nlokalise %s", key, other, key);
    script s; setup(&s, 200, "{}", NULL, true); size_t before = setter_calls;
    br_results out = run(&s, NULL, false, input);
    CHECK(out.len == 3 && !s.http.calls && !s.http.releases && setter_calls == before);
    const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], false, NULL, NULL, 0);
    CHECK(out.items[0].extra_data != out.items[2].extra_data && out.items[0].raw.data != out.items[2].raw.data);
    br_results_clear(&out);
    out = run(&s, &s.ctx, true, input); CHECK(out.len == 3 && s.http.calls == 3 && s.http.releases == 3 && setter_calls == before + 3);
    for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], true, NULL, NULL, 0);
    br_results_clear(&out);
}

static void ordinary_verification(void)
{
    char input[60]; snprintf(input, sizeof(input), "lokalise %s", key);
    const struct { int status; bool verified; const char *cause; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {201, false, "unexpected status code: 201"}, {422, false, "unexpected status code: 422"}, {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, statuses[i].status, "not JSON", "body read failed", statuses[i].verified);
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, statuses[i].verified, statuses[i].cause, NULL, 0); br_results_clear(&out);
    }
    char with_key[140]; snprintf(with_key, sizeof(with_key), "transport %s then %s", key, key);
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create LokaliseToken result"}, {7, "cannot project LokaliseToken response"}, {-1, NULL}, {1, with_key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        script s; setup(&s, 200, NULL, NULL, false); s.http.send_rc = failures[i].rc; s.http.send_error = failures[i].cause;
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        const char *cause = i == 4 ? "transport [REDACTED] then [REDACTED]" : failures[i].cause ? failures[i].cause : "HTTP transport failed";
        check_result(&out.items[0], key, false, cause, NULL, 0); br_results_clear(&out);
    }
    script s; setup(&s, 200, NULL, NULL, false);
    br_results out = run(&s, NULL, true, input); CHECK(out.len == 1 && !s.http.calls && !s.http.releases);
    check_result(&out.items[0], key, false, "net/http: nil Context", NULL, 0); br_results_clear(&out);
}

static void typed_projects(void)
{
    const struct { const char *body, *read_error, *joined; size_t len; } cases[] = {
        {"{}", "late read failure", NULL, 0}, {"null", NULL, NULL, 0},
        {"{\"projects\":null}", NULL, NULL, 0}, {"{\"projects\":[]}", NULL, NULL, 0},
        {"{\"projects\":[{}]}", NULL, "", 0}, {"{\"projects\":[null,{}]}", NULL, ", ", 2},
        {"{\"projects\":[{\"created_by_email\":\"a\"},{\"created_by_email\":\"a\"},{}]}", NULL, "a, a, ", 6},
        {"{\"PROJECTS\":[{\"CREATED_BY_EMAIL\":\"folded\"}]}", NULL, "folded", 6},
        {"{\"project\u017f\":[{\"created_by_email\":\"folded\"}]}", NULL, "folded", 6},
        {"{\"projects\":[{\"CreatedByEmail\":\"ignored\"}]}", NULL, "", 0},
        {"{\"projects\":[{\"created_by_email\":\"first\",\"created_by_email\":\"last\",\"created_by_email\":null}]}", NULL, "last", 4},
        {"{\"projects\":[{\"created_by_email\":\"a\"},{\"created_by_email\":\"b\"},{\"created_by_email\":\"c\"}],\"projects\":[{}],\"projects\":[null,{},{}]}", NULL, "a, b, c", 7},
        {"{\"projects\":[{\"created_by_email\":\"a\"},{\"created_by_email\":\"b\"}],\"projects\":[{\"created_by_email\":null}]}", NULL, "a", 1},
        {"{\"projects\":[{\"created_by_email\":\"old\"}],\"projects\":null,\"projects\":[{}]}", NULL, "", 0},
        {"{\"projects\":[{\"created_by_email\":\"old\"}],\"projects\":[],\"projects\":[null]}", NULL, "", 0},
        {"{\"projects\":[{\"created_by_email\":\"old\"}],\"projects\":[]}", NULL, NULL, 0},
        {"{\"projects\":[{\"created_by_email\":\"a\"}],\"unknown\":1e99999999999,\"integer\":999999999999999999999999999999999999}", NULL, "a", 1},
        {"{\"projects\":[{\"created_by_email\":\"first\"}]} {\"projects\":[{\"created_by_email\":\"second\"}]}", "late read failure", "first", 5},
        {"{\"projects\":[{\"created_by_email\":\"d\u00e9j\u00e0\"},{\"created_by_email\":\"x\\u0000y\"},{\"created_by_email\":\"\\ud800\"}]}", NULL, "d\u00e9j\u00e0, x\0y, \xef\xbf\xbd", 16},
        {"{\"projects\":[{\"created_by_email\":\"\xff\\n\xef\xbf\xbd\"}]}", NULL, "\xef\xbf\xbd\n\xef\xbf\xbd", 7},
    };
    char input[60]; snprintf(input, sizeof(input), "lokalise %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        script s; setup(&s, 200, cases[i].body, cases[i].read_error, true);
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, true, NULL, cases[i].joined, cases[i].len); br_results_clear(&out);
    }
    const char *invalid[] = {
        "", " ", "{", "{\"projects\":[", "{\"projects\":[],}", "[]", "false", "7", "\"text\"",
        "{\"projects\":{}}", "{\"projects\":false}", "{\"projects\":[false]}", "{\"projects\":[[]]}",
        "{\"projects\":[{\"created_by_email\":7,\"created_by_email\":\"later\"}]}",
        "{\"projects\":[{\"created_by_email\":false},{}],\"projects\":[{\"created_by_email\":\"later\"}]}",
        "{\"projects\":7,\"projects\":[{\"created_by_email\":\"later\"}]}",
        "{\"projects\":[false,{\"created_by_email\":\"later\"}]}",
        "{\"projects\":[{\"created_by_email\":7}],\"projects\":null,\"projects\":[{}]}",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
        script s; setup(&s, 200, invalid[i], i < 4 ? "read failure" : NULL, true);
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, true, NULL, NULL, 0); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void preparation_failures(void)
{
    char input[60]; snprintf(input, sizeof(input), "lokalise %s", key);
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        script s; setup(&s, 200, NULL, NULL, false);
        if (i == 0) s.ctx.transport = NULL;
        if (i == 1) s.transport.send = NULL;
        if (i == 2) s.ctx.cancelled = cancelled;
        if (i == 3) s.ctx.deadline_monotonic_ms = 1;
        if (i == 4) s.ctx.user_agent = "bad\r\nagent";
        if (i == 5) s.ctx.cancelled = arm_headers;
        if (i == 6) { s.ctx.cancelled = arm_agent; s.ctx.user_agent = NULL; }
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && !s.http.calls && s.http.releases == (i ? 1u : 0u) && !fail_after && !fail_agent);
        check_result(&out.items[0], key, false, causes[i], NULL, 0); br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->verified && prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures(void)
{
    char input[120]; snprintf(input, sizeof(input), "lokalise %s\nlokalise %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    const char *expected[] = {
        "out of memory iterating regex", "out of memory copying detector capture", "cannot create LokaliseToken result", "cannot create LokaliseToken result",
        "cannot store LokaliseToken verification error", "cannot store LokaliseToken verification error", "cannot join LokaliseToken project creators", "cannot insert LokaliseToken creator metadata",
    };
    for (size_t failure = 0; failure < sizeof(expected) / sizeof(*expected); ++failure) {
        script s; setup(&s, failure == 5 ? 500 : 200, "{\"projects\":[{\"created_by_email\":\"join@example.invalid\"}]}", NULL, failure != 5);
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 41; fail_after = 2; }
        if (failure == 2) { fail_size = 40; fail_after = 2; }
        if (failure == 3) fail_key_after = 2;
        if (failure == 4) fail_setter_after = 2;
        if (failure == 5) { fail_strdup_text = "unexpected status code: 500"; fail_strdup_after = 4; }
        if (failure == 6) fail_join_after_setter = 2;
        if (failure == 7) fail_metadata_after = 2;
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !strcmp(error, expected[failure]));
        CHECK(!fail_after && !fail_key_after && !fail_setter_after && !fail_strdup_after && !fail_join_after_setter && !fail_metadata_after);
        CHECK(s.http.calls == (failure < 2 ? 0u : failure < 4 ? 1u : 2u) && s.http.releases == s.http.calls && !s.borrowed_token);
        check_prior(&out, &prior); free(error); fail_strdup_text = NULL;
    }
    const char *sticky[] = {
        "{\"projects\":[{\"created_by_email\":7,\"created_by_email\":\"later\"}]}",
        "{\"projects\":7,\"projects\":[{\"created_by_email\":\"later\"}]}",
        "{\"projects\":[false,{\"created_by_email\":\"later\"}]}",
    };
    for (size_t i = 0; i < sizeof(sticky) / sizeof(*sticky); ++i) {
        script s; setup(&s, 200, sticky[i], NULL, true);
        size_t before = projection_calls; fail_projection_after = 1; char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !fail_projection_after);
        CHECK(!strcmp(error, "synthetic positive LokaliseToken projection failure") && projection_calls == before + 1);
        CHECK(s.http.calls == 1 && s.http.releases == 1 && setter_calls == s.setters_before);
        check_prior(&out, &prior); free(error);
    }
    /* Owned repair failure must not become 200's ordinary decode suppression. */
    script s; setup(&s, 200, "{\"projects\":[{\"created_by_email\":\"\xff\"}]}", NULL, true);
    fail_repair = true; char *error = NULL;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !fail_repair && !fail_after);
    CHECK(!strcmp(error, "cannot repair Google JSON string") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error); error = NULL;
    /* Initial zeroed allocation can compile to calloc; growth uses the existing
     * malloc seam and must still be fatal before ordinary decode suppression. */
    setup(&s, 200, "{\"projects\":[{},{},{},{},{},{},{},{},{}]}", NULL, true);
    fail_size = 16 * (sizeof(br_json *) + sizeof(br_slice) + sizeof(br_bytes)); fail_after = 1;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate LokaliseToken project slots") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error); error = NULL;
    for (size_t mode = 0; mode < 3; ++mode) {
        setup(&s, 200, NULL, NULL, false);
        if (mode == 0) fail_key_after = 1;
        if (mode == 1) { fail_strdup_text = "net/http: nil Context"; fail_strdup_after = 1; }
        if (mode == 2) { fail_size = 40; fail_after = 2; }
        CHECK(invoke(&s, NULL, mode != 2, data, &out, &error) != 0 && error);
        CHECK(!fail_key_after && !fail_strdup_after && !fail_after && !s.http.calls && !s.http.releases);
        check_prior(&out, &prior); free(error); error = NULL; fail_strdup_text = NULL;
    }
    setup(&s, 200, "{}", NULL, true);
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append LokaliseToken result") && s.http.calls == 1 && s.http.releases == 1 && setter_calls == s.setters_before + 1);
    check_prior(&out, &prior); free(error);
    fail_key_after = 2;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_key_after);
    check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_extraction(); ordinary_verification(); typed_projects(); preparation_failures(); owned_failures();
    CHECK(!active && !fail_after && !fail_key_after && !fail_metadata_after && !fail_setter_after && !fail_projection_after && !fail_join_after_setter && !fail_strdup_after && !fail_agent && !fail_repair);
    return test_finish("LokaliseToken");
}
