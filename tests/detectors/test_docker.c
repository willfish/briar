/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char config[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\"}}}";
static const char escaped[] = "{\\\"auths\\\":{\\\"reg.invalid\\\":{\\\"auth\\\":\\\"dTo=\\\"}}}";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;
static const char *fail_part_name;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

/* Keep string copies inside this fixture's malloc fault boundary. */
char *strdup(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && (!fail_part_name || !strcmp(name, fail_part_name)) && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_docker_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_docker_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_docker_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 343 && detector->version == 0 && !strcmp(detector->name, "Docker"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Docker credentials can be used to pull images from private registries."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "\"auths\"") && !strcmp(detector->keywords[1], "\\\"auths\\"));
    CHECK(strlen(detector->keywords[1]) == 8 && detector->keywords[1][7] == '\\');
    CHECK(detector->max_secret_size == 4096 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *registry, const char *auth,
                         const void *username, size_t username_len, bool verified, const char *error)
{
    CHECK(result->detector_type == 343 && result->raw.len == strlen(auth) && !memcmp(result->raw.data, auth, strlen(auth)));
    CHECK(result->verified == verified && !result->verification_from_cache);
    CHECK(error ? result->verification_error && !strcmp(result->verification_error, error) : !result->verification_error);
    CHECK(!result->detector_name && !result->redacted && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "registry", &part) && !strcmp(json_object_get_string(part), registry));
    CHECK(json_object_object_get_ex(result->secret_parts, "auth", &part) && !strcmp(json_object_get_string(part), auth));
    CHECK(!json_object_object_get_ex(result->secret_parts, "password", &part));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "Username", &part));
    CHECK(json_object_get_string_len(part) == (int)username_len && !memcmp(json_object_get_string(part), username, username_len));
    char *expected = malloc(strlen(registry) + strlen(auth) + 32); CHECK(expected);
    int n = sprintf(expected, "{\"registry\":\"%s\",\"auth\":\"%s\"}", registry, auth);
    CHECK(n >= 0 && result->raw_v2.len == (size_t)n && !memcmp(result->raw_v2.data, expected, (size_t)n));
    free(expected);
}

static br_results no_verify(const br_detector *detector, const char *input)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); CHECK(!http.calls && !http.releases); return results;
}

static void credentials_and_normalization(const br_detector *detector)
{
    const struct { const char *fields, *auth, *user; } cases[] = {
        {"\"auth\":\"dXNlcjpwYXNz\"", "dXNlcjpwYXNz", "user"},
        {"\"username\":\"user\",\"password\":\"pass\"", "dXNlcjpwYXNz", "user"},
        {"\"username\":\"user\"", NULL, NULL},
        {"\"password\":\"pass\"", NULL, NULL},
        {"\"auth\":\"%%%%\",\"username\":\"user\",\"password\":\"pass\"", "dXNlcjpwYXNz", "user"},
        {"\"auth\":\"YWJj\",\"username\":\"user\",\"password\":\"pass\"", "dXNlcjpwYXNz", "user"},
        {"\"auth\":\"YWJj\"", NULL, NULL},
        {"\"auth\":\"Og==\",\"username\":\"user\",\"password\":\"pass\"", NULL, NULL},
        {"\"auth\":\"OnA=\"", "OnA=", ""},
        {"\"auth\":\"dTo=\"", "dTo=", "u"},
        {"\"auth\":\"dTp=\"", "dTo=", "u"}, /* Nonzero pad bits, canonical re-encoding. */
        {"\"auth\":\"dTo\"", NULL, NULL},
        {"\"auth\":\"dTo=AAAA\",\"username\":\"x\",\"password\":\"y\"", "eDp5", "x"},
        {"\"auth\":\"dX\\u000aNl\\u000dcjpwYXNz\"", "dXNlcjpwYXNz", "user"},
        {"\"auth\":\"dXNlcjpwYXNz\",\"username\":\"x\",\"password\":\"y\"", "dXNlcjpwYXNz", "user"},
        {"\"username\":\"u\",\"username\":null,\"password\":\"p\"", "dTpw", "u"},
        {"\"username\":\"\\\\nuser\",\"password\":\"p\"", "bnVzZXI6cA==", "nuser"}, /* One-pass replacer precedence. */
        {"\"auth\":\"dTo=\",\"ignored\":1e99999,\"email\":\"\"", "dTo=", "u"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char input[512]; snprintf(input, sizeof(input), "{\"auths\":{\"reg.invalid\":{%s}}}", cases[i].fields);
        br_results results = no_verify(detector, input);
        CHECK(results.len == (cases[i].auth ? 1u : 0u));
        if (cases[i].auth) check_result(&results.items[0], "reg.invalid", cases[i].auth, cases[i].user, strlen(cases[i].user), false, NULL);
        br_results_clear(&results);
    }
    const char nul_config[] = "{\"auths\":{\"reg.invalid\":{\"username\":\"u\\u0000\",\"password\":\"p\\u0000\"}}}";
    br_results results = no_verify(detector, nul_config); CHECK(results.len == 1);
    check_result(&results.items[0], "reg.invalid", "dQA6cAA=", "u\0", 2, false, NULL); br_results_clear(&results);
    char combined[512]; snprintf(combined, sizeof(combined), "%s\n%s\n%s", config, config, escaped);
    results = no_verify(detector, combined); CHECK(results.len == 2); /* Original uniqueness, not normalized uniqueness. */
    for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], "reg.invalid", "dTo=", "u", 1, false, NULL);
    br_results_clear(&results);
    char vt[128]; snprintf(vt, sizeof(vt), "{\v%s", config + 1);
    results = no_verify(detector, vt); CHECK(!results.len); br_results_clear(&results); /* RE2 Perl whitespace excludes VT. */
    char literal_ws[160]; snprintf(literal_ws, sizeof(literal_ws), "{\\n%s", escaped + 1);
    results = no_verify(detector, literal_ws); CHECK(results.len == 1); br_results_clear(&results);
    char *large = malloc(5200); CHECK(large);
    strcpy(large, "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\",\"email\":\"");
    size_t n = strlen(large); memset(large + n, 'x', 5000); strcpy(large + n + 5000, "\"}}}");
    results = no_verify(detector, large); CHECK(results.len == 1); br_results_clear(&results); free(large);
}

static const br_result *registry_result(const br_results *results, const char *registry)
{
    for (size_t i = 0; i < results->len; ++i) {
        br_json *part = NULL;
        if (json_object_object_get_ex(results->items[i].secret_parts, "registry", &part) && !strcmp(json_object_get_string(part), registry)) return &results->items[i];
    }
    CHECK(false); return NULL;
}

static void typed_maps_and_examples(const br_detector *detector)
{
    const char duplicate[] = "{\"auths\":{\"reg.invalid\":{\"username\":\"u\",\"password\":\"p\"},\"reg.invalid\":{\"password\":\"p\"}}}";
    br_results results = no_verify(detector, duplicate); CHECK(!results.len); br_results_clear(&results);
    const char merge[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\"}},\"AUTHS\":{\"other.invalid\":{\"AUTH\":\"OnA=\"}}}";
    results = no_verify(detector, merge); CHECK(results.len == 2);
    check_result(registry_result(&results, "reg.invalid"), "reg.invalid", "dTo=", "u", 1, false, NULL);
    check_result(registry_result(&results, "other.invalid"), "other.invalid", "OnA=", "", 0, false, NULL); br_results_clear(&results);
    const char clear[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\"}},\"auths\":null,\"auths\":{\"other.invalid\":{\"auth\":\"OnA=\"}}}";
    results = no_verify(detector, clear); CHECK(results.len == 1);
    check_result(&results.items[0], "other.invalid", "OnA=", "", 0, false, NULL); br_results_clear(&results);
    const char literal_v2[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\"},\"a\\u0022b.invalid\":{\"auth\":\"OnA=\"}}}";
    results = no_verify(detector, literal_v2); CHECK(results.len == 2);
    check_result(registry_result(&results, "a\"b.invalid"), "a\"b.invalid", "OnA=", "", 0, false, NULL); br_results_clear(&results);
    const char *examples[] = {"https://index.docker.io/v1/", "registry.hostname.com", "registry.example.com:5000", "registry2.example.com:5000", "your.private.registry.example.com"};
    for (size_t i = 0; i < 5; ++i) {
        char input[256]; snprintf(input, sizeof(input), "{\"auths\":{\"%s\":{\"auth\":\"dTo=\"}}}", examples[i]);
        results = no_verify(detector, input); CHECK(!results.len); br_results_clear(&results);
    }
    results = no_verify(detector, "{\"auths\":{\"docker.io\":{\"auth\":\"dTo=\"}}}"); CHECK(results.len == 1);
    check_result(&results.items[0], "index.docker.io", "dTo=", "u", 1, false, NULL); br_results_clear(&results);
    results = no_verify(detector, "{\"auths\":{\"HTTPS://index.docker.io/v1/\":{\"auth\":\"dTo=\"}}}"); CHECK(results.len == 1); br_results_clear(&results);
}

typedef struct {
    const char *url, *authorization, *send_error, *body_error;
    br_slice body;
    const br_header *headers;
    size_t nheaders;
    int status, send_rc;
    bool poison_error;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    bool nested;
    const br_scan_ctx *expected_ctx;
    br_http_response *responses[2];
    const char *borrowed_url[2], *borrowed_auth[2];
    bool fault_setter;
    size_t failures_before;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 2 && ctx == steps->expected_ctx);
    CHECK(http->releases == (steps->nested ? 0u : at));
    if (at && steps->nested) CHECK(steps->responses[0] && steps->responses[0]->headers == steps->rows[0].headers);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 343 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, row->url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, row->authorization));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Content-Type") && !strcmp(request->headers[2].value, "application/json"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog docker-offline"));
    steps->borrowed_url[at] = request->url; steps->borrowed_auth[at] = request->headers[0].value;
    http->response = (br_http_response){.status = row->status, .headers = row->headers, .nheaders = row->nheaders, .body = row->body, .body_error = row->body_error};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
    if (steps->fault_setter) {
        CHECK(row->body_error); fail_size = strlen(row->body_error) + 1; fail_after = 1; steps->failures_before = allocation_failures;
    }
}

static int injected_send(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; script *steps = http->user;
    int rc = test_http_send(user, ctx, request, response, error);
    steps->responses[http->calls - 1] = response; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    size_t at = steps->nested ? 1 - http->releases : http->releases;
    CHECK(at < steps->count && response == steps->responses[at]);
    CHECK(steps->borrowed_url[at] && !strcmp(steps->borrowed_url[at], steps->rows[at].url));
    CHECK(steps->borrowed_auth[at] && !strcmp(steps->borrowed_auth[at], steps->rows[at].authorization));
    if (steps->nested && at == 1) CHECK(steps->responses[0]->headers == steps->rows[0].headers);
    if (steps->fault_setter) CHECK(!fail_after && allocation_failures == steps->failures_before + 1);
    if (steps->rows[at].poison_error) memset((char *)steps->rows[at].body_error, '!', strlen(steps->rows[at].body_error));
    steps->borrowed_url[at] = steps->borrowed_auth[at] = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, injected_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "docker-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count);
    for (size_t i = 0; i < steps->count; ++i) CHECK(!steps->borrowed_url[i] && !steps->borrowed_auth[i]);
    return results;
}

static void initial_verification(const br_detector *detector)
{
    const char *valid[] = {"{}", "null", "true", "\"text\"", "1234567890123456789012345678901234567890", "1e99999"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        reply row = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 200, .body = {(const unsigned char *)valid[i], strlen(valid[i])}};
        script steps = {.rows = &row, .count = 1}; br_results results = run(detector, config, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, true, NULL); br_results_clear(&results);
    }
    reply bad = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 200, .body = {(const unsigned char *)"{}junk", 6}};
    script bad_steps = {.rows = &bad, .count = 1}; br_results results = run(detector, config, &bad_steps); CHECK(results.len == 1);
    check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, false, NULL); br_results_clear(&results);
    char leaf[512], expected[512]; snprintf(leaf, sizeof(leaf), "read %s / %s / dTo= / u", config, escaped);
    snprintf(expected, sizeof(expected), "read [REDACTED] / %s / dTo= / u", escaped);
    reply read_error = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 200, .body_error = leaf, .poison_error = true,
        .body = {(const unsigned char *)"null", 4}};
    script read_steps = {.rows = &read_error, .count = 1}; results = run(detector, escaped, &read_steps); CHECK(results.len == 1);
    check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, false, expected); br_results_clear(&results);
    const char *causes[] = {"failed to make request: literal leaf", ""};
    for (size_t i = 0; i < 2; ++i) {
        reply row = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = i ? 200 : 401,
            .send_rc = i ? 0 : 1, .send_error = i ? NULL : causes[i], .body_error = i ? causes[i] : NULL};
        script steps = {.rows = &row, .count = 1}; results = run(detector, config, &steps);
        check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, false, causes[i]); br_results_clear(&results);
    }
    reply status = {.url = "https://reg.invalid//v2/", .authorization = "Basic dTo=", .status = 201, .body_error = "ignored"};
    script status_steps = {.rows = &status, .count = 1};
    results = run(detector, "{\"auths\":{\"reg.invalid//\":{\"auth\":\"dTo=\"}}}", &status_steps);
    check_result(&results.items[0], "reg.invalid//", "dTo=", "u", 1, false, "unexpected HTTP response status 201 for 'https://reg.invalid//v2/'"); br_results_clear(&results);
}

static void challenges(const br_detector *detector)
{
    br_header header = {"wWw-aUtHeNtIcAtE", "Bearer realm=\"https://old.invalid/\",realm=\"https://auth.invalid/token?old=1#frag\",service=\"s/a+?\",scope=\"ignored\""};
    const int statuses[] = {200, 401, 403, 500};
    for (size_t i = 0; i < 4; ++i) {
        reply rows[] = {{.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 401, .headers = &header, .nheaders = 1, .body_error = "ignored initial read"},
            {.url = "https://auth.invalid/token?account=u&service=s%2Fa%2B%3F#frag", .authorization = "Basic dTo=", .status = statuses[i], .body_error = "ignored follow read"}};
        script steps = {.rows = rows, .count = 2, .nested = true}; br_results results = run(detector, config, &steps);
        check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, statuses[i] == 200,
            statuses[i] == 500 ? "unexpected HTTP response status 500 for 'https://auth.invalid/token?account=u&service=s%2Fa%2B%3F#frag'" : NULL);
        br_results_clear(&results);
    }
    const struct { const char *header, *error; } rejected[] = {
        {"", NULL}, {"Basic realm=\"x\"", "unsupported WWW-Authenticate auth scheme: Basic realm=\"x\""},
        {"Bearer", "invalid WWW-Authenticate header format"},
        {"Bearer realm=\"\"", "unexpected empty realm for WWW-Authenticate header: Bearer realm=\"\""},
        {"Bearer  realm=\"https://auth.invalid/\"", "unexpected empty realm for WWW-Authenticate header: Bearer  realm=\"https://auth.invalid/\""},
        {"Bearer realm=\"http://[\"", NULL}, {"Bearer realm=\"https://auth.invalid/%zz\"", NULL},
        {"Bearer realm=\"https://u:p@auth.invalid/token\"", "unsupported: Docker realm URL outside native ASCII http(s) subset"},
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_header headers[] = {{"Www-Authenticate", rejected[i].header}, {"Www-Authenticate", "Bearer realm=\"https://unused.invalid/\""}};
        reply row = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 401, .headers = headers, .nheaders = 2, .body_error = "ignored"};
        script steps = {.rows = &row, .count = 1}; br_results results = run(detector, config, &steps);
        check_result(&results.items[0], "reg.invalid", "dTo=", "u", 1, false, rejected[i].error); br_results_clear(&results);
    }
    /* Only parts[1] is parsed: the space before service discards that parameter. */
    header.value = "Bearer realm=\"https://auth.invalid/token\", service=\"ignored\"";
    reply spaced[] = {{.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 401, .headers = &header, .nheaders = 1},
                      {.url = "https://auth.invalid/token?account=u&service=", .authorization = "Basic dTo=", .status = 200}};
    script spaced_steps = {.rows = spaced, .count = 2, .nested = true}; br_results results = run(detector, config, &spaced_steps); CHECK(results.items[0].verified); br_results_clear(&results);
    header.value = "Bearer \xc2\xa0realm\xc2\xa0=\xc2\xa0\"\"https://auth.invalid/token\"\"\xc2\xa0,\xe1\x9a\x80service\xe1\x9a\x80=\xe3\x80\x80\"svc\"\xe3\x80\x80";
    static const unsigned char username[] = {' ', 'a', '+', 'b', '&', 0xc3, 0xa9, 0};
    char *authorization = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){username, sizeof(username)}, (br_slice){(const unsigned char *)"p", 1}, &authorization, &error) == 0 && !error);
    const char query_config[] = "{\"auths\":{\"reg.invalid\":{\"username\":\" a+b&\\u00e9\\u0000\",\"password\":\"p\"}}}";
    reply query[] = {{.url = "https://reg.invalid/v2/", .authorization = authorization, .status = 401, .headers = &header, .nheaders = 1},
                     {.url = "https://auth.invalid/token?account=+a%2Bb%26%C3%A9%00&service=svc", .authorization = authorization, .status = 200}};
    script query_steps = {.rows = query, .count = 2, .nested = true}; results = run(detector, query_config, &query_steps);
    check_result(&results.items[0], "reg.invalid", authorization + 6, username, sizeof(username), true, NULL); br_results_clear(&results); free(authorization);
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void errors_and_resources(const br_detector *detector)
{
    br_results results = prior_result(); unsigned char *prior = results.items[0].raw.data; char *error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){0}, &results, &error) == -1 && error && strstr(error, "unsupported"));
    CHECK(results.len == 1 && results.items[0].raw.data == prior); free(error); error = NULL;
    br_scan_ctx ctx = {0}; char partial[512]; snprintf(partial, sizeof(partial), "%s\n{\"auths\":{\"bad.invalid\":{\"auth\":\"dTo=\",}}}", config);
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)partial, strlen(partial)}, &results, &error) == 1 && error);
    CHECK(results.len == 2 && results.items[0].raw.data == prior); check_result(&results.items[1], "reg.invalid", "dTo=", "u", 1, false, NULL);
    free(error); error = NULL; br_results_clear(&results);
    const char typed[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\",\"username\":1,\"email\":\"\"}}}";
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)typed, sizeof(typed) - 1}, &results, &error) == 1 && error && strstr(error, "cannot unmarshal number"));
    CHECK(!results.len); free(error); error = NULL; br_results_clear(&results);
    char two[256]; snprintf(two, sizeof(two), "%s\n{\"auths\":{\"other.invalid\":{\"auth\":\"OnA=\"}}}", config);
    results = prior_result(); prior = results.items[0].raw.data; fail_part_name = "Username"; fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)two, strlen(two)}, &results, &error) == -1 && error && !fail_part_after);
    CHECK(results.len == 1 && results.items[0].raw.data == prior && results.items[0].verified); free(error); error = NULL;
    fail_size = sizeof(br_span); fail_after = 1; /* Full-match regex has only group zero. */
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)config, sizeof(config) - 1}, &results, &error) == -1 && error && !fail_after);
    CHECK(results.len == 1 && results.items[0].raw.data == prior); free(error); error = NULL;
    reply row = {.url = "https://reg.invalid/v2/", .authorization = "Basic dTo=", .status = 200, .body_error = "synthetic setter copy allocation boundary"};
    script steps = {.rows = &row, .count = 1, .fault_setter = true}; test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, injected_send, release_response}; br_scan_ctx verifying = {.transport = &transport, .user_agent = "docker-offline"}; steps.expected_ctx = &verifying;
    CHECK(detector->scan(detector, &verifying, true, (br_slice){(const unsigned char *)config, sizeof(config) - 1}, &results, &error) == -1 && error && !fail_after);
    CHECK(results.len == 1 && results.items[0].raw.data == prior && http.calls == 1 && http.releases == 1); free(error); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); credentials_and_normalization(detector); typed_maps_and_examples(detector);
    initial_verification(detector); challenges(detector); errors_and_resources(detector);
    return test_finish("Docker");
}
