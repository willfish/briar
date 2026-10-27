/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char api[] = "A7b9C2d5E6f8G3h4J1k0M2n4P6q8R1s0";
static const char api2[] = "Z9y8X7w6V5u4T3s2R1q0P9n8M7k6J5h4";
static const char app[] = "S3t5U7v9W2x4Y6z8A1b3C5d7E9f2G4h6J8k0M3n5";
static const char app2[] = "U8v6W4x2Y0z9A7b5C3d1E8f6G4h2J0k9M7n5P3q1";
static size_t fail_size, fail_after, failed_allocations, fail_add_after;

/* Target real native resource boundaries, not production-only failure APIs. */
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
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(api) == 32 && strlen(api2) == 32 && strlen(app) == 40 && strlen(app2) == 40);
    CHECK(br_datadogtoken_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:datadog|dd)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_datadogtoken_init(&detector, &error) == -1 && !detector && error && !fail_after);
    free(error); error = NULL;
    CHECK(br_datadogtoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_datadogtoken_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 39 && detector->version == 0 && !strcmp(detector->name, "DatadogToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "datadog") && !strcmp(detector->keywords[1], "ddog-gov"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(detector->validate_endpoints && !strcmp(detector->cloud_endpoint, "https://api.datadoghq.com"));
    CHECK(detector->validate_endpoints(NULL, &error) != 0 && error); free(error); error = NULL;
    const char *empty[] = {""}; br_endpoints settings = {.configured = empty, .nconfigured = 1};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    settings.nconfigured = 0;
    CHECK(detector->validate_endpoints(&settings, &error) != 0 && error); free(error);
    return detector;
}

static void field(br_json *object, const char *name, br_slice expected)
{
    br_json *value = NULL;
    bool found = json_object_object_get_ex(object, name, &value);
    CHECK(found == (expected.data != NULL));
    if (!expected.data) return;
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void result(const br_result *value, const char *expected_api, const char *expected_app,
                    bool verified, const char *endpoint, const char *error)
{
    CHECK(value->detector_type == 39 && !value->detector_name);
    CHECK(value->raw.len == 40 && !memcmp(value->raw.data, expected_app, 40));
    CHECK(value->raw_v2.len == 72 && !memcmp(value->raw_v2.data, expected_app, 40) && !memcmp(value->raw_v2.data + 40, expected_api, 32));
    CHECK(value->verified == verified && !value->verification_from_cache);
    CHECK((value->verification_error != NULL) == (error != NULL));
    if (error) CHECK(!strcmp(value->verification_error, error));
    CHECK(!value->redacted && !value->structured_data && !value->primary_secret.data && !value->primary_secret.len);
    CHECK(!value->primary_line && !value->chunk_offset && !value->chunk_offset_set);
    CHECK(value->secret_parts && json_object_object_length(value->secret_parts) == (endpoint ? 3 : 2));
    field(value->secret_parts, "api_key", text(expected_api)); field(value->secret_parts, "app_key", text(expected_app));
    field(value->secret_parts, "endpoint", endpoint ? text(endpoint) : (br_slice){0});
    CHECK(value->extra_data && json_object_is_type(value->extra_data, json_type_object));
    field(value->extra_data, "Type", TEXT("Application+APIKey"));
}

static void metadata(const br_result *value, br_slice emails, br_slice name, br_slice url)
{
    field(value->extra_data, "user_emails", emails);
    field(value->extra_data, "org_name", name); field(value->extra_data, "org_url", url);
    CHECK(json_object_object_length(value->extra_data) == 1 + (emails.data ? 1 : 0) + (name.data ? 1 : 0) + (url.data ? 1 : 0));
}

static br_slice pair_input(char *buffer, size_t size, const char *api_key, const char *app_key)
{
    int len = snprintf(buffer, size, "dd %s\ndatadog %s", api_key, app_key);
    CHECK(len > 0 && (size_t)len < size);
    return (br_slice){(const unsigned char *)buffer, (size_t)len};
}

static void extraction_case(const br_detector *detector, const void *input, size_t len,
                            const char *expected_api, const char *expected_app)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results found = test_scan(detector, &ctx, false, input, len);
    CHECK(found.len == (expected_api ? 1u : 0u) && !http.calls && !http.releases);
    if (expected_api) { result(&found.items[0], expected_api, expected_app, false, NULL, NULL); metadata(&found.items[0], (br_slice){0}, (br_slice){0}, (br_slice){0}); }
    br_results_clear(&found);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed_api[34], changed_app[42];
    const char *prefixes[] = {"dd", "DaTaDoG", "preDDsuffix", "ddog-gov"};
    for (size_t p = 0; p < 4; ++p) {
        snprintf(input, sizeof(input), "%s %s\r\n%s %s", prefixes[p], api, prefixes[p], app);
        extraction_case(detector, input, strlen(input), api, app);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dd%*s%s\ndatadog %s", (int)gap, "", api, app);
        extraction_case(detector, input, strlen(input), gap == 40 ? api : NULL, app);
        snprintf(input, sizeof(input), "dd %s\ndatadog%*s%s", api, (int)gap, "", app);
        extraction_case(detector, input, strlen(input), gap == 40 ? api : NULL, app);
    }
    /* Actual prefix dd, NOT dispatch keyword ddog-gov: its suffix uses six gap characters. */
    for (int gap = 34; gap <= 35; ++gap) {
        snprintf(input, sizeof(input), "ddog-gov%*s%s\ndatadog %s", gap, "", api, app);
        extraction_case(detector, input, strlen(input), gap == 34 ? api : NULL, app);
    }
    memcpy(changed_api, api, sizeof(api)); memcpy(changed_app, app, sizeof(app));
    changed_api[10] = '-'; changed_app[20] = '-';
    br_slice data = pair_input(input, sizeof(input), changed_api, changed_app);
    extraction_case(detector, data.data, data.len, changed_api, changed_app);
    changed_api[10] = '_'; data = pair_input(input, sizeof(input), changed_api, app);
    extraction_case(detector, data.data, data.len, NULL, NULL);
    memcpy(changed_api, api, sizeof(api)); changed_app[20] = '_'; data = pair_input(input, sizeof(input), api, changed_app);
    extraction_case(detector, data.data, data.len, NULL, NULL);
    const char *bad[] = {"dd _%s\ndd %s", "dd %s_\ndd %s", "dd x%s\ndd %s", "dd %s9\ndd %s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), bad[i], api, app); extraction_case(detector, input, strlen(input), NULL, NULL); }
    snprintf(input, sizeof(input), "dd %.31s\ndd %s", api, app); extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "dd %s\ndd %.39s", api, app); extraction_case(detector, input, strlen(input), NULL, NULL);
    memset(changed_api, 'A', 32); changed_api[32] = '\0'; memset(changed_app, 'A', 40); changed_app[40] = '\0';
    data = pair_input(input, sizeof(input), changed_api, changed_app);
    extraction_case(detector, data.data, data.len, changed_api, changed_app); /* No entropy or equal-content filter. */
    memcpy(changed_app, app, sizeof(app)); changed_app[39] = '-';
    snprintf(input, sizeof(input), "dd %s\ndd %sZ", api, changed_app);
    extraction_case(detector, input, strlen(input), api, changed_app); /* Source word-boundary quirk. */
    snprintf(input, sizeof(input), "%s %s", api, app); extraction_case(detector, input, strlen(input), NULL, NULL);
    extraction_case(detector, NULL, 0, NULL, NULL);
}

typedef struct {
    const char *base, *api, *app, *send_error, *body_error;
    int status, rc;
    br_slice body;
} reply;
typedef struct {
    reply rows[24]; size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_url;
    unsigned char *owned_body;
    bool copy_body, suffix;
    size_t arm_size, arm_after, arm_call;
} script;

static void check_url(const char *url, const char *base)
{
    static const char path[] = "/api/v2/users";
    size_t len = strlen(base);
    CHECK(url && strlen(url) == len + sizeof(path) - 1);
    CHECK(!memcmp(url, base, len) && !memcmp(url + len, path, sizeof(path)));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    reply *row = &steps->rows[at];
    CHECK(request->detector_type == 39 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, row->base);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Dd-Api-Key") && !strcmp(request->headers[1].value, row->api));
    CHECK(!strcmp(request->headers[2].name, "Dd-Application-Key") && !strcmp(request->headers[2].value, row->app));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, steps->suffix ? "TruffleHog datadog-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    br_slice body = row->body;
    if (steps->copy_body && body.len) {
        steps->owned_body = malloc(body.len); CHECK(steps->owned_body);
        memcpy(steps->owned_body, body.data, body.len); body.data = steps->owned_body;
    }
    http->response = (br_http_response){.status = row->status, .body = body, .body_error = row->body_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *steps = http->user;
    /* Arm only AFTER the transport owns its diagnostic: this targets real
     * provider decode/cause/setter allocations, not shared setup stages. */
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->count);
    check_url(steps->borrowed_url, steps->rows[http->calls - 1].base);
    steps->borrowed_url = NULL;
    free(steps->owned_body); steps->owned_body = NULL; /* Projection must retain its strings. */
    test_http_release(user, response);
}

static int invoke(const br_detector *detector, br_slice input, bool verify, const br_endpoints *settings,
                   script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = settings, .user_agent = steps->suffix ? "datadog-offline" : NULL};
    steps->ctx = &ctx;
    int rc = detector->scan(detector, &ctx, verify, input, out, error);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_url && !steps->owned_body);
    return rc;
}

static br_results run(const br_detector *detector, br_slice input, const br_endpoints *settings, script *steps)
{
    br_results out = {0}; char *error = NULL;
    int rc = invoke(detector, input, true, settings, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void products_and_endpoints(const br_detector *detector)
{
    char input[512]; size_t len = 0;
    const char *apis[] = {api, api2, api}, *apps[] = {app, app2, app};
    for (size_t i = 0; i < 3; ++i) len += (size_t)snprintf(input + len, sizeof(input) - len, "dd %s\ndd %s\n", apps[i], apis[i]);
    input[len++] = '\0'; input[len++] = (char)0xff;
    br_slice data = {(const unsigned char *)input, len};
    br_endpoints zero = {0}; script steps = {0};
    br_results out = run(detector, data, &zero, &steps);
    CHECK(out.len == 9);
    for (size_t a = 0; a < 3; ++a) for (size_t p = 0; p < 3; ++p)
        result(&out.items[a * 3 + p], apis[a], apps[p], false, NULL, NULL);
    br_results_clear(&out);
    steps = (script){.count = 9};
    for (size_t a = 0; a < 3; ++a) for (size_t p = 0; p < 3; ++p)
        steps.rows[a * 3 + p] = (reply){.base = "https://api.datadoghq.com", .api = apis[a], .app = apps[p], .status = 200, .body = TEXT("{}")};
    out = run(detector, data, NULL, &steps); CHECK(out.len == 9);
    for (size_t a = 0; a < 3; ++a) for (size_t p = 0; p < 3; ++p)
        result(&out.items[a * 3 + p], apis[a], apps[p], true, "https://api.datadoghq.com", NULL);
    br_results_clear(&out);

    len = (size_t)snprintf(input, sizeof(input), "dd %s\ndd %s api.datadoghq.com api.datadoghq.com API.DATADOGHQ.COM", api, app);
    data = (br_slice){(const unsigned char *)input, len};
    steps = (script){.count = 2};
    for (size_t i = 0; i < 2; ++i) steps.rows[i] = (reply){.base = "https://api.datadoghq.com", .api = api, .app = app, .status = 403};
    out = run(detector, data, NULL, &steps); CHECK(out.len == 1);
    result(&out.items[0], api, app, false, "https://api.datadoghq.com", NULL); br_results_clear(&out);
    const char *configured[] = {"https://unit.invalid/base/", "", "https://unit.invalid/base/", "https://api.datadoghq.com"};
    br_endpoints settings = {.configured = configured, .nconfigured = 4, .use_cloud = true, .use_found = true};
    const char *expected[] = {configured[0], "", configured[3], "https://api.datadoghq.com", "https://api.datadoghq.com"};
    steps = (script){.count = 5, .suffix = true};
    for (size_t i = 0; i < 5; ++i) steps.rows[i] = (reply){.base = expected[i], .api = api, .app = app, .status = 403};
    out = run(detector, data, &settings, &steps); CHECK(out.len == 1);
    result(&out.items[0], api, app, false, expected[4], NULL); br_results_clear(&out);
    settings = (br_endpoints){.use_cloud = true, .cloud = ""}; steps = (script){0};
    out = run(detector, data, &settings, &steps); CHECK(out.len == 1); result(&out.items[0], api, app, false, NULL, NULL); br_results_clear(&out);

    /* Complete unbounded found label, lower-case grammar, optional one label,
     * and literal configured suffix concatenation rather than DC URL rewriting. */
    char host[1400], big_input[1600], base[1450];
    memcpy(host, "api.", 4); memset(host + 4, 'a', 1200); memcpy(host + 1204, ".ddog-gov.eu", sizeof(".ddog-gov.eu"));
    snprintf(base, sizeof(base), "https://%s", host);
    len = (size_t)snprintf(big_input, sizeof(big_input), "dd %s\ndd %s %s", api, app, host);
    settings = (br_endpoints){.use_found = true}; steps = (script){.count = 1};
    steps.rows[0] = (reply){.base = base, .api = api, .app = app, .status = 401};
    out = run(detector, (br_slice){(const unsigned char *)big_input, len}, &settings, &steps);
    CHECK(out.len == 1); result(&out.items[0], api, app, false, base, NULL); br_results_clear(&out);
    const char *literal[] = {"https://unit.invalid/path/?q=1#fragment"};
    settings = (br_endpoints){.configured = literal, .nconfigured = 1}; steps = (script){.count = 1};
    steps.rows[0] = (reply){.base = literal[0], .api = api, .app = app, .status = 200, .body = TEXT("null")};
    out = run(detector, data, &settings, &steps); CHECK(out.len == 1); result(&out.items[0], api, app, true, literal[0], NULL); br_results_clear(&out);
}

static void sticky_errors_and_presence(const br_detector *detector)
{
    char input[128], sensitive[160]; br_slice data = pair_input(input, sizeof(input), api, app);
    const char *bases[] = {"https://one.invalid", "https://two.invalid", "https://three.invalid", "https://unreached.invalid"};
    br_endpoints settings = {.configured = bases, .nconfigured = 4};
    snprintf(sensitive, sizeof(sensitive), "bad %s %s", api, app);
    script steps = {.count = 3};
    steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .rc = 1, .send_error = sensitive};
    steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 403};
    steps.rows[2] = (reply){.base = bases[2], .api = api, .app = app, .status = 200, .body = TEXT("null")};
    br_results out = run(detector, data, &settings, &steps); CHECK(out.len == 1);
    result(&out.items[0], api, app, true, bases[2], "bad [REDACTED] [REDACTED]"); br_results_clear(&out);
    settings.nconfigured = 3; steps = (script){.count = 3};
    steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 503};
    steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 200, .body = TEXT("{bad")};
    steps.rows[2] = (reply){.base = bases[2], .api = api, .app = app, .status = 401};
    out = run(detector, data, &settings, &steps); result(&out.items[0], api, app, false, bases[2], "unexpected status code: 503"); br_results_clear(&out);
    settings.nconfigured = 2;
    steps = (script){.count = 2};
    steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 503};
    steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 200, .body = TEXT("{bad")};
    out = run(detector, data, &settings, &steps);
    result(&out.items[0], api, app, true, bases[1], "unexpected status code: 503");
    metadata(&out.items[0], (br_slice){0}, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    const struct { br_slice body; const char *read_error; bool present; } cases[] = {
        {TEXT("null"), NULL, true}, {TEXT("{} {}"), NULL, true}, {TEXT("{}\xff"), NULL, true},
        {TEXT("{\"data\":null}"), "", true}, {TEXT("{"), "", false}, {TEXT(""), NULL, false},
        {TEXT("[]"), NULL, false}, {TEXT("true"), NULL, false}, {TEXT("\"text\""), NULL, false},
        {TEXT("{\"data\":false}"), NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        steps = (script){.count = cases[i].present ? 1u : 2u};
        steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = cases[i].body, .body_error = cases[i].read_error};
        steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 403};
        out = run(detector, data, &settings, &steps); CHECK(out.len == 1);
        result(&out.items[0], api, app, cases[i].present, bases[cases[i].present ? 0 : 1], NULL); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 201, 204, 299, 300, 401, 403, 429, 500};
    settings.nconfigured = 1;
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1}; steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = statuses[i], .body = TEXT("{}")};
        char error[80]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        out = run(detector, data, &settings, &steps);
        result(&out.items[0], api, app, false, bases[0], statuses[i] == 401 || statuses[i] == 403 ? NULL : error); br_results_clear(&out);
    }
    char overlap[41]; memcpy(overlap, api, 32); memcpy(overlap + 32, "Q7r9S2t4", 9);
    data = pair_input(input, sizeof(input), api, overlap); snprintf(sensitive, sizeof(sensitive), "fail %s and %s", overlap, api);
    steps = (script){.count = 1}; steps.rows[0] = (reply){.base = bases[0], .api = api, .app = overlap, .rc = -1, .send_error = sensitive};
    out = run(detector, data, &settings, &steps);
    result(&out.items[0], api, overlap, false, bases[0], "fail [REDACTED]Q7r9S2t4 and [REDACTED]"); br_results_clear(&out);
}

static void prior_check(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static void json_projection(const br_detector *detector)
{
    /* First 16 fixtures reproduce the parent evidence's selected pinned-source
     * contracts. These are native fixtures, never a Go runtime dependency. */
    const struct { const char *json; bool decoded, panic; br_slice emails, name, url; } cases[] = {
        {"null", true, false, {0}, {0}, {0}},
        {"{} {\"data\":[null]}", true, false, {0}, {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"a\",\"verified\":true},\"ATTRIBUTES\":null,\"attributes\":{\"disabled\":null}}]}", true, false, TEXT("a"), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":17,\"email\":\"later\"}}]}", false, false, {0}, {0}, {0}},
        {"{\"unused\":1e10000}", true, false, {0}, {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"a\",\"verified\":true}},{\"attributes\":{\"email\":\"b\",\"verified\":true}}],\"data\":[{}],\"data\":[{},{}]}", true, false, TEXT("a, b"), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"old\",\"verified\":true}}],\"data\":null,\"data\":[{}]}", true, false, TEXT(""), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"old\",\"verified\":true}}],\"data\":[],\"data\":[{}]}", true, false, TEXT(""), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"a\",\"verified\":true}},{\"attributes\":{\"email\":\"b\",\"verified\":true}}],\"data\":[null],\"data\":[{},{}]}", true, false, TEXT("b"), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"fallback\"}},{\"attributes\":{\"email\":\"\",\"verified\":true}},{\"attributes\":{\"email\":\"skip\",\"verified\":true,\"service_account\":true}}]}", true, false, TEXT(""), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"fallback\",\"disabled\":true}},{\"attributes\":{\"email\":\"skip\",\"verified\":true,\"service_account\":true}}]}", true, false, TEXT("fallback"), {0}, {0}},
        {"{\"included\":[{\"type\":\"orgs\",\"attributes\":{\"disabled\":true}},{\"type\":\"orgs\",\"attributes\":{\"name\":\"N\",\"url\":\"U\"}},null]}", true, false, {0}, TEXT("N"), TEXT("U")},
        {"{\"included\":[null,{\"type\":\"orgs\"}]}", true, true, {0}, {0}, {0}},
        {"{\"data\":[null]}", true, true, {0}, {0}, {0}},
        {"{\"data\":[null],\"included\":false}", false, false, {0}, {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"a\\u0000b\",\"verified\":true}}],\"included\":[{\"type\":\"orgs\\u0000suffix\",\"attributes\":{\"name\":\"wrong\"}},{\"type\":\"orgs\",\"attributes\":{\"name\":\"\\u0000\",\"url\":\"u\\u0000v\"}}]}", true, false, TEXT("a\0b"), TEXT("\0"), TEXT("u\0v")},
        {"{\"data\":[{\"attributes\":{\"email\":\"a\",\"email\":null,\"verified\":true,\"verified\":null}},{\"attributes\":{\"email\":\"a\",\"verified\":true}}]}", true, false, TEXT("a, a"), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"svc\",\"verified\":true,\"service_account\":true,\"service_account\":null}},{\"attributes\":{\"email\":\"ok\",\"verified\":true}}]}", true, false, TEXT("ok"), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"disabled\",\"verified\":true,\"disabled\":true,\"disabled\":null}},{\"attributes\":{\"email\":\"ok\",\"verified\":true}}]}", true, false, TEXT("ok"), {0}, {0}},
        {"{\"included\":[{\"type\":\"other\"},{\"type\":\"orgs\",\"attributes\":{\"name\":\"hidden\"}}],\"included\":[{}],\"included\":[{},{}]}", true, false, {0}, TEXT("hidden"), TEXT("")},
        {"{\"included\":[{\"type\":\"orgs\",\"attributes\":{\"name\":\"old\"}}],\"included\":[],\"included\":[{}]}", true, false, {0}, {0}, {0}},
        {"{\"included\":[{\"type\":\"orgs\",\"attributes\":{\"name\":\"old\"}}],\"included\":null,\"included\":[{}]}", true, false, {0}, {0}, {0}},
        {"{\"included\":[{\"type\":\"orgs\"},{\"type\":\"orgs\",\"attributes\":{\"name\":\"hidden\"}}],\"included\":[null],\"included\":[{},{}]}", true, false, {0}, TEXT("hidden"), TEXT("")},
        {"{\"included\":[{\"type\":\"orgs\",\"type\":null,\"attributes\":{\"name\":\"N\"},\"attributes\":null,\"ATTRIBUTES\":{\"url\":\"U\",\"name\":null}}]}", true, false, {0}, TEXT("N"), TEXT("U")},
        {"{\"data\":[{},null],\"data\":[{}]}", true, false, TEXT(""), {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"good\",\"verified\":true}},null]}", true, true, {0}, {0}, {0}},
        {"{\"data\":[{\"attributes\":{\"email\":\"\\u03bb\\u2603\",\"verified\":true}}],\"included\":[{\"type\":\"orgs\"}]}", true, false, TEXT("\xce\xbb\xe2\x98\x83"), TEXT(""), TEXT("")},
        {"{\"DATA\":[{\"ATTRIBUTES\":{\"EMAIL\":\"ok\",\"VERIFIED\":true,\"di\\u017fabled\":false}}]}", true, false, TEXT("ok"), {0}, {0}},
    };
    char input[128]; br_slice data = pair_input(input, sizeof(input), api, app);
    const char *bases[] = {"https://json-one.invalid", "https://json-two.invalid"};
    br_endpoints settings = {.configured = bases, .nconfigured = 2};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = cases[i].decoded ? 1u : 2u, .copy_body = true};
        steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = text(cases[i].json)};
        steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 403};
        if (!cases[i].panic) {
            br_results out = run(detector, data, &settings, &steps); CHECK(out.len == 1);
            result(&out.items[0], api, app, cases[i].decoded, bases[cases[i].decoded ? 0 : 1], NULL);
            metadata(&out.items[0], cases[i].emails, cases[i].name, cases[i].url); br_results_clear(&out);
        } else {
            br_result prior = {0}; br_results out = {0}; char *error = NULL;
            CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
            CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved_error = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
            CHECK(invoke(detector, data, true, &settings, &steps, &out, &error) == -1 && error && strstr(error, "unsupported upstream panic"));
            prior_check(&out, raw, saved_error, parts); free(error); br_results_clear(&out);
        }
    }
    /* Validate every known field even when unused, noneligible, or overwritten. */
    const char *bad[] = {
        "{\"data\":{},\"data\":[]}", "{\"included\":false,\"included\":[]}", "{\"data\":[17]}",
        "{\"data\":[{\"attributes\":false}]}", "{\"data\":[{\"attributes\":{\"email\":true}}]}",
        "{\"data\":[{\"attributes\":{\"verified\":1}}]}", "{\"data\":[{\"attributes\":{\"disabled\":\"false\"}}]}",
        "{\"data\":[{\"attributes\":{\"service_account\":[]}}]}", "{\"included\":[{\"type\":false}]}",
        "{\"included\":[{\"type\":\"unused\",\"attributes\":{\"name\":1}}]}",
        "{\"included\":[{\"attributes\":{\"url\":[]}}]}", "{\"included\":[{\"attributes\":{\"disabled\":0}}]}",
        "{\"included\":[{\"type\":\"orgs\"},null,{\"attributes\":{\"name\":false}}]}",
        "{\"data\":[{\"attributes\":{\"email\":1e10000,\"email\":\"later\"}}]}",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = text(bad[i])};
        steps.rows[1] = (reply){.base = bases[1], .api = api, .app = app, .status = 403};
        br_results out = run(detector, data, &settings, &steps); result(&out.items[0], api, app, false, bases[1], NULL);
        metadata(&out.items[0], (br_slice){0}, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    }
    /* Long metadata is joined without a provider-specific cap, and survives
     * release of the copied response body before metadata extraction. */
    char long_json[11300], joined[11002];
    size_t at = (size_t)snprintf(long_json, sizeof(long_json), "{\"data\":[{\"attributes\":{\"email\":\"");
    memset(long_json + at, 'a', 5000); at += 5000;
    at += (size_t)snprintf(long_json + at, sizeof(long_json) - at, "\",\"verified\":true}},{\"attributes\":{\"email\":\"");
    memset(long_json + at, 'b', 6000); at += 6000;
    at += (size_t)snprintf(long_json + at, sizeof(long_json) - at, "\",\"verified\":true}}]}");
    memset(joined, 'a', 5000); memcpy(joined + 5000, ", ", 2); memset(joined + 5002, 'b', 6000);
    script long_steps = {.count = 1, .copy_body = true};
    long_steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = {(const unsigned char *)long_json, at}};
    br_results long_out = run(detector, data, &settings, &long_steps); CHECK(long_out.len == 1);
    result(&long_out.items[0], api, app, true, bases[0], NULL);
    metadata(&long_out.items[0], (br_slice){(const unsigned char *)joined, sizeof(joined)}, (br_slice){0}, (br_slice){0});
    br_results_clear(&long_out);

    /* A singleton's 317-byte slice needs no temporary join buffer. Arm the
     * allocator observer after send to reject that redundant allocation. */
    char single_json[512], single_email[317];
    memset(single_email, 'e', sizeof(single_email));
    at = (size_t)snprintf(single_json, sizeof(single_json), "{\"data\":[{\"attributes\":{\"email\":\"");
    memcpy(single_json + at, single_email, sizeof(single_email)); at += sizeof(single_email);
    at += (size_t)snprintf(single_json + at, sizeof(single_json) - at, "\",\"verified\":true}}]}");
    script single_steps = {.count = 1, .copy_body = true, .arm_call = 1, .arm_size = sizeof(single_email), .arm_after = 1};
    single_steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = {(const unsigned char *)single_json, at}};
    size_t before = failed_allocations;
    br_results single_out = run(detector, data, &settings, &single_steps);
    CHECK(fail_after == 1 && failed_allocations == before);
    fail_after = 0;
    CHECK(single_out.len == 1); result(&single_out.items[0], api, app, true, bases[0], NULL);
    metadata(&single_out.items[0], (br_slice){(const unsigned char *)single_email, sizeof(single_email)}, (br_slice){0}, (br_slice){0});
    br_results_clear(&single_out);
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts_and_resources(const br_detector *detector)
{
    char input[192]; br_slice data = pair_input(input, sizeof(input), api, app);
    br_results out = test_scan(detector, NULL, true, data.data, data.len);
    CHECK(out.len == 1); result(&out.items[0], api, app, false, "https://api.datadoghq.com", "net/http: nil Context"); br_results_clear(&out);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctxs[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *errors[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < 4; ++i) {
        http.calls = http.releases = 0;
        out = test_scan(detector, &ctxs[i], true, data.data, data.len); CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result(&out.items[0], api, app, false, "https://api.datadoghq.com", errors[i]); br_results_clear(&out);
    }
    const char *bases[] = {"https://resource-check.invalid/provider-path/"};
    br_endpoints settings = {.configured = bases, .nconfigured = 1};
    const struct { size_t add, size; const char *error; } faults[] = {
        {3, 0, "cannot create DatadogToken Type metadata"},
        {4, 0, "cannot store DatadogToken endpoint"},
        {5, 0, "cannot store DatadogToken user emails"},
        {6, 0, "cannot store DatadogToken organization"},
        {7, 0, "cannot store DatadogToken organization"},
        {0, 2 * sizeof(br_span), "out of memory iterating regex"},
        {0, 72, "cannot create DatadogToken result"},
    };
    const char body[] = "{\"data\":[{\"attributes\":{\"email\":\"a\"}}],\"included\":[{\"type\":\"orgs\",\"attributes\":{\"name\":\"N\",\"url\":\"U\"}}]}";
    for (size_t f = 0; f < sizeof(faults) / sizeof(faults[0]); ++f) {
        br_result prior = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
        fail_add_after = faults[f].add;
        if (faults[f].size) { fail_size = faults[f].size; fail_after = 1; }
        script steps = {.count = f >= 1 && f <= 4 ? 1u : 0u};
        steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = TEXT(body)};
        CHECK(invoke(detector, data, true, &settings, &steps, &out, &error) == -1 && error && !strcmp(error, faults[f].error));
        CHECK(!fail_add_after && !fail_after); prior_check(&out, raw, saved, parts); free(error); br_results_clear(&out);
    }
    /* URL, status-cause, sanitizer and decoder failures are owned fatal errors,
     * not an ordinary absent decoded response with verified=true. */
    char sensitive[160]; snprintf(sensitive, sizeof(sensitive), "bad %s %s", api, app);
    const char huge[] = "{\"unused\":9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}";
    for (int mode = 0; mode < 4; ++mode) {
        script steps = {.count = mode == 0 ? 0u : 1u};
        steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = mode == 1 ? 503 : 200, .body = TEXT(huge)};
        const char *expected;
        if (mode == 0) { fail_size = strlen(bases[0]) + sizeof("/api/v2/users"); fail_after = 1; expected = "cannot create DatadogToken URL"; }
        else {
            steps.arm_call = 1; steps.arm_after = 1;
            if (mode == 1) { steps.arm_size = sizeof("unexpected status code: 503"); expected = "cannot create DatadogToken status cause"; }
            else if (mode == 2) { steps.rows[0].rc = 1; steps.rows[0].send_error = sensitive; steps.arm_size = strlen(sensitive) + 1; expected = "cannot sanitize DatadogToken verification error"; }
            else { steps.arm_size = sizeof(huge); expected = "cannot decode DatadogToken response"; }
        }
        char *error = NULL; size_t before = failed_allocations;
        CHECK(invoke(detector, data, true, &settings, &steps, &out, &error) == -1 && error && !strcmp(error, expected));
        CHECK(!out.len && !fail_after && failed_allocations == before + 1); free(error); br_results_clear(&out);
    }
    /* A second pair's failure rolls back the first pair, preserving caller data. */
    int len = snprintf(input, sizeof(input), "dd %s\ndd %s\ndd %s", api, app, app2); data = (br_slice){(const unsigned char *)input, (size_t)len};
    br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
    fail_size = 72; fail_after = 2; script steps = {.count = 1};
    steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = TEXT("{}")};
    CHECK(invoke(detector, data, true, &settings, &steps, &out, &error) == -1 && error && !fail_after); prior_check(&out, raw, saved, parts); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; steps = (script){0};
    CHECK(invoke(detector, data, false, &settings, &steps, &out, &error) == -1 && error && !strcmp(error, "cannot append DatadogToken result"));
    out.cap = cap; prior_check(&out, raw, saved, parts); free(error); br_results_clear(&out);
    const char invalid[] = "{\"data\":[{\"attributes\":{\"email\":\"\xff\"}}]}";
    data = pair_input(input, sizeof(input), api, app); steps = (script){.count = 1};
    steps.rows[0] = (reply){.base = bases[0], .api = api, .app = app, .status = 200, .body = TEXT(invalid)}; error = NULL;
    CHECK(invoke(detector, data, true, &settings, &steps, &out, &error) == -1 && error && strstr(error, "invalid UTF-8 in consumed"));
    CHECK(!out.len); free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); products_and_endpoints(detector); sticky_errors_and_presence(detector);
    json_projection(detector); contexts_and_resources(detector);
    return test_finish("DatadogToken");
}
