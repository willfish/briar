/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/endpoints.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <limits.h>

static char key[33], other[33];
static const char cloud[] = "https://api.datadoghq.com";
static const char suffix[] = "/api/v1/validate";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after, part_failures;
static const char *fail_part_name;

/* Exercise real resource boundaries, not invented verifier outcomes. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures; return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && (!fail_part_name || !strcmp(name, fail_part_name)) && --fail_part_after == 0) {
        ++part_failures; return 1;
    }
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_datadogapikey_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:datadog|dd)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_datadogapikey_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_datadogapikey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_datadogapikey_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 1043 && detector->version == 0 && !strcmp(detector->name, "DatadogApikey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "datadog") && !strcmp(detector->keywords[1], "ddog-gov"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(detector->validate_endpoints == br_endpoints_validate_configured && !strcmp(detector->cloud_endpoint, cloud));
    br_endpoints empty = {0};
    CHECK(detector->validate_endpoints(&empty, &error) == -1 && !strcmp(error, "at least one endpoint required"));
    free(error); error = NULL;
    const char *configured[] = {"", "relative", "relative"};
    br_endpoints settings = {.configured = configured, .nconfigured = 3};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified,
                         const char *endpoint, const char *error)
{
    CHECK(result->detector_type == 1043 && result->raw.len == 32 && !memcmp(result->raw.data, expected, 32));
    CHECK(result->verified == verified && !result->verification_from_cache);
    CHECK(error ? result->verification_error && !strcmp(result->verification_error, error) : !result->verification_error);
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len && !result->redacted);
    CHECK(!result->extra_data && !result->structured_data && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (endpoint ? 2 : 1));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "api_key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "endpoint", &part) == (endpoint != NULL));
    if (endpoint) CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), endpoint));
}

static void extraction_case(const br_detector *detector, const void *data, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, data, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false, NULL, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *accepted[] = {"datadog = '%s'", "DaTaDoG\r\n%s", "dd %s", "DD\r%s", "ddog-gov:%s", "address:%s", "predatadogsuffix:%s", "datadog-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s datadog", "data dog %s", "datadog%s", "datadog _%s", "datadog %s_", "datadog X%s", "datadog %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dd%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
        memcpy(input, "datadog", 7);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 7 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 7 + 2 * gap, key, sizeof(key));
        extraction_case(detector, input, 7 + 2 * gap + 32, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "datadog %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0';
    snprintf(input, sizeof(input), "datadog %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "_./+=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = invalid[i];
        snprintf(input, sizeof(input), "datadog %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    /* The literal hyphen participates in ASCII word-boundary quirks. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "datadog %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "datadog%s", changed); extraction_case(detector, input, strlen(input), changed);
    changed[31] = '-';
    snprintf(input, sizeof(input), "datadog%sX", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[31] = '-';
    snprintf(input, sizeof(input), "dd %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "dd %sX", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, 'A', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "dd %s", changed); extraction_case(detector, input, strlen(input), changed); /* No hex/entropy/FP filter. */
    snprintf(input, sizeof(input), "dd %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "dd%c%s", 0, key);
    CHECK(n == 35); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%cdd %s%c", 0xff, key, 0xff);
    CHECK(n == 37); extraction_case(detector, input, (size_t)n, key); /* No global UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *base, *key, *send_error, *body_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const char *const *found;
    size_t nfound, found_seen;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *borrowed_key, *current_base, *agent_suffix;
    size_t fault_call, fault_size, failures_before;
    int fault; /* 1: real setter allocation; 2: real endpoint-part add. */
} script;

static bool url_is(const char *url, const char *base)
{
    size_t n = strlen(base);
    return strlen(url) == n + sizeof(suffix) - 1 && !memcmp(url, base, n) && !strcmp(url + n, suffix);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *step = &steps->rows[at];
    CHECK(request->detector_type == 1043 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len); /* NoBody identity is not proven. */
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    const char *base = step->base;
    if (!base) { /* Found-host map order is unspecified; compare a set. */
        size_t i = 0;
        while (i < steps->nfound && !url_is(request->url, steps->found[i])) ++i;
        CHECK(i < steps->nfound && i < sizeof(size_t) * 8 && !(steps->found_seen & ((size_t)1 << i)));
        steps->found_seen |= (size_t)1 << i; base = steps->found[i];
    }
    CHECK(url_is(request->url, base));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Dd-Api-Key"));
    CHECK(strlen(request->headers[0].value) == 32 && !memcmp(request->headers[0].value, step->key, 33));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->agent_suffix ? "TruffleHog datadogapikey-offline" : "TruffleHog"));
    /* Exact count excludes Type/Accept/Authorization and invented logical CL. */
    steps->borrowed_url = request->url; steps->borrowed_key = request->headers[0].value; steps->current_base = base;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = step->status, .body_error = step->body_error,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)}};
    http->send_error = step->send_error; http->send_rc = step->send_rc;
    if (steps->fault_call == http->calls) {
        if (steps->fault == 1) { fail_alloc_size = steps->fault_size; fail_alloc_after = 1; steps->failures_before = allocation_failures; }
        else if (steps->fault == 2) { fail_part_name = "endpoint"; fail_part_after = 1; steps->failures_before = part_failures; }
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && url_is(steps->borrowed_url, steps->current_base));
    CHECK(steps->borrowed_key && !memcmp(steps->borrowed_key, steps->rows[http->calls - 1].key, 33));
    if (steps->fault_call == http->calls) {
        if (steps->fault == 1) CHECK(!fail_alloc_after && allocation_failures == steps->failures_before + 1);
        if (steps->fault == 2) CHECK(!fail_part_after && part_failures == steps->failures_before + 1);
    } /* Setter/endpoint resources must be handled before release. */
    steps->borrowed_url = steps->borrowed_key = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify,
                      const br_endpoints *settings, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = settings, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url && !steps->borrowed_key);
    return results;
}

static void occurrences_defaults_and_statuses(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "datadog %s\ndd %s\ndatadog %s", key, other, key);
    for (int verify = 0; verify < 2; ++verify) {
        reply rows[] = {{.base = cloud, .key = key, .status = 200, .body_error = "ignored"},
                        {.base = cloud, .key = other, .status = 403, .body_error = ""},
                        {.base = cloud, .key = key, .status = 429}};
        script steps = {.rows = rows, .count = verify ? 3u : 0u, .agent_suffix = "datadogapikey-offline"};
        br_results results = run(detector, input, verify, NULL, &steps);
        CHECK(results.len == 3);
        check_result(&results.items[0], key, verify, verify ? cloud : NULL, NULL);
        check_result(&results.items[1], other, false, NULL, NULL);
        check_result(&results.items[2], key, false, NULL, verify ? "too many requests" : NULL);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == 3);
        const char *keys[] = {key, other, key};
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false, NULL, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "dd %s", key);
    br_endpoints zero = {0}; script no_attempts = {0};
    br_results results = run(detector, input, true, &zero, &no_attempts);
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL, NULL); br_results_clear(&results);
    const int statuses[] = {INT_MIN, -1, 0, 199, 200, 201, 204, 299, 300, 301, 400, 401, 403, 429, 500, 503, INT_MAX};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.base = cloud, .key = key, .status = statuses[i], .body_error = i % 2 ? "" : "ignored read failure", .nil_body = i % 3 == 0};
        script steps = {.rows = &row, .count = 1}; char expected[64];
        snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        const char *cause = statuses[i] == 200 || statuses[i] == 403 ? NULL : statuses[i] == 429 ? "too many requests" : expected;
        results = run(detector, input, true, NULL, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] == 200, statuses[i] == 200 ? cloud : NULL, cause); br_results_clear(&results);
    }
}

static void endpoint_sequences(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "dd %s", key);
    const char *bases[] = {"https://first.invalid/path/", "https://second.invalid", "https://third.invalid"};
    br_endpoints settings = {.configured = bases, .nconfigured = 3};
    const struct { int a, b, c; size_t count; bool verified; const char *error; } cases[] = {
        {429, 403, 200, 3, true, "too many requests"},
        {401, 200, 0, 2, true, "unexpected status code: 401"},
        {403, 200, 0, 2, true, NULL},
        {200, 0, 0, 1, true, NULL},
        {401, 403, 403, 3, false, "unexpected status code: 401"},
        {401, 403, 429, 3, false, "too many requests"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reply rows[] = {{.base = bases[0], .key = key, .status = cases[i].a},
                        {.base = bases[1], .key = key, .status = cases[i].b, .body_error = ""},
                        {.base = bases[2], .key = key, .status = cases[i].c, .body_error = "ignored"}};
        script steps = {.rows = rows, .count = cases[i].count};
        br_results results = run(detector, input, true, &settings, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, cases[i].verified, cases[i].verified ? bases[cases[i].count - 1] : NULL, cases[i].error);
        br_results_clear(&results);
    }
    char cause[192], redacted[192];
    snprintf(cause, sizeof(cause), "failed %s twice %s; other %s", key, key, other);
    snprintf(redacted, sizeof(redacted), "failed [REDACTED] twice [REDACTED]; other %s", other);
    reply rows[] = {{.base = bases[0], .key = key, .status = 200, .send_rc = 1, .send_error = cause, .body_error = "ignored"},
                    {.base = bases[1], .key = key, .status = 200}};
    script steps = {.rows = rows, .count = 2};
    br_results results = run(detector, input, true, &settings, &steps); CHECK(results.len == 1);
    check_result(&results.items[0], key, true, bases[1], redacted); br_results_clear(&results);
    /* Endpoint parts own BASE after the resolved list and mutable settings die. */
    char mutable_base[] = "https://owned.invalid/base";
    const char *one[] = {mutable_base}; br_endpoints owned = {.configured = one, .nconfigured = 1};
    reply row = {.base = mutable_base, .key = key, .status = 200}; script once = {.rows = &row, .count = 1};
    results = run(detector, input, true, &owned, &once); memset(mutable_base, 'x', strlen(mutable_base));
    CHECK(results.len == 1); check_result(&results.items[0], key, true, "https://owned.invalid/base", NULL); br_results_clear(&results);
    /* Relative/empty/query/fragment/slash inputs are concatenated literally. */
    const char *literal[] = {"", "relative//path", "https://synthetic.invalid/a/?q=1#frag"};
    br_endpoints raw = {.configured = literal, .nconfigured = 3};
    reply raw_rows[3];
    for (size_t i = 0; i < 3; ++i) raw_rows[i] = (reply){.base = literal[i], .key = key, .status = 403};
    script raw_steps = {.rows = raw_rows, .count = 3}; results = run(detector, input, true, &raw, &raw_steps);
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL, NULL); br_results_clear(&results);
}

static void found_hosts_and_endpoint_order(const br_detector *detector)
{
    const struct { const char *text, *base; } hosts[] = {
        {"api.datadoghq.com", "https://api.datadoghq.com"},
        {"https://api.eu.datadoghq.com/path", "https://api.eu.datadoghq.com"},
        {"api.us3.datadoghq.eu", "https://api.us3.datadoghq.eu"},
        {"api.-.ddog-gov.com", "https://api.-.ddog-gov.com"},
        {"api.ddog-gov.eu", "https://api.ddog-gov.eu"},
        {"x.api.datadoghq.com.other", "https://api.datadoghq.com"},
        {"api.datadoghq.com-extra", "https://api.datadoghq.com"},
        {"API.datadoghq.com", NULL}, {"api.US3.datadoghq.com", NULL}, {"api.us3.DATADOGHQ.com", NULL},
        {"api.datadoghq.COM", NULL}, {"api.foo.bar.datadoghq.com", NULL}, {"xapi.datadoghq.com", NULL},
        {"_api.datadoghq.com", NULL}, {"api.datadoghq.com_", NULL}, {"api.datadoghq.company", NULL}, {"api.datadoghq.net", NULL},
    };
    br_endpoints found_only = {.use_found = true}; char input[512];
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "dd %s\n%s", key, hosts[i].text);
        reply row = {.base = hosts[i].base, .key = key, .status = 403}; script steps = {.rows = &row, .count = hosts[i].base ? 1u : 0u};
        br_results results = run(detector, input, true, &found_only, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false, NULL, NULL); br_results_clear(&results);
    }
    const char *configured[] = {cloud, cloud, "https://api.US3.datadoghq.com"};
    const char *found[] = {cloud, "https://api.us3.datadoghq.com"};
    br_endpoints all = {.configured = configured, .nconfigured = 3, .use_cloud = true, .use_found = true};
    snprintf(input, sizeof(input), "dd %s\napi.datadoghq.com api.datadoghq.com api.us3.datadoghq.com", key);
    reply rows[] = {{.base = cloud, .key = key, .status = 403}, {.base = configured[2], .key = key, .status = 403},
                    {.base = cloud, .key = key, .status = 403}, {.key = key, .status = 403}, {.key = key, .status = 403}};
    script steps = {.rows = rows, .count = 5, .found = found, .nfound = 2};
    br_results results = run(detector, input, true, &all, &steps); CHECK(results.len == 1 && steps.found_seen == 3);
    check_result(&results.items[0], key, false, NULL, NULL); br_results_clear(&results);
    /* NULL cloud inherits, explicit empty cloud disables, and overrides replace. */
    all = (br_endpoints){.cloud = "", .use_cloud = true, .use_found = true};
    reply found_rows[] = {{.key = key, .status = 403}, {.key = key, .status = 403}};
    script only = {.rows = found_rows, .count = 2, .found = found, .nfound = 2};
    results = run(detector, input, true, &all, &only); CHECK(results.len == 1 && only.found_seen == 3); br_results_clear(&results);
    all = (br_endpoints){.cloud = "https://override.invalid", .use_cloud = true};
    reply override = {.base = all.cloud, .key = key, .status = 200}; script replaced = {.rows = &override, .count = 1};
    results = run(detector, input, true, &all, &replaced); CHECK(results.len == 1);
    check_result(&results.items[0], key, true, all.cloud, NULL); br_results_clear(&results);
    /* A label far beyond DNS/1024-byte limits is still a source regex match. */
    size_t label = 5000; char *host = malloc(label + 32), *base = malloc(label + 40), *large = malloc(label + 128);
    CHECK(host && base && large);
    memcpy(host, "api.", 4); memset(host + 4, 'a', label); strcpy(host + 4 + label, ".datadoghq.com");
    snprintf(base, label + 40, "https://%s", host); snprintf(large, label + 128, "dd %s\n%s", key, host);
    for (int verify = 0; verify < 2; ++verify) {
        reply long_row = {.base = base, .key = key, .status = 200}; script long_steps = {.rows = &long_row, .count = verify ? 1u : 0u};
        results = run(detector, large, verify, &found_only, &long_steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, verify, verify ? base : NULL, NULL); br_results_clear(&results);
    }
    free(large); free(base); free(host);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user; fail_alloc_size = 2 * sizeof(br_header); fail_alloc_after = 1; return false;
}

static void send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "dd %s", key);
    const char *causes[] = {"net/http: nil Context", "cannot create DatadogApikey result", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {.base = cloud, .key = key, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i], .body_error = "ignored"};
        script steps = {.rows = &row, .count = 1}; br_results results = run(detector, input, true, NULL, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&results);
    }
    const char *setup[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "bad\r\nagent" : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, false, NULL, setup[mode]); br_results_clear(&results);
    }
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
    br_json *part = NULL; CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "dd %s\ndd %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        reply rows[] = {{.base = cloud, .key = key, .status = 200}, {.base = cloud, .key = other, .status = 200}};
        script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        for (int failure = 0; failure < 8; ++failure) {
            bool verify = mode != 0 || failure >= 6;
            if (failure == 0) { fail_part_name = "api_key"; fail_part_after = 2; }
            else {
                fail_alloc_size = failure == 1 || failure == 3 ? 2 * sizeof(br_span) : failure == 2 ? 33 : failure == 4 ? 3 * sizeof(br_span) : failure == 5 ? 8 * sizeof(char *) : failure == 6 ? sizeof(cloud) : sizeof(cloud) + sizeof(suffix) - 1;
                fail_alloc_after = failure == 1 || failure == 2 || failure == 7 ? 2 : 1;
            }
            char *error = NULL;
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, verify, data, &results, &error);
            CHECK(rc == -1 && error && !fail_part_after && !fail_alloc_after);
            const char *expected = failure < 2 ? "cannot create DatadogApikey result" : failure == 2 ? "out of memory copying detector capture" : failure < 5 ? "out of memory iterating regex" : failure == 5 ? "out of memory collecting detector captures" : failure == 6 ? "out of memory copying endpoint" : "cannot allocate DatadogApikey request URL";
            CHECK(!strcmp(error, expected));
            CHECK(http.calls == (mode != 2 && verify && (failure == 0 || failure == 7) ? 1u : 0u) && http.releases == http.calls);
            check_prior(&results, raw, prior_error, parts); free(error); http.calls = http.releases = 0;
        }
        size_t cap = results.cap; results.cap = 0; char *error = NULL;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DatadogApikey result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
    /* Found HTTPS preparation is owned work even with no keys and no verify. */
    const char host[] = "api.xyz.ddog-gov.eu"; const char base[] = "https://api.xyz.ddog-gov.eu";
    for (int verify = 0; verify < 2; ++verify) {
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        fail_alloc_size = sizeof(base); fail_alloc_after = 1; char *error = NULL;
        CHECK(detector->scan(detector, NULL, verify, (br_slice){(const unsigned char *)host, sizeof(host) - 1}, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot prepare DatadogApikey found URL") && !fail_alloc_after);
        check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

static void endpoint_and_setter_failures(const br_detector *detector)
{
    char input[128], cause[2][160], redacted[160]; snprintf(input, sizeof(input), "dd %s\ndd %s", key, other);
    snprintf(cause[0], sizeof(cause[0]), "failed %s twice %s; other %s", key, key, other);
    snprintf(cause[1], sizeof(cause[1]), "failed %s twice %s; other %s", other, other, key);
    snprintf(redacted, sizeof(redacted), "failed [REDACTED] twice [REDACTED]; other %s", other);
    br_result probe = {0}; br_slice secret = {(const unsigned char *)key, 32};
    fail_alloc_size = strlen(redacted) + 1; fail_alloc_after = 1;
    CHECK(br_result_set_verification_error(&probe, cause[0], &secret, 1) == 1 && !fail_alloc_after && !probe.verification_error);
    br_result_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        reply rows[] = {{.base = cloud, .key = key, .status = 200}, {.base = cloud, .key = other, .status = 200}};
        if (mode == 0) for (size_t i = 0; i < 2; ++i) { rows[i].send_rc = 1; rows[i].send_error = cause[i]; }
        script steps = {.rows = rows, .count = 2, .fault_call = 2, .fault = mode == 0 ? 1 : 2, .fault_size = strlen(redacted) + 1};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        if (mode == 2) { fail_alloc_size = sizeof("net/http: nil Context"); fail_alloc_after = 2; }
        char *error = NULL;
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1);
        CHECK(error && !strcmp(error, mode == 1 ? "cannot create DatadogApikey endpoint part" : "cannot store DatadogApikey verification error"));
        CHECK(!fail_alloc_after && !fail_part_after && http.calls == (mode == 2 ? 0u : 2u) && http.releases == http.calls);
        check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 32, 0); test_secret(other, 32, 11);
    key[0] = 'G'; key[11] = '-'; key[21] = 'H'; key[31] = 'Z'; other[7] = '-'; other[27] = 'Y';
    const br_detector *detector = descriptor(); extraction(detector);
    occurrences_defaults_and_statuses(detector); endpoint_sequences(detector); found_hosts_and_endpoint_order(detector);
    send_errors(detector); resources_and_rollback(detector); endpoint_and_setter_failures(detector);
    return test_finish("DatadogApikey");
}
