/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *const *keys; size_t len; } expected_requests;

static void make_key(char key[111], bool admin, size_t shift)
{
    const char *prefix = admin ? "sk-ant-admin01-" : "sk-ant-api03-";
    size_t len = strlen(prefix);
    memcpy(key, prefix, len);
    test_secret(key + len, 93, shift);
    key[len + 7] = '_';
    key[len + 20] = '-';
    key[len + 32] = 'Z';
    memcpy(key + len + 93, "AA", 3);
}

static bool admin_key(const char *key)
{
    return !strncmp(key, "sk-ant-admin01", sizeof("sk-ant-admin01") - 1);
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_anthropic_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 933 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Anthropic"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Anthropic is an AI research company. "
        "The API keys can be used to access their AI models and services."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "sk-ant-api03"));
    CHECK(!strcmp(detector->keywords[1], "sk-ant-admin01"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_anthropic_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_anthropic_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_anthropic_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_anthropic_init(NULL, NULL) != 0);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verification_enabled)
{
    CHECK(result->detector_type == 933 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == strlen(key));
    CHECK(!memcmp(result->raw.data, key, strlen(key)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)strlen(key));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object));
    CHECK(json_object_object_length(result->extra_data) == (verification_enabled ? 1 : 0));
    br_json *type = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "Type", &type) == verification_enabled);
    if (verification_enabled) {
        CHECK(json_object_is_type(type, json_type_string));
        CHECK(!strcmp(json_object_get_string(type), admin_key(key) ? "Admin Key" : "API Key"));
    }
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const void *data, size_t len,
                              const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, data, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], keys[i], false);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char api[111], admin[111], changed[111], input[512];
    make_key(api, false, 0);
    make_key(admin, true, 9);
    CHECK(strlen(api) == 108 && strlen(admin) == 110);
    const char *one[] = {api}, *three[] = {api, admin, api};
    expect_extraction(detector, api, strlen(api), one, 1);
    snprintf(input, sizeof(input), "%s\r\n%s\n%s", api, admin, api);
    expect_extraction(detector, input, strlen(input), three, 3);
    const struct { const char *format; size_t count; } cases[] = {
        {"'%s'", 1},
        {"x%s", 0},
        {"_%s", 0},
        {"%s_", 0},
        {"%sQ", 0},
        {"\xc3\xa9%s\xc3\xa9", 1},
        {"%.107s", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, api);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, input, (size_t)len, one, cases[i].count);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    memcpy(changed, api, strlen(api) + 1);
    changed[0] = 'S';
    expect_extraction(detector, changed, strlen(changed), NULL, 0);
    memcpy(changed, api, strlen(api) + 1);
    changed[strlen(changed) - 1] = 'a';
    expect_extraction(detector, changed, strlen(changed), NULL, 0);
    memcpy(changed, api, strlen(api) + 1);
    changed[25] = '.';
    expect_extraction(detector, changed, strlen(changed), NULL, 0);

    /* Replace one payload rune with a non-ASCII letter, retaining 93 runes. */
    size_t at = strlen("sk-ant-api03-") + 5;
    memcpy(input, api, at);
    memcpy(input + at, "\xc3\xa9", 2);
    memcpy(input + at + 2, api + at + 1, strlen(api) - at);
    expect_extraction(detector, input, strlen(api) + 1, NULL, 0);
    snprintf(input, sizeof(input), "%.*sXAA", (int)strlen(api) - 2, api);
    expect_extraction(detector, input, strlen(input), NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const char *key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, admin_key(key) ?
        "https://api.anthropic.com/v1/organizations/api_keys" : "https://api.anthropic.com/v1/models"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 933);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    size_t auth = 0, content = 0, version = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "x-api-key")) {
            ++auth;
            CHECK(!strcmp(header->value, key));
        } else if (!strcmp(header->name, "Content-Type")) {
            ++content;
            CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "anthropic-version")) {
            ++version;
            CHECK(!strcmp(header->value, "2023-06-01"));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog anthropic-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected Anthropic request header");
        }
    }
    CHECK(auth == 1 && content == 1 && version == 1 && agent == 1);
}

static void verification_case(const br_detector *detector, const char *key,
                              br_http_response response, int send_rc, const char *send_error,
                              bool verified, const char *expected_error)
{
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    test_http http = {
        .response = response, .send_rc = send_rc, .send_error = send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "anthropic-test"};
    br_results results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    const br_result *result = &results.items[0];
    check_result(result, key, true);
    CHECK(result->verified == verified);
    if (expected_error) {
        CHECK(result->verification_error);
        CHECK(!strcmp(result->verification_error, expected_error));
        CHECK(!strstr(result->verification_error, key));
    } else {
        CHECK(!result->verification_error);
    }
    br_results_clear(&results);
}

static void test_requests_and_status(const br_detector *detector)
{
    char api[111], admin[111], input[512], sensitive[320];
    make_key(api, false, 0);
    make_key(admin, true, 9);
    const char *keys[] = {api, admin, api};
    expected_requests expected = {keys, 3};
    test_http http = {
        .response = {.status = 200, .body_error = "ignored on success"},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s\n%s\n%s", api, admin, api);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], keys[i], true);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    const struct { int status; const char *error; } cases[] = {
        {401, NULL}, {404, NULL},
        {201, "unexpected HTTP response status 201"},
        {400, "unexpected HTTP response status 400"},
        {403, "unexpected HTTP response status 403"},
        {429, "unexpected HTTP response status 429"},
        {500, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_http_response response = {.status = cases[i].status, .body_error = "read failed"};
        verification_case(detector, api, response, 0, NULL, false, cases[i].error);
    }
    snprintf(sensitive, sizeof(sensitive), "key %s failed; again %s", admin, admin);
    const struct { const char *cause, *error; } errors[] = {
        {"context deadline exceeded", "context deadline exceeded"},
        {"context canceled", "context canceled"},
        {sensitive, "key [REDACTED] failed; again [REDACTED]"},
        {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i)
        verification_case(detector, admin, (br_http_response){.status = 200}, 1,
                          errors[i].cause, false, errors[i].error);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, "unrelated", 9);
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

static void test_envelopes(const br_detector *detector)
{
    char key[111];
    make_key(key, false, 0);
    const char *status_only = "unexpected HTTP response status 400";
    const struct { const char *body, *error; } cases[] = {
        {"{\"error\":{\"type\":\"invalid_request_error\",\"message\":\"bad request\"}}",
         "unexpected HTTP response status 400 (invalid_request_error: bad request)"},
        {"{\"error\":{\"type\":\"t\"}}", "unexpected HTTP response status 400 (t: )"},
        {"{\"error\":{\"type\":\"t\",\"message\":null}}", "unexpected HTTP response status 400 (t: )"},
        {"{\"ERROR\":{\"TyPe\":\"t\",\"me\\u017f\\u017fage\":\"folded\"}}",
         "unexpected HTTP response status 400 (t: folded)"},
        {"{\"error\":{\"type\":\"bad\\u005frequest\",\"message\":\"line\\nquote\\\"slash\\\\end\"}} \r\n\t",
         "unexpected HTTP response status 400 (bad_request: line\nquote\"slash\\end)"},
        {"{\"error\":{\"type\":\"t\",\"unknown\":[1,{\"message\":false}]}}",
         "unexpected HTTP response status 400 (t: )"},
        {"null", status_only},
        {"[]", status_only},
        {"{\"error\":null}", status_only},
        {"{\"error\":\"bad\"}", status_only},
        {"{\"error\":{\"message\":\"missing type\"}}", status_only},
        {"{\"error\":{\"type\":\"\",\"message\":\"empty type\"}}", status_only},
        {"{\"error\":{\"type\":42,\"message\":\"m\"}}", status_only},
        {"{\"error\":{\"type\":\"t\",\"message\":false}}", status_only},
        {"{\"error\":{\"type\":\"t\"}", status_only},
        {"{\"error\":{\"type\":NaN}}", status_only},
        {"{\"error\":{\"type\":\"t\"}} junk", status_only},
        {"{\"error\":{\"type\":\"t\"}} {}", status_only},
        {"{\"error\":{\"type\":\"t\"}}\v", status_only},
        {"{\"error\":{\"type\":\"old\",\"TYPE\":\"new\"}}",
         "unexpected HTTP response status 400 (new: )"},
        {"{\"error\":{\"type\":\"t\",\"type\":null,\"message\":\"m\",\"message\":null}}",
         "unexpected HTTP response status 400 (t: m)"},
        {"{\"error\":{\"type\":\"t\",\"message\":\"old\"},\"error\":{\"message\":\"new\"}}",
         "unexpected HTTP response status 400 (t: new)"},
        {"{\"error\":{\"type\":\"t\",\"message\":\"m\"},\"error\":null}",
         "unexpected HTTP response status 400 (t: m)"},
        {"{\"error\":{\"type\":\"t\",\"type\":\"\"}}", status_only},
        {"{\"error\":{\"type\":42,\"type\":\"t\"}}", status_only},
        {"{\"error\":{\"type\":\"t\",\"message\":false,\"message\":\"m\"}}", status_only},
        {"{\"error\":42,\"error\":{\"type\":\"t\"}}", status_only},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_http_response response = {
            .status = 400,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)},
        };
        verification_case(detector, key, response, 0, NULL, false, cases[i].error);
    }
    char body[512];
    snprintf(body, sizeof(body), "{\"error\":{\"type\":\"%s\",\"message\":\"blocked %s %s\"}}", key, key, key);
    br_http_response response = {
        .status = 429, .body = {(const unsigned char *)body, strlen(body)},
    };
    verification_case(detector, key, response, 0, NULL, false,
                      "unexpected HTTP response status 429 ([REDACTED]: blocked [REDACTED] [REDACTED])");
    const char permission[] = "{\"error\":{\"type\":\"permission_error\",\"message\":\"denied\"}}";
    response = (br_http_response){.status = 403,
        .body = {(const unsigned char *)permission, sizeof(permission) - 1}};
    verification_case(detector, key, response, 0, NULL, false,
                      "unexpected HTTP response status 403 (permission_error: denied)");
}

static void test_body_cap(const br_detector *detector)
{
    char key[111];
    make_key(key, true, 0);
    unsigned char body[4098];
    const char document[] = "{\"error\":{\"type\":\"cap_error\",\"message\":\"bounded\"}}";
    const char *enriched = "unexpected HTTP response status 400 (cap_error: bounded)";
    const char *plain = "unexpected HTTP response status 400";
    memset(body, ' ', sizeof(body));
    memcpy(body, document, sizeof(document) - 1);
    br_http_response response = {.status = 400, .body = {body, 4096}};
    verification_case(detector, key, response, 0, NULL, false, enriched);
    response.body_error = "failure beyond read limit";
    verification_case(detector, key, response, 0, NULL, false, enriched);
    response.body.len = 4095;
    response.body_error = "failure before read limit";
    verification_case(detector, key, response, 0, NULL, false, plain);
    response.body_error = NULL;
    verification_case(detector, key, response, 0, NULL, false, enriched);
    body[4096] = 'x';
    response.body.len = 4097;
    response.body_error = "unobserved beyond cap";
    verification_case(detector, key, response, 0, NULL, false, enriched);

    /* A complete original document whose final brace lies beyond the cap. */
    const char head[] = "{\"error\":{\"type\":\"t\",\"message\":\"";
    size_t at = sizeof(head) - 1;
    memcpy(body, head, at);
    memset(body + at, 'm', 4094 - at);
    memcpy(body + 4094, "\"}}", 3);
    response = (br_http_response){.status = 400, .body = {body, 4097}};
    verification_case(detector, key, response, 0, NULL, false, plain);

    memset(body, ' ', sizeof(body));
    memcpy(body, document, sizeof(document) - 1);
    body[sizeof(document) - 1] = '\0';
    response.body.len = 4096;
    verification_case(detector, key, response, 0, NULL, false, plain);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_requests_and_status(detector);
    test_envelopes(detector);
    test_body_cap(detector);
    return test_finish("Anthropic");
}
