/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pinecone_init(const br_detector **out, char **error);

static char short_key[75], long_key[76];

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    struct json_object *obj = json_object_new_string("");
    if (!obj || !json_object_set_string_len(obj, value ? value : "", len)) {
        json_object_put(obj);
        return NULL;
    }
    return obj;
}

static void make_key(char *out, const char *label, char fill)
{
    size_t n = strlen(label);
    memcpy(out, "pcsk_", 5);
    memcpy(out + 5, label, n);
    out[5 + n] = '_';
    memset(out + 6 + n, fill, 63);
    out[6 + n + 63] = '\0';
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value) ||
        !json_object_is_type(value, json_type_string)) return NULL;
    return json_object_get_string(value);
}

static br_slice extra_bytes(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value) ||
        !json_object_is_type(value, json_type_string)) return (br_slice){0};
    return (br_slice){(const unsigned char *)json_object_get_string(value),
                      (size_t)json_object_get_string_len(value)};
}

static void check_base(const br_result *result, const char *expected, const char *label, bool verified, const char *cause)
{
    char redacted[16];
    memcpy(redacted, expected, 8);
    memcpy(redacted + 8, "...", 3);
    memcpy(redacted + 11, expected + strlen(expected) - 4, 4);
    redacted[15] = '\0';
    CHECK(result->detector_type == 1049);
    CHECK(result->raw.len == strlen(expected) && !memcmp(result->raw.data, expected, result->raw.len));
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), expected));
    CHECK(extra(result, "key_id") && !strcmp(extra(result, "key_id"), label));
    CHECK(result->verified == verified && !result->verification_from_cache);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    make_key(short_key, "abcde", 'A');
    make_key(long_key, "abcdef", 'B');
    CHECK(strlen(short_key) == 74 && strlen(long_key) == 75);
    CHECK(br_pinecone_init(NULL, &error) == -1); free(error);
    CHECK(!br_pinecone_init(&detector, &error) && !error);
    CHECK(detector->type == 1049 && !strcmp(detector->name, "Pinecone") && detector->version == 0);
    CHECK(!strcmp(detector->description, "Pinecone is a vector database service. API keys can be used to manage indexes and perform vector operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pcsk_") && detector->max_credential_span == -1);
    return detector;
}

typedef struct { const char *key, *body, *body_error, *send_error; int status; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.pinecone.io/indexes"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1049);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Api-Key") && !strcmp(request->headers[0].value, steps->key));
    CHECK(!strcmp(request->headers[1].name, "X-Pinecone-Api-Version") && !strcmp(request->headers[1].value, "2025-10"));
    CHECK(!strcmp(request->headers[2].name, "Accept") && !strcmp(request->headers[2].value, "application/json"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog"));
    http->response = (br_http_response){.status = steps->status, .body_error = steps->body_error};
    if (steps->body) http->response.body = (br_slice){(const unsigned char *)steps->body, strlen(steps->body)};
    http->send_error = steps->send_error; http->send_rc = steps->send_error ? -1 : 0;
}

static br_results once(const br_detector *detector, const char *input, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    return results;
}

static void extraction(const br_detector *detector)
{
    char input[2 * sizeof(short_key) + sizeof(long_key)];
    int n = snprintf(input, sizeof(input), "%s %s %s", short_key, long_key, short_key);
    CHECK(n >= 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_base(&results.items[0], short_key, "abcde", false, NULL);
    check_base(&results.items[1], long_key, "abcdef", false, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "x%s", short_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s", short_key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_base(&results.items[0], short_key, "abcde", false, "net/http: nil Context");
    CHECK(!extra(&results.items[0], "total_indexes") && !extra(&results.items[0], "permission"));
    br_results_clear(&results);
}

static void statuses(const br_detector *detector)
{
    char input[90]; snprintf(input, sizeof(input), "key %s", short_key);
    script denied = {.key = short_key, .status = 401, .body = "{\"indexes\":[]}"};
    br_results results = once(detector, input, &denied);
    check_base(&results.items[0], short_key, "abcde", false, NULL);
    CHECK(!extra(&results.items[0], "permission"));
    br_results_clear(&results);
    script restricted = {.key = short_key, .status = 403};
    results = once(detector, input, &restricted);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(extra(&results.items[0], "permission") && !strcmp(extra(&results.items[0], "permission"), "restricted"));
    br_results_clear(&results);
    script bad = {.key = short_key, .status = 500};
    results = once(detector, input, &bad);
    check_base(&results.items[0], short_key, "abcde", false, "unexpected HTTP response status 500");
    br_results_clear(&results);
    script unread = {.key = short_key, .status = 200, .body = "{\"indexes\":[]}", .body_error = "read failed"};
    results = once(detector, input, &unread);
    check_base(&results.items[0], short_key, "abcde", false, "read failed");
    br_results_clear(&results);
}

static void json_cases(const br_detector *detector)
{
    char input[90]; snprintf(input, sizeof(input), "%s", short_key);
    const char *malformed[] = {"{}", "null", "{\"indexes\":null}", "{\"Indexes\":[{\"name\":\"a\"}],\"indexes\":null}"};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.key = short_key, .status = 200, .body = malformed[i]};
        br_results results = once(detector, input, &steps);
        check_base(&results.items[0], short_key, "abcde", false, "unexpected response body structure");
        br_results_clear(&results);
    }
    script empty = {.key = short_key, .status = 200, .body = "{\"indexes\":[]}"};
    br_results results = once(detector, input, &empty);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(extra(&results.items[0], "total_indexes") && !strcmp(extra(&results.items[0], "total_indexes"), "0"));
    CHECK(!extra(&results.items[0], "index_0_name"));
    br_results_clear(&results);
    script ok = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[null,{\"name\":null,\"host\":\"idx-proj.svc.env.pinecone.io\","
        "\"spec\":{\"serverless\":{\"cloud\":\"aws\",\"region\":null}}},"
        "{\"name\":\"second\",\"host\":\"nosvc\",\"spec\":null}]}"};
    results = once(detector, input, &ok);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!strcmp(extra(&results.items[0], "total_indexes"), "3"));
    CHECK(!strcmp(extra(&results.items[0], "project_id"), "proj"));
    CHECK(!strcmp(extra(&results.items[0], "index_0_name"), ""));
    CHECK(!strcmp(extra(&results.items[0], "index_0_host"), ""));
    CHECK(!extra(&results.items[0], "index_0_cloud"));
    CHECK(!strcmp(extra(&results.items[0], "index_1_name"), ""));
    CHECK(!strcmp(extra(&results.items[0], "index_1_host"), "idx-proj.svc.env.pinecone.io"));
    CHECK(!strcmp(extra(&results.items[0], "index_1_cloud"), "aws"));
    CHECK(!strcmp(extra(&results.items[0], "index_1_region"), ""));
    CHECK(!strcmp(extra(&results.items[0], "index_2_name"), "second"));
    CHECK(!extra(&results.items[0], "index_2_cloud"));
    br_results_clear(&results);
    script typed = {.key = short_key, .status = 200, .body = "{\"indexes\":{\"name\":\"x\"}}"};
    results = once(detector, input, &typed);
    check_base(&results.items[0], short_key, "abcde", false,
        "json: cannot unmarshal object into Go struct field listIndexesResponse.indexes of type []pinecone.indexInfo");
    br_results_clear(&results);
    script named = {.key = short_key, .status = 200, .body = "{\"indexes\":[{\"name\":1}]}"};
    results = once(detector, input, &named);
    check_base(&results.items[0], short_key, "abcde", false,
        "json: cannot unmarshal number into Go struct field indexInfo.indexes.name of type string");
    br_results_clear(&results);
    script array = {.key = short_key, .status = 200, .body = "[]"};
    results = once(detector, input, &array);
    check_base(&results.items[0], short_key, "abcde", false,
        "json: cannot unmarshal array into Go value of type pinecone.listIndexesResponse");
    br_results_clear(&results);
    script reuse = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"kept\",\"host\":\"idx-proj.svc.env.pinecone.io\","
        "\"spec\":{\"serverless\":{\"cloud\":\"aws\",\"region\":\"us\"}}}],\"indexes\":[{}]}"};
    results = once(detector, input, &reuse);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!strcmp(extra(&results.items[0], "index_0_name"), "kept"));
    CHECK(!strcmp(extra(&results.items[0], "index_0_cloud"), "aws"));
    CHECK(!strcmp(extra(&results.items[0], "index_0_region"), "us"));
    br_results_clear(&results);
    script spec_null = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"a\",\"host\":\"h\",\"spec\":{\"serverless\":{\"cloud\":\"aws\",\"region\":\"us\"}}}],"
        "\"indexes\":[{\"spec\":null}]}"};
    results = once(detector, input, &spec_null);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!strcmp(extra(&results.items[0], "index_0_cloud"), "aws"));
    CHECK(!strcmp(extra(&results.items[0], "index_0_region"), "us"));
    br_results_clear(&results);
    script serverless_null = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"a\",\"spec\":{\"serverless\":{\"cloud\":\"aws\",\"region\":\"us\"},\"serverless\":null}}]}"};
    results = once(detector, input, &serverless_null);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!extra(&results.items[0], "index_0_cloud"));
    br_results_clear(&results);
    script merged = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"a\",\"spec\":{\"serverless\":{\"cloud\":\"aws\",\"region\":\"us\"},"
        "\"serverless\":{\"region\":\"eu\"}}}]}"};
    results = once(detector, input, &merged);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!strcmp(extra(&results.items[0], "index_0_cloud"), "aws"));
    CHECK(!strcmp(extra(&results.items[0], "index_0_region"), "eu"));
    br_results_clear(&results);
    script emptied = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"kept\",\"host\":\"idx-proj.svc.env.pinecone.io\"}],\"indexes\":[]}"};
    results = once(detector, input, &emptied);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(!strcmp(extra(&results.items[0], "total_indexes"), "0"));
    CHECK(!extra(&results.items[0], "index_0_name"));
    br_results_clear(&results);
    script cleared = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"kept\"}],\"indexes\":null}"};
    results = once(detector, input, &cleared);
    check_base(&results.items[0], short_key, "abcde", false, "unexpected response body structure");
    br_results_clear(&results);
    script embedded = {.key = short_key, .status = 200, .body =
        "{\"indexes\":[{\"name\":\"a\\u0000b\",\"host\":\"idx-pro\\u0000j.svc.env.pinecone.io\"}]}"};
    results = once(detector, input, &embedded);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    br_slice name = extra_bytes(&results.items[0], "index_0_name");
    br_slice project = extra_bytes(&results.items[0], "project_id");
    CHECK(name.len == 3 && name.data && !memcmp(name.data, "a\0b", 3));
    CHECK(project.len == 5 && project.data && !memcmp(project.data, "pro\0j", 5));
    br_results_clear(&results);
    script syntax = {.key = short_key, .status = 200, .body = "{"};
    results = once(detector, input, &syntax);
    check_base(&results.items[0], short_key, "abcde", false, "unexpected end of JSON input");
    br_results_clear(&results);
    static char raw[27];
    memcpy(raw, "{\"indexes\":[{\"name\":\"", 21);
    raw[21] = (char)0xff;
    memcpy(raw + 22, "\"}]}", 4);
    raw[26] = '\0';
    script utf = {.key = short_key, .status = 200, .body = raw};
    results = once(detector, input, &utf);
    check_base(&results.items[0], short_key, "abcde", true, NULL);
    CHECK(extra(&results.items[0], "index_0_name") && !strcmp(extra(&results.items[0], "index_0_name"), "\xef\xbf\xbd"));
    br_results_clear(&results);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); statuses(detector); json_cases(detector);
    return test_finish("Pinecone label redaction + index extra data + 403 restricted");
}
