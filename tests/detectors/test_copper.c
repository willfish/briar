/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_copper_init(const br_detector **out, char **error);

static const char email[] = "user@ExAmPlE.test";
static size_t fail_size, fail_alloc_after, fail_strdup_after, fail_part_after;
static const char *fail_strdup_text;

/* Exercise actual allocation and positive-return helper failures. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_strdup_after && (!fail_strdup_text || !strcmp(text, fail_strdup_text)) && --fail_strdup_after == 0)
        return NULL;
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_copper_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Copper detector output"));
    free(error); error = NULL;
    fail_size = sizeof("(?i:copper)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_copper_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_copper_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_copper_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 214 && detector->version == 0 && !strcmp(detector->name, "Copper"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Copper is a CRM platform that helps businesses manage their relationships with customers and leads. Copper API keys can be used to access and modify customer data and interactions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "copper"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_copper_init(NULL, NULL) == -1);
    return detector;
}

static void check_result(const br_result *result, const char *key, br_slice id, bool verified, const char *cause)
{
    CHECK(result->detector_type == 214 && result->verified == verified && !result->verification_from_cache);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, key, 32));
    CHECK(result->raw_v2.len == 32 + id.len && !memcmp(result->raw_v2.data, key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, id.data, id.len));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), key, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == id.len && !memcmp(json_object_get_string(part), id.data, id.len));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void expect_extraction(const br_detector *detector, br_slice input, const char *key, const char *id)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (id ? 1u : 0u) && !http.calls && !http.releases);
    if (id) check_result(&results.items[0], key, text(id), false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char key[33], changed[34], input[512]; test_secret(key, 32, 0);
    const struct { const char *format; bool match; } key_cases[] = {
        {"copper '%s' user@ExAmPlE.test", true}, {"preCoPpErsuffix\r\n%s user@ExAmPlE.test", true},
        {"%s user@ExAmPlE.test", false}, {"%s copper user@ExAmPlE.test", false},
        {"copper%s user@ExAmPlE.test", false}, {"copper _%s user@ExAmPlE.test", false},
        {"copper %s_ user@ExAmPlE.test", false}, {"copper %sx user@ExAmPlE.test", false},
        {"copper %.31s user@ExAmPlE.test", false}, {"copper .%s! user@ExAmPlE.test", true},
    };
    for (size_t i = 0; i < sizeof(key_cases) / sizeof(key_cases[0]); ++i) {
        snprintf(input, sizeof(input), key_cases[i].format, key);
        expect_extraction(detector, text(input), key, key_cases[i].match ? email : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[12] = 'A';
    snprintf(input, sizeof(input), "copper %s %s", changed, email); expect_extraction(detector, text(input), key, NULL);
    memset(changed, 'a', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "copper %s %s", changed, email); expect_extraction(detector, text(input), changed, email);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "copper", 6); memset(input + 6, '.', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s %s", key, email);
        expect_extraction(detector, text(input), key, gap == 40 ? email : NULL);
        size_t at = 6;
        for (size_t r = 0; r < gap; ++r) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
        snprintf(input + at, sizeof(input) - at, "%s %s", key, email);
        expect_extraction(detector, text(input), key, gap == 40 ? email : NULL);
    }
    const struct { const char *id, *capture; } ids[] = {
        {"abcd@AB.cd", "abcd@AB.cd"}, {"abc@AB.cd", NULL}, {"Abcd@AB.cd", NULL},
        {"_abcd@AB.cd", NULL}, {"abcd@AB.cd_", NULL}, {"abcd@AB.cd-", "abcd@AB.cd"},
        {"abcdefghijklmnopqrstuvwxy@AB.cd", "abcdefghijklmnopqrstuvwxy@AB.cd"},
        {"abcdefghijklmnopqrstuvwxyz@AB.cd", NULL}, {"abcd@A.cd", NULL},
        {"abcd@AB.c", NULL}, {"abcd@AB.abcdefg", NULL},
        {"abcd@ABCDEFGHIJKL.ABCDEF", "abcd@ABCDEFGHIJKL.ABCDEF"},
        {"abcd@AB@cd", "abcd@AB@cd"}, {"abcd@AB_cd", "abcd@AB_cd"},
        {"abcd@ABCDE", "abcd@ABCDE"}, {"abcd@ABCD", NULL},
        /* Greedy domain/wildcard/suffix backtracking can stop BEFORE a dot. */
        {"abcd@ABCDEFGHIJKLM.cd", "abcd@ABCDEFGHIJKLM"},
        {"abcd@ABCDEFGHIJKLMNOPQRS", "abcd@ABCDEFGHIJKLMNOPQRS"},
        {"abcd@ABCDEFGHIJKLMNOPQRST", NULL},
        {"abcd@AB\ncd", NULL}, {"abcd@AB\rcd", "abcd@AB\rcd"},
        {"abcd@AB\tcd", "abcd@AB\tcd"}, {"abcd@AB cd", "abcd@AB cd"},
        {"abcd@AB\x01" "cd", "abcd@AB\x01" "cd"},
        {"abcd@AB\x7f" "cd", "abcd@AB\x7f" "cd"},
        {"abcd@AB\xc3\xa9" "cd", "abcd@AB\xc3\xa9" "cd"},
        {"abcd@AB\xf0\x9f\x98\x80" "cd", "abcd@AB\xf0\x9f\x98\x80" "cd"},
        {"\xc3\xa9" "abcd@AB.cd\xc3\xa9", "abcd@AB.cd"},
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        snprintf(input, sizeof(input), "copper %s %s", key, ids[i].id);
        expect_extraction(detector, text(input), key, ids[i].capture);
    }
    expect_extraction(detector, (br_slice){0}, key, NULL);
    snprintf(input, sizeof(input), "copper %s", key); expect_extraction(detector, text(input), key, NULL);
    expect_extraction(detector, text(email), key, NULL);
    /* A NUL wildcard is part of every byte-valued identity, never a terminator. */
    static const unsigned char nul_id[] = "abcd@AB\0cd";
    size_t at = (size_t)snprintf(input, sizeof(input), "copper %s ", key);
    memcpy(input + at, nul_id, sizeof(nul_id) - 1);
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, at + sizeof(nul_id) - 1);
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], key, (br_slice){nul_id, sizeof(nul_id) - 1}, false,
            verify ? "unsupported: Copper ID contains NUL; ABI1 cannot represent HTTP header value" : NULL);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, at + sizeof(nul_id) - 1);
    CHECK(results.len == 1);
    check_result(&results.items[0], key, (br_slice){nul_id, sizeof(nul_id) - 1}, false, "net/http: nil Context");
    br_results_clear(&results);
    /* Binary input and prefix separators do not truncate later matches. */
    at = (size_t)snprintf(input, sizeof(input), "copper"); input[at++] = '\0';
    at += (size_t)snprintf(input + at, sizeof(input) - at, "%s %s", key, email);
    expect_extraction(detector, (br_slice){(const unsigned char *)input, at}, key, email);
}

typedef enum { NO_FAULT, FAIL_DUP, FAIL_NUMBER, FAIL_REDACTION } fault;
typedef struct {
    const char *key, *id, *body, *read_error, *send_error, *duplicate;
    int status, send_rc;
    fault fail;
} reply;
typedef struct {
    reply rows[16]; size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_key, *borrowed_id;
    char body[2048], read_error[512];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t index = http->calls - 1;
    CHECK(index < steps->count && http->releases == index && ctx == steps->ctx);
    reply *row = &steps->rows[index];
    CHECK(request->detector_type == 214 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.copper.com/developer_api/v1/users/me"));
    CHECK(!request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 5);
    CHECK(!strcmp(request->headers[0].name, "X-Pw-Accesstoken") && !strcmp(request->headers[0].value, row->key));
    CHECK(!strcmp(request->headers[1].name, "X-Pw-Application") && !strcmp(request->headers[1].value, "developer_api"));
    CHECK(!strcmp(request->headers[2].name, "X-Pw-Useremail") && !strcmp(request->headers[2].value, row->id));
    CHECK(!strcmp(request->headers[3].name, "Content-Type") && !strcmp(request->headers[3].value, "application/json"));
    CHECK(!strcmp(request->headers[4].name, "User-Agent") &&
          !strcmp(request->headers[4].value, ctx->user_agent ? "TruffleHog offline-copper" : "TruffleHog"));
    steps->borrowed_key = request->headers[0].value; steps->borrowed_id = request->headers[2].value;
    if (row->body) {
        CHECK(strlen(row->body) < sizeof(steps->body)); strcpy(steps->body, row->body);
    } else {
        br_json *object = json_object_new_object(), *value = json_object_new_string(row->id);
        CHECK(object && value && json_object_object_add_ex(object, "email", value, 0) == 0);
        const char *encoded = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
        CHECK(encoded && strlen(encoded) < sizeof(steps->body)); strcpy(steps->body, encoded);
        json_object_put(object);
    }
    if (row->read_error) { CHECK(strlen(row->read_error) < sizeof(steps->read_error)); strcpy(steps->read_error, row->read_error); }
    http->response = (br_http_response){.status = row->status, .body = text(steps->body),
        .body_error = row->read_error ? steps->read_error : NULL};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
    if (row->fail == FAIL_DUP) { fail_strdup_text = row->duplicate; fail_strdup_after = 1; }
    if (row->fail == FAIL_NUMBER) {
        fail_size = strlen("json: cannot unmarshal number 9223372036854775808 into Go struct field UserApiResponse.id of type int") + 1;
        fail_alloc_after = 1;
    }
    if (row->fail == FAIL_REDACTION) { fail_size = sizeof("[REDACTED]"); fail_alloc_after = 1; }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->borrowed_key) {
        reply *row = &steps->rows[http->calls - 1];
        CHECK(!strcmp(steps->borrowed_key, row->key) && !strcmp(steps->borrowed_id, row->id));
        steps->borrowed_key = steps->borrowed_id = NULL;
    }
    /* Borrowed read causes must have been copied before this invalidation. */
    memset(steps->body, '?', sizeof(steps->body)); memset(steps->read_error, '!', sizeof(steps->read_error));
    test_http_release(user, response);
}

static br_transport scripted_transport(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps, bool suffix)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = scripted_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = suffix ? "offline-copper" : NULL}; steps->ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_key && !steps->borrowed_id);
    return results;
}

static void verification_case(const br_detector *detector, const char *key, reply row, bool verified, const char *cause)
{
    char input[128]; snprintf(input, sizeof(input), "copper %s %s", key, email);
    row.key = key; row.id = email;
    script steps = {.rows = {row}, .count = 1};
    br_results results = run(detector, input, true, &steps, true);
    CHECK(results.len == 1); check_result(&results.items[0], key, text(email), verified, cause); br_results_clear(&results);
}

static void occurrences(const br_detector *detector)
{
    char key[33], other[33], input[4096]; test_secret(key, 32, 0); test_secret(other, 32, 7);
    const char *keys[] = {key, other, key}, *ids[] = {email, "abcd@AB.cd", email};
    size_t at = (size_t)snprintf(input, sizeof(input), "%s %s %s ", ids[0], ids[1], ids[2]);
    memset(input + at, '.', 2048); at += 2048;
    snprintf(input + at, sizeof(input) - at, "copper %s\ncopper %s\ncopper %s", key, other, key);
    for (int verify = 0; verify <= 1; ++verify) {
        script steps = {.count = verify ? 9 : 0};
        for (size_t k = 0; k < 3; ++k)
            for (size_t i = 0; i < 3; ++i)
                steps.rows[k * 3 + i] = (reply){.key = keys[k], .id = ids[i], .status = 200};
        br_results results = run(detector, input, verify, &steps, false); CHECK(results.len == 9);
        for (size_t k = 0; k < 3; ++k)
            for (size_t i = 0; i < 3; ++i) check_result(&results.items[k * 3 + i], keys[k], text(ids[i]), verify, NULL);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "copper %s %s %s", key, other, email);
    expect_extraction(detector, text(input), key, email); /* Only one prefixed whole key match. */
    snprintf(input, sizeof(input), "copper %s %s", key, email);
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], key, text(email), false, "net/http: nil Context"); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }

static void statuses_and_errors(const br_detector *detector)
{
    char key[33], other[33], message[256], expected[256]; test_secret(key, 32, 0); test_secret(other, 32, 7);
    const int statuses[] = {0, 199, 201, 204, 299, 300, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        snprintf(expected, sizeof(expected), "unexpected status code :%d", statuses[i]);
        verification_case(detector, key, (reply){.status = statuses[i], .body = "{", .read_error = "ignored drain failure"},
            false, statuses[i] == 401 ? NULL : expected);
    }
    verification_case(detector, key, (reply){.status = 200}, true, NULL);
    snprintf(message, sizeof(message), "%s %s %s %s", key, key, email, other);
    snprintf(expected, sizeof(expected), "[REDACTED] [REDACTED] %s %s", email, other);
    verification_case(detector, key, (reply){.status = 200, .read_error = message}, false, expected);
    verification_case(detector, key, (reply){.status = 200, .body = "{", .read_error = "ReadAll wins"}, false, "ReadAll wins");
    const char *errors[] = {"context canceled", "context deadline exceeded", "no such host", "out of memory constructing HTTP headers", message, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i)
        verification_case(detector, key, (reply){.status = 200, .send_rc = i % 2 ? 1 : -1, .send_error = errors[i]},
            false, i == 4 ? expected : errors[i] ? errors[i] : "HTTP transport failed");
    char input[128]; snprintf(input, sizeof(input), "copper %s %s", key, email);
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\nagent" : NULL};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1);
        const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
        check_result(&results.items[0], key, text(email), false, causes[mode]);
        CHECK(!http.calls && http.releases == (mode ? 1u : 0u)); br_results_clear(&results);
    }
    /* Other wildcard controls reach the shared invalid-header Do-error branch. */
    snprintf(input, sizeof(input), "copper %s abcd@AB\rcd", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(&results.items[0], key, text("abcd@AB\rcd"), false, "invalid HTTP header"); br_results_clear(&results);
    /* Failed verification of one occurrence does not suppress the next. */
    snprintf(input, sizeof(input), "copper %s copper %s %s", key, other, email);
    script steps = {.count = 2, .rows = {{.key = key, .id = email, .send_rc = 1, .send_error = "context canceled"}, {.key = other, .id = email, .status = 200}}};
    results = run(detector, input, true, &steps, false); CHECK(results.len == 2);
    check_result(&results.items[0], key, text(email), false, "context canceled"); check_result(&results.items[1], other, text(email), true, NULL); br_results_clear(&results);
}

static void typed_json(const br_detector *detector)
{
    char key[33]; test_secret(key, 32, 0);
    const char *mismatch = "email mismatch in verification response";
    const struct { const char *body; bool verified; const char *cause; } cases[] = {
        {"{\"id\":1,\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"id\":-9223372036854775808,\"email\":\"user@ExAmPlE.test\"} \r\n\t", true, NULL},
        {"{\"id\":9223372036854775807,\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"ID\":null,\"EMAIL\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"em\\u0061il\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"email\":\"user@example.test\"}", false, mismatch},
        {"{\"email\":\"USER@ExAmPlE.test\"}", false, mismatch},
        {"{\"email\":\" user@ExAmPlE.test\"}", false, mismatch},
        {"{\"email\":\"user@ExAmPlE.test\\u0000\"}", false, mismatch},
        {"{\"email\":null}", false, mismatch}, {"{}", false, mismatch}, {"null", false, mismatch},
        {"{\"nested\":{\"email\":\"user@ExAmPlE.test\"}}", false, mismatch},
        {"{\"email\":\"wrong\",\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"email\":\"user@ExAmPlE.test\",\"EMAIL\":\"wrong\"}", false, mismatch},
        {"{\"email\":\"user@ExAmPlE.test\",\"email\":null}", true, NULL},
        {"{\"email\":null,\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"email\":true,\"email\":\"user@ExAmPlE.test\"}", false, "json: cannot unmarshal bool into Go struct field UserApiResponse.email of type string"},
        {"{\"email\":1,\"email\":null}", false, "json: cannot unmarshal number into Go struct field UserApiResponse.email of type string"},
        {"{\"email\":[],\"email\":\"user@ExAmPlE.test\"}", false, "json: cannot unmarshal array into Go struct field UserApiResponse.email of type string"},
        {"{\"email\":{}}", false, "json: cannot unmarshal object into Go struct field UserApiResponse.email of type string"},
        {"{\"email\":\"user@ExAmPlE.test\",\"id\":null,\"ID\":1,\"id\":null}", true, NULL},
        {"{\"id\":\"1\",\"id\":0,\"email\":\"user@ExAmPlE.test\"}", false, "json: cannot unmarshal string into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":true}", false, "json: cannot unmarshal bool into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":[]}", false, "json: cannot unmarshal array into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":{}}", false, "json: cannot unmarshal object into Go struct field UserApiResponse.id of type int"},
        {"{\"email\":\"user@ExAmPlE.test\",\"id\":9223372036854775808}", false, "json: cannot unmarshal number 9223372036854775808 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":-9223372036854775809,\"id\":0}", false, "json: cannot unmarshal number -9223372036854775809 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":18446744073709551616}", false, "json: cannot unmarshal number 18446744073709551616 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":0.0,\"id\":null}", false, "json: cannot unmarshal number 0.0 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":0e0}", false, "json: cannot unmarshal number 0e0 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":1e9999}", false, "json: cannot unmarshal number 1e9999 into Go struct field UserApiResponse.id of type int"},
        {"{\"id\":-0,\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"unknown\":[1e9999,-9223372036854775809,{\"id\":1e9999}],\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"{\"unknown\":18446744073709551616000000,\"unknown\":1e9999,\"email\":\"user@ExAmPlE.test\"}", true, NULL},
        {"[]", false, "json: cannot unmarshal array into Go value of type copper.UserApiResponse"},
        {"true", false, "json: cannot unmarshal bool into Go value of type copper.UserApiResponse"},
        {"0", false, "json: cannot unmarshal number into Go value of type copper.UserApiResponse"},
        {"\"text\"", false, "json: cannot unmarshal string into Go value of type copper.UserApiResponse"},
        {"", false, "unexpected end of JSON input"}, {"{", false, "unexpected end of JSON input"},
        {"{} {}", false, "invalid character '{' after top-level value"},
        {"{\"id\":\"bad\"} garbage", false, "invalid character 'g' after top-level value"},
        {"{\"email\":\"user@ExAmPlE.test\"} trailing", false, "invalid character 't' after top-level value"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        verification_case(detector, key, (reply){.status = 200, .body = cases[i].body}, cases[i].verified, cases[i].cause);
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == prior->detector_type && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
    CHECK(results->items[0].secret_parts == prior->secret_parts);
}

static void resource_rollback(const br_detector *detector)
{
    char key[33], input[256]; test_secret(key, 32, 0);
    snprintf(input, sizeof(input), "copper %s copper %s %s", key, key, email);
    br_slice data = text(input);
    const struct { const char *body, *read_error, *cause; fault fail; const char *duplicate; } cases[] = {
        {"{\"email\":true}", NULL, "cannot decode Copper verification response", FAIL_DUP,
            "json: cannot unmarshal bool into Go struct field UserApiResponse.email of type string"},
        {"{\"id\":9223372036854775808}", NULL, "cannot decode Copper verification response", FAIL_NUMBER, NULL},
        {"{}", NULL, "cannot decode Copper verification response", FAIL_DUP, "email mismatch in verification response"},
        {"{", NULL, "cannot decode Copper verification response", FAIL_DUP, "unexpected end of JSON input"},
        {"[]", NULL, "cannot decode Copper verification response", FAIL_DUP, "json: cannot unmarshal array into Go value of type copper.UserApiResponse"},
        {NULL, "borrowed read failure", "cannot set Copper verification error", FAIL_DUP, "borrowed read failure"},
        {NULL, key, "cannot set Copper verification error", FAIL_REDACTION, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_result owned = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&owned, 777, "prior", "key") == 0); owned.verified = true;
        owned.verification_error = strdup("caller-owned"); CHECK(owned.verification_error && br_results_push(&results, &owned) == 0);
        br_result prior = results.items[0];
        script steps = {.count = 2, .rows = {{.key = key, .id = email, .status = 200},
            {.key = key, .id = email, .status = 200, .body = cases[i].body, .read_error = cases[i].read_error,
             .fail = cases[i].fail, .duplicate = cases[i].duplicate}}};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = scripted_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
        int rc = detector->scan(detector, &ctx, true, data, &results, &error);
        if (rc != -1 || !error || strcmp(error, cases[i].cause))
            fprintf(stderr, "resource case %zu: rc=%d cause=%s pending=%zu/%zu calls=%zu releases=%zu\n", i, rc, error ? error : "(none)", fail_strdup_after, fail_alloc_after, http.calls, http.releases);
        CHECK(rc == -1 && error && !strcmp(error, cases[i].cause));
        CHECK(!fail_strdup_after && !fail_alloc_after && http.calls == 2 && http.releases == 2 && !steps.borrowed_key);
        check_prior(&results, &prior); free(error); br_results_clear(&results);
    }
    for (int mode = 0; mode < 3; ++mode) {
        br_result owned = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&owned, 777, "prior", "key") == 0); owned.verified = true;
        owned.verification_error = strdup("caller-owned"); CHECK(owned.verification_error && br_results_push(&results, &owned) == 0);
        br_result prior = results.items[0];
        /* A positive object-add failure in the second finding beats any keep,
         * nil-context constructor cause, or disabled-verification outcome. */
        script steps = {.count = 1, .rows = {{.key = key, .id = email, .status = 200}}};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = scripted_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
        fail_part_after = 3;
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot create Copper result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls); check_prior(&results, &prior);
        free(error); error = NULL;
        /* Positive regex workspace and append-guard errors normalize to -1. */
        fail_size = 2 * sizeof(br_span); fail_alloc_after = 1;
        CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, &prior);
        size_t cap = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Copper result"));
        results.cap = cap; check_prior(&results, &prior); free(error); error = NULL;
        fail_strdup_text = "net/http: nil Context"; fail_strdup_after = 1;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot set Copper verification error"));
        CHECK(!fail_strdup_after); check_prior(&results, &prior); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); statuses_and_errors(detector); typed_json(detector); resource_rollback(detector);
    return test_finish("Copper");
}
