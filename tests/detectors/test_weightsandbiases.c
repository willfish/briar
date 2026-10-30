/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

int br_weightsandbiases_v1_init(const br_detector **out, char **error);
int br_weightsandbiases_v2_init(const br_detector **out, char **error);

static const char v1_key[] = "eedf1c984f6b995ec40ecc6658356044847ffb31";
static const char v1_other[] = "eedf1c984f6b995ec40ecc6658356044847ffb32";
static const char v2_key[] =
    "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";
static const char v2_other[] =
    "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";

static const br_detector *init_one(int (*factory)(const br_detector **, char **), int version,
                                   const char *keyword)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(factory(&detector, &error) == 0 && !error && detector);
    CHECK(factory(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1005 && detector->version == version);
    CHECK(!strcmp(detector->name, "WeightsAndBiases") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Weights & Biases is a Machine Learning Operations (MLOps) platform that helps track experiments, version datasets, evaluate model performance, and collaborate with team members"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], keyword));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(factory(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_version(const br_result *result, const char *version)
{
    CHECK(result->extra_data);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "version", &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK(!strcmp(json_object_get_string(value), version));
}

static void expect_key(const br_result *result, const char *key, const char *version)
{
    CHECK(result->detector_type == 1005 && !result->detector_name);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    expect_version(result, version);
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_raw(const br_detector *detector, const char *input, const char **keys,
                       size_t count, const char *version)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        expect_key(&results.items[i], keys[i], version);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        CHECK(json_object_object_length(results.items[i].extra_data) == 1);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    const char *one[] = {v1_key}, *both[] = {v1_key, v1_other};
    char input[512];
    snprintf(input, sizeof(input), "WANDB_API_KEY = '%s'", v1_key);
    expect_raw(v1, input, one, 1, "1");
    snprintf(input, sizeof(input), "WANDB_API_KEY = '%s'\nWANDB_API_KEY= '%s'", v1_key, v1_other);
    expect_raw(v1, input, both, 2, "1");
    snprintf(input, sizeof(input), "wandb %s wandb %s", v1_key, v1_key);
    expect_raw(v1, input, one, 1, "1"); /* Unique map drops the second copy. */
    expect_raw(v1, "", NULL, 0, "1");
    expect_raw(v1, v1_key, NULL, 0, "1");
    snprintf(input, sizeof(input), "wandb %.39s", v1_key);
    expect_raw(v1, input, NULL, 0, "1");
    snprintf(input, sizeof(input), "wandb %sf", v1_key);
    expect_raw(v1, input, NULL, 0, "1");
    char upper[41];
    memcpy(upper, v1_key, 41);
    upper[0] = 'E';
    snprintf(input, sizeof(input), "wandb %s", upper);
    expect_raw(v1, input, NULL, 0, "1");
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "wandb%.*s%s", gap, "-----------------------------------------", v1_key);
        expect_raw(v1, input, gap == 40 ? one : NULL, gap == 40 ? 1 : 0, "1");
    }
    snprintf(input, sizeof(input), "prefixwandbsuffix %s", v1_key);
    expect_raw(v1, input, one, 1, "1");

    const char *v2_one[] = {v2_key}, *v2_both[] = {v2_key, v2_other};
    snprintf(input, sizeof(input), "WANDB_API_KEY = '%s'", v2_key);
    expect_raw(v2, input, v2_one, 1, "2");
    snprintf(input, sizeof(input), "%s\n%s\n%s", v2_key, v2_other, v2_key);
    expect_raw(v2, input, v2_both, 2, "2"); /* Unprefixed; duplicate collapsed. */
    expect_raw(v2, v1_key, NULL, 0, "2");
    snprintf(input, sizeof(input), "wandb_v1_%.26s_%.49s", v2_key + 9, v2_key + 37);
    expect_raw(v2, input, NULL, 0, "2");
    expect_raw(v1, v2_key, NULL, 0, "1");
}

typedef struct { const char *key; const char *body; } expected_request;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_request *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.wandb.ai/graphql"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1005);
    CHECK(request->body.len == strlen("{\"query\": \"query Viewer { viewer { id username email admin } }\"}"));
    CHECK(!memcmp(request->body.data, "{\"query\": \"query Viewer { viewer { id username email admin } }\"}",
                  request->body.len));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char *authorization = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)"api", 3},
                             (br_slice){(const unsigned char *)expected->key, strlen(expected->key)},
                             &authorization, NULL) == 0);
    CHECK(!strcmp(request->headers[1].value, authorization));
    free(authorization);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog wandb-test"));
}

static void expect_verify(const br_detector *detector, test_http *http, const char *input,
                          const char *key, const char *version, bool verified, const char *error,
                          const char *username, const char *email, const char *admin)
{
    expected_request expected = {key, NULL};
    http->calls = http->releases = 0;
    http->inspect = inspect;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "wandb-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    expect_key(&results.items[0], key, version);
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, key));
    } else CHECK(!results.items[0].verification_error);
    if (username) {
        br_json *value = NULL;
        CHECK(json_object_object_length(results.items[0].extra_data) == 4);
        CHECK(json_object_object_get_ex(results.items[0].extra_data, "username", &value));
        CHECK(!strcmp(json_object_get_string(value), username));
        CHECK(json_object_object_get_ex(results.items[0].extra_data, "email", &value));
        CHECK(!strcmp(json_object_get_string(value), email));
        CHECK(json_object_object_get_ex(results.items[0].extra_data, "admin", &value));
        CHECK(!strcmp(json_object_get_string(value), admin));
    } else CHECK(json_object_object_length(results.items[0].extra_data) == 1);
    br_results_clear(&results);
}

static void expect_field_bytes(br_json *object, const char *key, const void *bytes, size_t len)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, key, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == len);
    if (len) CHECK(!memcmp(json_object_get_string(value), bytes, len));
}

static void expect_nul_meta(const br_detector *detector, const char *input, const char *key,
                            const char *body, const void *username, size_t username_len,
                            const void *email, size_t email_len)
{
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}}};
    expected_request expected = {key, NULL};
    http.inspect = inspect;
    http.user = &expected;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "wandb-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_length(results.items[0].extra_data) == 4);
    expect_field_bytes(results.items[0].extra_data, "username", username, username_len);
    expect_field_bytes(results.items[0].extra_data, "email", email, email_len);
    expect_field_bytes(results.items[0].extra_data, "admin", "false", 5);
    br_results_clear(&results);
}

static void verification(const br_detector *v1, const br_detector *v2)
{
    char input[256], body[256];
    snprintf(input, sizeof(input), "wandb %s", v1_key);
    snprintf(body, sizeof(body),
             "{\"data\":{\"viewer\":{\"id\":\"1\",\"username\":\"ada\",\"email\":\"a@b.c\",\"admin\":true}}}");
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}}};
    expect_verify(v1, &http, input, v1_key, "1", true, NULL, "ada", "a@b.c", "true");
    snprintf(body, sizeof(body),
             "{\"DATA\":{\"Viewer\":{\"Username\":\"Ada\",\"Email\":\"\",\"Admin\":false}}}");
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    expect_verify(v1, &http, input, v1_key, "1", true, NULL, "Ada", "", "false");
    snprintf(body, sizeof(body), "{\"data\":{\"viewer\":{\"username\":\"\"}}}");
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    expect_verify(v1, &http, input, v1_key, "1", false, NULL, NULL, NULL, NULL);
    snprintf(body, sizeof(body), "{\"data\":{\"viewer\":{\"id\":3,\"username\":\"alice\"}}}");
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    expect_verify(v1, &http, input, v1_key, "1", false,
                  "json: cannot unmarshal number into Go struct field .data.viewer.id of type string",
                  NULL, NULL, NULL);
    snprintf(body, sizeof(body), "{\"data\":{\"viewer\":{\"id\":1,\"id\":\"later\",\"username\":\"alice\"}}}");
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    expect_verify(v1, &http, input, v1_key, "1", false,
                  "json: cannot unmarshal number into Go struct field .data.viewer.id of type string",
                  NULL, NULL, NULL);
    snprintf(body, sizeof(body), "{\"data\":{\"viewer\":{\"username\":\"alice\",\"username\":null,\"email\":null,\"admin\":null}}}");
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    expect_verify(v1, &http, input, v1_key, "1", true, NULL, "alice", "", "false");
    const char leading[] = {'\0', 'a', 'l', 'i', 'c', 'e'};
    expect_nul_meta(v1, input, v1_key,
                    "{\"data\":{\"viewer\":{\"username\":\"\\u0000alice\"}}}",
                    leading, sizeof(leading), "", 0);
    const char embedded[] = {'a', '\0', 'b'};
    expect_nul_meta(v1, input, v1_key,
                    "{\"data\":{\"viewer\":{\"username\":\"a\\u0000b\",\"email\":\"a\\u0000b\"}}}",
                    embedded, sizeof(embedded), embedded, sizeof(embedded));
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    expect_verify(v1, &http, input, v1_key, "1", false, NULL, NULL, NULL, NULL);
    http.response.body = (br_slice){(const unsigned char *)"null", 4};
    expect_verify(v1, &http, input, v1_key, "1", false, NULL, NULL, NULL, NULL);
    http.response.body = (br_slice){(const unsigned char *)"not-json", 8};
    expect_verify(v1, &http, input, v1_key, "1", false, "invalid character 'o' looking for beginning of value",
                  NULL, NULL, NULL);
    http.response.body = (br_slice){0};
    http.response.body_error = "read failed";
    expect_verify(v1, &http, input, v1_key, "1", false, "read failed", NULL, NULL, NULL);
    http.response.body_error = NULL;
    const struct { int status; const char *error; } statuses[] = {
        {401, NULL}, {201, "unexpected HTTP response status 201"},
        {403, "unexpected HTTP response status 403"}, {500, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.response.status = statuses[i].status;
        http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
        expect_verify(v1, &http, input, v1_key, "1", false, statuses[i].error, NULL, NULL, NULL);
    }
    http = (test_http){.send_rc = -1, .send_error = "context canceled"};
    expect_verify(v1, &http, input, v1_key, "1", false, "context canceled", NULL, NULL, NULL);
    char sensitive[160];
    snprintf(sensitive, sizeof(sensitive), "token %s rejected", v1_key);
    http.send_error = sensitive;
    expect_verify(v1, &http, input, v1_key, "1", false, "token [REDACTED] rejected", NULL, NULL, NULL);
    http.send_error = NULL;
    /* br_http_send supplies this text when the mock diagnostic is NULL. */
    expect_verify(v1, &http, input, v1_key, "1", false, "HTTP transport failed", NULL, NULL, NULL);

    char *nil_error = NULL;
    br_results nil_results = {0};
    CHECK(v1->scan(v1, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                   &nil_results, &nil_error) == 0 && !nil_error);
    CHECK(nil_results.len == 1 && !nil_results.items[0].verified);
    CHECK(!strcmp(nil_results.items[0].verification_error, "net/http: nil Context"));
    expect_version(&nil_results.items[0], "1");
    br_results_clear(&nil_results);

    snprintf(input, sizeof(input), "%s", v2_key);
    snprintf(body, sizeof(body),
             "{\"data\":{\"viewer\":{\"username\":\"bot\",\"email\":\"b@c.d\",\"admin\":false}}} trailing");
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}}};
    expect_verify(v2, &http, input, v2_key, "2", true, NULL, "bot", "b@c.d", "false");
}

static int wb_hook_mode, wb_type_calls;

static int wb_hook_document(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (wb_hook_mode == 1) return 2;
    return br_json_first_document(body, read_error, out, end, cause);
}

static int wb_hook_visit(br_slice object, br_json_member_fn visit, void *user)
{
    int rc = br_json_each_member(object, visit, user);
    if (!rc && wb_hook_mode == 2) return 1;
    return rc;
}

static int wb_hook_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++wb_type_calls;
    if (wb_hook_mode == 3 && wb_type_calls == 1) {
        if (cause) *cause = NULL;
        return 0;
    }
    if (wb_hook_mode == 4 && wb_type_calls == 2) return 1;
    return br_json_type_cause(value, field, expected, cause);
}

#define br_json_first_document wb_hook_document
#define br_json_each_member wb_hook_visit
#define br_json_type_cause wb_hook_type
#define br_weightsandbiases_v1_init wb_hook_v1
#define br_weightsandbiases_v2_init wb_hook_v2
#include "../../src/detectors/weightsandbiases.c"
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_type_cause
#undef br_weightsandbiases_v1_init
#undef br_weightsandbiases_v2_init

static void wb_seam(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(wb_hook_v1(&detector, &error) == 0 && detector && !error);
    const char *text = "wandb eedf1c984f6b995ec40ecc6658356044847ffb31";
    const char *sticky = "{\"data\":{\"viewer\":{\"id\":3,\"username\":1}}}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)sticky, strlen(sticky)}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "wandb-test"};
    br_slice input = {(const unsigned char *)text, strlen(text)};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);

    wb_hook_mode = 1;
    br_results results = {0};
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot decode WeightsAndBiases response"));
    CHECK(results.len == 1 && results.items[0].detector_type == 9);
    free(error); error = NULL;
    br_results_clear(&results);

    wb_hook_mode = 3;
    wb_type_calls = 0;
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) == 0 && !error);
    CHECK(wb_type_calls == 2 && results.len == 1 && !results.items[0].verified);
    CHECK(!results.items[0].verification_error);
    br_results_clear(&results);

    wb_hook_mode = 4;
    wb_type_calls = 0;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(wb_type_calls == 2 && error && results.len == 1);
    free(error); error = NULL;
    br_results_clear(&results);

    wb_hook_mode = 2;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && results.len == 1);
    free(error);
    br_results_clear(&results);
    br_result_clear(&prior);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *v1 = init_one(br_weightsandbiases_v1_init, 1, "wandb");
    const br_detector *v2 = init_one(br_weightsandbiases_v2_init, 2, "wandb_v1_");
    CHECK(strlen(v1_key) == 40 && strlen(v2_key) == 9 + 27 + 1 + 49);
    extraction(v1, v2);
    verification(v1, v2);
    wb_seam();
    char *error = NULL;
    CHECK(v1->scan(NULL, NULL, false, (br_slice){0}, &(br_results){0}, &error) != 0 && error);
    free(error);
    return test_finish("WeightsAndBiases");
}
