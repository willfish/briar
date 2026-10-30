/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_json;
static int force_null_send;
static br_http_response forced_response;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int (*real_http_send)(const br_scan_ctx *, const br_http_request *, br_http_response *, char **) = br_http_send;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
static int http_send_hook(const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    if (force_null_send) {
        if (response) *response = forced_response;
        if (error) *error = NULL;
        return 1;
    }
    return real_http_send(ctx, request, response, error);
}
#define br_json_first_document first_hook
#define br_http_send http_send_hook
#include "../../src/detectors/typeform.c"
#undef br_json_first_document
#undef br_http_send

static int tf_type_calls, tf_type_fatal_after, tf_type_null;
static int tf_type_hook(br_json *value, const char *field, char **cause)
{
    ++tf_type_calls;
    if (tf_type_fatal_after && tf_type_calls >= tf_type_fatal_after) {
        if (cause) *cause = NULL;
        return -1;
    }
    if (tf_type_null) {
        if (cause) *cause = NULL;
        return 1;
    }
    return typeform_type_cause_real(value, field, cause);
}

static const char v1_key[] = "tfpsOcxPYaEVD4SNQ5f7HptyomeOpE1SaEuEbkusbBLR";
static const char v1_other[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char v2_key[] = "tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB";

static const br_detector *init_one(int (*init)(const br_detector **, char **), int version,
                                   const char *keyword)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 370 && detector->version == version && !strcmp(detector->name, "Typeform"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Typeform is a service for creating forms and surveys. Typeform API keys can be used to access and manage forms and responses."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], keyword));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(init(&again, &error) == 0 && !error && again == detector);
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Typeform detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    return detector;
}

static void expect_header(const br_http_request *request, const char *key)
{
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.typeform.com/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 370);
    CHECK(!request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog typeform-offline"));
}

static void inspect_v1(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    expect_header(request, v1_key);
}

static void inspect_v2(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    expect_header(request, v2_key);
}

static void check_key(const br_result *result, const char *key)
{
    test_key_result(result, 370, key, "key");
}

static void extraction_v1(const br_detector *detector)
{
    char near[160], far[160], invalid[96], folded[96];
    snprintf(near, sizeof(near), "typeform %s TYPEFORM %s", v1_key, v1_other);
    snprintf(far, sizeof(far), "typeform keyword is not close to the real key in the data\n = '%s'", v1_key);
    snprintf(invalid, sizeof(invalid), "typeform = '%s'", "tf?sOcxPYaEVD4SNQ5f7HptyomeOpE1SaEuEbkusbBLR");
    snprintf(folded, sizeof(folded), "typeform token = '%s'", v1_key);
    br_results results = test_scan(detector, NULL, false, folded, strlen(folded));
    CHECK(results.len == 1); check_key(&results.items[0], v1_key); br_results_clear(&results);
    results = test_scan(detector, NULL, false, near, strlen(near));
    CHECK(results.len == 2);
    check_key(&results.items[0], v1_key); check_key(&results.items[1], v1_other);
    CHECK(results.items[0].raw.data != results.items[1].raw.data);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, far, strlen(far));
    CHECK(!results.len); br_results_clear(&results);
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(!results.len); br_results_clear(&results);
    /* The published duplicate fixture is one keyword and a second key past the window. */
    char published[180];
    snprintf(published, sizeof(published), "typeform token = '%s' | '%s'", v1_key, v1_key);
    results = test_scan(detector, NULL, false, published, strlen(published));
    CHECK(results.len == 1); check_key(&results.items[0], v1_key); br_results_clear(&results);
}

static void extraction_v2(const br_detector *detector)
{
    const char *input = "typeform_token = 'tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB'";
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_key(&results.items[0], v2_key); br_results_clear(&results);
    char both[180];
    snprintf(both, sizeof(both), "%s %s", v2_key, v2_key);
    results = test_scan(detector, NULL, false, both, strlen(both));
    CHECK(results.len == 2);
    check_key(&results.items[0], v2_key); check_key(&results.items[1], v2_key);
    br_results_clear(&results);
    char short_key[64], long_key[80];
    memset(short_key, 'a', 39); short_key[39] = '\0';
    memset(long_key, 'b', 60); long_key[60] = '\0';
    char rejected[160];
    snprintf(rejected, sizeof(rejected), "tfp_%s tfp_%s", short_key, long_key);
    results = test_scan(detector, NULL, false, rejected, strlen(rejected));
    CHECK(!results.len); br_results_clear(&results);
    char minimum[64];
    memset(minimum, 'c', 40); minimum[40] = '\0';
    snprintf(rejected, sizeof(rejected), "tfp_%s", minimum);
    results = test_scan(detector, NULL, false, rejected, strlen(rejected));
    CHECK(results.len == 1 && results.items[0].raw.len == 44); br_results_clear(&results);
}

static void verify_status(const br_detector *detector, const char *input, const char *key,
                          void (*inspect)(test_http *, const br_scan_ctx *, const br_http_request *),
                          bool version_two)
{
    static const int statuses[] = {200, 401, 403, 404, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body = {(const unsigned char *)"null", 4}},
                          .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "typeform-offline"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_key(&results.items[0], key);
        if (statuses[i] == 200) {
            CHECK(results.items[0].verified && !results.items[0].verification_error);
            if (version_two) CHECK(!results.items[0].extra_data);
            else CHECK(!results.items[0].extra_data);
        } else if (statuses[i] == 401 || statuses[i] == 403) {
            CHECK(!results.items[0].verified && !results.items[0].verification_error && !results.items[0].extra_data);
        } else {
            char message[64];
            snprintf(message, sizeof(message), version_two ? "unexpected status code %d" : "unexpected status code: %d", statuses[i]);
            CHECK(!results.items[0].verified && results.items[0].verification_error);
            CHECK(!strcmp(results.items[0].verification_error, message) && !results.items[0].extra_data);
        }
        br_results_clear(&results);
    }
    char echoed[160];
    snprintf(echoed, sizeof(echoed), "dial failed while sending %s", key);
    test_http http = {.send_rc = 1, .send_error = echoed, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "typeform-offline"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, echoed));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void extra_data(const br_detector *detector)
{
    const char *body = "{\"user_id\":\"u\",\"email\":null,\"alias\":\"a\",\"language\":\"l\",\"extra\":1}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}},
                      .inspect = inspect_v2};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "typeform-offline"};
    const char *input = "tfp_ABCDEfghijKLMNOPqrstuvWXYZ0123456789ABCDEFGH_ijK12340qqqBBB";
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 4);
    br_json *field = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "UserId", &field) && !strcmp(json_object_get_string(field), "u"));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Email", &field) && !strcmp(json_object_get_string(field), ""));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Alias", &field) && !strcmp(json_object_get_string(field), "a"));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Language", &field) && !strcmp(json_object_get_string(field), "l"));
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{\"email\":1}", 11};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data);
    CHECK(!strcmp(results.items[0].verification_error,
        "json: cannot unmarshal number into Go struct field TypeFormResponse.email of type string"));
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"[]", 2};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error,
        "json: cannot unmarshal array into Go value of type typeform.TypeFormResponse"));
    br_results_clear(&results);
    http.response.body = (br_slice){0};
    http.response.body_error = "synthetic read";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "synthetic read"));
    br_results_clear(&results);
    http.response.body_error = NULL;
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"[]", 2};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 200;
    static const char kept[] = "{\"email\":\"keep\",\"email\":null}";
    http.response.body = (br_slice){(const unsigned char *)kept, sizeof(kept) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Email", &field));
    CHECK(json_object_get_string_len(field) == 4 && !strcmp(json_object_get_string(field), "keep"));
    br_results_clear(&results);
    static const char nul_email[] = "{\"email\":\"ab\\u0000cd\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_email, sizeof(nul_email) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Email", &field));
    CHECK(json_object_get_string_len(field) == 5 &&
          !memcmp(json_object_get_string(field), "ab\0cd", 5));
    br_results_clear(&results);
    typeform_type_cause = tf_type_hook;
    tf_type_calls = 0; tf_type_null = 1; tf_type_fatal_after = 0;
    static const char later_alias[] = "{\"email\":1,\"alias\":\"a\"}";
    http.response.body = (br_slice){(const unsigned char *)later_alias, sizeof(later_alias) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(!results.items[0].extra_data && tf_type_calls == 1);
    br_results_clear(&results);
    tf_type_calls = 0; tf_type_null = 0; tf_type_fatal_after = 2;
    char *scan_error = NULL;
    br_results failed = {0};
    static const char later_bool[] = "{\"email\":1,\"alias\":true}";
    http.response.body = (br_slice){(const unsigned char *)later_bool, sizeof(later_bool) - 1};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &failed, &scan_error) != 0);
    CHECK(!failed.len && tf_type_calls >= 2);
    free(scan_error);
    br_results_clear(&failed);
    typeform_type_cause = typeform_type_cause_real;
    tf_type_calls = tf_type_null = tf_type_fatal_after = 0;
    forced_response = (br_http_response){.status = 200,
        .body = {(const unsigned char *)"{\"email\":\"should-not-verify\"}", 28}};
    force_null_send = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(!results.items[0].extra_data);
    br_results_clear(&results);
    force_null_send = 0;
    force_json = 2;
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    scan_error = NULL;
    failed = (br_results){0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    force_json = 0;
}

static void rollback(const br_detector *detector, const char *input)
{
    br_result sentinel = {.detector_type = 777, .verified = true};
    sentinel.raw.data = malloc(5); CHECK(sentinel.raw.data);
    memcpy(sentinel.raw.data, "prior", 5); sentinel.raw.len = 5;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    br_results results = {0};
    CHECK(br_results_push(&results, &sentinel) == 0);
    size_t capacity = results.cap;
    results.cap = 0;
    char *error = NULL;
    br_slice data = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot append Typeform result"));
    CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].raw.data);
    CHECK(!memcmp(results.items[0].raw.data, "prior", 5));
    free(error);
    results.cap = capacity;
    br_results_clear(&results);
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &results, &error) == -1 && error);
    free(error);
}

int main(void)
{
    const br_detector *v1 = init_one(br_typeform_v1_init, 1, "typeform");
    const br_detector *v2 = init_one(br_typeform_v2_init, 2, "tfp_");
    extraction_v1(v1);
    extraction_v2(v2);
    char v1_input[80], v2_input[96];
    snprintf(v1_input, sizeof(v1_input), "typeform %s", v1_key);
    snprintf(v2_input, sizeof(v2_input), "%s", v2_key);
    verify_status(v1, v1_input, v1_key, inspect_v1, false);
    verify_status(v2, v2_input, v2_key, inspect_v2, true);
    extra_data(v2);
    rollback(v1, v1_input);
    return test_finish("Typeform v1/v2");
}
