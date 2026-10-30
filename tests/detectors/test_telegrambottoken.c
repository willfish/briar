/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int tg_doc_rc;
static int tg_visit_rc;
static int tg_type_null;
static int tg_type_fatal_after;
static int tg_type_fatal_rc;
static int tg_type_calls;

int br_telegrambottoken_json_document(br_slice body, const char *read_error, br_json **out,
                                      size_t *end, char **cause)
{
    if (tg_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return tg_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_telegrambottoken_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return tg_visit_rc && rc == 0 ? tg_visit_rc : rc;
}

int br_telegrambottoken_type_cause(br_json *value, const char *field, const char *expected,
                                   char **cause)
{
    ++tg_type_calls;
    if (tg_type_fatal_after && tg_type_calls >= tg_type_fatal_after) {
        if (cause) *cause = NULL;
        return tg_type_fatal_rc ? tg_type_fatal_rc : -1;
    }
    if (tg_type_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, field, expected, cause);
}

int br_telegrambottoken_init(const br_detector **out, char **error);

static const char key[] = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_telegrambottoken_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_telegrambottoken_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 91 && !strcmp(detector->name, "TelegramBotToken"));
    CHECK(!strcmp(detector->description,
                  "Telegram Bot API tokens are used to authenticate requests to the Telegram Bot API. They can be used to control and interact with Telegram bots."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "telegram") &&
          !strcmp(detector->keywords[1], "tgram"));
    CHECK(detector->max_credential_span == -1);
    CHECK(strlen(key) == 9 + 1 + 35);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "telegram %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 91, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "tgram://%s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 91, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "tgram %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "telegram %s telegram %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static int tg_status;
static const char *tg_body;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/getMe", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->nheaders == 1 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    http->response.status = tg_status;
    if (tg_body) http->response.body = (br_slice){(const unsigned char *)tg_body, strlen(tg_body)};
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "telegram %s", key);
    tg_status = 200;
    tg_body = "{\"ok\":true,\"result\":{\"is_bot\":true,\"username\":\"demo_bot\"}}";
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && results.items[0].extra_data);
    CHECK(!strcmp(json_object_get_string(json_object_object_get(results.items[0].extra_data, "username")),
                  "demo_bot"));
    br_results_clear(&results);
    tg_body = "{\"ok\":false,\"result\":{\"username\":\"ignored\"}}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data);
    br_results_clear(&results);
    tg_body = "{\"ok\":true,\"ok\":null,\"result\":{\"username\":\"ada\"}}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && results.items[0].extra_data);
    CHECK(!strcmp(json_object_get_string(json_object_object_get(results.items[0].extra_data, "username")),
                  "ada"));
    br_results_clear(&results);
    tg_body = "{\"ok\":true,\"result\":{\"username\":\"keep\"},\"result\":null,\"result\":{\"username\":\"ada\"}}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].extra_data);
    CHECK(!strcmp(json_object_get_string(json_object_object_get(results.items[0].extra_data, "username")),
                  "ada"));
    br_results_clear(&results);
    tg_body = "{\"ok\":true,\"result\":{\"username\":\"keep\",\"username\":null}}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].extra_data);
    CHECK(!strcmp(json_object_get_string(json_object_object_get(results.items[0].extra_data, "username")),
                  "keep"));
    br_results_clear(&results);
    tg_type_calls = 0;
    tg_type_null = 1;
    tg_body = "{\"ok\":true,\"result\":{\"username\":1}}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data);
    br_results_clear(&results);
    tg_type_null = 0;
    br_results_clear(&results);
    tg_body = "not-json";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data &&
          !results.items[0].verification_error);
    br_results_clear(&results);
    tg_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    tg_status = 200;
    tg_body = "{}";
    tg_doc_rc = 2;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[96];
    snprintf(input, sizeof(input), "telegram %s", key);
    br_results fatal = {0};
    char *scan_error = NULL;
    br_slice bytes = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Telegram response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    tg_doc_rc = 0;
    tg_visit_rc = 1;
    tg_body = "{\"ok\":1}";
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Telegram response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    tg_visit_rc = 0;
    tg_type_calls = 0;
    tg_type_fatal_after = 2;
    tg_body = "{\"ok\":1,\"result\":{\"username\":1}}";
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Telegram response") && !fatal.len);
    CHECK(tg_type_calls >= 2);
    free(scan_error);
    br_results_clear(&fatal);
    for (int code = 1; code <= 2; ++code) {
        tg_type_calls = 0;
        tg_type_fatal_after = 2;
        tg_type_fatal_rc = code;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot decode Telegram response") && !fatal.len);
        CHECK(tg_type_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    tg_type_fatal_after = 0;
    tg_type_fatal_rc = 0;
    return test_finish("telegrambottoken");
}
