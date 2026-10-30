/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pastebin_init(const br_detector **out, char **error);

static const char key[] = "AbC_def0123456789GhIjKlMnOpQrStU";
static const char other[] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[40];
    CHECK(len >= 0 && (size_t)len < sizeof(copy));
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_pastebin_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Pastebin detector output"));
    free(error);
    error = NULL;
    CHECK(!br_pastebin_init(&detector, &error) && detector && !error);
    CHECK(!br_pastebin_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 492 && !detector->version && !strcmp(detector->name, "Pastebin") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Pastebin is a website where users can store plain text. Pastebin keys can be used to access and manipulate stored data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pastebin"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->false_positive);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 492, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[160], changed[40];
    snprintf(input, sizeof(input), "pastebin '%s'", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "PASTEBIN=%s", other);
    expect_one(detector, input, other);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "paste bin %s", key);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[3] = '-';
    snprintf(input, sizeof(input), "pastebin %s", changed);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "pastebin %s_", key);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "pastebin %.31s", key);
    expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        char gap_input[96];
        memcpy(gap_input, "pastebin", 8);
        memset(gap_input + 8, '.', gap);
        memcpy(gap_input + 8 + gap, key, 32);
        br_results results = test_scan(detector, NULL, false, gap_input, (size_t)(8 + gap + 32));
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        if (gap == 40) check_result(&results.items[0], key, false);
        br_results_clear(&results);
    }
}

static int field_at(const unsigned char *body, size_t len, const char *boundary, const char *name,
                    const char *value)
{
    char header[96];
    int n = snprintf(header, sizeof(header), "Content-Disposition: form-data; name=\"%s\"\r\n\r\n%s", name, value);
    CHECK(n > 0 && (size_t)n < sizeof(header));
    for (size_t i = 0; i + (size_t)n <= len; ++i)
        if (!memcmp(body + i, header, (size_t)n)) return 1;
    (void)boundary;
    return 0;
}

static int paste_status;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(request->detector_type == 492 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://pastebin.com/api/api_post.php"));
    CHECK(request->nheaders == 2 && !request->dedup_key.len && request->body.len == 469 && request->body.data);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    const char *type = request->headers[0].value;
    static const char prefix[] = "multipart/form-data; boundary=";
    CHECK(!strncmp(type, prefix, sizeof(prefix) - 1) && strlen(type) == sizeof(prefix) - 1 + 60);
    const char *boundary = type + sizeof(prefix) - 1;
    for (size_t i = 0; i < 60; ++i) {
        char c = boundary[i];
        CHECK((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    CHECK(field_at(request->body.data, request->body.len, boundary, "api_dev_key", http->user));
    CHECK(field_at(request->body.data, request->body.len, boundary, "api_paste_code", "test"));
    CHECK(field_at(request->body.data, request->body.len, boundary, "api_option", "paste"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    http->response = (br_http_response){.status = paste_status, .body_error = "ignored close"};
}

static void verification(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "pastebin %s\npastebin %s", key, other);
    test_http http = {.inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    /* Two calls share one inspect user; check the first key, then swap. */
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && !http.calls);
    br_results_clear(&results);
    http.user = (void *)key;
    paste_status = 201;
    snprintf(input, sizeof(input), "pastebin %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    http.user = (void *)other;
    paste_status = 500;
    snprintf(input, sizeof(input), "pastebin %s", other);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
    http.send_error = "boom";
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "pastebin %s\npastebin %s", key, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    char *error = NULL;
    fail_finding_after = 2;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create Pastebin result") && results.len == 1);
    CHECK(results.items[0].detector_type == 777);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("Pastebin occurrences, multipart body, 2xx, nil skip, rollback");
}
