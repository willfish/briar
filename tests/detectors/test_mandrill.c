/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_mandrill_init(const br_detector **out, char **error);

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_mandrill_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Mandrill detector output"));
    free(error);
    CHECK(br_mandrill_init(NULL, NULL) != 0);
    CHECK(br_mandrill_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_mandrill_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 172 && detector->version == 0 && !strcmp(detector->name, "Mandrill"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Mandrill is a transactional email API for Mailchimp users. Mandrill API keys can be used to send and track email messages."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mandrill"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 172, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const char *key = "z8A3Owe1WRrHmg4AHQZlwK";
    const char *second = "abc_DEF-0123456789abcd";
    const char *keys[] = {key, second};
    char input[256];
    const struct { const char *format; size_t count; } cases[] = {
        {"mandrill token = '%s'", 1},
        {"MANDRILL: %s", 1},
        {"%s", 0},
        {"%s mandrill", 0},
        {"mandrill%s", 0},
        {"mandrill %.21s", 0},
        {"mandrill %sq", 1}, /* trailing word char is outside the bounded capture */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_keys(detector, input, keys, cases[i].count == 1 && i == 6 ? 0 : cases[i].count);
    }
    snprintf(input, sizeof(input), "mandrill %sq", key);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "mandrill %s\nmandrill %s", key, key);
    const char *dups[] = {key, key};
    expect_keys(detector, input, dups, 2);
    /* FindAll consumes the prefix, so one keyword anchors only the first key. */
    snprintf(input, sizeof(input), "mandrill %s %s", key, second);
    expect_keys(detector, input, keys, 1);
    snprintf(input, sizeof(input), "mandrill %s\nmandrill %s", key, second);
    expect_keys(detector, input, keys, 2);
    memcpy(input, "mandrill", 8);
    memset(input + 8, ' ', 40);
    memcpy(input + 48, key, 22);
    input[70] = 0;
    expect_keys(detector, input, keys, 1);
    input[8 + 40] = 'x';
    memmove(input + 49, key, 22);
    input[71] = 0;
    expect_keys(detector, input, NULL, 0);
    expect_keys(detector, "", NULL, 0);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    char body[40];
    snprintf(body, sizeof(body), "{\"key\": \"%s\"}", key);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://mandrillapp.com/api/1.0/users/info"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 172);
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(!request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t typed = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Content-Type")) {
            ++typed;
            CHECK(!strcmp(request->headers[i].value, "application/json"));
        } else if (!strcmp(request->headers[i].name, "User-Agent")) ++agent;
        else CHECK(!"unexpected Mandrill header");
    }
    CHECK(typed == 1 && agent == 1 && ctx);
}

static void verification(const br_detector *detector)
{
    const char *key = "z8A3Owe1WRrHmg4AHQZlwK";
    char input[64];
    snprintf(input, sizeof(input), "mandrill %s", key);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 172, key, "key");
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = 1, .send_error = "context deadline exceeded", .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&failed);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && failed.calls == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Mandrill");
}
