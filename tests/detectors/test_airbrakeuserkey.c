/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_airbrakeuserkey_init(&detector, &error) == 0 && !error && detector);
    const void *compiled = detector->state;
    CHECK(br_airbrakeuserkey_init(&again, &error) == 0 && !error && again == detector);
    CHECK(compiled && again->state == compiled);
    CHECK(detector->type == 126 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AirbrakeUserKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Airbrake is an error and performance monitoring service. "
        "Airbrake User Keys can be used to access and manage error reports and performance data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "airbrake"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key)
{
    /* Reuse the shared key assertions; check this provider's ExtraData separately. */
    br_result key_fields = *result;
    key_fields.extra_data = NULL;
    test_key_result(&key_fields, 126, key, "key");
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object));
    CHECK(json_object_object_length(result->extra_data) == 1);
    br_json *guide = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &guide));
    CHECK(json_object_is_type(guide, json_type_string));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/airbrake/"));
}

static void expect_keys(const br_detector *detector, const void *input, size_t len,
                         const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        size_t k = 0;
        for (; k < count; ++k)
            if (results.items[i].raw.len == strlen(keys[k]) &&
                !memcmp(results.items[i].raw.data, keys[k], strlen(keys[k]))) break;
        CHECK(k < count);
        check_result(&results.items[i], keys[k]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        /* The upstream map has unspecified order, but cannot emit a key twice. */
        for (size_t j = 0; j < i; ++j)
            CHECK(memcmp(results.items[i].raw.data, results.items[j].raw.data, 40) != 0);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[512], changed[41];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "airbrake = '%s'", key);
    expect_keys(detector, input, strlen(input), one, 1);
    expect_keys(detector, NULL, 0, NULL, 0);
    expect_keys(detector, key, 40, NULL, 0);
    snprintf(input, sizeof(input), "%s airbrake", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "preAIRBRAKEsuffix:%s", key);
    expect_keys(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "airbrake\r\n%s", key);
    expect_keys(detector, input, strlen(input), one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "airbrake");
        memset(input + at, ' ', gap);
        memcpy(input + at + gap, key, 41);
        expect_keys(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } bad_boundaries[] = {
        {"_", ""}, {"x", ""}, {"", "_"}, {"", "q"},
    };
    for (size_t i = 0; i < sizeof(bad_boundaries) / sizeof(bad_boundaries[0]); ++i) {
        snprintf(input, sizeof(input), "airbrake %s%s%s",
                 bad_boundaries[i].before, key, bad_boundaries[i].after);
        expect_keys(detector, input, strlen(input), NULL, 0);
    }
    snprintf(input, sizeof(input), "airbrake %.39s", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    const char invalid[] = {'_', '%', '$', ':', '/'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[20] = invalid[i];
        snprintf(input, sizeof(input), "airbrake %s", changed);
        expect_keys(detector, input, strlen(input), NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[0] = '-';
    const char *hyphen[] = {changed};
    snprintf(input, sizeof(input), "airbrake%s", changed);
    expect_keys(detector, input, strlen(input), hyphen, 1);
    snprintf(input, sizeof(input), "airbrake %s", changed);
    expect_keys(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[39] = '-';
    snprintf(input, sizeof(input), "airbrake %s", changed);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "airbrake %sQ", changed);
    expect_keys(detector, input, strlen(input), hyphen, 1);

    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s\nairbrake %s", other, key, other);
    const char *unique[] = {key, other};
    expect_keys(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", key, key);
    expect_keys(detector, input, strlen(input), one, 1);
    memset(changed, 'a', 40);
    changed[40] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "airbrake %s", changed);
    expect_keys(detector, input, strlen(input), low_entropy, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "airbrake %s", changed);
    expect_keys(detector, input, strlen(input), low_entropy, 1);
    size_t at = (size_t)snprintf(input, sizeof(input), "airbrake");
    input[at++] = '\0';
    memcpy(input + at, key, 40);
    expect_keys(detector, input, at + 40, one, 1);
}

typedef struct {
    const char *key, *other, *agent;
    size_t key_calls, other_calls;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    char url[128];
    snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects?key=%s", expected->key);
    if (!strcmp(request->url, url)) {
        ++expected->key_calls;
    } else {
        CHECK(expected->other);
        snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects?key=%s", expected->other);
        CHECK(!strcmp(request->url, url));
        ++expected->other_calls;
    }
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 126);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, expected->agent));
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    char input[256];
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", key, key);
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.key = key, .agent = "TruffleHog detector-test"};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body-read failure"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "detector-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(expected.key_calls == 1 && !expected.other_calls);
        check_result(&results.items[0], key);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    char transport_error[256];
    snprintf(transport_error, sizeof(transport_error),
             "Get https://api.airbrake.io/api/v4/projects?key=%s: timeout for %s", key, key);
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s\nairbrake %s", other, key, other);
    expected_requests expected = {.key = key, .other = other, .agent = "TruffleHog"};
    test_http http = {.send_rc = -1, .send_error = transport_error,
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(expected.key_calls == 1 && expected.other_calls == 1);
    CHECK(results.items[0].raw.len == 40 && results.items[1].raw.len == 40);
    CHECK(memcmp(results.items[0].raw.data, results.items[1].raw.data, 40) != 0);
    for (size_t i = 0; i < results.len; ++i) {
        bool first = !memcmp(results.items[i].raw.data, key, 40);
        check_result(&results.items[i], first ? key : other);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        /* No secret args means errors retain even repeated synthetic key material. */
        CHECK(!strcmp(results.items[i].verification_error, transport_error));
    }
    br_results_clear(&results);

    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "airbrake", 8);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "airbrake %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_result(&results.items[0], key);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[41], other[41];
    test_secret(key, 40, 0);
    key[0] = 'B';
    key[13] = '-';
    key[39] = 'Z';
    memcpy(other, key, sizeof(other));
    other[0] = 'b'; /* Distinct casing must not collapse in the unique-key map. */
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("AirbrakeUserKey");
}
