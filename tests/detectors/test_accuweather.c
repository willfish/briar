/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void check_findings(const br_results *results, const char *const *keys, size_t count,
                            bool verified, const char *error)
{
    CHECK(results->len == count);
    /* Upstream iterates a map, so compare unique key sets rather than map order. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results->len; ++j) {
            if (results->items[j].raw.len == strlen(keys[i]) &&
                !memcmp(results->items[j].raw.data, keys[i], strlen(keys[i]))) {
                CHECK(!result);
                result = &results->items[j];
            }
        }
        CHECK(result);
        test_key_result(result, 303, keys[i], "key");
        CHECK(result->verified == verified);
        if (error) {
            CHECK(result->verification_error && !strcmp(result->verification_error, error));
            CHECK(!strstr(result->verification_error, keys[i]));
        } else CHECK(!result->verification_error);
    }
}

static void test_descriptor(const br_detector *detector, int version)
{
    CHECK(detector->type == 303 && detector->version == version);
    CHECK(!strcmp(detector->name, "Accuweather") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "AccuWeather is a weather forecasting service. "
                  "AccuWeather API keys can be used to access weather data and forecasts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "accuweather"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_detector_is_default(detector, NULL));
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    check_findings(&results, keys, count, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector, const char *key, const char *other)
{
    const bool v1 = detector->version == 1;
    const size_t len = strlen(key), prefix_len = strlen("accuweather");
    const char *one[] = {key};
    char input[256], changed[36];
    const struct { const char *format; bool matches; } cases[] = {
        {"accuweather = '%s'", true},
        {"%s", false}, {"%s accuweather", false},
        {"preACCUWEATHERsuffix:%s", true},
        {"accuweather%s", v1},
        {"accuweather _%s", v1},
        {"accuweather X%s", v1}, /* v1 may capture a longer token's suffix. */
        {"accuweather %s_", false},
        {"accuweather\r%s", true},
        {"accuweather\n%s", true},
        {"accuweather\r\n%s", true},
        {"accuweather \xc3\xa9%s\xc3\xa9", true}, /* ASCII word boundaries. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "accuweather %.*s", (int)len - 1, key);
    expect_extraction(detector, input, strlen(input), NULL, 0);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "accuweather", prefix_len);
        memset(input + prefix_len, '-', gap);
        memcpy(input + prefix_len + gap, key, len + 1);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + prefix_len, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);

        /* PrefixRegex counts runes, not bytes. */
        size_t at = prefix_len;
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, len + 1);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }

    memcpy(changed, key, len + 1);
    changed[len / 2] = '$';
    snprintf(input, sizeof(input), "accuweather %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key, len + 1);
    if (v1) {
        changed[0] = '%';
        const char *percent[] = {changed};
        snprintf(input, sizeof(input), "accuweather %s", changed);
        expect_extraction(detector, input, strlen(input), percent, 1);
        changed[len - 1] = '%';
        snprintf(input, sizeof(input), "accuweather %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
        snprintf(input, sizeof(input), "accuweather %sX", changed);
        expect_extraction(detector, input, strlen(input), percent, 1);
    } else {
        changed[7] = '%';
        snprintf(input, sizeof(input), "accuweather %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }

    memset(changed, 'a', len);
    changed[len] = '\0';
    snprintf(input, sizeof(input), "accuweather %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    /* Filtering must not cause a consumed prefix to be reused for another key. */
    snprintf(input, sizeof(input), "accuweather %s %s", changed, key);
    expect_extraction(detector, input, strlen(input), NULL, 0);

    const char *below = v1 ? "0123456789abcdef" : "0123456789abcde";
    const char *accepted = v1 ? "0123456789abcdefg" : "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) changed[i] = below[i % strlen(below)];
    snprintf(input, sizeof(input), "accuweather %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    for (size_t i = 0; i < len; ++i) changed[i] = accepted[i % strlen(accepted)];
    const char *threshold[] = {changed}; /* v2 is exactly 4 bits; v1 is just above. */
    snprintf(input, sizeof(input), "accuweather %s", changed);
    expect_extraction(detector, input, strlen(input), threshold, 1);

    snprintf(input, sizeof(input), "accuweather %s\naccuweather %s\naccuweather %s",
             other, key, other);
    const char *unique[] = {key, other};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "accuweather %s %s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);

    memcpy(input, "accuweather", prefix_len);
    input[prefix_len] = '\0';
    memcpy(input + prefix_len + 1, key, len);
    expect_extraction(detector, input, prefix_len + 1 + len, one, 1);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i) {
        char url[192];
        snprintf(url, sizeof(url),
                 "https://dataservice.accuweather.com/locations/v1/cities/autocomplete?apikey=%s&q=----&language=en-us",
                 expected->keys[i]);
        if (!strcmp(request->url, url)) ++matches;
    }
    CHECK(matches == 1); /* Includes the raw percent signs in v1 keys. */
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 303);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog accuweather-test"));
}

static void test_verification(const br_detector *detector, const char *key, const char *other)
{
    const char *one[] = {key};
    expected_requests expected = {one, 1};
    char input[256], secret_error[128];
    snprintf(input, sizeof(input), "accuweather %s", key);
    snprintf(secret_error, sizeof(secret_error), "timeout for %s; key=%s", key, key);
    const struct {
        int status;
        const char *body_error, *send_error;
        int send_rc;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body_error = "ignored body-read failure", .verified = true},
        {.status = 403, .body_error = "ignored body-read failure", .verified = true},
        {.status = 401, .body_error = "ignored body-read failure"},
        {.status = 201, .error = "unexpected HTTP response status 201"},
        {.status = 500, .body_error = "ignored body-read failure",
         .error = "unexpected HTTP response status 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled",
         .error = "context canceled"},
        {.status = 403, .send_rc = -1, .send_error = "context deadline exceeded",
         .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
        {.status = 200, .send_rc = -1, .send_error = secret_error,
         .error = "timeout for [REDACTED]; key=[REDACTED]"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = cases[i].body_error},
            .send_error = cases[i].send_error, .send_rc = cases[i].send_rc,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "accuweather-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1);
        check_findings(&results, one, 1, cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }

    char low[36];
    memset(low, 'a', strlen(key));
    low[strlen(key)] = '\0';
    snprintf(input, sizeof(input), "accuweather %s\naccuweather %s\naccuweather %s", low, key, key);
    test_http http = {.response = {.status = 403}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "accuweather-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1); /* Filter and deduplicate before HTTP. */
    check_findings(&results, one, 1, true, NULL);
    br_results_clear(&results);

    http = (test_http){0};
    snprintf(input, sizeof(input), "accuweather %s", low);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    check_findings(&results, NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);

    const char *two[] = {key, other};
    expected = (expected_requests){two, 2};
    http = (test_http){.send_rc = -1, .send_error = "context canceled",
                       .inspect = inspect_request, .user = &expected};
    snprintf(input, sizeof(input), "accuweather %s\naccuweather %s", key, other);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2);
    check_findings(&results, two, 2, false, "context canceled");
    br_results_clear(&results);

    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "accuweather %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    check_findings(&results, one, 1, false, "HTTP transport not installed");
    br_results_clear(&results);
}

int main(void)
{
    int (*const factories[])(const br_detector **, char **) = {
        br_accuweather_v1_init, br_accuweather_v2_init,
    };
    const br_detector *versions[2] = {0};
    const void *patterns[2] = {0};
    CHECK(BR_ABI_REVISION == 1);
    for (size_t i = 0; i < 2; ++i) {
        char *error = NULL;
        CHECK(factories[i](&versions[i], &error) == 0 && !error && versions[i]);
        patterns[i] = versions[i]->state;
        test_descriptor(versions[i], (int)i + 1);
        CHECK(factories[i](NULL, &error) != 0 && error);
        free(error);
        CHECK(factories[i](NULL, NULL) != 0);
        const br_detector *again = NULL;
        CHECK(factories[i](&again, &error) == 0 && !error && again == versions[i]);
        CHECK(again->state == patterns[i]);

        const size_t len = i == 0 ? 35 : 32;
        char key[36], other[36];
        test_secret(key, len, 0);
        test_secret(other, len, 9);
        key[0] = 'B';
        other[0] = 'M';
        if (i == 0) { key[7] = '%'; key[8] = 'Z'; other[7] = '%'; }
        test_extraction(versions[i], key, other);
        test_verification(versions[i], key, other);
    }
    CHECK(versions[0] != versions[1] && patterns[0] != patterns[1]);
    CHECK(versions[0]->scan == versions[1]->scan);
    for (size_t i = 0; i < 2; ++i) {
        const br_detector *again = NULL;
        CHECK(factories[i](&again, NULL) == 0 && again == versions[i]);
        CHECK(again->state == patterns[i]);
    }
    return test_finish("Accuweather v1/v2");
}
