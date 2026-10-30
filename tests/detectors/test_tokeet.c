/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_tokeet_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "abcdef01-2345-6789-abcd-ef0123456789";
static const char id[] = "1234567890.1234";
static const char other_id[] = "1234567890X1234";

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 864, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_tokeet_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_tokeet_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_tokeet_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 864 && !strcmp(detector->name, "Tokeet"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "tokeet"));
    CHECK(!strcmp(detector->description,
                  "Tokeet is a property management software used for managing rental properties. Tokeet API keys can be used to access and modify property data and manage bookings."));
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[220];
    snprintf(input, sizeof(input), "tokeet %s %s", id, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "tokeet %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "tokeet %s %s tokeet %s %s", id, key, other_id, other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], key, false);
    result_is(&out.items[2], other, false);
    result_is(&out.items[3], other, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "tokeet 123456789.1234 %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "tokeet %s %s", id, key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://capi.tokeet.com/v1/user?account=1234567890.1234"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 864);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, key));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "tokeet %s %s", id, key);
    const int statuses[] = {200, 299, 300};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "tokeet-test"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] < 300);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = 1, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Tokeet");
}
