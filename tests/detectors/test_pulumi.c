/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include <stdio.h>

int br_pulumi_init(const br_detector **out, char **error);

static const br_detector *init_detector(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_pulumi_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_pulumi_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 914 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Pulumi") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Pulumi is an Infrastructure as Code platform. Pulumi API keys can be used to manage cloud infrastructure and services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pul-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_pulumi_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_one(const br_detector *detector, const char *input, const char *key)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    if (!key) CHECK(!results.len);
    else {
        CHECK(results.len == 1);
        test_key_result(&results.items[0], detector->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    CHECK(ctx && request);
    CHECK(!strcmp(request->url, "https://api.pulumi.com/api/user/stacks"));
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 914);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.pulumi+8"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization"));
    char expect2[1104];
    snprintf(expect2, sizeof(expect2), "token %s", key);
    CHECK(!strcmp(request->headers[2].value, expect2));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    CHECK(!strcmp(request->headers[3].value, "TruffleHog pulumi-test"));
}

static void expect_status(const br_detector *detector, const char *input, const char *key,
                           int status, const char *body, const char *body_error, bool verified)
{
    test_http http = {.response = {.status = status, .body_error = body_error}, .inspect = inspect, .user = (void *)key};
    if (body) http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pulumi-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], detector->type, key, "key");
    CHECK(results.items[0].verified == verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *detector = init_detector();
    const char *key = "pul-xm8r0t347qgoqhrp4c5pq0jkkabeue0x7u35l2ac";
    const char *invalid = "pul-xm8r0t347qgoqhrp4c?pq0jkkabeue0x7u35l2ac";
    char input[2048];
    snprintf(input, sizeof(input), "token = '%s'", key);
    expect_one(detector, input, key);
    expect_one(detector, key, key);
    snprintf(input, sizeof(input), "%s %s %s", key, key, invalid);
    {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 2);
        test_key_result(&results.items[0], detector->type, key, "key");
        test_key_result(&results.items[1], detector->type, key, "key");
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "%s = '%s'", "pul-", invalid);
    expect_one(detector, input, NULL);
    expect_one(detector, "", NULL);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 0}, NULL, &error) != 0 && error);
    free(error);

    snprintf(input, sizeof(input), "%s %s", "pul-", key);
    const int ok_status[] = {200, 204, 299};
    const int bad_status[] = {199, 300, 401, 403, 404, 500};
    for (size_t i = 0; i < sizeof(ok_status) / sizeof(ok_status[0]); ++i)
        expect_status(detector, input, key, ok_status[i], NULL, NULL, true);
    for (size_t i = 0; i < sizeof(bad_status) / sizeof(bad_status[0]); ++i)
        expect_status(detector, input, key, bad_status[i], "ignored", NULL, false);
    test_http failed = {.send_rc = -1, .send_error = "context canceled", .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&failed);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pulumi-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(failed.calls == 1 && failed.releases == 1);
    br_results_clear(&results);
    char *nil_error = NULL;
    br_results nil_results = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &nil_results, &nil_error) == 0 && !nil_error && !nil_results.len);
    br_results_clear(&nil_results);
    return test_finish("Pulumi");
}
