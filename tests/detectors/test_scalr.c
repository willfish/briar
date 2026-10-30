/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_scalr_init(const br_detector **out, char **error);

static const char valid_key[] =
    "bmy2Q33nZnlwZ5wCu_umGbBHF_6547oPzvAGLpUEwhWwOJmU5DUlZIOWZ0Yr7g2Yt4s3ZyyfWxzOlLLOmkGXpzuQ3.gEhgGUHUngyyiPIZjVoYQ.W0O8k4G3JBC705AXkXxANwrF";
static const char valid_id[] = "h7bcggvlzhq6t5m47f37jav";
static const char *seen_id;
static const char *seen_key;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(valid_key) == 136 && strlen(valid_id) == 23);
    CHECK(br_scalr_init(&detector, &error) == 0 && detector && detector->type == 852);
    CHECK(!strcmp(detector->name, "Scalr") && !strcmp(detector->keywords[0], "scalr"));
    CHECK(!strcmp(detector->description,
                  "Scalr is a cloud management platform that allows users to manage and automate "
                  "cloud infrastructure. Scalr keys can be used to access and manage cloud resources "
                  "within the Scalr platform."));
    CHECK(detector->max_credential_span == 1024 && detector->state && !detector->clean);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[96], authorization[152];
    (void)http;
    snprintf(url, sizeof(url), "https://%s.scalr.io/api/iacp/v3/agents", seen_id);
    snprintf(authorization, sizeof(authorization), "Bearer %s", seen_key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 852);
    CHECK(!request->body.len && request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") &&
          !strcmp(request->headers[1].value, "application/vnd.api+json"));
    CHECK(!strcmp(request->headers[2].name, "Prefer") && !strcmp(request->headers[2].value, "profile=preview"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
}

static void run(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "scalr token - '%s'\nscalr token - '%s'\n", valid_key, valid_id);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 852, valid_key, "key");
    test_key_result(&results.items[1], 852, valid_key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scalr abcde\nscalr %s", valid_key);
    seen_id = "abcde";
    seen_key = valid_key;
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && results.items[0].verified);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scalr token - '%s'\nscalr token - '%s'\n", valid_key, valid_id);
    seen_id = "token";
    http = (test_http){.response = {.status = 500, .body_error = "ignored"}, .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && !results.items[0].verified && !results.items[1].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scalr %s", valid_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("Scalr");
}
