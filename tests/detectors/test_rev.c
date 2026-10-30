/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_rev_init(const br_detector **out, char **error);

static const char user[] = "T5LJHzWwZzdpmNtxKDaDcDUlckU=";
static const char client[] = "utD8J485zVIeRCbHyU8yYfw55m2";
static char seen_auth[80];

static void expect_pair(const br_result *result)
{
    br_json *part = NULL;
    CHECK(result->detector_type == 368 && result->raw.len == 28 && !memcmp(result->raw.data, user, 28));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->verified && !result->verification_error);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), user));
    CHECK(json_object_object_get_ex(result->secret_parts, "client", &part) && !strcmp(json_object_get_string(part), client));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.rev.com/api/v1/orders"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 368);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(user) == 28 && strlen(client) == 27);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_rev_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 368 && !strcmp(detector->name, "Rev") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "rev"));
    CHECK(!strcmp(detector->description, "Rev is a transcription service. Rev API keys can be used to access and modify transcription orders and data."));
    char input[256];
    snprintf(input, sizeof(input), "rev token - '%s '\nrev token - '%s '\n", user, client);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0]);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rev %s\rrev %s\n", user, client);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0]);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "preview %s %s ", user, client);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rev %s rev %s rev %s ", user, user, client);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rev %s rev %s", user, client);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rev T5LJHzWwZzdpmN?xKDaDcDUlckU= rev utD8J485zVIeRC?HyU8yYfw55m2 ");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 204};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "rev %s rev %s ", user, client);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strcmp(seen_auth, "Rev utD8J485zVIeRCbHyU8yYfw55m2:T5LJHzWwZzdpmNtxKDaDcDUlckU="));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 401;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Rev");
}
