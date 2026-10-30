/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_smooch_init(const br_detector **out, char **error);

static char key[29], secret[87], seen_auth[180];
static const char basic[] = "Basic YWN0X2FhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYTpCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg==";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.smooch.io/v2/apps"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 608);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.smooch+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[1].value);
}

int main(void)
{
    memcpy(key, "act_", 4);
    memset(key + 4, 'a', 24);
    key[28] = '\0';
    memset(secret, 'B', 86);
    secret[86] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_smooch_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 608 && !strcmp(detector->name, "Smooch") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "smooch"));
    CHECK(!strcmp(detector->description, "Smooch is a messaging platform that allows businesses to communicate with their customers across various messaging channels. Smooch API keys can be used to access and manage these communications."));
    char input[160];
    snprintf(input, sizeof(input), "SMOOCH %s smooch %s", key, secret);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].raw.len == 28 && !memcmp(out.items[0].raw.data, key, 28));
    CHECK(out.items[0].raw_v2.len == 114 && !memcmp(out.items[0].raw_v2.data, key, 28));
    CHECK(!memcmp(out.items[0].raw_v2.data + 28, secret, 86));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(out.items[0].secret_parts, "secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    br_results_clear(&out);
    snprintf(input, sizeof(input), "smooch %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 204};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "smooch %s smooch %s", key, secret);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !strcmp(seen_auth, basic));
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
    return test_finish("Smooch");
}
