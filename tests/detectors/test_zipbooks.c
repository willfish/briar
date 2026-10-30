/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zipbooks_init(const br_detector **out, char **error);

static const char email[] = "hi@ex.co";
static const char password[] = "passw0rd";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    const char body[] = "{\"email\":\"hi@ex.co\",\"password\":\"passw0rd\"}";
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.zipbooks.com/v2/auth/login"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 600);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog zipbooks-offline"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, strlen(body)));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zipbooks_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 600 && !strcmp(detector->name, "ZipBooks"));
    CHECK(detector->max_credential_span == 1024 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->description,
        "ZipBooks is an accounting software service that allows businesses to manage their finances online. The credentials can be used to access and manage financial data."));
    CHECK(br_zipbooks_init(NULL, &error) != 0 && error); free(error);
    char input[160];
    snprintf(input, sizeof(input), "zipbooks %s%*s password %s", email, 41, "", password);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(email) && !memcmp(results.items[0].raw.data, email, strlen(email)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "email", &part));
    CHECK(!strcmp(json_object_get_string(part), email));
    CHECK(!json_object_object_get_ex(results.items[0].secret_parts, "password", &part));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s %s%*s password %s password %s", email, email, 41, "", password, "second!");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    CHECK(!memcmp(results.items[0].raw.data, email, strlen(email)));
    CHECK(!memcmp(results.items[1].raw.data, email, strlen(email)));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s", email);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s%*s password %s", email, 41, "", password);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "zipbooks-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 404; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    char echoed[80];
    snprintf(echoed, sizeof(echoed), "dial %s", email);
    http.send_rc = 1; http.send_error = echoed; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && strstr(results.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(results.items[0].verification_error, email));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("ZipBooks");
}
