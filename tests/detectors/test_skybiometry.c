/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_skybiometry_init(const br_detector **out, char **error);

static const char key[] = "abcdefghijklmnopqrstuvwxy";
static const char secret[] = "zyxwvutsrqponmlkjihgfedcb";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char first[128], second[128];
    snprintf(first, sizeof(first),
             "https://api.skybiometry.com/fc/account/authenticate?api_key=%s&api_secret=%s",
             key, secret);
    snprintf(second, sizeof(second),
             "https://api.skybiometry.com/fc/account/authenticate?api_key=%s&api_secret=%s",
             secret, key);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, http->calls == 1 ? first : second));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 520);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog skybiometry-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 25 && strlen(secret) == 25);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_skybiometry_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 520 && !strcmp(detector->name, "SkyBiometry"));
    CHECK(detector->max_credential_span == 1024 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->description,
        "SkyBiometry is a facial recognition service. SkyBiometry API keys can be used to access and utilize their facial recognition API."));
    CHECK(br_skybiometry_init(NULL, &error) != 0 && error); free(error);
    char input[160];
    snprintf(input, sizeof(input), "skybiometry %s skybiometry %s", key, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    CHECK(results.items[0].raw.len == 25 && !memcmp(results.items[0].raw.data, secret, 25));
    CHECK(results.items[1].raw.len == 25 && !memcmp(results.items[1].raw.data, key, 25));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "skybiometry %s skybiometry %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "skybiometry keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "skybiometry %s skybiometry %s", key, secret);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "skybiometry-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified && http.calls == 2);
    br_results_clear(&results);
    http.response.status = 400; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    char echoed[96];
    snprintf(echoed, sizeof(echoed), "dial %s", secret);
    http.send_rc = 1; http.send_error = echoed; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && strstr(results.items[0].verification_error, secret));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 2 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("SkyBiometry");
}
