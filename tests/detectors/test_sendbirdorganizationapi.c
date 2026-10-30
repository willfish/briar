/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sendbirdorganizationapi_init(const br_detector **out, char **error);

static char key[25];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://gate.sendbird.com/api/v2/applications"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 2);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Sendbirdorganizationapitoken"))
            auth = !strcmp(request->headers[i].value, key);
    CHECK(auth);
}

int main(void)
{
    for (int i = 0; i < 24; ++i) key[i] = "0123456789abcdef"[i % 16];
    key[24] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sendbirdorganizationapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 751 && !strcmp(detector->name, "SendbirdOrganizationAPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sendbird"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[96];
    snprintf(input, sizeof(input), "sendbirdorgapi %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 751, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "organization %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "sendbirdorgapi %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    http.response.status = 403;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.status = 500;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);

    br_results empty = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &empty, &error) != 0);
    CHECK(empty.len == 0 && error && !strcmp(error, "net/http: nil Context"));
    free(error);
    return test_finish("sendbirdorganizationapi");
}
