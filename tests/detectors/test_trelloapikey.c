/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_trelloapikey_init(const br_detector **out, char **error);

static const char key[] = "NKVmEKtpJvQXU95OfApuFxCOmaRLcRsc";
static const char key2[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
static const char token[] = "Zqpox-FOtGtvV58NCfjox3y2KROmjsbvAUW2jLSL9XfPFs3P98BwmjzMKJA1KVPa";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[160];
    snprintf(url, sizeof(url), "https://api.trello.com/1/members/me?key=%s&token=%s", key, token);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 94 && request->nheaders == 1);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_trelloapikey_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 94 && !strcmp(detector->name, "TrelloApiKey"));
    CHECK(detector->max_credential_span == 1024 && !strcmp(detector->keywords[0], "trello"));
    char input[320];
    snprintf(input, sizeof(input), "trelloapikey token - '%s'\ntrelloapikey token - '%s'\n", token, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].redacted, key));
    CHECK(results.items[0].raw.len == 32 && !memcmp(results.items[0].raw.data, key, 32));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "trello %s trello %s trello %s trello %s", key, key2, token, token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2 && !memcmp(results.items[0].raw.data, key, 32) && !memcmp(results.items[1].raw.data, key, 32));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "trello %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    snprintf(input, sizeof(input), "%s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "trello %s %s", key, token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    http.send_rc = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    return test_finish("trelloapikey");
}
