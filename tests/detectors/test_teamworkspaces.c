/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_teamworkspaces_init(const br_detector **, char **);

static char token[81], trimmed[80];

static void build(char tail)
{
    memcpy(token, "tkn.v1_", 7);
    memset(token + 7, 'a', 71);
    token[78] = '=';
    token[79] = tail;
    token[80] = 0;
    memcpy(trimmed, token, 79);
    trimmed[79] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char authorization[128];
    snprintf(authorization, sizeof(authorization), "Bearer %s", trimmed);
    CHECK(!strcmp(request->url, "https://example.teamwork.com/spaces/api/v1/users.json"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog") && request->timeout_ms == 5000);
}

int main(void)
{
    build(' ');
    CHECK(strlen(token) == 80 && strlen(trimmed) == 79);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_teamworkspaces_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 630 && detector->nkeywords == 2);
    char input[160];
    snprintf(input, sizeof(input), "teamwork %s", token);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    test_key_result(&results.items[0], 630, trimmed, "key");
    br_results_clear(&results);
    build('\n');
    snprintf(input, sizeof(input), "teamworkspaces %s", token);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.len == 79);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamwork %s", trimmed);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    build(' ');
    snprintf(input, sizeof(input), "teamwork %s", token);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    printf("teamworkspaces: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
