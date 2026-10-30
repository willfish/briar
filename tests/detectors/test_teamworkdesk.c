/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_teamworkdesk_init(const br_detector **out, char **error);

static const char tail[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static char token[80];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[96];
    snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://example.teamwork.com/desk/api/v2/me.json"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_teamworkdesk_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 629 && !strcmp(detector->name, "TeamworkDesk"));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "teamwork"));
    CHECK(!strcmp(detector->keywords[1], "teamworkdesk"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "TeamworkDesk is a helpdesk software that allows teams to manage customer communications. TeamworkDesk tokens can be used to access and manage customer support tickets and other related data."));
    return detector;
}

int main(void)
{
    CHECK(strlen(tail) == 71);
    snprintf(token, sizeof(token), "tkn.v1_%s=", tail);
    const br_detector *detector = descriptor();
    char input[220];
    snprintf(input, sizeof(input), "TEAMWORKDESK%*s%s ", 40, "", token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 629, token, "key");
    CHECK(results.items[0].raw.len == 79);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamwork %s\r", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.data[78] == '=');
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamwork %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamwork %s ", token);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("TeamworkDesk");
}
