/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_tallyfy_init(const br_detector **, char **);

static char token[986];

static void make_token(void)
{
    size_t at = 0;
    for (size_t i = 0; i < 36; ++i) token[at++] = 'a';
    token[at++] = '.';
    for (size_t i = 0; i < 264; ++i) token[at++] = 'b';
    token[at++] = '.';
    for (size_t i = 0; i < 683; ++i) token[at++] = (i % 2) ? '-' : 'c';
    token[at] = 0;
    CHECK(at == 985);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.tallyfy.com/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 719);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, token));
}

static void exercise(const br_detector *detector)
{
    size_t cap = 32 + 985 * 2;
    char *input = malloc(cap);
    CHECK(input);
    snprintf(input, cap, "tallyfy %s tallyfy %s", token, token);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    test_key_result(&out.items[0], 719, token, "key");
    br_results_clear(&out);
    snprintf(input, cap, "tallyfy %s", token);
    http.response = (br_http_response){.status = 204};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 401};
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    free(input);
}

int main(void)
{
    make_token();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tallyfy_init(&detector, &error) == 0 && detector->type == 719 && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "tallyfy"));
    exercise(detector);
    return test_finish("Tallyfy");
}
