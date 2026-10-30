/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_viewneo_init(const br_detector **out, char **error);

enum { PART1 = 120, PART2 = 150, PART3 = 600, TOKEN = PART1 + 1 + PART2 + 1 + PART3 };

static char token[TOKEN + 1];

static void fill(char *out, size_t n, char c)
{
    memset(out, c, n);
}

static const br_detector *descriptor(void)
{
    fill(token, PART1, 'a');
    token[PART1] = '.';
    fill(token + PART1 + 1, PART2, 'b');
    token[PART1 + 1 + PART2] = '.';
    fill(token + PART1 + 1 + PART2 + 1, PART3, 'c');
    token[TOKEN] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_viewneo_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_viewneo_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 706 && !strcmp(detector->name, "Viewneo"));
    CHECK(!strcmp(detector->description,
                  "Viewneo is a digital signage platform. Viewneo API keys can be used to access and manage digital signage content and settings."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "viewneo"));
    CHECK(detector->max_secret_size == 1500 && detector->max_credential_span == -1);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char *input = malloc(16 + TOKEN + 201);
    CHECK(input);
    snprintf(input, 16 + TOKEN + 201, "viewneo %s", token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 706, token, "key");
    br_results_clear(&results);
    memset(input + strlen(input), 'c', 201);
    input[8 + TOKEN + 201] = '\0';
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.len == PART1 + 1 + PART2 + 1 + 800);
    br_results_clear(&results);
    free(input);
}

static int view_status;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://cloud.viewneo.com/api/v1.0/playlist"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") &&
          !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) &&
          !strcmp(request->headers[1].value + 7, token));
    http->response.status = view_status;
}

static void verification(const br_detector *detector)
{
    char *input = malloc(16 + TOKEN);
    CHECK(input);
    snprintf(input, 16 + TOKEN, "viewneo %s", token);
    view_status = 200;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    view_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    free(input);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("viewneo");
}
