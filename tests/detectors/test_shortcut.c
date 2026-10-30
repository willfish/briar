/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_shortcut_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shortcut_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_shortcut_init(&detector, &error) == 0 && !error && detector->type == 587);
    CHECK(!strcmp(detector->name, "Shortcut"));
    CHECK(!strcmp(detector->keywords[0], "shortcut"));
    CHECK(!strcmp(detector->description, "Shortcut is a project management tool. Shortcut API keys can be used to access and modify project data."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.app.shortcut.com/api/v3/member"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 587);
    CHECK(!request->body.len && request->nheaders == 3);
    size_t token = 0, typed = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Shortcut-Token")) {
            ++token;
            CHECK(!strcmp(request->headers[i].value, http->user));
        } else if (!strcmp(request->headers[i].name, "Content-Type")) {
            ++typed;
            CHECK(!strcmp(request->headers[i].value, "application/json"));
        }
    }
    CHECK(token == 1 && typed == 1);
}

static void extraction(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "shortcut token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 587, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "SHORTCUT %s\nshortcut %s", key, "01234567-89AB-cdef-0123-456789abcdef");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s shortcut", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "shortcut %s", key);
    const unsigned char named[] = "id\n{\"name\":\"ada\"}\n";
    const unsigned char empty[] = "{\"id\":1}";
    const struct { int status; const unsigned char *body; size_t len; const char *read_error; bool verified; const char *error; } cases[] = {
        {200, named, sizeof(named) - 1, NULL, true, NULL},
        {200, empty, sizeof(empty) - 1, NULL, false, NULL},
        {401, named, sizeof(named) - 1, NULL, false, NULL},
        {200, (const unsigned char *)"no", 2, "read reset", false, "read reset"},
        {200, (const unsigned char *)"name", 4, "read reset", false, "read reset"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {cases[i].body, cases[i].len}, .body_error = cases[i].read_error},
            .inspect = inspect, .user = (void *)key,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char huge[65538];
    memset(huge, 'x', sizeof(huge));
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)huge, sizeof(huge)}}, .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "bufio.Scanner: token too long"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    CHECK(!results.items[0].verified);
    br_results_clear(&results);
    http = (test_http){.send_rc = 1, .send_error = "context canceled", .inspect = inspect, .user = (void *)key};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "context canceled"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Shortcut");
}
