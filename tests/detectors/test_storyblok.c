/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_storyblok_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://api.storyblok.com/v1/cdn/spaces/me/?token=%s", (char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 222);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_storyblok_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 222 && !strcmp(detector->name, "StoryblokAccessToken"));
    CHECK(!strcmp(detector->keywords[0], "storyblok"));
    char key[25];
    memset(key, 'a', 22);
    memcpy(key + 22, "tt", 3);
    char input[96];
    snprintf(input, sizeof(input), "storyblok %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 222, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "storyblok %s storyblok %s", key, key);
    br_results unique = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(unique.len == 1);
    br_results_clear(&unique);
    char other[25];
    memset(other, 'B', 22);
    memcpy(other + 22, "tt", 3);
    snprintf(input, sizeof(input), "storyblok %s storyblok %s", key, other);
    br_results both = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(both.len == 2);
    br_results_clear(&both);
    snprintf(input, sizeof(input), "storyblok %.21stt", key);
    br_results short_key = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(short_key.len == 0);
    br_results_clear(&short_key);

    snprintf(input, sizeof(input), "storyblok %s", key);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, "unexpected status code: 403"},
        {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect_request, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        if (cases[i].cause) CHECK(!strcmp(results.items[0].verification_error, cases[i].cause));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 1 && !nil.items[0].verified);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(!strcmp(nil.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil);
    return test_finish("StoryblokAccessToken");
}
