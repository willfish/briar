/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_unifyid_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    static const char payload[] = "{\"token\": \"sample\"}";
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.unify.id/v1/humandetect/verify"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-API-Key"));
    CHECK(!strcmp(request->headers[1].value, http->user));
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 606);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_unifyid_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 606 && !strcmp(detector->keywords[0], "unify"));
    char key[45], input[96];
    memset(key, 'A', 44);
    key[10] = '_';
    key[20] = '=';
    key[30] = '-';
    key[44] = '\0';
    snprintf(input, sizeof(input), "unify %sEXTRA", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 606, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "unify %.43s", key);
    br_results short_key = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(short_key.len == 0);
    br_results_clear(&short_key);
    snprintf(input, sizeof(input), "%s", key);
    br_results bare = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(bare.len == 0);
    br_results_clear(&bare);

    snprintf(input, sizeof(input), "unify %s", key);
    const char *invalid = "invalid token";
    const struct { int status; const char *body; bool verified; } cases[] = {
        {200, "", true}, {400, invalid, true}, {400, "other", false}, {401, invalid, false}, {500, "", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
                                       .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}},
                          .inspect = inspect_request, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && http.calls == 1);
        br_results_clear(&results);
    }
    test_http unread = {.response = {.status = 200, .body_error = "read failed"}, .inspect = inspect_request, .user = key};
    br_transport unread_transport = test_transport(&unread);
    br_scan_ctx unread_ctx = {.transport = &unread_transport};
    br_results skipped = test_scan(detector, &unread_ctx, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 0);
    br_results_clear(&nil);
    return test_finish("UnifyID");
}
