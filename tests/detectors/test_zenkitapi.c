/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zenkitapi_init(const br_detector **out, char **error);

static char key[42], other[42];

static void fill(char *out, char mark)
{
    memcpy(out, "01234567-", 9);
    for (size_t i = 0; i < 32; ++i) out[9 + i] = (i % 2) ? 'a' + (char)(i % 26) : 'A';
    out[9] = mark;
    out[41] = '\0';
}

static void result_is(const br_result *result, const char *capture, bool verified, const char *cause)
{
    test_key_result(result, 720, capture, "key");
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    fill(key, 'Z');
    fill(other, 'Q');
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_zenkitapi_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_zenkitapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_zenkitapi_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 720 && !strcmp(detector->name, "ZenkitAPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "zenkit"));
    CHECK(!strcmp(detector->description,
                  "Zenkit is a collaborative SaaS platform for project management, database building, and more. Zenkit API keys can be used to access and interact with Zenkit's services programmatically."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "zenkit %s\nZENKIT %s\nzenkit %s", key, other, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false, NULL);
    result_is(&out.items[1], other, false, NULL);
    result_is(&out.items[2], key, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "zenkit 0123456A-%s", key + 9);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, "https://base.zenkit.com/api/v1/users/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 720);
    CHECK(!strcmp(request->headers[0].name, "Zenkit-Api-Key") && !strcmp(request->headers[0].value, key));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[56];
    snprintf(input, sizeof(input), "zenkit %s", key);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, "net/http: nil Context");
    br_results_clear(&out);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, "unexpected status code: 403"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "zenkit-test"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, cases[i].verified, cases[i].cause);
        br_results_clear(&out);
    }
    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "failed %s", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    result_is(&out.items[0], key, false, "failed [REDACTED]");
    br_results_clear(&out);
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
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("ZenkitAPI");
}
