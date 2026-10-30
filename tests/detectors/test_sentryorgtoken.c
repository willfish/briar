/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sentryorgtoken_init(const br_detector **out, char **error);

static char token[208], other[208];

static void fill(char *out, size_t shift)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=_+/";
    memcpy(out, "sntrys_eyJ", 10);
    for (size_t i = 0; i < 197; ++i) out[10 + i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    out[206] = 'Z'; /* A trailing non-word symbol would miss the final word boundary. */
    out[207] = '\0';
}

static void result_is(const br_result *result, const char *capture, bool verified, const char *cause)
{
    test_key_result(result, 1017, capture, "key");
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    fill(token, 1);
    fill(other, 7);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_sentryorgtoken_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_sentryorgtoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_sentryorgtoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1017 && !strcmp(detector->name, "SentryOrgToken"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sntrys_eyJ"));
    CHECK(!strcmp(detector->description,
                  "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry Organization Auth Tokens can be used in many places to interact with Sentry programmatically. For example, they can be used for sentry-cli, bundler plugins, or similar use cases."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[640];
    br_results out = test_scan(detector, NULL, false, token, 207);
    CHECK(out.len == 1);
    result_is(&out.items[0], token, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "x%s", token);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(input, token, 206);
    out = test_scan(detector, NULL, false, input, 206);
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(input, token, 207);
    input[207] = 'a';
    out = test_scan(detector, NULL, false, input, 208);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s %s", token, other, token);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], token, false, NULL);
    result_is(&out.items[1], other, false, NULL);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[224];
    snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://sentry.io/api/0/auth/validate"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1017 && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
    (void)http;
}

static void verification(const br_detector *detector)
{
    br_results out = test_scan(detector, NULL, true, token, 207);
    CHECK(out.len == 1);
    result_is(&out.items[0], token, false, "net/http: nil Context");
    br_results_clear(&out);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "sentry-test"};
        out = test_scan(detector, &ctx, true, token, 207);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], token, cases[i].verified, cases[i].cause);
        br_results_clear(&out);
    }
    char sensitive[240];
    snprintf(sensitive, sizeof(sensitive), "failed %s", token);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, token, 207);
    result_is(&out.items[0], token, false, "failed [REDACTED]");
    br_results_clear(&out);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, token, 207);
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
    return test_finish("SentryOrgToken");
}
