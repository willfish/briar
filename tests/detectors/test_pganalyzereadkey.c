/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_pganalyzereadkey_init(const br_detector **out, char **error);

static char key[33], other[33];

static void fill(char *out, size_t shift)
{
    memcpy(out, "pgar_", 5);
    test_secret(out + 5, 27, shift);
    out[5] = 'A';
    out[12] = '9';
}

static void result_is(const br_result *result, const char *capture, bool verified, const char *cause)
{
    CHECK(result->detector_type == 1054);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, capture, 32));
    CHECK(!result->raw_v2.data && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), capture));
    CHECK(json_object_object_get_ex(result->secret_parts, "access_type", &part));
    CHECK(!strcmp(json_object_get_string(part), "read"));
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    fill(key, 1);
    fill(other, 8);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_pganalyzereadkey_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_pganalyzereadkey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_pganalyzereadkey_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1054 && !detector->version && !strcmp(detector->name, "PgAnalyzeReadKey"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "pganalyze is a PostgreSQL monitoring and performance analysis platform. pganalyze Read API keys can be used to access read-only monitoring and query performance data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pgar_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->false_positive);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160], short_key[32], long_key[34];
    snprintf(input, sizeof(input), "token %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, NULL);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, 32);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, NULL);
    br_results_clear(&out);
    memcpy(short_key, key, 31);
    short_key[31] = '\0';
    snprintf(input, sizeof(input), "%s", short_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(long_key, key, 32);
    long_key[32] = 'a';
    long_key[33] = '\0';
    out = test_scan(detector, NULL, false, long_key, 33);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "x%s %s_", key, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s\n%s\n%s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false, NULL);
    result_is(&out.items[1], other, false, NULL);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *capture = http->user;
    char authorization[40];
    snprintf(authorization, sizeof(authorization), "Token %s", capture);
    CHECK(ctx && ctx->transport);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://app.pganalyze.com/graphql"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1054 && !request->body.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog pganalyze-test"));
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, "net/http: nil Context");
    br_results_clear(&out);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL},
        {403, false, "unexpected HTTP response status 403"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body_error = "ignored drain"},
                          .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "pganalyze-test"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, cases[i].verified, cases[i].cause);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = -1, .send_error = "synthetic transport failure", .inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pganalyze-test"};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], key, false, "synthetic transport failure");
    br_results_clear(&out);
    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "failed %s", key);
    http.send_error = sensitive;
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
    return test_finish("PgAnalyzeReadKey");
}
