/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_rubygems_init(const br_detector **out, char **error);

#define br_results_push rubygems_real_push
#define br_result_set_verification_error rubygems_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[58], other[58];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request);

int br_results_push(br_results *out, br_result *result)
{
    return rubygems_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    return rubygems_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 200);
    CHECK(request->nheaders >= 2 + 1);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "*/*"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, key));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid RubyGems detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 200 && detector->version == 0 && !strcmp(detector->name, "RubyGems"));
    CHECK(!strcmp(detector->description, "RubyGems is a package manager for the Ruby programming language. RubyGems API keys can be used to publish and manage gems (libraries) on the RubyGems platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "rubygems"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[400];
    static char request_double[600];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "rubygems %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 200, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rubygems %s\nrubygems %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    br_results_clear(&out);
    const char *rejected[] = {"rubygems short", "rubygems"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls);
        br_results_clear(&none);
    }
    snprintf(input, sizeof(input), "rubygems %s", key);
    snprintf(request_double, sizeof(request_double), "%s", "https://rubygems.org/api/v1/gems.json");
    http.inspect = inspect;
    http.user = request_double;
    const struct { int status; bool verified; } cases[] = {{200, true}, {201, true}, {299, true}, {300, false}, {401, false}, {403, true}, {500, false}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status, .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

int main(void)
{
    for (size_t i = 0; i < 57; ++i) {
        key[i] = "ab12z9"[i % 6];
        other[i] = "9z21ba"[i % 6];
    }
    memcpy(key, "rubygems_", 9);
    memcpy(other, "rubygems_", 9);
    for (size_t i = 9; i < 57; ++i) { key[i] = "ab12z9"[i % 6]; other[i] = "9z21ba"[i % 6]; }
    key[57] = other[57] = '\0';
    CHECK(strlen(key) == 57 && strlen(other) == 57);
    exercise(open_detector(br_rubygems_init));
    return test_finish("RubyGems");
}
