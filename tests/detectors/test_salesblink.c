/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_salesblink_init(const br_detector **out, char **error);

#define br_results_push salesblink_real_push
#define br_result_set_verification_error salesblink_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[69], other[69];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request);

int br_results_push(br_results *out, br_result *result)
{
    return salesblink_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    return salesblink_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 252);
    CHECK(request->nheaders >= 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, (const char *)http->user + strlen((const char *)http->user) + 1));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Salesblink detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 252 && detector->version == 0 && !strcmp(detector->name, "Salesblink"));
    CHECK(!strcmp(detector->description, "Salesblink is a sales outreach tool that helps automate email, LinkedIn, and cold call outreach. Salesblink API keys can be used to access and manage sales outreach campaigns and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "salesblink"));
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
    snprintf(input, sizeof(input), "salesblink %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 252, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "salesblink %s\nsalesblink %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    br_results_clear(&out);
    const char *rejected[] = {"salesblink short", "salesblink"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls);
        br_results_clear(&none);
    }
    snprintf(input, sizeof(input), "salesblink %s", key);
    snprintf(request_double, sizeof(request_double), "https://run.salesblink.io/api/public/lists");
    memcpy(request_double + strlen(request_double) + 1, key, strlen(key) + 1);
    http.inspect = inspect;
    http.user = request_double;
    const struct { int status; bool verified; } cases[] = {{200, true}, {201, true}, {299, true}, {300, false}, {401, false}, {500, false}};
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
    for (size_t i = 0; i < 68; ++i) {
        key[i] = "ab12Az"[i % 6];
        other[i] = "zA21ba"[i % 6];
    }
    memcpy(key, "key-", 4);
    memcpy(other, "key-", 4);
    other[68 - 1] = 'z';
    key[68] = other[68] = '\0';
    CHECK(strlen(key) == 68 && strlen(other) == 68);
    exercise(open_detector(br_salesblink_init));
    return test_finish("Salesblink");
}
