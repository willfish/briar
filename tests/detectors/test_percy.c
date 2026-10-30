/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_percy_init(const br_detector **out, char **error);

#define br_results_push percy_real_push
#define br_result_set_verification_error percy_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[65], other[65];
static const char url[] = "https://percy.io/api/v1/projects";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return percy_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return percy_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 912);
    CHECK(request->nheaders >= 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") &&
          !strcmp(request->headers[0].value, "application/vnd.percy+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") &&
          !strncmp(request->headers[1].value, "Token ", 6) &&
          !strcmp(request->headers[1].value + 6, key));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Percy detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 912 && detector->version == 0 && !strcmp(detector->name, "Percy"));
    CHECK(!strcmp(detector->description, "Percy is a visual testing and review platform. Percy tokens can be used to access and manage visual testing projects."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "percy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[200];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "percy PERCY_TOKEN=%s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 912, key, "key");
    br_results_clear(&out);
    /* The literal prefix is required: a bare 64-byte value yields nothing. */
    snprintf(input, sizeof(input), "percy %s", key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "percy PERCY_TOKEN=%s percy PERCY_TOKEN=%s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {204, true}, {299, true}, {300, false}, {401, false}, {500, false},
    };
    snprintf(input, sizeof(input), "percy PERCY_TOKEN=%s", key);
    http.inspect = inspect;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && percy_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    http.response = (br_http_response){.status = 200};
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Percy result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    for (size_t i = 0; i < 64; ++i) { key[i] = "0123456789AaFf"[i % 12]; other[i] = "fedcba9876543210"[i % 16]; }
    key[64] = other[64] = '\0';
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    exercise(open_detector(br_percy_init));
    CHECK(!setter_calls);
    return test_finish("Percy");
}
