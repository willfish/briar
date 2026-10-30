/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_pixabay_init(const br_detector **out, char **error);

#define br_results_push pixabay_real_push
#define br_result_set_verification_error pixabay_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1";
static const char other[] = "01234567-89ab-cdef-0123-456789abcd";
static const char url[] = "https://pixabay.com/api/?key=";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return pixabay_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return pixabay_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char expected[sizeof(url) + 34 + 40];
    snprintf(expected, sizeof(expected), "%s%s&q=yellow+flowers&image_type=photo", url, key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 494);
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Pixabay detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 494 && detector->version == 0 && !strcmp(detector->name, "Pixabay"));
    CHECK(!strcmp(detector->description, "Pixabay is a website for sharing photos, illustrations, vector graphics, and film footage under a proprietary license. Pixabay API keys can be used to access and retrieve this media content programmatically."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pixabay"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[200];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "pixabay %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 494, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "pixabay %s pixabay %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 494, key, "key");
    test_key_result(&out.items[1], 494, other, "key");
    br_results_clear(&out);
    const char *rejected[] = {
        "pixabay B7C9D2E5-F6A8-B3C4-D1E0-F2A4B6C8D1",
        "pixabay b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d",
        "pixabay b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1a",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {204, true}, {299, true}, {300, false}, {401, false}, {500, false},
    };
    snprintf(input, sizeof(input), "pixabay %s", key);
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
    CHECK(prior.verification_error && pixabay_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    http.response = (br_http_response){.status = 200};
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Pixabay result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    CHECK(strlen(key) == 34 && strlen(other) == 34);
    exercise(open_detector(br_pixabay_init));
    CHECK(!setter_calls);
    return test_finish("Pixabay");
}
