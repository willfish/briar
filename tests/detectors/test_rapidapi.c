/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_rapidapi_init(const br_detector **out, char **error);

#define br_results_push rapidapi_real_push
#define br_result_set_verification_error rapidapi_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[51], other[51];
static const char url[] = "https://covid-19-tracking.p.rapidapi.com/v1";
static size_t push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return rapidapi_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    return rapidapi_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 99);
    CHECK(request->nheaders >= 1 && !strcmp(request->headers[0].name, "x-rapidapi-key"));
    CHECK(!strcmp(request->headers[0].value, (const char *)http->user));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Rapidapi detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 99 && detector->version == 0 && !strcmp(detector->name, "RapidApi"));
    CHECK(!strcmp(detector->description, "RapidAPI is a platform for connecting to thousands of APIs. RapidAPI keys can be used to access and interact with these APIs."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "rapidapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[400], header[128];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "rapidapi %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 99, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "rapidapi %s rapidapi %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    br_results_clear(&out);
    const char *rejected[] = {"rapidapi ab12", "rapidapi ab12_AB-12ab12_AB-12ab12_AB-12ab12_AB-12ab12_AB"};
    for (size_t i = 0; i < 2 && rejected[i]; ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
    snprintf(input, sizeof(input), "rapidapi %s", key);
    snprintf(header, sizeof(header), "%s%s", "", key);
    http.inspect = inspect;
    http.user = header;
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {201, true}, {299, true}, {300, false}, {401, false}, {500, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
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
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && rapidapi_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 200};
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Rapidapi result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    for (size_t i = 0; i < 50; ++i) {
        key[i] = "ab12_A"[i % 6];
        other[i] = "Z9y8-7"[i % 6];
    }
    key[50] = other[50] = '\0';
    CHECK(strlen(key) == 50 && strlen(other) == 50);
    exercise(open_detector(br_rapidapi_init));
    return test_finish("RapidApi");
}
