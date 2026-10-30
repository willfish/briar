/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_postman_init(const br_detector **out, char **error);

#define br_results_push postman_real_push
#define br_result_set_verification_error postman_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[65], other[65];
static const char url[] = "https://api.getpostman.com/collections";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return postman_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return postman_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 118);
    CHECK(request->nheaders >= 2);
    CHECK(!strcmp(request->headers[0].name, "x-api-key") && !strcmp(request->headers[0].value, http->user));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Postman detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 118 && detector->version == 0 && !strcmp(detector->name, "Postman"));
    CHECK(!strcmp(detector->description, "Postman is a collaboration platform for API development. Postman API keys can be used to access and modify collections, environments, and other resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "PMAK-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[200];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 118, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    const char *rejected[] = {
        "PMAK-abc",
        "pmak-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL},
        {403, false, "unexpected HTTP response status 403"},
        {500, false, "unexpected HTTP response status 500"},
    };
    snprintf(input, sizeof(input), "%s", key);
    http.inspect = inspect;
    http.user = (void *)key;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        setter_calls = 0;
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == 1);
        CHECK(out.items[0].verified == cases[i].verified);
        if (cases[i].cause) CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].cause));
        else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    setter_calls = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == 1);
    CHECK(!out.items[0].verified && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "timeout"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    setter_calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == 1);
    CHECK(!out.items[0].verified && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && postman_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    http.response = (br_http_response){.status = 200};
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Postman result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    memcpy(key, "PMAK-", 5);
    for (size_t i = 5; i < 64; ++i) key[i] = "ab12-AB"[i % 7];
    key[64] = '\0';
    memcpy(other, "PMAK-", 5);
    for (size_t i = 5; i < 64; ++i) other[i] = "Z9y8-X7"[i % 7];
    other[64] = '\0';
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    exercise(open_detector(br_postman_init));
    return test_finish("Postman");
}
