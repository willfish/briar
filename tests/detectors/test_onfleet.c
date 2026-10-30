/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_onfleet_init(const br_detector **out, char **error);

#define br_results_push onfleet_real_push
#define br_result_set_verification_error onfleet_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3";
static const char other[] = "0123456789abcdef0123456789abcdef";
static const char url[] = "https://onfleet.com/api/v2/organization";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return onfleet_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return onfleet_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 986);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
    CHECK(request->nheaders >= 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    const char *value = request->headers[0].value;
    char *expected = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)http->user, 32}, (br_slice){0},
                             &expected, NULL) == 0 && expected);
    CHECK(!strcmp(value, expected));
    free(expected);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Onfleet detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 986 && detector->version == 0 && !strcmp(detector->name, "Onfleet"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Onfleet is a delivery management software that allows businesses to manage and analyze their delivery operations. Onfleet API keys can be used to access and manage the delivery data and operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "onfleet"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->false_positive);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[200];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "onfleet %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 986, key, "key");
    br_results_clear(&out);
    /* Source de-duplicates through a map; first-seen order is preserved. */
    snprintf(input, sizeof(input), "onfleet %s onfleet %s onfleet %s", key, key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 986, key, "key");
    test_key_result(&out.items[1], 986, other, "key");
    br_results_clear(&out);
    const char *rejected[] = {
        "onfleet B7C9D2E5F6A8B3C4D1E0F2A4B6C8D1E3",
        "onfleet b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e",
        "onfleet b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3a",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
}

static void verify_policy(const br_detector *detector)
{
    char input[70];
    snprintf(input, sizeof(input), "onfleet %s", key);
    test_http http = {.inspect = inspect, .user = (void *)key};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {204, true, NULL}, {401, false, NULL},
        {403, false, "unexpected HTTP response status 403"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        setter_calls = 0;
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == 1);
        test_key_result(&out.items[0], 986, key, "key");
        CHECK(out.items[0].verified == cases[i].verified);
        if (cases[i].cause)
            CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].cause));
        else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    /* A whole send failure is an ordinary cause and releases once. */
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.response = (br_http_response){.status = 200};
    setter_calls = 0;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == 1);
    CHECK(!out.items[0].verified && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "timeout"));
    br_results_clear(&out);
    /* Nil context still publishes with the constructor cause; no send/release. */
    http.calls = http.releases = 0;
    setter_calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == 1);
    CHECK(!out.items[0].verified && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
}

static void rollback(const br_detector *detector)
{
    char input[70];
    snprintf(input, sizeof(input), "onfleet %s", key);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && onfleet_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Onfleet result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(http.calls == 1 && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    const br_detector *detector = open_detector(br_onfleet_init);
    grammar(detector);
    verify_policy(detector);
    rollback(detector);
    return test_finish("Onfleet");
}
