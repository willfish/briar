/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_onesignal_init(const br_detector **out, char **error);

/* Observe the absent setter and exercise a later push failure. */
#define br_results_push onesignal_real_push
#define br_result_set_verification_error onesignal_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3";
static const char other[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char url[] = "https://onesignal.com/api/v1/apps";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return onesignal_real_setter(result, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return onesignal_real_push(out, result);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 835);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
    CHECK(request->nheaders >= 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") &&
          !strcmp(request->headers[0].value, "application/vnd.onesignal+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    /* Basic base64("<key>:") for whichever capture this call belongs to. */
    const char *value = request->headers[1].value;
    char *expected = NULL;
    for (size_t i = 0; i < 2; ++i) {
        const char *candidate = i ? other : key;
        free(expected);
        expected = NULL;
        CHECK(br_http_basic_auth((br_slice){(const unsigned char *)candidate, 36},
                                 (br_slice){0}, &expected, NULL) == 0 && expected);
        if (!strcmp(value, expected)) break;
    }
    CHECK(expected && !strcmp(value, expected));
    free(expected);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid OneSignal detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 835 && detector->version == 0 && !strcmp(detector->name, "Onesignal"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "OneSignal is a customer engagement platform that enables businesses to send push notifications, in-app messages, SMS, and emails. OneSignal API keys can be used to access and send messages through these channels."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "onesignal"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->false_positive);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[220];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "onesignal %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 835, key, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "onesignal %s onesignal %s", key, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "onesignal %s onesignal %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 835, key, "key");
    test_key_result(&out.items[1], 835, other, "key");
    br_results_clear(&out);
    /* The grammar is lowercase UUID only, with both boundaries required. */
    test_http silent = {0};
    br_transport silent_transport = test_transport(&silent);
    br_scan_ctx quiet = {.transport = &silent_transport};
    const char *rejected[] = {
        "onesignal B7C9D2E5-F6A8-B3C4-D1E0-F2A4B6C8D1E3",
        "onesignal b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e",
        "onesignal b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3a",
        "onesignal xb7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &quiet, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !silent.calls && !silent.releases);
        br_results_clear(&none);
    }
}

static void verify_policy(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "onesignal %s", key);
    test_http http = {.inspect = inspect};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {204, true}, {299, true}, {199, false}, {300, false}, {401, false}, {500, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        test_key_result(&out.items[0], 835, key, "key");
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    /* A whole mixed preparation/Do failure stays unverified with no setter. */
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.response = (br_http_response){.status = 200};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    /* Nil context drops after the finding exists: no send and no release. */
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
    /* NoV still emits the finding with no context work at all. */
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void rollback(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "onesignal %s", key);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && onesignal_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append OneSignal result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    CHECK(strlen(key) == 36 && strlen(other) == 36);
    const br_detector *detector = open_detector(br_onesignal_init);
    grammar(detector);
    verify_policy(detector);
    rollback(detector);
    CHECK(!setter_calls);
    return test_finish("OneSignal");
}
