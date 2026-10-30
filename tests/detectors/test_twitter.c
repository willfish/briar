/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <json-c/json.h>
#include <string.h>

int br_twitter_v1_init(const br_detector **, char **);
int br_twitter_v2_init(const br_detector **, char **);

static const char v1_token[] =
    "EGGIFBZPKVTIKCEJCSRHQY%5PabdkLS20yFOCKlOiXqbTG%PHGkqp%Ybm%2YgUAvoI-%3ZXVX8KgdsYSJ1DEgoxhGkoY6cNMN8EZidvGnJQ4Z8-4V2fSbdMU";
static const char v2_token[] =
    "6pvFJmFvkNjdMImKVWF1NOZ%9n5K8rIH4JOfczZSg5uAsHErlQY6c5TrAygcZYF9WttO1m4LGhg0IUbFgXcaXtAmH4SnIb5cHac0sNcQHVKXZgaKxMqw1Fvt87RcyYKJ1bSP0BGPE%p912wZKbAkTcRfglLMyrcV6aMnuxbj7ctFoulIgFw8Aljzv87cs4";
static const char *fail_copy;

char *strdup(const char *s)
{
    if (fail_copy && !strcmp(s, fail_copy)) return NULL;
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *token = http->user;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.twitter.com/2/tweets/20"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 676);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static void check_version(const br_result *result, const char *token, const char *version)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, "version", &value));
    CHECK(value && !strcmp(json_object_get_string(value), version));
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, result->raw.len));
    CHECK(result->detector_type == 676 && !result->redacted);
}

static const br_detector *open_one(int (*init)(const br_detector **, char **), int version, const char *description)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(init(&detector, &error) == 0 && detector && !error);
    const br_detector *again = NULL;
    CHECK(init(&again, &error) == 0 && again == detector);
    CHECK(!strcmp(detector->name, "Twitter") && detector->version == version && detector->type == 676);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "twitter"));
    CHECK(detector->max_credential_span == 1024 && !strcmp(detector->description, description));
    return detector;
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[1600], gap[64];
    snprintf(input, sizeof(input), "twitter %s twitter %s", v1_token, v1_token);
    br_results out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_version(&out.items[0], v1_token, "1");
    br_results_clear(&out);
    out = test_scan(v2, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "twitter %s", v2_token);
    out = test_scan(v2, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_version(&out.items[0], v2_token, "2");
    br_results_clear(&out);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    memset(gap, ' ', 41);
    gap[41] = 0;
    snprintf(input, sizeof(input), "twitter%s%s", gap, v1_token);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void verification(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "twitter %s", v1_token);
    test_http http = {.inspect = inspect, .user = (void *)v1_token};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, "unexpected status code 403"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(out.items[0].verified == cases[i].verified);
        if (cases[i].cause) CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].cause));
        else CHECK(!out.items[0].verification_error);
        check_version(&out.items[0], v1_token, "1");
        br_results_clear(&out);
    }
    http.send_rc = 1;
    http.send_error = "dial twitter token failed";
    http.calls = http.releases = 0;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "dial twitter token failed"));
    br_results_clear(&out);
    http.send_rc = 0;
    http.send_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    ctx.cancelled = cancelled;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verification_error && !strcmp(out.items[0].verification_error, "context canceled"));
    br_results_clear(&out);
    ctx.cancelled = NULL;
    ctx.deadline_monotonic_ms = 1;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verification_error && !strcmp(out.items[0].verification_error, "context deadline exceeded"));
    br_results_clear(&out);
}

static void rollback(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "twitter %s", v1_token);
    test_http http = {.inspect = inspect, .user = (void *)v1_token, .response = {.status = 503}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = {0};
    br_result prior = {0};
    char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&out, &prior));
    unsigned char *saved = out.items[0].raw.data;
    fail_copy = "unexpected status code 503";
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error);
    fail_copy = NULL;
    CHECK(rc == -1 && error && *error && http.calls == 1 && http.releases == 1);
    CHECK(out.len == 1 && out.items[0].raw.data == saved && out.items[0].detector_type == 777);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *v1 = open_one(br_twitter_v1_init, 1,
        "Twitter API keys can be used to interact with the Twitter API to post tweets, read timelines, and access other Twitter functionalities.");
    const br_detector *v2 = open_one(br_twitter_v2_init, 2,
        "Twitter API keys can be used to access and interact with Twitter's platform programmatically.");
    extraction(v1, v2);
    verification(v1);
    rollback(v1);
    return test_finish("Twitter v1 and v2");
}
