/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <json-c/json.h>
#include <string.h>

int br_stripe_init(const br_detector **, char **);

static char live[29], restricted[29];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *key = http->user;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.stripe.com/v1/charges"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 16);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, key));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
}

static void check_guide(const br_result *result, const char *key)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, "rotation_guide", &value));
    CHECK(value && !strcmp(json_object_get_string(value), "https://howtorotate.com/docs/tutorials/stripe/"));
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, result->raw.len));
}

static void exercise(const br_detector *detector)
{
    char input[160];
    test_http http = {.inspect = inspect, .user = live};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s %s sk_test_%s pk_live_%s", live, live, live + 8, live + 8);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    check_guide(&out.items[0], live);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s", restricted);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    check_guide(&out.items[0], restricted);
    br_results_clear(&out);
    http.user = restricted;
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, restricted, strlen(restricted));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1);
    br_results_clear(&out);
    http.user = live;
    const struct { int status; bool verified; } cases[] = {{200, true}, {403, true}, {401, false}, {201, false}, {500, false}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status};
        out = test_scan(detector, &ctx, true, live, strlen(live));
        CHECK(out.len == 1 && out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.send_rc = 1; http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, live, strlen(live));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.send_rc = 0; http.send_error = NULL; http.calls = 0;
    out = test_scan(detector, NULL, true, live, strlen(live));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

int main(void)
{
    memcpy(live, "sk_live_", 8);
    memcpy(restricted, "rk_live_", 8);
    for (int i = 0; i < 20; ++i) {
        live[8 + i] = "abcdefghijklmnopqrst"[(size_t)i];
        restricted[8 + i] = "ABCDEFGHIJKLMNOPQRST"[(size_t)i];
    }
    live[28] = restricted[28] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_stripe_init(&detector, &error) == 0 && detector->type == 16 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->keywords[0], "k_live") && detector->max_credential_span == -1);
    exercise(detector);
    return test_finish("Stripe");
}
