/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_teletype_init(const br_detector **out, char **error);

static char key[65];

static void result_is(const br_result *result, bool verified)
{
    test_key_result(result, 777, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 64, 4);
    key[2] = '-';
    key[63] = 'Z';
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_teletype_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_teletype_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_teletype_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 777 && !strcmp(detector->name, "Teletype"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "teletype"));
    CHECK(!strcmp(detector->description,
                  "Teletype is a messaging service. Teletype API keys can be used to access and send messages through the Teletype API."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "teletype %s\nteletype %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], false);
    result_is(&out.items[1], false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "teletype %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->url, "https://api.teletype.app/public/api/v1/messages"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 777);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Auth-Token") && !strcmp(request->headers[1].value, key));
    (void)http;
}

static br_results once(const br_detector *detector, int status, const char *body, const char *read_error, int send_rc)
{
    test_http http = {.response = {.status = status, .body_error = read_error}, .send_rc = send_rc, .inspect = inspect};
    if (body) http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    if (send_rc) http.send_error = "synthetic transport failure";
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "teletype-test"};
    char input[80];
    snprintf(input, sizeof(input), "teletype %s", key);
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    return out;
}

static void verification(const br_detector *detector)
{
    br_results out = once(detector, 200, "welcome", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], true);
    br_results_clear(&out);
    out = once(detector, 200, "x\"code\":401y", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
    out = once(detector, 500, "\"code\":401", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
    out = once(detector, 200, "welcome", "synthetic read failure", 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "welcome", NULL, 1);
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Teletype");
}
