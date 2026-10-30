/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_http_send toggl_real_send
#include "../../src/http.c"
#undef br_http_send

int br_toggltrack_init(const br_detector **out, char **error);

static const char key[] = "aA0123456789abcdefghijklmnopqrst";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_toggltrack_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_toggltrack_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 290 && !strcmp(detector->name, "TogglTrack"));
    CHECK(!strcmp(detector->description,
                  "TogglTrack is a time tracking tool. TogglTrack API keys can be used to access and manage time tracking data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "toggl"));
    CHECK(detector->max_credential_span == -1);
    CHECK(strlen(key) == 32);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[96], rejected[96];
    snprintf(input, sizeof(input), "toggl %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 290, key, "key");
    br_results_clear(&results);
    snprintf(rejected, sizeof(rejected), "toggl B%s", key + 1);
    results = test_scan(detector, NULL, false, rejected, strlen(rejected));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "toggl %s toggl %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static int toggl_status;
static bool toggl_transport;
static bool saw_basic;

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                 br_http_response *response, char **error)
{
    (void)ctx;
    CHECK(request && response);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.track.toggl.com/api/v8/me"));
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
    saw_basic = true;
    CHECK(request->dedup_key.len == 36 && !memcmp(request->dedup_key.data, "290:", 4) &&
          !memcmp(request->dedup_key.data + 4, key, 32));
    memset(response, 0, sizeof(*response));
    if (toggl_transport) {
        if (error) *error = strdup("dial tcp: connection refused");
        return -1;
    }
    response->status = toggl_status;
    if (error) *error = NULL;
    return 0;
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "toggl %s", key);
    toggl_status = 200;
    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && saw_basic);
    br_results_clear(&results);
    toggl_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    toggl_transport = true;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("toggltrack");
}
