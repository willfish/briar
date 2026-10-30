/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_wrike_init(const br_detector **out, char **error);

static const char key[] =
    "eyHrUMIkHqmEhqDBTWcuk5kL.tRiP-uQD9ZZSHfYYzdqRYHgkfiPEplgL1INSyA_c9VgbpVIzvFhVx0vzWzhxv9CdyLTr6FCvmDDrxM5BU0gQdyDGgXosinkyl4Z_7OIbHY08sImeavc-fxQ1OzVo6mqb-bDmxwuVWIE5WXb2bcRRnKotFAa4.pCkZAYDxZd66Yt6fK7HM33G6Rr.ALuDQg2mFdemMy1_WIOh9-0l6b6iP2anAp0CbxpcXlrecGHaMgrgzla41NrfpzWjAKlOwq.hbIKdPLLK0bOvg2m6ETkKdGhfRRHkYAqyYO.EhONITs48Eb21kDH0gc";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app-us2.wrike.com/api/v4/contacts?me=true"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 248);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog wrike-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 335);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_wrike_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 248 && !strcmp(detector->name, "Wrike"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "wrike"));
    CHECK(!strcmp(detector->description,
        "Wrike is a collaborative work management platform that helps teams organize and manage their work. Wrike API keys can be used to access and modify data within Wrike."));
    CHECK(br_wrike_init(NULL, &error) != 0 && error); free(error);
    char input[800];
    snprintf(input, sizeof(input), "wrike token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 248, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "wrike keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    char invalid[400];
    snprintf(invalid, sizeof(invalid), "ey?%s", key + 3);
    snprintf(input, sizeof(input), "wrike = '%s'", invalid);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "wrike %s", key);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "wrike-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "WRIKE %s\nwrike %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    return test_finish("Wrike");
}
