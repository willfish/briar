/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_youtubeapikey_init(const br_detector **out, char **error);

static const char key[] = "8SN8OtkzJ6z2tcFtv93Gl63o97LGGBvYAyJviDg";
static const char id[] = "0ifNmkGT6biPToj9TDGYqyFP";
static char seen_url[160];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->nheaders == 1);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 46);
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
}

int main(void)
{
    CHECK(strlen(key) == 39 && strlen(id) == 24);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_youtubeapikey_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 46 && !strcmp(detector->name, "YoutubeApiKey") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "youtube"));
    CHECK(!strcmp(detector->description, "YouTube API Keys allow access to various functionalities of the YouTube Data API, enabling operations such as retrieving video details and managing playlists."));
    char input[160];
    snprintf(input, sizeof(input), "youtubeapikey token - '%s'\nyoutubeapikey token - '%s'\n", key, id);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 46, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "youtube 8SN8OtkzJ6z2tcFtv93-l63o97LGGBvYAyJviDg youtube 0ifNmkGT6biPToj9TDGYqy-P");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].raw.len == 39);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "youtube 0ifNmkGT6biPToj9TDGYqy_P");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "youtube %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "youtube %s youtube %s", key, id);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified);
    CHECK(!strcmp(seen_url, "https://www.googleapis.com/youtube/v3/channelSections?key=8SN8OtkzJ6z2tcFtv93Gl63o97LGGBvYAyJviDg&channelId=0ifNmkGT6biPToj9TDGYqyFP"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("YoutubeApiKey");
}
