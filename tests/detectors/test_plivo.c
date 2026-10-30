/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <json-c/json.h>
#include <string.h>

int br_plivo_init(const br_detector **, char **);

static char key[41], id[21], auth[128];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 80);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, auth));
}

static void exercise(const br_detector *detector)
{
    char input[160], url[80];
    char *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, 20},
                             (br_slice){(const unsigned char *)key, 40}, &error, NULL) == 0);
    /* basic auth writes to the third argument. */
    free(error);
    char *encoded = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, 20},
                             (br_slice){(const unsigned char *)key, 40}, &encoded, &error) == 0 && encoded);
    snprintf(auth, sizeof(auth), "%s", encoded);
    free(encoded);
    snprintf(url, sizeof(url), "https://api.plivo.com/v1/Account/%s/Number/", id);
    snprintf(input, sizeof(input), "plivo %s %s", id, key);
    test_http http = {.inspect = inspect, .user = url};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    CHECK(out.items[0].raw.len == 40 && !memcmp(out.items[0].raw.data, key, 40));
    CHECK(out.items[0].raw_v2.len == 60 && !memcmp(out.items[0].raw_v2.data, key, 40) &&
          !memcmp(out.items[0].raw_v2.data + 40, id, 20));
    CHECK(out.items[0].redacted && !strcmp(out.items[0].redacted, id));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(out.items[0].secret_parts, "id", &part) && !strcmp(json_object_get_string(part), id));
    br_results_clear(&out);
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 401};
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

int main(void)
{
    for (int i = 0; i < 40; ++i) key[i] = "abcdefghijklmnopqrstuvwxyz0123456789_-ab"[(size_t)i];
    for (int i = 0; i < 20; ++i) id[i] = 'A' + (i % 26);
    key[40] = id[20] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_plivo_init(&detector, &error) == 0 && detector->type == 80 && detector->max_credential_span == 1024);
    exercise(detector);
    return test_finish("Plivo");
}
