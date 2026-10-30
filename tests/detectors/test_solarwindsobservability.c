/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_solarwindsobservability_init(const br_detector **out, char **error);

static const char key[] = "Xwl4ViaAFDLrAmFX9g1blkUVC5dJj2he3a1tzkpJ4-PznQukQruRjqMFbEG73L92LJyBGMZ";
static const char xml_key[] = "zxsb8yzT0RbIJ1TAalB87LOVUcT1b4uEgvT4tXCcSqv_gcmlrx5aQRleHPDFKePjpHFof5J";
static int script_status[4];
static int script_rc[4];
static const char *script_error[4];
static size_t script_at;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 71 && strlen(xml_key) == 71);
    CHECK(br_solarwindsobservability_init(&detector, &error) == 0 && detector && detector->type == 1069);
    CHECK(!strcmp(detector->name, "SolarWindsObservability") && !strcmp(detector->keywords[0], "solarwinds"));
    CHECK(!strcmp(detector->description,
                  "SolarWinds Observability is a cloud-based SaaS observability platform "
                  "(successor to AppOptics). Its API tokens can be used to access and manage "
                  "monitoring data and configurations."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const char *const regions[] = {"na-01", "na-02", "eu-01", "ap-01"};
    char url[64], authorization[80];
    size_t at = http->calls - 1;
    CHECK(ctx && at < 4);
    snprintf(url, sizeof(url), "https://api.%s.cloud.solarwinds.com/v1/metrics", regions[at]);
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1069);
    CHECK(request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response.status = script_status[at];
    http->send_rc = script_rc[at];
    http->send_error = script_error[at];
    ++script_at;
}

static void expect_region(const br_result *result, const char *region)
{
    br_json *part = NULL;
    CHECK(result->verified && !result->verification_error && result->extra_data);
    CHECK(json_object_object_get_ex(result->secret_parts, "region", &part) &&
          !strcmp(json_object_get_string(part), region));
    CHECK(json_object_object_get_ex(result->extra_data, "region", &part) &&
          !strcmp(json_object_get_string(part), region));
    CHECK(json_object_object_length(result->secret_parts) == 2);
}

static void run(const br_detector *detector)
{
    const char *sample =
        "solarwindsKey := \"Xwl4ViaAFDLrAmFX9g1blkUVC5dJj2he3a1tzkpJ4-PznQukQruRjqMFbEG73L92LJyBGMZ\"";
    const char *xml =
        "<id>{solarwinds}</id><secret>{AQAAABAAA zxsb8yzT0RbIJ1TAalB87LOVUcT1b4uEgvT4tXCcSqv_gcmlrx5aQRleHPDFKePjpHFof5J}</secret>";
    br_results results = test_scan(detector, NULL, false, sample, strlen(sample));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1069, key, "key");
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, xml, strlen(xml));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1069, xml_key, "key");
    br_results_clear(&results);
    const struct { int statuses[4]; int rcs[4]; const char *errors[4]; size_t calls; bool verified;
                   const char *region, *error; } cases[] = {
        {{200, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, 1, true, "na-01", NULL},
        {{401, 401, 401, 401}, {0, 0, 0, 0}, {0, 0, 0, 0}, 4, false, NULL, NULL},
        {{500, 401, 200, 500}, {0, 0, 0, 0}, {0, 0, 0, 0}, 3, true, "eu-01", NULL},
        {{401, 500, 401, 401}, {0, 0, 0, 0}, {0, 0, 0, 0}, 4, false, NULL,
         "unexpected HTTP response status 500 from region na-02"},
        {{0, 0, 0, 0}, {1, 1, 1, 1}, {0, 0, 0, 0}, 4, false, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        memcpy(script_status, cases[i].statuses, sizeof(script_status));
        memcpy(script_rc, cases[i].rcs, sizeof(script_rc));
        memcpy(script_error, cases[i].errors, sizeof(script_error));
        script_at = 0;
        test_http http = {.inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, sample, strlen(sample));
        CHECK(results.len == 1 && http.calls == cases[i].calls && http.releases == cases[i].calls);
        if (cases[i].verified) expect_region(&results.items[0], cases[i].region);
        else {
            test_key_result(&results.items[0], 1069, key, "key");
            CHECK(!results.items[0].verified);
            if (cases[i].error) CHECK(results.items[0].verification_error &&
                                      !strcmp(results.items[0].verification_error, cases[i].error));
            else CHECK(!results.items[0].verification_error);
        }
        br_results_clear(&results);
    }
    results = test_scan(detector, NULL, true, sample, strlen(sample));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context") && !results.items[0].extra_data);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("SolarWindsObservability");
}
