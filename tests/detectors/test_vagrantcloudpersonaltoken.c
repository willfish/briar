/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_vagrantcloudpersonaltoken_init(const br_detector **out, char **error);

static const char key1[] =
    "VVVVVVVVVVVVVV!atlasv1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char key2[] =
    "aaaaaaaaaaaaaa.atlasv1!bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[120];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key1);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://app.vagrantup.com/api/v2/authenticate"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_vagrantcloudpersonaltoken_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 946 && !strcmp(detector->name, "VagrantCloudPersonalToken"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "vagrant"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Vagrant Cloud is a service for managing and distributing development environments. Personal tokens can be used to authenticate and interact with the Vagrant Cloud API."));
    return detector;
}

int main(void)
{
    CHECK(strlen(key1) == 90 && key1[14] == '!' && strlen(key2) == 90);
    const br_detector *detector = descriptor();
    char input[280];
    snprintf(input, sizeof(input), "VAGRANT%*s%s vagrant %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 946, key1, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "vagrant %s", key1);
    const int statuses[] = {200, 201, 202, 401, 403};
    for (size_t i = 0; i < 5; ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] <= 202));
        if (statuses[i] == 403) {
            CHECK(results.items[0].verification_error &&
                  !strcmp(results.items[0].verification_error, "unexpected HTTP response status 403"));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char echoed[160];
    snprintf(echoed, sizeof(echoed), "dial failed %s", key1);
    test_http failed = {.send_rc = -1, .send_error = echoed, .inspect = inspect};
    br_transport transport = test_transport(&failed);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(results.items[0].verification_error, key1));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("VagrantCloudPersonalToken");
}
