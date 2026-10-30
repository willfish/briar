/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_protocolsio_init(const br_detector **out, char **error);

static char key[65], other[65];

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 411, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 64, 2);
    test_secret(other, 64, 9);
    key[0] = 'a';
    other[0] = 'z';
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_protocolsio_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_protocolsio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_protocolsio_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 411 && !detector->version && !strcmp(detector->name, "ProtocolsIO"));
    CHECK(!strcmp(detector->keywords[0], "protocols") && detector->nkeywords == 1);
    CHECK(!strcmp(detector->description,
                  "Protocols.io is a platform for developing and sharing reproducible research protocols. The API keys can be used to access and manage protocols and data on the platform."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "protocols %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, 64);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "PROTOCOLS\n%s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memcpy(input, "protocols", 9);
    memset(input + 9, '.', 40);
    memcpy(input + 49, key, 64);
    out = test_scan(detector, NULL, false, input, 113);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memset(input + 9, '.', 41);
    memcpy(input + 50, key, 64);
    out = test_scan(detector, NULL, false, input, 114);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "protocols %sX", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "protocols %s\nprotocols %s\nprotocols %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "protocols %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[72];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://www.protocols.io/api/v3/session/profile"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 411 && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "protocols %s", key);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "protocolsio-test"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = 1, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("ProtocolsIO");
}
