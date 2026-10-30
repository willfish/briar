/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_virustotal_init(const br_detector **out, char **error);

static char key[65], other[65];

static void fill(char *out, size_t shift)
{
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; ++i) out[i] = alphabet[(i + shift) % 16];
    out[64] = '\0';
}

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 497, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    fill(key, 1);
    fill(other, 3);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_virustotal_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_virustotal_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_virustotal_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 497 && !strcmp(detector->name, "VirusTotal"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "virustotal"));
    CHECK(!strcmp(detector->description,
                  "VirusTotal is an online service that analyzes files and URLs for viruses, worms, trojans, and other kinds of malicious content. VirusTotal API keys can be used to access and integrate this service into applications."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "virustotal %s\nVIRUSTOTAL %s\nvirustotal %s", key, other, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "virustotal %sA", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "virustotal %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://www.virustotal.com/api/v3/metadata"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 497);
    CHECK(!strcmp(request->headers[0].name, "X-Apikey") && !strcmp(request->headers[0].value, key));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "virustotal %s", key);
    const int statuses[] = {199, 200, 299, 300};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "vt-test"};
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
    return test_finish("VirusTotal");
}
