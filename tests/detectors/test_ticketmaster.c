/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_ticketmaster_init(const br_detector **, char **);
static char key[33], other[33], expected_url[512];

static void fill(char *out, size_t n, const char *alphabet, size_t shift)
{
    size_t m = strlen(alphabet);
    for (size_t i = 0; i < n; ++i) out[i] = alphabet[(i + shift) % m];
    out[n] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 563);
    CHECK(request->nheaders == 1);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
    CHECK(!request->body.data);
}

static const br_detector *open_detector(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_ticketmaster_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(br_ticketmaster_init(&detector, &error) == 0 && detector && !error);
    const br_detector *again = NULL;
    CHECK(br_ticketmaster_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "TicketMaster") && detector->type == 563 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ticketmaster"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description, "TicketMaster API keys can be used to access and modify event data and other related services provided by TicketMaster."));
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[1200], gap[64];
    br_transport transport;
    test_http http = {0};
    transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "ticketmaster %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    test_key_result(&out.items[0], 563, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ticketmaster %s ticketmaster %s", key, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ticketmaster %s ticketmaster %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    memset(gap, ' ', 41); gap[41] = 0;
    snprintf(input, sizeof(input), "ticketmaster%s%s", gap, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, &ctx, false, "no-secret", 9);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ticketmaster %s", key);
    snprintf(expected_url, sizeof(expected_url), "https://app.ticketmaster.com/discovery/v2/events.json?apikey=%s", key);
    http.user = expected_url;
    http.inspect = inspect;
    const int statuses[] = {200, 201, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){.status = statuses[i]};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(out.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.send_rc = 1; http.send_error = "timeout"; http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.send_rc = 0; http.send_error = NULL; http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

int main(void)
{
    fill(key, 32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 0);
    fill(other, 32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3);
    CHECK(strcmp(key, other));
    exercise(open_detector());
    return test_finish("TicketMaster");
}
