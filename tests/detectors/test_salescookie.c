/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_salescookie_init(const br_detector **, char **);
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
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 300);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "X-Apikey"));
    CHECK(!strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    static const char body[] =
        "{\"date\":\"2021-07-04T02:47:42.1442597Z\",\"uniqueId\":\"id-123\",\"revenue\":1.3,\"profit\":-2.5,"
        "\"currency\":\"USD\",\"transactionStatus\":\"closed won\",\"customer\":\"Candy By Mail\","
        "\"product\":\"Lemon Cake\",\"owner1\":\"John Doe\",\"owner2\":\"Jane Doe\",\"owner3\":\"Bob Smith\","
        "\"team1\":\"USA\",\"team2\":\"Washington\",\"team3\":\"98004\",\"quantity\":3,\"costPerUnit\":3.14,"
        "\"taxes\":6.54,\"otherText1\":\"additional data\",\"otherText2\":\"more data\","
        "\"otherText3\":\"even more data\",\"otherNumeric1\":123.45,\"otherNumeric2\":54.321,"
        "\"otherNumeric3\":-98.76,\"otherDate1\":\"2019-01-03T06:03:01Z\","
        "\"otherDate2\":\"2019-05-10T08:05:09Z\",\"otherDate3\":\"2019-09-04T12:17:33Z\"}";
    CHECK(request->body.len == sizeof(body) - 1 && !memcmp(request->body.data, body, request->body.len));
}

static const br_detector *open_detector(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salescookie_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(br_salescookie_init(&detector, &error) == 0 && detector && !error);
    const br_detector *again = NULL;
    CHECK(br_salescookie_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "Salescookie") && detector->type == 300 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "salescookie"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description, "Salescookie is a sales performance management tool. Salescookie API keys can be used to create and manage transactions within the platform."));
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[1200], gap[64];
    br_transport transport;
    test_http http = {0};
    transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "salescookie %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    test_key_result(&out.items[0], 300, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "salescookie %s salescookie %s", key, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "salescookie %s salescookie %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    memset(gap, ' ', 41); gap[41] = 0;
    snprintf(input, sizeof(input), "salescookie%s%s", gap, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, &ctx, false, "no-secret", 9);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "salescookie %s", key);
    snprintf(expected_url, sizeof(expected_url), "%s", "https://salescookie.com/app/Api/CreateTransaction");
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
    return test_finish("Salescookie");
}
