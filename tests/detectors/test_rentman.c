/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_rentman_init(const br_detector **out, char **error);

static const char key[] = "eytuZDhcszM3EZO7iPeRfJfZMoRMLXe7qoNV.eyA3uoaQ3ttxNcElupuqjIGN2K-bLTq_RVtB6w6ySxFCOttLniQBf84yvwaBBjw4W1veuikC2uWzoW5Gtw-CpEC-.35zBGkn7t7G19FduNmXTy1r_8bXME-VD5xIflYzioiZvyRLfy685qs8TQDIJV7zLi98cPLrLTE_yXwmppu9o88_OWPzh9oAqmVGqvX5Z_1RXqd6e5MsaTFx22tqKw14njwD.qvyujp.NR6QOQmyREUt2XnUtqdupyGX";
static const char invalid[] = "aytuZDhcszM3EZO7iPeRfJfZMoRMLXe7qoNV.eyA3uoaQ3ttxNcElupuqjIGN2K-bLTq_RVtB6w6ySxFCOttLniQBf84yvwaBBjw4W1veuikC2uWzoW5Gtw-CpEC-.35zBGkn7t7G19FduNmXTy1r_8bXME-VD5xIflYzioiZvyRLfy685qs8TQDIJV7zLi98cPLrLTE_yXwmppu9o88_OWPzh9oAqmVGqvX5Z_1RXqd6e5MsaTFx22tqKw14njwD.qvyujp.NR6QOQmyREUt2XnUtqdupyG?";
static int fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    CHECK(copy);
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.rentman.net/files"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 836);
    CHECK(request->nheaders == 3 && !request->body.len);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    char want[400];
    snprintf(want, sizeof(want), "Bearer %s", key);
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, want));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_rentman_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 836 && !strcmp(detector->name, "Rentman") && !strcmp(detector->keywords[0], "rentman"));
    CHECK(detector->max_credential_span == -1 && strlen(key) == 289);
    char input[800];
    snprintf(input, sizeof(input), "rentman token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 836, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "RENTMAN %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "rentman %s rentman %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "rentman%*s%s", gap, "", key);
        results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "rentman %s", invalid);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, "rentman keyword is not close to the real key in the data\n = 'eytuZDhcszM3EZO7iPeRfJfZMoRMLXe7qoNV.eyA3uoaQ3ttxNcElupuqjIGN2K-bLTq_RVtB6w6ySxFCOttLniQBf84yvwaBBjw4W1veuikC2uWzoW5Gtw-CpEC-.35zBGkn7t7G19FduNmXTy1r_8bXME-VD5xIflYzioiZvyRLfy685qs8TQDIJV7zLi98cPLrLTE_yXwmppu9o88_OWPzh9oAqmVGqvX5Z_1RXqd6e5MsaTFx22tqKw14njwD.qvyujp.NR6QOQmyREUt2XnUtqdupyGX'", strlen("rentman keyword is not close to the real key in the data\n = 'eytuZDhcszM3EZO7iPeRfJfZMoRMLXe7qoNV.eyA3uoaQ3ttxNcElupuqjIGN2K-bLTq_RVtB6w6ySxFCOttLniQBf84yvwaBBjw4W1veuikC2uWzoW5Gtw-CpEC-.35zBGkn7t7G19FduNmXTy1r_8bXME-VD5xIflYzioiZvyRLfy685qs8TQDIJV7zLi98cPLrLTE_yXwmppu9o88_OWPzh9oAqmVGqvX5Z_1RXqd6e5MsaTFx22tqKw14njwD.qvyujp.NR6QOQmyREUt2XnUtqdupyGX'"));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "rentman %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1 && http.calls == 0);
    free(error);
    br_results_clear(&results);
    return test_finish("rentman");
}
