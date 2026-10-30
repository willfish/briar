/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_rechargepayments_init(const br_detector **out, char **error);

static void hex(char *out, size_t len, char fill)
{
    memset(out, fill, len);
    out[len] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.rechargeapps.com/token_information"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Recharge-Access-Token"));
    CHECK(!strcmp(request->headers[1].value, http->user));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 818);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_rechargepayments_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 818 && detector->nkeywords == 15);
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "sk_1x1"));
    CHECK(!strcmp(detector->keywords[14], "X-Recharge-Access-Token"));
    char newer[80], sha[57], md5[33], input[256];
    hex(newer, 64, 'a');
    hex(sha, 56, 'b');
    hex(md5, 32, 'c');
    char token[96];
    snprintf(token, sizeof(token), "sk_test_10x3_%s", newer);
    snprintf(input, sizeof(input), "%s %s %s", token, sha, md5);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 3);
    test_key_result(&found.items[0], 818, token, "key");
    test_key_result(&found.items[1], 818, sha, "key");
    test_key_result(&found.items[2], 818, md5, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "sk_4x1_%s", newer);
    br_results rejected = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(rejected.len == 0);
    br_results_clear(&rejected);
    snprintf(input, sizeof(input), "%s %s", sha, sha);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "%s", token);
    const struct { int status; bool verified; } cases[] = {{200, true}, {201, false}, {401, false}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect_request, .user = token};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 0);
    br_results_clear(&nil);
    return test_finish("RechargePayments");
}
