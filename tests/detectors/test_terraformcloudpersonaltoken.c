/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_terraformcloudpersonaltoken_init(const br_detector **out, char **error);

static char *token(char *out, char sep)
{
    memset(out, 'a', 14);
    out[14] = sep;
    memcpy(out + 15, "atlasv1", 7);
    out[22] = sep;
    memset(out + 23, 'b', 67);
    out[90] = '\0';
    return out;
}

static void expect_one(const br_detector *detector, const char *input, const char *key, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count);
    if (count) test_key_result(&results.items[0], 93, key, "key");
    br_results_clear(&results);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char bearer[128];
    snprintf(bearer, sizeof(bearer), "Bearer %s", (char *)http->user);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.terraform.io/api/v2/account/details"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 93);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, bearer));
    CHECK(!request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_terraformcloudpersonaltoken_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 93 && !strcmp(detector->name, "TerraformCloudPersonalToken"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".atlasv1."));
    CHECK(!strcmp(detector->description,
        "Terraform Cloud is a service that provides infrastructure automation. "
        "Terraform Cloud personal tokens can be used to access and manage infrastructure as code."));
    char key[91], other[91], input[256];
    token(key, '.');
    token(other, 'X');
    snprintf(input, sizeof(input), "token %s", key);
    expect_one(detector, input, key, 1);
    snprintf(input, sizeof(input), "token %s", other);
    expect_one(detector, input, other, 1);
    snprintf(input, sizeof(input), "%.89s", key);
    expect_one(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%s extra", key);
    expect_one(detector, input, key, 1);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "%s", key);
    const struct { int status, send_rc; bool verified; } cases[] = {
        {200, 0, true}, {299, 0, true}, {199, 0, false}, {401, 0, false}, {200, 1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .send_rc = cases[i].send_rc,
                          .send_error = cases[i].send_rc ? "dial failed" : NULL,
                          .inspect = inspect_request, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    return test_finish("TerraformCloudPersonalToken");
}
