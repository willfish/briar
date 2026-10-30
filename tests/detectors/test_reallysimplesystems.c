/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_reallysimplesystems_init(const br_detector **out, char **error);

static const char upstream[] =
    "eyt_8-ytglklqvyjGF6dgbXsCSMRLdryUWQCSQ1n1uSph1Ppl.jMeMx0EkxVLcmbKPTi7kPYKzNa04V96eiJlV.XxtKFDKTJCkcThvKR2x0ctVUL.FrbHVXEx55VZZPD0FKW4onNDO05Ab_9cbnrLTr4d--.eyX.hZw.Q5g-pvyWS5jjDUyiE60WZSgQq4uM8PUVw1-OJegMnGGLEKq48G5X7zgQAcYvUIRQy4Ku.gKQkNFIL4Nlj3ob7Bi4VUDs_DjvtS_Jxho-Hn_hgIhfYQVw19wQCcc8m7v2jCXz2MTi74vpzW7aY2C123i5uFr1KdVQLX.Xlf5ZtuLAsYZ5MsG1G6VYO_t7l6nl8D-Y3fml7uSGPXkeQT7AW1HKOTrBdGj0L_OMMYBaZ4-R9tnUjM7Jf1LExVn2NIQnNGR7Jyl69WigxQGLaUbNvE9DQkVtV4ar0FORi8mrwAQdb5UxZkOxW4me_F189Y-rs0h9q4vrjmM3Fu1Uj_UCrV4IP6AYr4b9yXzgAlcybQSNUISltLwYC.07LKjRy.dLvF-A2b5mIjyKbR3rOUmiXfeAveBRakkEOKSNOSTDVM839O9a-8tqAggj8eDdPunO8Pg6L_Af_eJowZNhtRluVuFDTHuUW.lAG1bqm.ZJQak800cspbDbB8InwOb0V1UvoO.c.ZOAWM3fQVoidNeDbKbWKR3JdE3iWCGsqz89Zdd6LkxwHAd5TRLn.ZVg67d1.g2S3kadXrTZ0qN6o_7apQ38PbGKydnCTLMfdgN6uIPqAtQntsF6YNvNfFHnXgsfhTkVUDJc5g6oQB_jDeGa8rkCmH6_DO6Z1qV04G.fj.QLJIgMhcdGL8Y3NMRv87spZxNWmX1glZ1AYQlWbbqwzAC1v-p0ImXQSuq6G8aIt8e4w7FnOmOn_Q0NwD85JRgdy.W4f.5hX-zLhj1RDqvC1-Ebd2OLDdne0xqMMNe4kGnzQ6dpDtbZXPcim443CyFxaFD_DK5-Iupc032AKV_Sm9eDSlRuAmAQ7LhvypNWi_6e9NuVUEQ5P6HfBe1eXkZ3y5HkZpWbJqJW2D";
static char token[1159];

static void make_token(size_t tail)
{
    memset(token, 'a', sizeof(token) - 1);
    memcpy(token, "ey", 2);
    token[155] = 'x';
    memcpy(token + 156, "ey", 2);
    token[2 + 153 + 1 + 2 + tail] = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(upstream) == 1074);
    CHECK(br_reallysimplesystems_init(&detector, &error) == 0 && detector && detector->type == 276);
    CHECK(!strcmp(detector->name, "ReallySimpleSystems") && !strcmp(detector->keywords[0], "reallysimplesystems"));
    CHECK(!strcmp(detector->description,
                  "ReallySimpleSystems is a CRM system. The detected credentials can be used to "
                  "access and manage customer relationship data and workflows within the "
                  "ReallySimpleSystems platform."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[1166];
    (void)http;
    snprintf(authorization, sizeof(authorization), "Bearer %s", upstream);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://apiv4.reallysimplesystems.com/accounts"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 276);
    CHECK(request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
}

static void run(const br_detector *detector)
{
    char input[1400];
    snprintf(input, sizeof(input), "reallysimplesystems token = '%s'", upstream);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 276, upstream, "key");
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, upstream, strlen(upstream));
    CHECK(results.len == 1);
    br_results_clear(&results);
    {
        char invalid[1075];
        memcpy(invalid, upstream, sizeof(invalid));
        invalid[0] = 'a';
        results = test_scan(detector, NULL, false, invalid, 1074);
        CHECK(!results.len);
        br_results_clear(&results);
    }
    make_token(915);
    results = test_scan(detector, NULL, false, token, strlen(token));
    CHECK(!results.len);
    br_results_clear(&results);
    make_token(916);
    results = test_scan(detector, NULL, false, token, strlen(token));
    CHECK(results.len == 1 && results.items[0].raw.len == 1074);
    br_results_clear(&results);
    static const unsigned char valid_json[] = "null";
    static const unsigned char invalid_json[] = "not-json";
    snprintf(input, sizeof(input), "reallysimplesystems token = '%s'", upstream);
    const struct { int status; const unsigned char *body; size_t len; const char *body_error; int send_rc; bool verified; size_t count; } cases[] = {
        {200, valid_json, 4, NULL, 0, true, 1},
        {204, invalid_json, 8, NULL, 0, false, 1},
        {401, valid_json, 4, NULL, 0, false, 1},
        {200, valid_json, 4, "read failed", 0, false, 0},
        {200, valid_json, 4, NULL, 1, false, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {cases[i].body, cases[i].len},
                                       .body_error = cases[i].body_error},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "down" : NULL,
                          .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == cases[i].count && http.calls == 1 && http.releases == 1);
        if (cases[i].count) {
            CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        }
        br_results_clear(&results);
    }
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("ReallySimpleSystems");
}
