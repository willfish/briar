/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_overloop_init(const br_detector **out, char **error);

static const char key[] = "Uf0rlS3D-nwUKNuo1FO2oQpaT43SaLG4jBvJupG--kBPLxhjOV";
static const char other[] = "Uf0rlS3D-nwUKNuo1FO2oQpaT43SaLG4jBvJupG--kBPLxhjOW";
static char seen_auth[80];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.overloop.com/public/v1/users"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 965 && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!request->body.data && !request->dedup_key.data);
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

static const br_detector *open_detector(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_overloop_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_overloop_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 965 && !strcmp(detector->name, "Overloop"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "overloop"));
    CHECK(detector->max_credential_span == -1 && detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description, "Overloop is a service that provides API keys for accessing its platform. These keys can be used to interact with the Overloop API to manage and retrieve user data."));
    return detector;
}

int main(void)
{
    CHECK(strlen(key) == 50 && strlen(other) == 50);
    const br_detector *detector = open_detector();
    char input[256], gap[48];
    snprintf(input, sizeof(input), "overloop '%s'", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 965, key, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "OVERLOOP %s overloop %s", key, other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[1], 965, other, "key");
    br_results_clear(&out);

    memset(gap, '.', 40);
    gap[40] = '\0';
    snprintf(input, sizeof(input), "overloop%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    gap[40] = '.';
    gap[41] = '\0';
    snprintf(input, sizeof(input), "overloop%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "overloop %sx", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "overloop %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {299, true, NULL}, {401, false, NULL}, {403, false, "unexpected HTTP response status 403"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status, .body_error = "ignored"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(out.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(!strcmp(out.items[0].verification_error, cases[i].error));
        else CHECK(!out.items[0].verification_error);
        CHECK(!strcmp(seen_auth, key));
        br_results_clear(&out);
    }
    char noisy[80];
    snprintf(noisy, sizeof(noisy), "bad %s", key);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = noisy;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error, "bad [REDACTED]"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Overloop");
}
