/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sanity_init(const br_detector **out, char **error);

static const char key[] = "skCrESWvpXysjmfakeaMGdMecRnw2mTVURqlVABArKApL1j4SLUhFAKEEizjp7ymM8pebv0ScqyqelbLD";
static char other[82], seen_auth[96];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.sanity.io/vX/access/permissions/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1012);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(key) == 81);
    memcpy(other, key, 82);
    other[80] = 'M';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sanity_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 1012 && !strcmp(detector->name, "Sanity") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "sanity"));
    CHECK(!strcmp(detector->description, "Sanity is the modern CMS that transforms content into a competitive advantage. Customize, collaborate, and scale your digital experiences seamlessly."));
    char input[320];
    snprintf(input, sizeof(input), "SANITY %s sanity %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 1012, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "sanity %s sanity %s", key, other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && !memcmp(out.items[1].raw.data, other, 81));
    br_results_clear(&out);
    snprintf(input, sizeof(input), "sanity skCr_SWvpXysjmfakeaMGdMecRnw$mTVURqlVABArKApL1j4SLUhFAKEEizjp7ymM8pebv0ScqyqelbLD");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "sanity %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {201, false, "unexpected status code: 201"},
        {401, false, NULL}, {403, false, NULL}, {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && out.items[0].verified == cases[i].verified && http.releases == 1);
        if (cases[i].error) CHECK(!strcmp(out.items[0].verification_error, cases[i].error));
        else CHECK(!out.items[0].verification_error);
        CHECK(!strncmp(seen_auth, "Bearer ", 7) && !strcmp(seen_auth + 7, key));
        br_results_clear(&out);
    }
    char noisy[128];
    snprintf(noisy, sizeof(noisy), "denied %s", key);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = noisy;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !strcmp(out.items[0].verification_error, noisy));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !http.calls);
    CHECK(!strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    return test_finish("Sanity");
}
