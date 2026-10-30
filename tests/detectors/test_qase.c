/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_qase_init(const br_detector **, char **);

static char key[41], other[41];
static const char *fail_copy;

char *strdup(const char *s)
{
    if (fail_copy && !strcmp(s, fail_copy)) return NULL;
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

static void fill(char *out, size_t shift)
{
    const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (size_t i = 0; i < 40; ++i) out[i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    out[40] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.qase.io/v1/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 761);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Token") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
}

static void exercise(const br_detector *detector)
{
    char input[256];
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "qase %s qase %s", key, key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    test_key_result(&out.items[0], 761, key, "key");
    br_results_clear(&out);
    char gap[48];
    memset(gap, ' ', 41); gap[41] = 0;
    snprintf(input, sizeof(input), "qase%s%s", gap, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "qase %s", key);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && out.items[0].verified == cases[i].verified);
        if (cases[i].cause) CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].cause));
        else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.send_rc = 1; http.send_error = "dial failed"; http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "dial failed"));
    br_results_clear(&out);
    http.send_rc = 0; http.send_error = NULL; http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    http.response = (br_http_response){.status = 503};
    br_result prior = {0};
    char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&out, &prior));
    unsigned char *saved = out.items[0].raw.data;
    fail_copy = "unexpected status code: 503";
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error);
    fail_copy = NULL;
    CHECK(rc == -1 && error && out.len == 1 && out.items[0].raw.data == saved);
    free(error);
    br_results_clear(&out);
    (void)other;
}

int main(void)
{
    fill(key, 1);
    fill(other, 4);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_qase_init(&detector, &error) == 0 && detector && detector->type == 761 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->keywords[0], "qase") && detector->max_credential_span == -1);
    exercise(detector);
    return test_finish("Qase");
}
