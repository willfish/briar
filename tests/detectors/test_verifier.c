/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_verifier_init(const br_detector **out, char **error);

static char key[97];
static const char email[] = "user@example.com";
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[192];
    snprintf(url, sizeof(url), "https://verifier.meetchopra.com/verify/%s?token=%s", email, key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 1);
}

int main(void)
{
    for (int i = 0; i < 96; ++i) key[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i % 36];
    key[96] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_verifier_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 373 && !strcmp(detector->name, "Verifier") && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "verifier"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[320];
    snprintf(input, sizeof(input), "verifier %s verifier %s verifier %s", email, key, email);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 373, key, "key");
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "verifier %s %s", email, key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("verifier");
}
