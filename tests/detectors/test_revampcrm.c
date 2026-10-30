/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_revampcrm_init(const br_detector **out, char **error);

static char token[41];
static const char id[] = "abcdefghijklmnopqrstuvwxyzab";
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.revampcrm.com/api/1.0/User/WhoAmI"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 2);
    char *expected = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                             (br_slice){(const unsigned char *)token, 40}, &expected, NULL) == 0);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    free(expected);
    CHECK(auth);
}

int main(void)
{
    test_secret(token, 40, 4);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_revampcrm_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 299 && !strcmp(detector->name, "RevampCRM") && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "revampcrm"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[160];
    snprintf(input, sizeof(input), "revamp %s %s", id, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 299, token, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "crm %s %s", id, token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "revamp %s %s", id, token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("revampcrm");
}
