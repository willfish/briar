/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_websitepulse_init(const br_detector **out, char **error);

static char key[33], id[9];

static void result_is(const br_result *result, bool verified)
{
    test_key_result(result, 870, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) key[i] = hex[i % 16];
    key[32] = '\0';
    memcpy(id, "user.name", 9);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_websitepulse_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_websitepulse_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_websitepulse_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 870 && !strcmp(detector->name, "Websitepulse"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "websitepulse"));
    CHECK(!strcmp(detector->description,
                  "Websitepulse is a web-based service that monitors websites and servers. The keys and IDs can be used to access and manage monitoring configurations."));
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "websitepulse %s %s", id, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "websitepulse %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "websitepulse abc");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "websitepulse %s %s", id, key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.websitepulse.com/textserver.php?method=GetContacts&username=%s&key=%s", id, key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 870);
    CHECK(!request->body.len);
    (void)http;
}

static br_results once(const br_detector *detector, int status, const char *body, const char *read_error, int send_rc)
{
    test_http http = {.response = {.status = status, .body_error = read_error}, .send_rc = send_rc, .inspect = inspect};
    if (body) http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    if (send_rc) http.send_error = "synthetic transport failure";
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pulse-test"};
    char input[64];
    snprintf(input, sizeof(input), "websitepulse %s %s", id, key);
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    return out;
}

static void verification(const br_detector *detector)
{
    br_results out = once(detector, 500, "xActive", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], true);
    br_results_clear(&out);
    out = once(detector, 200, "active", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
    out = once(detector, 200, "Active", "synthetic read failure", 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "Active", NULL, 1);
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Websitepulse");
}
