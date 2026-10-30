/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_typetalk_init(const br_detector **out, char **error);

static char key[65], id[33];

static void result_is(const br_result *result, bool verified)
{
    test_key_result(result, 809, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 64, 3);
    test_secret(id, 32, 9);
    key[0] = 'A';
    id[0] = 'b';
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_typetalk_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_typetalk_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_typetalk_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 809 && !strcmp(detector->name, "Typetalk"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "typetalk"));
    CHECK(!strcmp(detector->description,
                  "Typetalk is a Japanese chat app. API keys can be used to read potentially sensitive chat messages."));
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[240];
    snprintf(input, sizeof(input), "typetalk %s %s", id, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "typetalk %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "typetalk %s %s typetalk %s %s", id, key, id, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "typetalk %s %s", id, key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[256];
    snprintf(url, sizeof(url),
             "https://typetalk.com/oauth2/access_token?client_id=%s&client_secret=%s&grant_type=client_credentials",
             id, key);
    CHECK(ctx && !strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 809);
    CHECK(!request->body.len && request->nheaders == 1);
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "typetalk %s %s", id, key);
    const int statuses[] = {200, 299, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "typetalk-test"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], statuses[i] < 300);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = 1, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Typetalk");
}
