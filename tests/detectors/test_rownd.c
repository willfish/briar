/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_rownd_init(const br_detector **out, char **error);

static const char *key = "rvhpdb59-6ni1-60q3-jqng-orz5edgkq333";
static const char *secret = "uuzywot3x1nlfeogbyft1r9ojb234smw0fnmn7s8kj1s1cc1";
static const char *id = "174079606475951818";

typedef struct { const char *id, *key, *secret; } expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *want = http->user;
    char url[96];
    snprintf(url, sizeof(url), "https://api.rownd.io/applications/%s/users/data", want->id);
    CHECK(ctx && request && !strcmp(request->url, url) && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 673);
    CHECK(!request->body.data && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "x-rownd-app-key"));
    CHECK(!strcmp(request->headers[0].value, want->key));
    CHECK(!strcmp(request->headers[1].name, "x-rownd-app-secret"));
    CHECK(!strcmp(request->headers[1].value, want->secret));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
}

static void expect_pair(const br_result *result, const char *want_key, const char *want_secret)
{
    char raw_v2[128];
    snprintf(raw_v2, sizeof(raw_v2), "%s%s", want_key, want_secret);
    CHECK(result->detector_type == 673);
    CHECK(result->raw.len == strlen(want_key) && !memcmp(result->raw.data, want_key, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    CHECK(!result->redacted && !result->extra_data);
    br_json *value = NULL;
    CHECK(json_object_object_length(result->secret_parts) == 2);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(!strcmp(json_object_get_string(value), want_key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &value));
    CHECK(!strcmp(json_object_get_string(value), want_secret));
    CHECK(!json_object_object_get_ex(result->secret_parts, "id", &value));
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_rownd_init(&detector, &error) == 0 && !error && detector && detector->type == 673);
    CHECK(!strcmp(detector->name, "Rownd") && !strcmp(detector->keywords[0], "rownd") &&
          detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Rownd is a platform for user data management. Rownd credentials can be used to access and modify user data and application settings."));
    CHECK(br_rownd_init(NULL, &error) != 0 && error);
    free(error);

    char input[512];
    snprintf(input, sizeof(input), "rownd token - '%s'\nrownd token - '%s'\nrownd token - '%s'\n", key, secret, id);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    expect_pair(&results.items[0], key, secret);
    CHECK(!results.items[0].verified);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "rownd token - '%s'\nrownd token - '%s'\nrownd token - '%s'\n",
             "rvhpdb59?6ni1-60q3-jqng-orz5edgkq333",
             "uuzywot3x1nlfeogbyft1r9o?b234smw0fnmn7s8kj1s1cc1", "17?079606475951818");
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "rownd%*s%s\nrownd %s\nrownd %s", 41, "", id, key, secret);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "ROWND %s\nrownd %s\nrownd %s", key, secret, id);
    expected want = {id, key, secret};
    http.inspect = inspect;
    http.user = &want;
    http.response.status = 204;
    ctx.user_agent = "rownd-test";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    expect_pair(&results.items[0], key, secret);
    br_results_clear(&results);

    const int bad[] = {199, 300, 401, 500};
    for (size_t i = 0; i < 4; ++i) {
        http.calls = http.releases = 0;
        http.response.status = bad[i];
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    http.send_rc = -1;
    http.send_error = "context canceled";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);

    br_results skipped = {0};
    char *nil_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &skipped, &nil_error) == 0 && !nil_error && !skipped.len);

    snprintf(input, sizeof(input), "rownd %s\nrownd %s\nrownd %s\nrownd %s", id, "174079606475951819", key, secret);
    http.inspect = NULL;
    http.send_rc = 0;
    http.send_error = NULL;
    http.calls = http.releases = 0;
    http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2);
    expect_pair(&results.items[0], key, secret);
    expect_pair(&results.items[1], key, secret);
    br_results_clear(&results);
    return test_finish("Rownd");
}
