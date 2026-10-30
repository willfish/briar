/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_saucelabs_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other_key[] = "89abcdef-0123-4567-89ab-cdef01234567";
static const char host[] = "api.us-west-1.saucelabs.com";
static const char other_host[] = "api.eu-east-3.saucelabs.com";

static const char *part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, name, &value));
    return json_object_get_string(value);
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, name, &value));
    return json_object_get_string(value);
}

static void result_is(const br_result *result, const char *user, const char *secret,
                      const char *base, bool verified, const char *cause)
{
    size_t u = strlen(user), k = strlen(secret);
    CHECK(result->detector_type == 398);
    CHECK(result->raw.len == u && !memcmp(result->raw.data, user, u));
    CHECK(result->raw_v2.len == u + k && !memcmp(result->raw_v2.data, user, u));
    CHECK(!memcmp(result->raw_v2.data + u, secret, k));
    CHECK(!result->redacted && !result->structured_data);
    CHECK(json_object_object_length(result->secret_parts) == 2);
    CHECK(!strcmp(part(result, "username"), user) && !strcmp(part(result, "key"), secret));
    CHECK(json_object_object_length(result->extra_data) == 1 && !strcmp(extra(result, "Base URL"), base));
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_saucelabs_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_saucelabs_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_saucelabs_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 398 && !strcmp(detector->name, "SauceLabs"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "saucelabs"));
    CHECK(!strcmp(detector->description,
                  "A service for cross browser testing, API keys can create and access tests from potentially sensitive internal websites"));
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[512], user[72];
    snprintf(input, sizeof(input), "saucelabs alice %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], "alice", key, host, false, NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "username bob\nsaucelabs %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], "bob", key, host, false, NULL);
    result_is(&out.items[1], key, key, host, false, NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "saucelabs alice username bob %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], "alice", key, host, false, NULL);
    result_is(&out.items[1], "bob", key, host, false, NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "saucelabs %s saucelabs %s", key, other_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    const char *users[] = {key, key, other_key, other_key};
    const char *keys[] = {key, other_key, key, other_key};
    for (size_t i = 0; i < 4; ++i) result_is(&out.items[i], users[i], keys[i], host, false, NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "saucelabs alice %s %s", key, other_host);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], "alice", key, other_host, false, NULL);
    result_is(&out.items[1], ".com", key, other_host, false, NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "saucelabs alice %s %s %s", key, host, other_host);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    result_is(&out.items[0], "alice", key, host, false, NULL);
    result_is(&out.items[1], "alice", key, other_host, false, NULL);
    result_is(&out.items[2], ".com", key, host, false, NULL);
    result_is(&out.items[3], ".com", key, other_host, false, NULL);
    br_results_clear(&out);

    /* The key must stay within 40 characters of its own saucelabs prefix. */
    memset(user, 'a', 70);
    user[70] = '\0';
    snprintf(input, sizeof(input), "saucelabs alice %s username %s", key, user);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], "alice", key, host, false, NULL);
    result_is(&out.items[1], user, key, host, false, NULL);
    br_results_clear(&out);
    user[70] = 'b';
    user[71] = '\0';
    snprintf(input, sizeof(input), "saucelabs alice %s username %s", key, user);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[1].raw.len == 70 && !memcmp(out.items[1].raw.data, user, 70));
    br_results_clear(&out);
    /* A one-character label is below the username bound; the nearby key still is. */
    snprintf(input, sizeof(input), "saucelabs a %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, key, host, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "saucelabs a_b-c.d %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], "a_b-c.d", key, host, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "saucelabs alice 01234567-89AB-cdef-0123-456789abcdef");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "saucelabs alice %s api.us-west-1Xsaucelabs.com", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], "alice", key, "api.us-west-1Xsaucelabs.com", false, NULL);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char *authorization = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)"alice", 5},
                             (br_slice){(const unsigned char *)key, strlen(key)},
                             &authorization, &error) == 0 && !error);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.us-west-1.saucelabs.com/team-management/v1/teams"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 398 && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    free(authorization);
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "saucelabs alice %s", key);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], "alice", key, host, false, "net/http: nil Context");
    br_results_clear(&out);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {403, true, NULL}, {401, false, NULL},
        {500, false, "unexpected status code 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "sauce-test"};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], "alice", key, host, cases[i].verified, cases[i].cause);
        br_results_clear(&out);
    }
    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "alice failed %s", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sauce-test"};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], "alice", key, host, false, "alice failed [REDACTED]");
    br_results_clear(&out);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("SauceLabs");
}
