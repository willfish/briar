/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

int br_sentrytoken_v1_init(const br_detector **out, char **error);
int br_sentrytoken_v2_init(const br_detector **out, char **error);
int br_finding_key(br_result *result, int32_t type, const char *key, const char *part_name);

static const char token[] = "ad00eba0e2b5b057146e1b2b9373f86dbb0e712d106529111d97cb13f081de20";
static const char other[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char v2_token[] = "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";
static const char v2_other[] = "sntryu_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static const br_detector *init_one(int (*init)(const br_detector **, char **), int version,
                                   const char *const *keywords, size_t nkeywords)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 87 && detector->version == version);
    CHECK(!strcmp(detector->name, "SentryToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. "
        "Sentry tokens can be used to access and manage projects and organizations within Sentry."));
    CHECK(detector->nkeywords == nkeywords);
    for (size_t i = 0; i < nkeywords; ++i) CHECK(!strcmp(detector->keywords[i], keywords[i]));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 87, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction_v1(const br_detector *detector)
{
    char input[512];
    const char *one[] = {token};
    snprintf(input, sizeof(input), "SENTRY token = '%s'", token);
    expect_keys(detector, input, one, 1);
    expect_keys(detector, token, NULL, 0); /* Prefix is required. */
    snprintf(input, sizeof(input), "%s sentry", token);
    expect_keys(detector, input, NULL, 0);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "sentry%.*s%s", gap,
                 "-----------------------------------------", token);
        expect_keys(detector, input, one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "sentry\n%s", token);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "sentry %sX", token);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "sentry AD00eba0e2b5b057146e1b2b9373f86dbb0e712d106529111d97cb13f081de20");
    expect_keys(detector, input, NULL, 0); /* Capture is lowercase hex. */
    snprintf(input, sizeof(input), "sentry %s\nsentry %s\nsentry %s", other, token, other);
    const char *unique[] = {other, token};
    expect_keys(detector, input, unique, 2);
    snprintf(input, sizeof(input), "sentry %s", v2_token);
    expect_keys(detector, input, NULL, 0);
}

static void extraction_v2(const br_detector *detector)
{
    char input[400];
    const char *one[] = {v2_token};
    expect_keys(detector, v2_token, one, 1); /* Unprefixed. */
    snprintf(input, sizeof(input), "prefix %s suffix", v2_token);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "%sX", v2_token);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "SNTRYU_%s", token);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%s %s %s", v2_other, v2_token, v2_other);
    const char *unique[] = {v2_other, v2_token};
    expect_keys(detector, input, unique, 2);
    expect_keys(detector, token, NULL, 0);
}

typedef struct { const char *token; } expected_request;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_request *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://sentry.io/api/0/auth/validate/"));
    CHECK(request->detector_type == 87 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char authorization[96];
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected->token);
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog sentry-test"));
}

static void expect_verified(const br_detector *detector, const char *key, const char *input,
                            test_http *http, bool verified, const char *error)
{
    expected_request expected = {key};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sentry-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 87, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error &&
                     !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *input)
{
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {201, false, "unexpected HTTP response status 201"},
        {404, false, "unexpected HTTP response status 404"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body_error = "ignored drain failure"}};
        expect_verified(detector, key, input, &http, cases[i].verified, cases[i].error);
    }
    const char *bodies[] = {
        "{\"detail\":\"You do not have permission to perform this action.\"}",
        "[\"You do not have permission to perform this\",\"action.\"]",
        "{\"detail\":\"nope\"}",
        "not-json",
        "",
        "{\"detail\":\"You do not have permission to perform this action.\",\"ignored\":1e10000}",
        "{\"detail\":\"nope\",\"detail\":\"You do not have permission to perform this action.\"}",
        "{\"detail\":\"\\u0000You do not have permission to perform this action.\"}",
        "{\"detail\":{\"a\\u0000b\":\"nope\"},\"detail\":\"You do not have permission to perform this action.\"}",
        "{\"detail\":{\"a\\u0000b\":\"nope\"},\"detail\":null}",
    };
    const char *errors[] = {
        NULL, NULL, NULL, "invalid character 'o' looking for beginning of value", "EOF",
        "json: cannot unmarshal number 1e10000 into Go value of type float64", NULL, NULL, NULL, NULL,
    };
    const bool verified[] = {true, true, false, false, false, false, true, true, true, false};
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        test_http http = {.response = {.status = 403,
            .body = {(const unsigned char *)bodies[i], strlen(bodies[i])}}};
        expect_verified(detector, key, input, &http, verified[i], errors[i]);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1, .send_error = "context canceled"};
    expect_verified(detector, key, input, &http, false, "context canceled");
    char sensitive[160];
    snprintf(sensitive, sizeof(sensitive), "dial failed for %s", key);
    char redacted[160];
    snprintf(redacted, sizeof(redacted), "dial failed for [REDACTED]");
    http.send_error = sensitive;
    expect_verified(detector, key, input, &http, false, redacted);
    http.send_error = NULL;
    /* br_http_send supplies this text when the mock diagnostic is NULL. */
    expect_verified(detector, key, input, &http, false, "HTTP transport failed");

    br_results nil_results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil_results.len == 1 && !nil_results.items[0].verified);
    test_key_result(&nil_results.items[0], 87, key, "key");
    CHECK(nil_results.items[0].verification_error &&
          !strcmp(nil_results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil_results);

    br_scan_ctx offline = {0};
    br_results offline_results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(offline_results.len == 1 && !offline_results.items[0].verified);
    CHECK(offline_results.items[0].verification_error &&
          !strcmp(offline_results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&offline_results);

    const char *nul_key = "{\"a\\u0000b\":\"You do not have permission to perform this action.\"}";
    test_http nul_http = {.response = {.status = 403,
        .body = {(const unsigned char *)nul_key, strlen(nul_key)}}};
    br_transport nul_transport = test_transport(&nul_http);
    br_scan_ctx nul_ctx = {.transport = &nul_transport, .user_agent = "sentry-test"};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, &nul_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot verify SentryToken"));
    CHECK(kept.len == 1 && kept.items[0].detector_type == 9 && !kept.items[0].verified);
    free(error);
    br_results_clear(&kept);
    br_result_clear(&prior);
}

static int sentry_hook_mode;

static int sentry_hook_document(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (sentry_hook_mode == 1) return 2;
    return br_json_first_document(body, read_error, out, end, cause);
}

#define br_json_first_document sentry_hook_document
#define br_sentrytoken_v1_init sentry_hook_v1
#define br_sentrytoken_v2_init sentry_hook_v2
#include "../../src/detectors/sentrytoken.c"
#undef br_json_first_document
#undef br_sentrytoken_v1_init
#undef br_sentrytoken_v2_init

static void sentry_seam(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(sentry_hook_v1(&detector, &error) == 0 && detector && !error);
    sentry_hook_mode = 1;
    const char *text = "sentry ad00eba0e2b5b057146e1b2b9373f86dbb0e712d106529111d97cb13f081de20";
    const char *body = "{\"detail\":\"You do not have permission to perform this action.\"}";
    test_http http = {.response = {.status = 403, .body = {(const unsigned char *)body, strlen(body)}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sentry-test"};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results results = {0};
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)},
                         &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot verify SentryToken"));
    CHECK(results.len == 1 && results.items[0].detector_type == 9 && !results.items[0].verified);
    free(error);
    br_results_clear(&results);
    br_result_clear(&prior);
}

int main(void)
{
    const char *v1_keywords[] = {"sentry"};
    const char *v2_keywords[] = {"sentry", "sntryu"};
    const br_detector *v1 = init_one(br_sentrytoken_v1_init, 1, v1_keywords, 1);
    const br_detector *v2 = init_one(br_sentrytoken_v2_init, 2, v2_keywords, 2);
    extraction_v1(v1);
    extraction_v2(v2);
    char input[160];
    snprintf(input, sizeof(input), "sentry %s", token);
    verification(v1, token, input);
    verification(v2, v2_token, v2_token);
    sentry_seam();
    char *error = NULL;
    CHECK(br_sentrytoken_v1_init(NULL, &error) != 0 && error);
    free(error);
    return test_finish("sentrytoken");
}
