/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_phraseaccesstoken_init(const br_detector **out, char **error);

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_phraseaccesstoken_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_phraseaccesstoken_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_phraseaccesstoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1037 && !strcmp(detector->name, "PhraseAccessToken"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
                  "Phrase is a translation management platform for software projects. Phrase API "
                  "keys can be used to access translation projects, locales, and manage translations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "phrase"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 1037, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char key[65], other[65], input[400];
    test_secret(key, 64, 0);
    test_secret(other, 64, 5);
    const char *keys[] = {key, other};
    const char *one[] = {key};
    snprintf(input, sizeof(input), "phrase token = %s", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "ACCESSTOKEN:%s", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "access_token='%s'", key);
    expect_keys(detector, input, one, 1);
    expect_keys(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "phrase%*s%s", 40, "", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "phrase%*s%s", 41, "", key);
    expect_keys(detector, input, NULL, 0);
    memcpy(input, "phrase", 6);
    size_t at = 6;
    for (size_t i = 0; i < 40; ++i) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
    memcpy(input + at, key, 64);
    input[at + 64] = 0;
    expect_keys(detector, input, one, 1);
    key[0] = 'A';
    snprintf(input, sizeof(input), "phrase %s", key);
    expect_keys(detector, input, NULL, 0);
    key[0] = 'b';
    key[8] = '-';
    snprintf(input, sizeof(input), "phrase %s", key);
    expect_keys(detector, input, NULL, 0);
    key[8] = 'd';
    snprintf(input, sizeof(input), "phrase %s\nphrase %s\naccess_token %s", key, key, other);
    expect_keys(detector, input, keys, 2); /* First-seen unique, not Go map order. */
    snprintf(input, sizeof(input), "phrase %.63s", key);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "phrase %sq", key);
    expect_keys(detector, input, NULL, 0);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.phrase.com/v2/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1037);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 2);
    char authorization[72];
    snprintf(authorization, sizeof(authorization), "token %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static void verification(const br_detector *detector)
{
    char key[65], input[160], sensitive[160];
    test_secret(key, 64, 2);
    snprintf(input, sizeof(input), "phrase %s", key);
    snprintf(sensitive, sizeof(sensitive), "dial %s: %s", key, key);
    const struct { int status, send_rc; const char *send_error, *error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true},
        {401, 0, NULL, NULL, false},
        {403, 0, NULL, NULL, false},
        {402, 0, NULL, "unexpected HTTP response status 402", false},
        {500, 0, NULL, "unexpected HTTP response status 500", false},
        {200, 1, sensitive, "dial [REDACTED]: [REDACTED]", false},
        {200, 1, NULL, "HTTP transport failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body_error = "ignored drain"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect, .user = key,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 1037, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error &&
                                  !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    CHECK(!results.items[0].verified);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "phrase %s phrase %s", key, key);
    test_http http = {.response = {.status = 200}, .inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && results.items[0].verified);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("PhraseAccessToken");
}
