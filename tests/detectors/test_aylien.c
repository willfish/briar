/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

static size_t fail_key_after;

/* Exercise the real positive metadata failure after one pair was appended. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_key_after && !strcmp(name, "key") && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

typedef struct { const char *key, *id; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aylien_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 485 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Aylien"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Aylien is a text analysis platform that provides natural language processing "
        "and machine learning APIs. Aylien API keys can be used to access and analyze text data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aylien"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_aylien_init(&again, &error) == 0 && !error && again == detector);
    CHECK(br_aylien_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void check_pair(const br_result *result, const expected_pair *pair)
{
    CHECK(result->detector_type == 485 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 32 && !memcmp(result->raw.data, pair->key, 32));
    CHECK(result->raw_v2.data && result->raw_v2.len == 40 &&
          !memcmp(result->raw_v2.data, pair->key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair->id, 8));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *id = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &id));
    CHECK(json_object_is_type(key, json_type_string) && json_object_is_type(id, json_type_string));
    CHECK(json_object_get_string_len(key) == 32 && !strcmp(json_object_get_string(key), pair->key));
    CHECK(json_object_get_string_len(id) == 8 && !strcmp(json_object_get_string(id), pair->id));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                              const void *input, size_t len, const expected_pair *pair,
                              size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pair);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], id[9], input[1536];
    /* Both synthetic captures contain letters outside the hexadecimal alphabet. */
    test_secret(key, 32, 0);
    test_secret(id, 8, 9);
    expected_pair pair = {key, id};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"aylien '%s'\naylien '%s'", 1},
        {"AYLIEN %s\nAyLiEn %s", 1},
        {"prefixayliensuffix %s\naylien %s", 1},
        {"%s\n%s", 0},
        {"aylien _%s\naylien %s", 0},
        {"aylien %s_\naylien %s", 0},
        {"aylien %sx\naylien %s", 0},
        {"aylien %.31s\naylien %s", 0},
        {"aylien G%.31s\naylien %s", 0},
        {"aylien %s\naylien _%s", 0},
        {"aylien %s\naylien %s_", 0},
        {"aylien %s\naylien %sx", 0},
        {"aylien %s\naylien %.7s", 0},
        {"aylien %s\naylien G%.7s", 0},
        {"aylien\r\n%s\naylien\r\n%s", 1},
        {"aylien %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, id);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)len, &pair, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "aylien", 6);
        memset(input + 6, '-', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s\naylien %s", key, id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "aylien %s\naylien", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
    }

    /* FindAll does not reuse one prefix to capture a second adjacent key. */
    char second[33];
    test_secret(second, 32, 13);
    snprintf(input, sizeof(input), "aylien %s %s\naylien %s", key, second, id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);

    /* The multipart span is engine metadata, not a detector-local pairing limit. */
    size_t at = (size_t)snprintf(input, sizeof(input), "aylien %s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\naylien %s", id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);

    memset(key, 'a', 32);
    memset(id, '0', 8);
    snprintf(input, sizeof(input), "aylien %s\naylien %s", key, id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.aylien.com/news/stories"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 485);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    /* Only the two provider headers and the shared User-Agent are present. */
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "X-AYLIEN-NewsAPI-Application-ID"));
    CHECK(!strcmp(request->headers[0].value, pair->id));
    CHECK(!strcmp(request->headers[1].name, "X-AYLIEN-NewsAPI-Application-Key"));
    CHECK(!strcmp(request->headers[1].value, pair->key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ?
                  "TruffleHog aylien-test" : "TruffleHog"));
}

static void test_pairing(const br_detector *detector)
{
    char first[33], second[33], first_id[9], second_id[9], input[256];
    test_secret(first, 32, 0);
    test_secret(second, 32, 11);
    test_secret(first_id, 8, 3);
    test_secret(second_id, 8, 19);
    snprintf(input, sizeof(input),
             "aylien %s\naylien %s\naylien %s\naylien %s\naylien %s\naylien %s",
             second_id, first, second, first_id, first, second_id);
    const expected_pair pairs[] = {
        {first, second_id}, {first, first_id}, {first, second_id},
        {second, second_id}, {second, first_id}, {second, second_id},
        {first, second_id}, {first, first_id}, {first, second_id},
    };
    expected_requests expected = {pairs, sizeof(pairs) / sizeof(pairs[0])};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {
            .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == expected.len);
        CHECK(http.calls == (verify ? expected.len : 0) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            check_pair(&results.items[i], &pairs[i]);
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[33], id[9], input[128], sensitive_error[128], redacted[96];
    test_secret(key, 32, 0);
    test_secret(id, 8, 9);
    snprintf(input, sizeof(input), "aylien %s\naylien %s", key, id);
    snprintf(sensitive_error, sizeof(sensitive_error), "id=%s key=%s again=%s", id, key, key);
    snprintf(redacted, sizeof(redacted), "id=%s key=[REDACTED] again=[REDACTED]", id);
    const expected_pair pair = {key, id};
    expected_requests expected = {&pair, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {302, 0, NULL, false, "unexpected status code: 302"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive_error, false, redacted},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    /* Neither body bytes nor a read error changes any status-only outcome. */
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = sensitive_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "aylien-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        check_pair(result, &pair);
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            CHECK(!strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, key));
        } else {
            CHECK(!result->verification_error);
        }
        br_results_clear(&results);
    }

    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const char *single_parts[] = {key, id};
    for (size_t i = 0; i < sizeof(single_parts) / sizeof(single_parts[0]); ++i) {
        snprintf(input, sizeof(input), "aylien %s", single_parts[i]);
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
        br_results_clear(&results);
    }
}

static void test_late_failure_rollback(const br_detector *detector)
{
    static const unsigned char input[] =
        "aylien 0123456789abcdefghijklmnopqrstuv\n"
        "aylien vutsrqponmlkjihgfedcba9876543210\n"
        "aylien q7r8s9t0";
    for (int with_prior = 0; with_prior < 2; ++with_prior) {
        for (int with_error = 0; with_error < 2; ++with_error) {
            br_results out = {0}; br_result prior = {0}; char *error = NULL;
            if (with_prior) {
                CHECK(br_finding_key(&prior, 12345, "keep", "prior") == 0);
                prior.verified = true; prior.verification_error = strdup("caller-owned");
                CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
                prior = out.items[0];
            }
            fail_key_after = 2;
            CHECK(detector->scan(detector, NULL, false, (br_slice){input, sizeof(input) - 1},
                                 &out, with_error ? &error : NULL) == -1);
            CHECK(!fail_key_after && out.len == (size_t)with_prior);
            CHECK(with_error ? error != NULL : error == NULL);
            if (with_prior) {
                CHECK(out.items[0].raw.data == prior.raw.data && out.items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
                CHECK(out.items[0].secret_parts == prior.secret_parts && out.items[0].detector_type == 12345 && out.items[0].verified);
                CHECK(out.items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
            }
            free(error); br_results_clear(&out);
        }
    }
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_pairing(detector);
    test_verification(detector);
    test_late_failure_rollback(detector);
    return test_finish("Aylien");
}
