/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Factory is not in the shared detector header yet. */
extern int br_knapsackpro_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings and HTTP stay linked. */
#define br_results_push knapsackpro_real_push
#define br_result_set_verification_error knapsackpro_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return knapsackpro_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return knapsackpro_real_setter(result, cause, secrets, count);
}

static char key[33], other_key[33];
typedef struct { const char *const *keys; size_t count; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_knapsackpro_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 760 && detector->version == 0);
    CHECK(!strcmp(detector->name, "KnapsackPro") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "KnapsackPro is a tool for optimal test suite parallelization. Its tokens "
        "can be used to access and manage test suite runs and configurations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "knapsackpro"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_knapsackpro_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_knapsackpro_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_knapsackpro_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_knapsackpro_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                              const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 760, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[33];
    const char *one[] = {key};
    const struct { const char *format; size_t count; } cases[] = {
        {"knapsackpro = '%s'", 1},
        {"KNAPSACKPRO: %s", 1},
        {"prefixknapsackprosuffix=%s", 1},
        {"%s", 0},
        {"%s knapsackpro", 0},
        {"knapsackpro%s", 0},
        {"knapsackpro _%s", 0},
        {"knapsackpro %s_", 0},
        {"knapsackpro %sQ", 0},
        {"knapsackpro %.31s", 0},
        {"knapsackpro\r\n%s", 1},
        {"knapsackpro \xc3\xa9%s\xc3\xa9", 1},
        {"knapsackpro %s %s", 1}, /* Second key has no keyword; not a uniqueness filter. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, other_key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, input, (size_t)len, one, cases[i].count);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    const char prefix[] = "knapsackpro";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[12] = 'Z';
    snprintf(input, sizeof(input), "knapsackpro %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    changed[12] = '-';
    snprintf(input, sizeof(input), "knapsackpro %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "knapsackpro %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    const char *ordered[] = {key, other_key, key};
    snprintf(input, sizeof(input), "knapsackpro %s\nknapsackpro %s\nknapsackpro %s",
             key, other_key, key);
    expect_extraction(detector, input, strlen(input), ordered, 3);
    snprintf(input, sizeof(input), "knapsackpro token = '%s' | '%s'", key, other_key);
    expect_extraction(detector, input, strlen(input), one, 1);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const char *expected_key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.knapsackpro.com/v1/builds?page=1"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 760);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Knapsack-Pro-Test-Suite-Token"));
    CHECK(!strcmp(request->headers[1].value, expected_key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value,
                  ctx->user_agent ? "TruffleHog knapsackpro-test" : "TruffleHog"));
}

static void test_verification(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "knapsackpro %s", key);
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'j', 's', 'o', 'n'};
    const struct {
        int status, send_rc;
        const char *body_error, *send_error;
        bool verified;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 204, .body_error = "ignored drain", .verified = true},
        {.status = 299, .verified = true},
        {.status = 199},
        {.status = 300, .body_error = "ignored"},
        {.status = 401},
        {.status = 404},
        {.status = 500},
        {.status = 200, .send_rc = 1, .send_error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1},
    };
    const char *keys[] = {key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {keys, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "knapsackpro-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 760, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    const char *ordered[] = {key, other_key, key};
    expected_requests expected = {ordered, 3};
    test_http http = {.response = {.status = 201}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "knapsackpro %s\nknapsackpro %s\nknapsackpro %s",
             key, other_key, key);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 760, ordered[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http = (test_http){0};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == 0 && !error);
    CHECK(results.len == 3 && !http.calls && !http.releases);
    CHECK(!results.items[0].verified);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static void keep_prior(br_results *results, br_result *sentinel, unsigned char **raw, char **cause)
{
    memset(sentinel, 0, sizeof(*sentinel));
    sentinel->detector_type = 12345;
    sentinel->verified = true;
    sentinel->raw.data = malloc(4);
    CHECK(sentinel->raw.data);
    memcpy(sentinel->raw.data, "keep", 4);
    sentinel->raw.len = 4;
    sentinel->verification_error = strdup("caller-owned");
    CHECK(sentinel->verification_error);
    *raw = sentinel->raw.data;
    *cause = sentinel->verification_error;
    CHECK(br_results_push(results, sentinel) == 0);
}

static void prior_unchanged(const br_results *results, unsigned char *raw, char *cause)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned"));
}

/* These fail an archived verify && !ctx return: that path never captures or
 * creates a finding, so an injected +1 cannot be observed. */
static void test_nil_context(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "knapsackpro %s", key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory iterating regex",
        "out of memory creating KnapsackPro result",
    };
    for (int mode = 0; mode < 2; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span);
            fail_after = 1;
        } else fail_part_after = 1;
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, messages[mode]));
        CHECK(!fail_after && !fail_part_after);
        CHECK(!http.calls && !http.releases);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 200}};
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other_key, 32, 9);
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("KnapsackPro");
}
