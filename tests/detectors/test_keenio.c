/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

extern int br_keenio_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings and HTTP stay linked. */
#define br_results_push keenio_real_push
#define br_result_set_verification_error keenio_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls;
static bool fail_next_malloc, arm_request;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "key") && arm_request) {
        arm_request = false;
        fail_next_malloc = true;
    }
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return keenio_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return keenio_real_setter(result, cause, secrets, count);
}

static char key[65], other_key[65], id[25], other_id[25];
typedef struct {
    const char *const *keys;
    const char *const *ids;
    size_t count;
} expected_requests;

static void upper_secret(char *out, size_t len, size_t shift)
{
    test_secret(out, len, shift);
    for (size_t i = 0; i < len; ++i)
        if (out[i] >= 'a' && out[i] <= 'z') out[i] = (char)(out[i] - 'a' + 'A');
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_keenio_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 140 && detector->version == 0);
    CHECK(!strcmp(detector->name, "KeenIO") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "KeenIO is an analytics platform that allows you to collect, analyze, and visualize event data. KeenIO API keys can be used to access and manage this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "keen"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *state = detector->state;
    CHECK(br_keenio_init(&again, &error) == 0 && !error && again == detector && again->state == state);
    CHECK(br_keenio_init(&again, NULL) == 0 && again == detector);
    CHECK(br_keenio_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_keenio_init(NULL, NULL) != 0);
    return detector;
}

static void expect_keys(const br_detector *detector, const void *input, size_t len,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 140, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        CHECK(!strstr((const char *)results.items[i].raw.data, id));
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[512], changed[65];
    const char *one[] = {key};
    const char *pair[] = {key, key};
    const char *product[] = {key, key, other_key, other_key};
    snprintf(input, sizeof(input), "keen %s\nkeen %s", key, id);
    expect_keys(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "KEEN %s keen %s\nkeen %s", key, id, other_id);
    expect_keys(detector, input, strlen(input), pair, 2);
    snprintf(input, sizeof(input), "keen %s\nkeen %s\nkeen %s\nkeen %s",
             key, other_key, id, other_id);
    expect_keys(detector, input, strlen(input), product, 4);
    snprintf(input, sizeof(input), "keen %s\nkeen %s\nkeen %s", key, id, id);
    expect_keys(detector, input, strlen(input), pair, 2);
    snprintf(input, sizeof(input), "keen %s", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "keen %s", id);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "%s %s", key, id);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "keen%s keen%s", key, id);
    expect_keys(detector, input, strlen(input), NULL, 0);
    expect_keys(detector, NULL, 0, NULL, 0);

    char gap[160];
    memcpy(gap, "keen", 4);
    memset(gap + 4, '.', 40);
    memcpy(gap + 44, key, 64);
    memcpy(gap + 108, "\nkeen ", 6);
    memcpy(gap + 114, id, sizeof(id));
    expect_keys(detector, gap, strlen(gap), one, 1);
    memset(gap + 4, '.', 41);
    memcpy(gap + 45, key, 64);
    memcpy(gap + 109, "\nkeen ", 6);
    memcpy(gap + 115, id, sizeof(id));
    expect_keys(detector, gap, strlen(gap), NULL, 0);

    memcpy(changed, key, sizeof(changed));
    changed[3] = 'a';
    snprintf(input, sizeof(input), "keen %s\nkeen %s", changed, id);
    expect_keys(detector, input, strlen(input), NULL, 0);
    memcpy(changed, id, 24);
    changed[2] = 'A';
    changed[24] = '\0';
    snprintf(input, sizeof(input), "keen %s\nkeen %s", key, changed);
    expect_keys(detector, input, strlen(input), NULL, 0);

    char far[1400];
    size_t at = 0;
    memcpy(far + at, "keen ", 5); at += 5;
    memcpy(far + at, key, 64); at += 64;
    memset(far + at, '.', 1100); at += 1100;
    memcpy(far + at, " keen ", 6); at += 6;
    memcpy(far + at, id, sizeof(id));
    expect_keys(detector, far, strlen(far), one, 1);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    size_t index = http->calls - 1;
    const char *expected_key = expected->keys[index];
    const char *expected_id = expected->ids[index];
    char url[96];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(snprintf(url, sizeof(url), "https://api.keen.io/3.0/organizations/%s/projects",
                   expected_id) > 0);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, url));
    CHECK(!strstr(request->url, expected_key));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 140);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, expected_key));
    CHECK(strncmp(request->headers[1].value, "Bearer ", 7) != 0);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value,
                  ctx->user_agent ? "TruffleHog keenio-test" : "TruffleHog"));
}

static void test_verification(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "keen %s\nkeen %s", key, id);
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
    const char *ids[] = {id};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {keys, ids, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "keenio-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 140, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    const char *pair_keys[] = {key, key};
    const char *pair_ids[] = {id, other_id};
    expected_requests expected = {pair_keys, pair_ids, 2};
    test_http http = {.response = {.status = 201}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "keen %s\nkeen %s\nkeen %s", key, id, other_id);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        test_key_result(&results.items[i], 140, key, "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http = (test_http){0};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && !http.calls && !http.releases);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == 0 && !error);
    CHECK(results.len == 2 && !http.calls && !http.releases);
    CHECK(!results.items[0].verified);
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
    const char *none = "keen";
    br_slice empty = {(const unsigned char *)none, strlen(none)};
    for (int capture = 0; capture < 2; ++capture) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {0};
        fail_size = 2 * sizeof(br_span);
        fail_after = (size_t)capture + 1; /* 1 is the key FindAll; 2 is the id FindAll. */
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, empty, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory iterating regex"));
        CHECK(!fail_after);
        CHECK(!http.calls && !http.releases);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    char input[160];
    snprintf(input, sizeof(input), "keen %s\nkeen %s", key, id);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory creating KeenIO result",
        "out of memory creating KeenIO request",
    };
    for (int mode = 0; mode < 2; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        if (mode == 0) fail_part_after = 1;
        else arm_request = true;
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, messages[mode]));
        CHECK(!fail_part_after && !fail_next_malloc && !arm_request);
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
    const char *ids[] = {id};
    expected_requests expected = {keys, ids, 1};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

int main(void)
{
    upper_secret(key, 64, 0);
    upper_secret(other_key, 64, 3);
    test_secret(id, 24, 1);
    test_secret(other_id, 24, 7);
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("KeenIO");
}
