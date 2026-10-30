/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_newrelicpersonalapikey_init(const br_detector **out, char **error);

static const char key[] = "ABGA-4OmA485kfT9jonFpx22nzcpJWZjceM2El878Hz6G6_";
static const char other[] = "ABGA-4OmA485kfT9jonFpx22nzcpJWZjceM2El878Hz6G6Z";
static const char bad[] = "ABGA-4OmA485kfT9jonFpx?2nzcpJWZjceM2El878Hz6G6_";
static const char us_url[] = "https://api.newrelic.com/v2/users.json";
static const char eu_url[] = "https://api.eu.newrelic.com/v2/users.json";
static size_t fail_part_after;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 47 && strlen(other) == 47 && strlen(bad) == 47);
    CHECK(br_newrelicpersonalapikey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicPersonalApiKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_newrelicpersonalapikey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_newrelicpersonalapikey_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 50 && detector->version == 0);
    CHECK(!strcmp(detector->name, "NewRelicPersonalApiKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "New Relic is a software analytics and performance monitoring company. New Relic Personal API keys can be used to access and manage your New Relic account and data."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "newrelic"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 50, secret, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_nov(const br_detector *detector, const void *data, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, data, len);
    CHECK(http.calls == 0 && http.releases == 0);
    if (!expected) CHECK(out.len == 0);
    else {
        CHECK(out.len == 1);
        expect_key(&out.items[0], expected, false);
    }
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    CHECK(snprintf(input, sizeof(input), "newrelicpersonalapikey token = '%s'", key) > 0);
    expect_nov(detector, input, strlen(input), key);
    CHECK(snprintf(input, sizeof(input), "NewRelic %s", key) > 0);
    expect_nov(detector, input, strlen(input), key);
    CHECK(snprintf(input, sizeof(input), "NEWRELIC\t%s", key) > 0);
    expect_nov(detector, input, strlen(input), key);

    char gap[160];
    memcpy(gap, "newrelic", 8);
    memset(gap + 8, ' ', 40);
    memcpy(gap + 48, key, 47);
    expect_nov(detector, gap, 95, key);
    memset(gap + 8, ' ', 41);
    memcpy(gap + 49, key, 47);
    expect_nov(detector, gap, 96, NULL);

    char vt[64];
    memcpy(vt, "newrelic", 8);
    vt[8] = '\v';
    memcpy(vt + 9, key, 47);
    expect_nov(detector, vt, 56, key);

    CHECK(snprintf(input, sizeof(input), "newrelic%s", key) > 0);
    expect_nov(detector, input, strlen(input), NULL);
    CHECK(snprintf(input, sizeof(input), "%s newrelic", key) > 0);
    expect_nov(detector, input, strlen(input), NULL);
    CHECK(snprintf(input, sizeof(input), "newrelicpersonalapikey = '%s'", bad) > 0);
    expect_nov(detector, input, strlen(input), NULL);
    CHECK(snprintf(input, sizeof(input),
                   "newrelicpersonalapikey keyword is not close to the real key in the data\n = '%s'",
                   key) > 0);
    expect_nov(detector, input, strlen(input), NULL);
    expect_nov(detector, key, 47, NULL);
    expect_nov(detector, "", 0, NULL);

    char dotted[48];
    memcpy(dotted, key, 48);
    dotted[1] = '.';
    CHECK(snprintf(input, sizeof(input), "newrelic %s", dotted) > 0);
    expect_nov(detector, input, strlen(input), dotted);
    memcpy(dotted, key, 48);
    dotted[46] = '.';
    CHECK(snprintf(input, sizeof(input), "newrelic %s", dotted) > 0);
    expect_nov(detector, input, strlen(input), NULL);
}

static void duplicates(const br_detector *detector)
{
    char input[256];
    CHECK(snprintf(input, sizeof(input), "newrelicpersonalapikey token = '%s' | '%s'", key, key) > 0);
    expect_nov(detector, input, strlen(input), key);

    CHECK(snprintf(input, sizeof(input), "newrelic %s newrelic %s", key, key) > 0);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "newrelic %s newrelic %s", key, other) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], other, false);
    br_results_clear(&out);
}

typedef struct {
    const char *url, *key, *body_error, *send_error;
    int status, send_rc;
} step;
typedef struct {
    const step *steps;
    size_t count, at;
    const br_scan_ctx *ctx;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(steps->at < steps->count);
    const step *st = &steps->steps[steps->at++];
    CHECK(ctx == steps->ctx);
    CHECK(request->method && !strcmp(request->method, "GET"));
    CHECK(request->url && !strcmp(request->url, st->url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 50);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(request->headers[0].value && !strcmp(request->headers[0].value, st->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") &&
          !strcmp(request->headers[1].value, "TruffleHog"));
    http->response = (br_http_response){.status = st->status, .body_error = st->body_error};
    http->send_rc = st->send_rc;
    http->send_error = st->send_error;
}

static br_results verify_scan(const br_detector *detector, script *steps, const char *input)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    steps->at = 0;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && steps->at == steps->count);
    return out;
}

static void decisions(const br_detector *detector)
{
    char input[128];
    CHECK(snprintf(input, sizeof(input), "newrelic %s", key) > 0);
    const step us_ok[] = {
        {.url = us_url, .key = key, .status = 200, .body_error = "read failed"},
        {.url = eu_url, .key = key, .status = 500, .send_rc = 1, .send_error = "eu down"},
    };
    script steps = {.steps = us_ok, .count = 2};
    br_results out = verify_scan(detector, &steps, input);
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, true);
    br_results_clear(&out);

    const int us_plain[] = {199, 200, 299, 300, 401};
    const bool us_verified[] = {false, true, true, false, false};
    for (size_t i = 0; i < sizeof(us_plain) / sizeof(us_plain[0]); ++i) {
        const step rows[] = {
            {.url = us_url, .key = key, .status = us_plain[i]},
            {.url = eu_url, .key = key, .status = 200},
        };
        steps = (script){.steps = rows, .count = 2};
        out = verify_scan(detector, &steps, input);
        CHECK(out.len == 1);
        expect_key(&out.items[0], key, us_verified[i]);
        br_results_clear(&out);
    }

    const step eu_ok[] = {
        {.url = us_url, .key = key, .send_rc = 1, .send_error = "us down"},
        {.url = eu_url, .key = key, .status = 200, .body_error = "ignored"},
    };
    steps = (script){.steps = eu_ok, .count = 2};
    out = verify_scan(detector, &steps, input);
    expect_key(&out.items[0], key, true);
    br_results_clear(&out);

    const int eu_plain[] = {199, 299, 300};
    const bool eu_verified[] = {false, true, false};
    for (size_t i = 0; i < sizeof(eu_plain) / sizeof(eu_plain[0]); ++i) {
        const step rows[] = {
            {.url = us_url, .key = key, .send_rc = 1},
            {.url = eu_url, .key = key, .status = eu_plain[i], .body_error = "body"},
        };
        steps = (script){.steps = rows, .count = 2};
        out = verify_scan(detector, &steps, input);
        expect_key(&out.items[0], key, eu_verified[i]);
        br_results_clear(&out);
    }

    const step both[] = {
        {.url = us_url, .key = key, .send_rc = 1, .send_error = "connection refused"},
        {.url = eu_url, .key = key, .send_rc = 1, .send_error = "connection refused"},
    };
    steps = (script){.steps = both, .count = 2};
    out = verify_scan(detector, &steps, input);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "newrelic %s newrelic %s", key, other) > 0);
    const step mixed[] = {
        {.url = us_url, .key = key, .status = 200},
        {.url = eu_url, .key = key, .status = 404},
        {.url = us_url, .key = other, .send_rc = 1},
        {.url = eu_url, .key = other, .status = 500},
    };
    steps = (script){.steps = mixed, .count = 4};
    out = verify_scan(detector, &steps, input);
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, true);
    expect_key(&out.items[1], other, false);
    br_results_clear(&out);
}

static bool always_cancelled(void *user)
{
    (void)user;
    return true;
}

static void skips_and_guards(const br_detector *detector)
{
    char input[80];
    CHECK(snprintf(input, sizeof(input), "newrelic %s", key) > 0);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx live = {.transport = &transport};
    br_results out = test_scan(detector, &live, false, data.data, data.len);
    CHECK(http.calls == 0 && http.releases == 0 && out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    out = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(out.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    CHECK(out.items[0].verified && !strcmp(saved, "caller-owned"));

    br_scan_ctx missing = {0};
    CHECK(detector->scan(detector, &missing, true, data, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && !out.items[1].verified && !out.items[1].verification_error);
    expect_key(&out.items[1], key, false);
    br_results_clear(&out);

    br_scan_ctx cancelled = {.transport = &transport, .cancelled = always_cancelled};
    out = test_scan(detector, &cancelled, true, data.data, data.len);
    CHECK(http.calls == 0 && http.releases == 2 && out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    http.releases = 0;

    br_scan_ctx expired = {.transport = &transport, .deadline_monotonic_ms = 1};
    out = test_scan(detector, &expired, true, data.data, data.len);
    CHECK(http.calls == 0 && http.releases == 2 && out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(detector->scan(NULL, &live, false, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized NewRelicPersonalApiKey scan"));
    free(error);
    error = NULL;
    CHECK(detector->scan(detector, &live, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(out.len == 0);
}

static void allocation_rollback(const br_detector *detector)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "newrelic %s newrelic %s", key, other);
    CHECK(n == 113);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    size_t capacity = out.cap;
    const step rows[] = {
        {.url = us_url, .key = key, .status = 200},
        {.url = eu_url, .key = key, .status = 200},
        {.url = us_url, .key = other, .status = 200},
        {.url = eu_url, .key = other, .status = 200},
    };
    script steps = {.steps = rows, .count = 4};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicPersonalApiKey result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);
    error = NULL;

    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicPersonalApiKey result"));
    CHECK(http.calls == 2 && http.releases == 2 && steps.at == 2);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verified);
    free(error);
    error = NULL;
    http.calls = http.releases = steps.at = 0;

    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append NewRelicPersonalApiKey result"));
    CHECK(http.calls == 2 && http.releases == 2);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    out.cap = capacity;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    duplicates(detector);
    decisions(detector);
    skips_and_guards(detector);
    allocation_rollback(detector);
    return test_finish("NewRelicPersonalApiKey");
}
