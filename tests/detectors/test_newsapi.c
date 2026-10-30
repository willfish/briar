/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error newsapi_real_setter
#define br_results_push newsapi_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newsapi_init(const br_detector **out, char **error);

static const char key[] = "kxbj4b6u2iazvhc8n6b3oz0j5x6nrpyy";
static const char other[] = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
static const char description[] =
    "NewsAPI provides access to news articles from various sources. NewsAPI keys can be used to query and retrieve news data.";
static const char url_prefix[] =
    "https://newsapi.org/v2/everything?q=Apple&from=2021-09-29&sortBy=popularity&apiKey=";
static size_t fail_key_after, fail_push_after, setter_calls;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return newsapi_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return newsapi_real_push(out, owned);
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 207, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 33 && sizeof(other) == 33);
    CHECK(br_newsapi_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Newsapi detector output"));
    free(error);
    error = NULL;
    CHECK(br_newsapi_init(NULL, NULL) == -1);
    CHECK(br_newsapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_newsapi_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 207 && d->version == 0 && !strcmp(d->name, "Newsapi") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "newsapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, text, len);
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[220];
    int n = snprintf(input, sizeof(input), "newsapi %s", key);
    br_results out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "NewsAPI\n%s", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "newsapi %sa", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    memcpy(input, "newsapi", 7);
    memset(input + 7, '.', 40);
    memcpy(input + 47, key, 32);
    out = test_scan(d, &ctx, false, input, 79);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memset(input + 7, '.', 41);
    memcpy(input + 48, key, 32);
    out = test_scan(d, &ctx, false, input, 80);
    CHECK(!out.len);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "newsapi%s", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "newsapi token = '%s' | '%s'", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "newsapi %s newsapi %s", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], key, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "newsapi %s\nNEWSAPI %s", key, other);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    br_results_clear(&out);

    char upper[33];
    memcpy(upper, key, 33);
    upper[0] = 'K';
    n = snprintf(input, sizeof(input), "newsapi %s", upper);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "newsapi %s", "kxbj4b6u2iazvhc8?6b3oz0j5x6nrpyy");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "newsapi %s", "kxbj4b6u2iazvhc8n6b3oz0j5x6nrpy");
    expect_none(d, input, (size_t)n);
    out = test_scan(d, NULL, false, "newsapi kxbj4b6u2iazvhc8n6b3oz0j5x6nrpyy", 40);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

typedef struct {
    const char *keys[2];
    bool pair;
    const char *borrowed_url;
    int status, send_rc;
    const char *send_error, *body_error;
} script;

static void expect_url(const char *url, const char *secret)
{
    char want[128];
    int n = snprintf(want, sizeof(want), "%s%s", url_prefix, secret);
    CHECK(n == 115 && url && !strcmp(url, want) && !strchr(url, '%'));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = s->pair ? (http->calls == 1 ? key : other) : s->keys[0];
    CHECK(ctx && http->calls == http->releases + 1 && want);
    CHECK(!strcmp(request->method, "GET"));
    expect_url(request->url, want);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 207);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog newsapi-offline"));
    s->borrowed_url = request->url;
    s->keys[http->calls - 1] = want;
    static const unsigned char body[] = {0xff, 0, '{'};
    http->response = (br_http_response){
        .status = s->status, .body = {body, sizeof(body)}, .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (s->borrowed_url) {
        expect_url(s->borrowed_url, s->keys[http->releases]);
        s->borrowed_url = NULL;
    }
    test_http_release(user, response);
}

static br_results verify_one(const br_detector *d, const br_scan_ctx *ctx)
{
    return test_scan(d, ctx, true, "newsapi kxbj4b6u2iazvhc8n6b3oz0j5x6nrpyy", 40);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.keys = {key}, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "newsapi-offline"};
    const int statuses[] = {199, 200, 204, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i];
        s.body_error = "ignored read failure";
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        br_results out = verify_one(d, &ctx);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_url);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }

    s.status = 200;
    s.send_rc = -1;
    s.send_error = "unexpected HTTP response status 500";
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = verify_one(d, &ctx);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    http.calls = http.releases = 0;
    out = test_scan(d, NULL, true, "newsapi kxbj4b6u2iazvhc8n6b3oz0j5x6nrpyy", 40);
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "newsapi-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    out = verify_one(d, &stopped);
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    char input[96];
    int n = snprintf(input, sizeof(input), "newsapi %s newsapi %s", key, other);
    s.pair = true;
    s.status = 204;
    s.body_error = "ignored read failure";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_url);
    result_is(&out.items[0], key, true);
    result_is(&out.items[1], other, true);
    br_results_clear(&out);
    CHECK(!setter_calls);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(out->items[0].verified && !strcmp(out->items[0].verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    const char *text = "newsapi kxbj4b6u2iazvhc8n6b3oz0j5x6nrpyy newsapi a1b2c3d4e5f60718293a4b5c6d7e8f90";
    br_slice data = {(const unsigned char *)text, strlen(text)};
    script s = {.keys = {key, other}, .pair = true, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "newsapi-offline"};
    char *error = NULL;

    fail_key_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Newsapi finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_push_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_url);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
    CHECK(!setter_calls && !fail_key_after && !fail_push_after);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    return test_finish("Newsapi");
}
