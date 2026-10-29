/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error leadfeeder_real_setter
#define br_results_push leadfeeder_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_leadfeeder_init(const br_detector **out, char **error);

static const char key[] = "AbC9dE-f0GhI1jKl2MnO3pQr4StU5vWx6Yz7aB8cD2e";
static const char other[] = "zY9xW8-vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8bA7Z6q";
static const char description[] =
    "Leadfeeder is a tool that shows you the companies visiting your website, how they found you, and what they\xe2\x80\x99re interested in. Leadfeeder API keys can be used to access and manage this data.";
static const char url[] = "https://api.leadfeeder.com/accounts";
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
    return leadfeeder_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return leadfeeder_real_push(out, owned);
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 329, expected, "key");
    CHECK(result->raw.len == 43 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 43);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 44 && sizeof(other) == 44);
    CHECK(br_leadfeeder_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Leadfeeder detector output"));
    free(error);
    error = NULL;
    CHECK(br_leadfeeder_init(NULL, NULL) == -1);
    CHECK(br_leadfeeder_init(&d, &error) == 0 && d && !error);
    CHECK(br_leadfeeder_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 329 && d->version == 0 && !strcmp(d->name, "Leadfeeder") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(strstr(d->description, "they\xe2\x80\x99re") != NULL);
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "leadfeeder"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const char *text)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, text, strlen(text));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[256];
    int n = snprintf(input, sizeof(input), "leadfeeder %s", key);
    br_results out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1 && !http.calls && !http.releases);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "lEaDfEeDeR\n%s", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    memcpy(input, "leadfeeder", 10);
    memset(input + 10, '.', 40);
    memcpy(input + 50, key, 43);
    input[93] = '\0';
    out = test_scan(d, &ctx, false, input, 93);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    memset(input + 10, '.', 41);
    memcpy(input + 51, key, 43);
    input[94] = '\0';
    out = test_scan(d, &ctx, false, input, 94);
    CHECK(!out.len);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "leadfeeder%s", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "%s leadfeeder", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);

    char short_key[43];
    memcpy(short_key, key, 42);
    short_key[42] = '\0';
    n = snprintf(input, sizeof(input), "leadfeeder %s", short_key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "leadfeeder %sx", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "leadfeeder %s=", short_key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "leadfeeder %s\nLEADFEEDER %s", key, other);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "leadfeeder %s leadfeeder %s", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], key, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    CHECK(out.items[0].secret_parts != out.items[1].secret_parts);
    br_results_clear(&out);

    /* One consumed keyword is not a uniqueness map: the second copy is out of range. */
    n = snprintf(input, sizeof(input), "leadfeeder token = '%s' | '%s'", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    expect_none(d, "leadfeeder");
    expect_none(d, key);
    CHECK(!http.calls && !http.releases);
}

typedef struct {
    const char *key;
    bool pair;
    char expected_auth[56];
    const char *borrowed_url, *borrowed_auth;
    int status, send_rc;
    const char *send_error, *body_error;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = s->pair ? (http->calls == 1 ? key : other) : s->key;
    char expected[56];
    CHECK(ctx && http->calls == http->releases + 1 && want);
    CHECK(snprintf(expected, sizeof(expected), "Token token=%s", want) == 55);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 329);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, expected));
    CHECK(strncmp(request->headers[0].value, "Bearer ", 7) != 0);
    CHECK(strncmp(request->headers[0].value, "Basic ", 6) != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog leadfeeder-offline"));
    memcpy(s->expected_auth, expected, sizeof(expected));
    s->borrowed_url = request->url;
    s->borrowed_auth = request->headers[0].value;
    static const unsigned char body[] = {0xff, 0, '{'};
    http->response = (br_http_response){
        .status = s->status,
        .body = {body, sizeof(body)},
        .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(!strcmp(s->borrowed_url, url));
        CHECK(!strcmp(s->borrowed_auth, s->expected_auth));
        s->borrowed_url = s->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_results verify_one(const br_detector *d, script *s, const br_scan_ctx *ctx)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "leadfeeder %s", s->key);
    CHECK(n == 54);
    return test_scan(d, ctx, true, input, (size_t)n);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.key = key, .status = 200};
    CHECK(snprintf(s.expected_auth, sizeof(s.expected_auth), "Token token=%s", key) == 55);
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "leadfeeder-offline"};
    const int statuses[] = {199, 200, 204, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i];
        s.body_error = i % 2 ? "ignored read failure" : NULL;
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        br_results out = verify_one(d, &s, &ctx);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }

    s.status = 200;
    s.send_rc = -1;
    s.send_error = "cannot create Leadfeeder finding";
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = verify_one(d, &s, &ctx);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    s.send_error = key;
    http.calls = http.releases = 0;
    out = verify_one(d, &s, &ctx);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    s.send_rc = 0;
    s.send_error = NULL;
    s.body_error = NULL;
    s.status = 200;
    http.calls = http.releases = 0;
    out = test_scan(d, NULL, true, "leadfeeder AbC9dE-f0GhI1jKl2MnO3pQr4StU5vWx6Yz7aB8cD2e", 54);
    CHECK(!out.len && !out.items && !http.calls && !http.releases);
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "leadfeeder-offline", .cancelled = cancelled};
    http.calls = http.releases = 0;
    out = verify_one(d, &s, &stopped);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !s.borrowed_auth);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    char input[160];
    int n = snprintf(input, sizeof(input), "leadfeeder %s leadfeeder %s", key, other);
    http.calls = http.releases = 0;
    s.pair = true;
    s.send_rc = 1;
    s.send_error = "context deadline exceeded";
    s.status = 200;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
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

    char input[160];
    int n = snprintf(input, sizeof(input), "leadfeeder %s leadfeeder %s", key, other);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.pair = true, .status = 200};
    test_http http = {.inspect = inspect, .user = &s, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "leadfeeder-offline"};
    char *error = NULL;

    fail_key_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Leadfeeder finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_push_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Leadfeeder finding") && !fail_push_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_auth);
    prior_unchanged(&out, &prior);

    fail_push_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
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
    return test_finish("Leadfeeder");
}
