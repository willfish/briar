/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error lemlist_real_setter
#define br_results_push lemlist_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_lemlist_init(const br_detector **out, char **error);

static const char key[] = "24203d9f149dd02d1d944ee799cfb57e";
static const char other[] = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
static const char description[] =
    "Lemlist is an email outreach platform used for sending personalized emails. Lemlist API keys can be used to access and manage email campaigns and contacts.";
static const char url[] = "https://api.lemlist.com/api/team";
static size_t fail_size, fail_after, fail_key_after, fail_push_after, setter_calls, basic_allocations;
static bool track_basic;

void *malloc(size_t size)
{
    if (track_basic && size == 51) ++basic_allocations;
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return lemlist_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return lemlist_real_push(out, owned);
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static void expect_basic(const char *header, const char *secret)
{
    CHECK(header && !strncmp(header, "Basic ", 6) && strlen(header) == 50);
    CHECK(strncmp(header, "Bearer ", 7) != 0);
    unsigned char decoded[33];
    for (int i = 0; i < 11; ++i) {
        int a = b64_value(header[6 + i * 4]);
        int b = b64_value(header[7 + i * 4]);
        int c = b64_value(header[8 + i * 4]);
        int d = b64_value(header[9 + i * 4]);
        CHECK(a >= 0 && b >= 0 && c >= 0 && d >= 0);
        decoded[i * 3] = (unsigned char)((a << 2) | (b >> 4));
        decoded[i * 3 + 1] = (unsigned char)((b << 4) | (c >> 2));
        decoded[i * 3 + 2] = (unsigned char)((c << 6) | d);
    }
    CHECK(decoded[0] == ':' && !memcmp(decoded + 1, secret, 32));
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 841, expected, "key");
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
    CHECK(br_lemlist_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Lemlist detector output"));
    free(error);
    error = NULL;
    CHECK(br_lemlist_init(NULL, NULL) == -1);
    CHECK(br_lemlist_init(&d, &error) == 0 && d && !error);
    CHECK(br_lemlist_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 841 && d->version == 0 && !strcmp(d->name, "Lemlist") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lemlist"));
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
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[220];
    int n = snprintf(input, sizeof(input), "lemlist %s", key);
    br_results out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1 && !http.calls && !http.releases);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "LeMlIsT\n%s", key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    memcpy(input, "lemlist", 7);
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

    n = snprintf(input, sizeof(input), "lemlist%s", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%s lemlist", key);
    expect_none(d, input, (size_t)n);

    char upper[33];
    memcpy(upper, key, 33);
    upper[0] = 'A';
    n = snprintf(input, sizeof(input), "lemlist %s", upper);
    expect_none(d, input, (size_t)n);
    char short_key[32];
    memcpy(short_key, key, 31);
    short_key[31] = '\0';
    n = snprintf(input, sizeof(input), "lemlist %s", short_key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "lemlist %sx", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "lemlist %sg", short_key);
    expect_none(d, input, (size_t)n);

    n = snprintf(input, sizeof(input), "lemlist %s\nLEMLIST %s", key, other);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "lemlist %s lemlist %s", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], key, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "lemlist token = '%s' | '%s'", key, key);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    expect_none(d, "lemlist", 7);
    expect_none(d, key, 32);
    CHECK(!http.calls && !http.releases);
}

typedef struct {
    const char *key;
    bool pair;
    const char *borrowed_url, *borrowed_auth;
    int status, send_rc;
    const char *send_error, *body_error;
    br_results *published;
    const char *saved_auth[2];
    const char *saved_key[2];
    size_t nsaved, nrelease_seen, release_len[2];
    bool lifo, immediate;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = s->pair ? (http->calls == 1 ? key : other) : s->key;
    CHECK(ctx && want);
    if (s->send_rc != 0)
        CHECK(http->calls == http->releases + 1);
    if (s->lifo && s->nsaved < 2) {
        s->saved_auth[s->nsaved] = request->headers[0].value;
        s->saved_key[s->nsaved] = want;
        ++s->nsaved;
    }
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 841);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    expect_basic(request->headers[0].value, want);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog lemlist-offline"));
    s->borrowed_url = request->url;
    s->borrowed_auth = request->headers[0].value;
    s->key = want;
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
    if (s->lifo) {
        CHECK(s->nsaved > 0 && s->published && s->published->len == 2);
        --s->nsaved;
        expect_basic(s->saved_auth[s->nsaved], s->saved_key[s->nsaved]);
        if (s->nrelease_seen < 2)
            s->release_len[s->nrelease_seen++] = s->published->len;
    } else if (s->borrowed_auth) {
        CHECK(!strcmp(s->borrowed_url, url));
        expect_basic(s->borrowed_auth, s->key);
        s->borrowed_url = s->borrowed_auth = NULL;
    }
    if (s->immediate && s->published && s->nrelease_seen < 2)
        s->release_len[s->nrelease_seen++] = s->published->len;
    test_http_release(user, response);
}

static br_results verify_one(const br_detector *d, const br_scan_ctx *ctx)
{
    char input[48];
    int n = snprintf(input, sizeof(input), "lemlist %s", key);
    CHECK(n == 40);
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
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lemlist-offline"};
    track_basic = true;
    const int statuses[] = {199, 200, 204, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        size_t before = basic_allocations;
        s.status = statuses[i];
        s.body_error = i % 2 ? "ignored read failure" : NULL;
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        br_results out = verify_one(d, &ctx);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
        CHECK(basic_allocations == before + 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }

    s.status = 200;
    s.send_rc = 1;
    s.send_error = "out of memory constructing Basic authentication";
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = verify_one(d, &ctx);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    s.send_rc = 0;
    s.send_error = NULL;
    s.body_error = NULL;
    size_t before = basic_allocations;
    http.calls = http.releases = 0;
    out = test_scan(d, NULL, true, "lemlist 24203d9f149dd02d1d944ee799cfb57e", 40);
    CHECK(!out.len && !http.calls && !http.releases && basic_allocations == before + 1);
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "lemlist-offline", .cancelled = cancelled};
    before = basic_allocations;
    http.calls = http.releases = 0;
    out = verify_one(d, &stopped);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && basic_allocations == before + 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    char input[96];
    int n = snprintf(input, sizeof(input), "lemlist %s lemlist %s", key, other);
    s.pair = true;
    s.send_rc = -1;
    s.send_error = key;
    s.status = 200;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_auth);
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

    char input[96];
    int n = snprintf(input, sizeof(input), "lemlist %s lemlist %s", key, other);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.pair = true, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lemlist-offline"};
    char *error = NULL;

    fail_key_after = 1;
    size_t before = basic_allocations;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Lemlist finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before);
    prior_unchanged(&out, &prior);

    fail_size = 51;
    fail_after = 1;
    before = basic_allocations;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before + 1);
    prior_unchanged(&out, &prior);

    fail_size = 51;
    fail_after = 2;
    before = basic_allocations;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
    CHECK(basic_allocations == before + 2);
    prior_unchanged(&out, &prior);

    fail_push_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
    CHECK(!setter_calls && !fail_after && !fail_key_after && !fail_push_after);
}

static void source_order(const br_detector *d)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "lemlist %s lemlist %s", key, other);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    track_basic = true;
    size_t before = basic_allocations;
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 2 && basic_allocations == before);
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    before = basic_allocations;
    fail_size = 51;
    fail_after = 1;
    char *error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    CHECK(basic_allocations == before + 1);
    prior_unchanged(&out, &prior);
    free(error);
    error = NULL;

    script s = {.pair = true, .status = 200, .send_rc = -1, .send_error = "transport", .immediate = true, .published = &out};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "lemlist-offline"};
    br_results sent = {0};
    s.published = &sent;
    CHECK(d->scan(d, &ctx, true, data, &sent, &error) == 0 && !error);
    CHECK(sent.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(s.nrelease_seen == 2 && s.release_len[0] == 0 && s.release_len[1] == 1);
    result_is(&sent.items[0], key, false);
    result_is(&sent.items[1], other, false);
    br_results_clear(&sent);

    s = (script){.pair = true, .status = 204, .lifo = true};
    http.user = &s;
    http.calls = http.releases = 0;
    br_results published = {0};
    s.published = &published;
    CHECK(d->scan(d, &ctx, true, data, &published, &error) == 0 && !error);
    CHECK(published.len == 2 && http.calls == 2 && http.releases == 2 && !s.nsaved);
    CHECK(s.nrelease_seen == 2 && s.release_len[0] == 2 && s.release_len[1] == 2);
    result_is(&published.items[0], key, true);
    result_is(&published.items[1], other, true);
    br_results_clear(&published);

    s = (script){.key = key, .status = 200};
    http.user = &s;
    http.calls = http.releases = 0;
    fail_push_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Lemlist finding") && !fail_push_after);
    CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
    prior_unchanged(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    source_order(d);
    return test_finish("Lemlist");
}
