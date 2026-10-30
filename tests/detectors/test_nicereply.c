/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error nicereply_real_setter
#define br_results_push nicereply_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_nicereply_init(const br_detector **out, char **error);

static int seam_basic(br_slice, br_slice, char **, char **);
static int seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static int (*real_basic)(br_slice, br_slice, char **, char **) = br_http_basic_auth;
static int (*real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *, char **) = br_http_send;
#define br_http_basic_auth seam_basic
#define br_http_send seam_send
#define br_nicereply_init observed_nicereply_init
#include "../../src/detectors/nicereply.c"
#undef br_http_basic_auth
#undef br_http_send
#undef br_nicereply_init

static const char key[] = "0123456789abcdef0123456789abcdef01234567";
static const char other[] = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
static const char description[] =
    "Nicereply is a customer satisfaction survey tool. Nicereply API keys can be used to access and manage survey data and user statistics.";
static const char url[] = "https://api.nicereply.com/v1/users/stats";
static size_t fail_key_after, fail_push_after, fail_basic_after, setter_calls, basic_allocations;
static bool track_basic, null_send_cause, encode_plus;
static int encode_fail_on, encode_calls;
static const char *seam_auth, *seam_url;

void *malloc(size_t size)
{
    if (track_basic && size == 63) ++basic_allocations;
    if (fail_basic_after && size == 63 && --fail_basic_after == 0) return NULL;
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
    return nicereply_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return nicereply_real_push(out, owned);
}

static void expect_basic(const char *header, const char *secret)
{
    char *owned = NULL;
    br_slice password = {(const unsigned char *)secret, 40};
    CHECK(real_basic((br_slice){0}, password, &owned, NULL) == 0 && owned);
    CHECK(header && !strcmp(header, owned));
    CHECK(!strncmp(header, "Basic ", 6) && strlen(header) == 62);
    CHECK(strncmp(header, "Bearer ", 7) != 0 && strstr(header, secret) == NULL);
    free(owned);
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 544, expected, "key");
    CHECK(result->raw.len == 40 && result->verified == verified && !result->verification_error);
    CHECK(!result->extra_data && !result->raw_v2.data && !result->redacted);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 41 && sizeof(other) == 41);
    CHECK(br_nicereply_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Nicereply detector output"));
    free(error);
    error = NULL;
    CHECK(br_nicereply_init(NULL, NULL) == -1);
    CHECK(br_nicereply_init(&d, &error) == 0 && d && !error);
    CHECK(br_nicereply_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 544 && d->version == 0 && !strcmp(d->name, "Nicereply"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nicereply"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    br_results out = test_scan(d, NULL, false, text, len);
    CHECK(!out.len && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[220];
    int n = snprintf(input, sizeof(input), "nicereply %s nicereply %s", key, key);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 2 && !setter_calls);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], key, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "NICEREPLY %s", other);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], other, false);
    br_results_clear(&out);

    memcpy(input, "nicereply", 9);
    memset(input + 9, ' ', 40);
    memcpy(input + 49, key, 40);
    out = test_scan(d, NULL, false, input, 89);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memset(input + 9, ' ', 41);
    memcpy(input + 50, key, 40);
    expect_none(d, input, 90);

    n = snprintf(input, sizeof(input), "nicereply%s", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%s nicereply", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "nicereply %sx", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "nicereply %s.", key);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "nicereply token = '%s' | '%s'", key, other);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    expect_none(d, "nicereply", 9);
    expect_none(d, key, 40);
}

typedef struct {
    const char *want, *borrowed_auth, *borrowed_url;
    int status, send_rc;
    const char *send_error, *body_error;
    bool second;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = s->second && http->calls == 2 ? other : s->want;
    CHECK(ctx && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 544);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    expect_basic(request->headers[0].value, want);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog nicereply-offline"));
    s->borrowed_url = request->url;
    s->borrowed_auth = request->headers[0].value;
    s->want = want;
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
    if (null_send_cause) {
        CHECK(seam_url && !strcmp(seam_url, url));
        expect_basic(seam_auth, key);
        seam_url = seam_auth = NULL;
    } else if (s && s->borrowed_auth) {
        CHECK(s->borrowed_url && !strcmp(s->borrowed_url, url));
        expect_basic(s->borrowed_auth, s->want);
        s->borrowed_url = s->borrowed_auth = NULL;
    }
    CHECK(!setter_calls);
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.want = key, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nicereply-offline"};
    char input[160];
    int n = snprintf(input, sizeof(input), "nicereply %s", key);
    track_basic = true;
    const int statuses[] = {199, 200, 204, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i];
        s.body_error = "ignored read failure";
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
        CHECK(!setter_calls);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }

    char rejected[80];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", key) > 0);
    s.status = 200;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    result_is(&out.items[0], key, false);
    CHECK(!out.items[0].verification_error && !strstr(rejected, "[REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "nicereply-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, input, (size_t)n);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "nicereply %s nicereply %s", key, other);
    s.second = true;
    s.status = 200;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    result_is(&out.items[0], key, true);
    result_is(&out.items[1], other, true);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    http.calls = http.releases = 0;
    size_t before = basic_allocations;
    out = test_scan(d, NULL, true, input, (size_t)n);
    CHECK(out.len == 0 && !http.calls && !http.releases && basic_allocations == before + 2 && !setter_calls);
    br_results_clear(&out);

    before = basic_allocations;
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2 && !http.calls && !http.releases && basic_allocations == before && !setter_calls);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    track_basic = false;
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verified && !out->items[0].verification_error);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char text[120];
    int n = snprintf(text, sizeof(text), "nicereply %s nicereply %s", key, other);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.want = key, .status = 200, .second = true};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nicereply-offline"};
    char *error = NULL;
    track_basic = true;
    size_t before = basic_allocations;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Nicereply finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before && !setter_calls);
    prior_unchanged(&out, &prior);

    fail_basic_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_basic_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && !setter_calls);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, (size_t)snprintf(text, sizeof(text), "nicereply %s", key)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Nicereply finding") && !fail_push_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_auth && !setter_calls);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    track_basic = false;
    br_results_clear(&out);
}

static int seam_basic(br_slice username, br_slice password, char **out, char **error)
{
    if (encode_plus || (encode_fail_on && ++encode_calls == encode_fail_on)) {
        encode_plus = false;
        if (out) *out = NULL;
        if (error) *error = NULL;
        return 1;
    }
    return real_basic(username, password, out, error);
}

static int seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                     br_http_response *response, char **error)
{
    if (!null_send_cause) return real_send(ctx, request, response, error);
    seam_url = request ? request->url : NULL;
    seam_auth = request && request->nheaders && request->headers ? request->headers[0].value : NULL;
    CHECK(request && !strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders >= 1 && request->headers && !strcmp(request->headers[0].name, "Authorization"));
    if (response) memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    return -1;
}

static void encode_and_null_send(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_nicereply_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_nicereply_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char text[120];
    int n = snprintf(text, sizeof(text), "nicereply %s", key);
    br_slice one = {(const unsigned char *)text, (size_t)n};
    script s = {.want = key, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nicereply-offline"};

    encode_plus = true;
    CHECK(observed->scan(observed, NULL, true, one, &out, &error) == -1);
    CHECK(!error && !encode_plus && !http.calls && !http.releases && !setter_calls);
    prior_unchanged(&out, &prior);

    encode_plus = true;
    http.calls = http.releases = 0;
    CHECK(observed->scan(observed, &ctx, true, one, &out, &error) == -1);
    CHECK(!error && !encode_plus && !http.calls && !http.releases && !setter_calls);
    prior_unchanged(&out, &prior);

    n = snprintf(text, sizeof(text), "nicereply %s nicereply %s", key, other);
    encode_calls = 0;
    encode_fail_on = 2;
    s.second = true;
    http.calls = http.releases = 0;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)text, (size_t)n}, &out, &error) == -1);
    CHECK(!error && encode_calls == 2 && http.calls == 1 && http.releases == 1);
    CHECK(!s.borrowed_auth && !setter_calls);
    prior_unchanged(&out, &prior);
    encode_fail_on = 0;

    null_send_cause = true;
    s.second = false;
    s.want = key;
    http.calls = http.releases = 0;
    n = snprintf(text, sizeof(text), "nicereply %s", key);
    br_results sent = test_scan(observed, &ctx, true, text, (size_t)n);
    CHECK(sent.len == 1 && !http.calls && http.releases == 1 && !seam_auth && !setter_calls);
    result_is(&sent.items[0], key, false);
    br_results_clear(&sent);
    null_send_cause = false;
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    encode_and_null_send();
    return test_finish("Nicereply");
}
