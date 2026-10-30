/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_paypaloauth_init(const br_detector **out, char **error);

static char id_long[81], id_short[45], key50[51];
static const char url[] = "https://api-m.sandbox.paypal.com/v1/oauth2/token";
static const char grant[] = "grant_type=client_credentials";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls;
static size_t alloc_self, alloc_other;
static bool fail_growth;
static size_t self_auth_size, other_auth_size;

static size_t basic_size(size_t id_len, size_t key_len)
{
    size_t total = id_len + 1 + key_len;
    size_t groups = total / 3 + (total % 3 != 0);
    return 7 + groups * 4;
}

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error paypal_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == self_auth_size) ++alloc_self;
    if (n == other_auth_size) ++alloc_other;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    (void)result; (void)cause; (void)secrets; (void)count;
    ++setter_calls;
    return paypal_real_setter(result, cause, secrets, count);
}

static void fill_id(char *out, size_t left, size_t right, char a, char b)
{
    memset(out, a, left);
    out[left] = '-';
    memset(out + left + 1, b, right);
    out[left + 1 + right] = '\0';
    CHECK(strlen(out) == left + 1 + right);
}

static char *basic_of(const char *id, const char *secret)
{
    char *out = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                             (br_slice){(const unsigned char *)secret, strlen(secret)},
                             &out, &error) == 0 && out && !error);
    CHECK(!strncmp(out, "Basic ", 6));
    return out;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    br_results empty = {0};
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_paypaloauth_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_paypaloauth_init(NULL, NULL) == -1);
    CHECK(br_paypaloauth_init(&d, &error) == 0 && d && !error);
    CHECK(br_paypaloauth_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 31 && d->version == 0 && !strcmp(d->name, "PaypalOauth"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PaypalOauth is used for authenticating with PayPal's API. These credentials can be used to access and perform transactions on behalf of a PayPal account."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "paypal"));
    CHECK(strcmp(d->keywords[0], "paypaloauth"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &empty, &error) == -1 && error);
    free(error);
    br_results_clear(&empty);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 31, key, "key");
    CHECK(r->raw.len == strlen(key) && r->verified == verified);
    CHECK(!r->extra_data && !r->raw_v2.data && !r->verification_error);
}

static void expect_raw(const br_detector *d, const void *text, size_t n,
                       const char *const *raws, size_t count)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count && !setter_calls);
    for (size_t i = 0; i < count; ++i) {
        check_result(&r.items[i], raws[i], false);
        if (i) CHECK(r.items[i].raw.data != r.items[0].raw.data);
    }
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[400], bad[90], far[1300];
    const char *self[] = {id_long};
    expect_raw(d, id_long, 80, self, 1);
    const char *short_self[] = {id_short};
    expect_raw(d, id_short, 44, short_self, 1);
    expect_raw(d, key50, 50, NULL, 0);
    int n = snprintf(input, sizeof(input), "%s %s", id_short, key50);
    CHECK(n > 0);
    const char *pair[] = {id_short, key50};
    expect_raw(d, input, (size_t)n, pair, 2);
    n = snprintf(input, sizeof(input), "%s %s %s", id_long, id_short, key50);
    CHECK(n > 0);
    const char *product[] = {id_long, id_short, key50, id_long, id_short, key50};
    expect_raw(d, input, (size_t)n, product, 6);
    n = snprintf(input, sizeof(input), "%s %s", id_short, id_short);
    CHECK(n > 0);
    const char *dups[] = {id_short, id_short, id_short, id_short};
    expect_raw(d, input, (size_t)n, dups, 4);
    memcpy(far, id_short, 44);
    memset(far + 44, '.', 1100);
    memcpy(far + 1144, key50, 50);
    expect_raw(d, far, 1194, pair, 2);
    memset(bad, 'g', 81); bad[81] = '\0';
    expect_raw(d, bad, 81, NULL, 0);
    memset(bad, 'g', 43); bad[43] = '\0';
    expect_raw(d, bad, 43, NULL, 0);
    memset(bad, 'h', 6);
    bad[6] = '-';
    memset(bad + 7, 'i', 38);
    bad[45] = '\0';
    expect_raw(d, bad, 45, NULL, 0);
    bad[0] = 'x';
    memcpy(bad + 1, id_short, 44);
    bad[45] = '\0';
    expect_raw(d, bad, 45, NULL, 0);
    expect_raw(d, "paypal", 6, NULL, 0);
    expect_raw(d, NULL, 0, NULL, 0);
}

typedef struct {
    const char *const *keys;
    const char *const *bearers;
    size_t count;
    const char *live[3];
    br_header markers[3];
    int statuses[3];
    const char *body_errors[3];
    int send_rc[3];
    size_t released_ids[3];
    size_t release_lengths[3];
    size_t sends_at_release[3];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != request->headers[3].value && !strcmp(e->live[i], e->bearers[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "POST") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 31);
    CHECK(request->body.data && request->body.len == sizeof(grant) - 1);
    CHECK(!memcmp(request->body.data, grant, sizeof(grant) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 5);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Accept-Language"));
    CHECK(!strcmp(request->headers[1].value, "en_US"));
    CHECK(!strcmp(request->headers[2].name, "Content-Type"));
    CHECK(!strcmp(request->headers[2].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[3].name, "Authorization"));
    CHECK(!strcmp(request->headers[3].value, e->bearers[at]));
    CHECK(strncmp(request->headers[3].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[4].name, "User-Agent"));
    CHECK(!strcmp(request->headers[4].value, "TruffleHog paypal-offline"));
    e->live[at] = request->headers[3].value;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_rc[at] ? "synthetic send error" : NULL;
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->bearers[id]));
        e->live[id] = NULL;
        e->released_ids[http->releases] = id;
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = http->calls;
    } else {
        CHECK(response && !response->headers && e->out);
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = 0;
    }
    test_http_release(user, response);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].verified && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static br_results scan_ok(const br_detector *d, const br_scan_ctx *ctx, const void *data,
                          size_t n, expected *e)
{
    br_results out = {0};
    e->out = &out;
    char *error = NULL;
    int rc = d->scan(d, ctx, true, (br_slice){data, n}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error && !setter_calls);
    return out;
}

static void verification(const br_detector *d)
{
    char *self = basic_of(id_short, id_short);
    const char *keys[] = {id_short};
    const char *bearers[] = {self};
    expected e = {.keys = keys, .bearers = bearers, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "paypal-offline"};
    e.ctx = &ctx;
    const struct { int status, rc; const char *body_error; bool verified; } cases[] = {
        {200, 0, NULL, true},
        {201, 0, "synthetic read failure", true},
        {299, 0, "", true},
        {199, 0, NULL, false},
        {300, 0, "", false},
        {401, 0, "read", false},
        {404, 0, NULL, false},
        {0, 0, NULL, false},
        {200, 4, "read", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        memset(e.live, 0, sizeof(e.live));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        br_results r = scan_ok(d, &ctx, id_short, 44, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], id_short, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));
    size_t built = alloc_self;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "paypal-offline"};
    br_results unpublished = scan_ok(d, &missing, id_short, 44, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0] && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    CHECK(alloc_self == built + 1);
    check_result(&unpublished.items[0], id_short, false);
    br_results_clear(&unpublished);
    free(self);
}

static void order_and_nil(const br_detector *d)
{
    char input[120];
    int n = snprintf(input, sizeof(input), "%s %s", id_short, key50);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char *first = basic_of(id_short, id_short);
    char *second = basic_of(id_short, key50);
    const char *keys[] = {id_short, key50};
    const char *bearers[] = {first, second};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 401}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "paypal-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live[i] && e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
    }
    check_result(&r.items[0], id_short, true);
    check_result(&r.items[1], key50, false);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    expected mixed_e = {.keys = keys, .bearers = bearers, .count = 2,
                        .statuses = {200, 201}, .send_rc = {5, 0}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed_e};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "paypal-offline"};
    mixed_e.ctx = &mixed_ctx;
    setter_calls = 0;
    br_results mixed = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed_e);
    CHECK(mixed.len == 2 && mixed_http.calls == 2 && mixed_http.releases == 2 && !setter_calls);
    CHECK(mixed_e.released_ids[0] == 0 && mixed_e.release_lengths[0] == 0 && mixed_e.sends_at_release[0] == 1);
    CHECK(mixed_e.released_ids[1] == 1 && mixed_e.release_lengths[1] == 2 && mixed_e.sends_at_release[1] == 2);
    check_result(&mixed.items[0], id_short, false);
    check_result(&mixed.items[1], key50, true);
    br_results_clear(&mixed);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases;
    size_t self_before = alloc_self, other_before = alloc_other;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(alloc_self == self_before + 1 && alloc_other == other_before + 1);
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);

    fail_size = self_auth_size;
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    free(error);
    free(first);
    free(second);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[120];
    int n = snprintf(input, sizeof(input), "%s %s", id_short, key50);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char *first = basic_of(id_short, id_short);
    char *second = basic_of(id_short, key50);
    const char *keys[] = {id_short, key50};
    const char *bearers[] = {first, second};
    expected e = {.keys = keys, .bearers = bearers, .count = 2, .statuses = {200, 201}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "paypal-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    e.out = &out;
    char *error = NULL;
    setter_calls = 0;

    fail_size = 45; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create PaypalOauth result"));
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append PaypalOauth result"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain PaypalOauth response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    free(first);
    free(second);
    br_results_clear(&out);
}

int main(void)
{
    fill_id(id_long, 7, 72, 'A', 'b');
    id_long[8] = '.';
    id_long[9] = '_';
    fill_id(id_short, 5, 38, 'C', 'd');
    memset(key50, 'e', 50);
    key50[2] = '-';
    key50[3] = '_';
    key50[4] = '.';
    key50[50] = '\0';
    self_auth_size = basic_size(44, 44);
    other_auth_size = basic_size(44, 50);
    CHECK(self_auth_size != other_auth_size);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    order_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !setter_calls);
    return test_finish("PaypalOauth");
}
