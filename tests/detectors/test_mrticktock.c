/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_mrticktock_init(const br_detector **out, char **error);

static const char email1[] = "user+tag@example.com";
static const char email2[] = "Other@ex.io";
static const char pass1[] = "Pass!=@#$%()_^9";
static const char pass2[] = "secondPass12";
static const char url[] = "https://mrticktock.com/app/api/is_timer_active";
static const char marker[] = "\"errors\":[]";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, watched;
static size_t watch_sizes[4], watch_n;
static bool fail_growth;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#include "../../src/result.c"
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    for (size_t i = 0; i < watch_n; ++i)
        if (n == watch_sizes[i]) ++watched;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_mrticktock_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_mrticktock_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:mrticktock)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_mrticktock_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_mrticktock_init(&d, &error) == 0 && d && !error);
    CHECK(br_mrticktock_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 691 && d->version == 0 && !strcmp(d->name, "Mrticktock"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Mrticktock is a service that tracks time-based activities. These credentials can be used to access and manage timers and associated data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mrticktock"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *email, bool verified)
{
    test_key_result(r, 691, email, "key");
    CHECK(r->verified == verified && !r->verification_error && !r->extra_data);
}

static void expect_n(const br_detector *d, const void *text, size_t n, size_t count, const char *email)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], email, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[220], longpass[64];
    int n = snprintf(input, sizeof(input), "%s mrticktock %s", email1, pass1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, email1);
    n = snprintf(input, sizeof(input), "%s", email1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "mrticktock %s", pass1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "mrticktock%s", pass1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "%s %s MrTickTock %s", email1, email1, pass1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, email1);
    n = snprintf(input, sizeof(input), "%s %s mrticktock %s mrticktock %s", email2, email1, pass1, pass2);
    CHECK(n > 0);
    br_results ordered = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(ordered.len == 4);
    check_result(&ordered.items[0], email2, false);
    check_result(&ordered.items[1], email2, false);
    check_result(&ordered.items[2], email1, false);
    check_result(&ordered.items[3], email1, false);
    CHECK(ordered.items[0].raw.data != ordered.items[1].raw.data);
    br_results_clear(&ordered);
    n = snprintf(input, sizeof(input), "%s mrticktock %s mrticktock %s", email1, pass1, pass1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 2, email1);
    memset(longpass, 'c', 51);
    n = snprintf(input, sizeof(input), "%s mrticktock ", email1);
    CHECK(n > 0);
    memcpy(input + n, longpass, 51);
    expect_n(d, input, (size_t)n + 51, 1, email1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        n = snprintf(input, sizeof(input), "%s mrticktock", email1);
        CHECK(n > 0);
        memset(input + n, '.', gap);
        memcpy(input + n + gap, pass1, strlen(pass1));
        expect_n(d, input, (size_t)n + gap + strlen(pass1), gap == 40 ? 1u : 0u, email1);
    }
    char wide[1300];
    memset(wide, ' ', sizeof(wide));
    memcpy(wide, email1, strlen(email1));
    memcpy(wide + 1100, "mrticktock ", 11);
    memcpy(wide + 1111, pass1, strlen(pass1));
    expect_n(d, wide, 1111 + strlen(pass1), 1, email1);
    expect_n(d, NULL, 0, 0, NULL);
}

typedef struct {
    const char *const *bodies;
    size_t count;
    const char *live[4];
    br_header markers[4];
    int statuses[4];
    br_slice responses[4];
    const char *body_errors[4];
    int send_rc[4];
    const char *send_errors[4];
    size_t released_ids[4];
    size_t release_lengths[4];
    size_t sends_at_release[4];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void expect_body(char *out, size_t n, const char *email, const char *password)
{
    int wrote = snprintf(out, n, "email=%s&password=%s", email, password);
    CHECK(wrote > 0 && (size_t)wrote < n);
    CHECK(strstr(out, email) && strstr(out, password));
    CHECK(!strstr(out, "%2B") && !strstr(out, "%2b") && !strstr(out, "%40") && !strstr(out, "%3D") && !strstr(out, "%3d"));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->body.data);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != (const char *)request->body.data && !strcmp(e->live[i], e->bodies[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "POST") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 691);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == strlen(e->bodies[at]));
    CHECK(!memcmp(request->body.data, e->bodies[at], request->body.len));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog mrticktock-offline"));
    e->live[at] = (const char *)request->body.data;
    e->markers[at] = (br_header){"synthetic-attempt", e->bodies[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body = e->responses[at], .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_errors[at];
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->bodies[id]));
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

static br_slice body_of(const char *text)
{
    return text ? (br_slice){(const unsigned char *)text, strlen(text)} : (br_slice){0};
}

static void one_input(char *input, size_t n, const char *email, const char *password)
{
    int wrote = snprintf(input, n, "%s%*s mrticktock %s", email, 50, "", password);
    CHECK(wrote > 0 && (size_t)wrote < n);
}

static br_results scan_ok(const br_detector *d, const br_scan_ctx *ctx, const void *data,
                          size_t n, expected *e)
{
    br_results out = {0};
    e->out = &out;
    char *error = NULL;
    int rc = d->scan(d, ctx, true, (br_slice){data, n}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void one_verify(const br_detector *d, test_http *http, br_scan_ctx *ctx, expected *e,
                       const char *email, const char *password, const char *form,
                       int status, int rc, const char *text, const char *body_error,
                       const char *send_error, bool kept, bool verified)
{
    char input[160];
    one_input(input, sizeof(input), email, password);
    const char *bodies[] = {form};
    e->bodies = bodies; e->count = 1;
    http->calls = http->releases = 0;
    memset(e->live, 0, sizeof(e->live));
    e->statuses[0] = status;
    e->responses[0] = body_of(text);
    e->body_errors[0] = body_error;
    e->send_rc[0] = rc;
    e->send_errors[0] = send_error;
    br_results r = scan_ok(d, ctx, input, strlen(input), e);
    CHECK(http->calls == 1 && http->releases == 1 && !e->live[0]);
    CHECK(e->sends_at_release[0] == 1 && e->released_ids[0] == 0);
    CHECK(e->release_lengths[0] == (rc == 0 && kept ? 1u : 0u));
    CHECK(r.len == (kept ? 1u : 0u));
    if (kept) check_result(&r.items[0], email, verified);
    br_results_clear(&r);
}

static void verification(const br_detector *d)
{
    char form[128], cut[128], hyphen[128], input[160];
    expect_body(form, sizeof(form), email1, pass1);
    expected e = {0};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mrticktock-offline"};
    e.ctx = &ctx;
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 200, 0, marker, NULL, NULL, true, true);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 299, 0, "xx\"errors\":[]yy", NULL, NULL, true, true);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 200, 0, "\"errors\": []", NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 200, 0, "\"Errors\":[]", NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 204, 0, "", NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 0, 0, marker, NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 401, 0, marker, NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 199, 0, marker, NULL, NULL, true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 200, 0, marker, "", NULL, false, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 201, 0, marker, "synthetic read failure", NULL, false, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 200, 1, marker, "read", "synthetic send error", true, false);
    one_verify(d, &http, &ctx, &e, email1, pass1, form, 500, 7, marker, NULL, pass1, true, false);
    char fifty[51];
    memset(fifty, 'c', 50); fifty[50] = '\0';
    expect_body(cut, sizeof(cut), email1, fifty);
    one_verify(d, &http, &ctx, &e, email1, "ccccccccccccccccccccccccccccccccccccccccccccccccccc", cut, 200, 0, marker, NULL, NULL, true, true);
    expect_body(hyphen, sizeof(hyphen), email1, "ab");
    one_verify(d, &http, &ctx, &e, email1, "ab-cd", hyphen, 200, 0, marker, NULL, NULL, true, true);
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));
    const char *bodies[] = {form};
    e.bodies = bodies; e.count = 1;
    e.statuses[0] = 200; e.responses[0] = body_of(marker); e.body_errors[0] = NULL;
    e.send_rc[0] = 0; e.send_errors[0] = NULL;
    size_t built = watched;
    watch_n = 1; watch_sizes[0] = strlen(form) + 1;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "mrticktock-offline"};
    one_input(input, sizeof(input), email1, pass1);
    br_results unpublished = scan_ok(d, &missing, input, strlen(input), &e);
    watch_n = 0;
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0]);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    CHECK(watched == built + 1);
    check_result(&unpublished.items[0], email1, false);
    br_results_clear(&unpublished);
}

static void product_and_nil(const br_detector *d)
{
    char input[220], b0[128], b1[128], b2[128], b3[128];
    int n = snprintf(input, sizeof(input), "%s %s %s%*s mrticktock %s mrticktock %s",
                     email2, email1, email2, 50, "", pass1, pass2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_body(b0, sizeof(b0), email2, pass1);
    expect_body(b1, sizeof(b1), email2, pass2);
    expect_body(b2, sizeof(b2), email1, pass1);
    expect_body(b3, sizeof(b3), email1, pass2);
    const char *bodies[] = {b0, b1, b2, b3};
    expected e = {.bodies = bodies, .count = 4, .statuses = {200, 200, 200, 200},
                  .responses = {body_of(marker), body_of(marker), body_of(marker), body_of(marker)}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mrticktock-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(!e.live[i]);
        CHECK(e.released_ids[i] == 3 - i);
        CHECK(e.release_lengths[i] == 4 && e.sends_at_release[i] == 4);
    }
    check_result(&r.items[0], email2, true);
    check_result(&r.items[1], email2, true);
    check_result(&r.items[2], email1, true);
    check_result(&r.items[3], email1, true);
    br_results_clear(&r);

    char pair[180], form1[128], form2[128];
    int pair_n = snprintf(pair, sizeof(pair), "%s%*s mrticktock %s mrticktock %s", email1, 50, "", pass1, pass2);
    CHECK(pair_n > 0 && (size_t)pair_n < sizeof(pair));
    expect_body(form1, sizeof(form1), email1, pass1);
    expect_body(form2, sizeof(form2), email1, pass2);
    const char *pair_forms[] = {form1, form2};
    expected unread = {.bodies = pair_forms, .count = 2, .statuses = {200, 200},
                       .responses = {{NULL, 8}, body_of(marker)}, .body_errors = {"", NULL}};
    test_http unread_http = {.inspect = inspect, .user = &unread};
    br_transport unread_transport = {&unread_http, test_http_send, release_response};
    br_scan_ctx unread_ctx = {.transport = &unread_transport, .user_agent = "mrticktock-offline"};
    unread.ctx = &unread_ctx;
    br_results dropped_read = scan_ok(d, &unread_ctx, pair, (size_t)pair_n, &unread);
    CHECK(dropped_read.len == 1 && unread_http.calls == 2 && unread_http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!unread.live[i]);
        CHECK(unread.released_ids[i] == 1 - i);
        CHECK(unread.release_lengths[i] == 1 && unread.sends_at_release[i] == 2);
    }
    check_result(&dropped_read.items[0], email1, true);
    br_results_clear(&dropped_read);

    expected failed_send = {.bodies = pair_forms, .count = 2, .statuses = {200, 201},
                            .responses = {body_of(marker), body_of(marker)},
                            .send_rc = {4, 0}, .send_errors = {"synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "mrticktock-offline"};
    failed_send.ctx = &failed_ctx;
    br_results mixed_fail = scan_ok(d, &failed_ctx, pair, (size_t)pair_n, &failed_send);
    CHECK(mixed_fail.len == 2 && failed_http.calls == 2 && failed_http.releases == 2);
    CHECK(failed_send.released_ids[0] == 0 && failed_send.sends_at_release[0] == 1);
    CHECK(failed_send.release_lengths[0] == 0);
    CHECK(failed_send.released_ids[1] == 1 && failed_send.sends_at_release[1] == 2);
    CHECK(failed_send.release_lengths[1] == 2);
    check_result(&mixed_fail.items[0], email1, false);
    check_result(&mixed_fail.items[1], email1, true);
    br_results_clear(&mixed_fail);

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
    watch_n = 4;
    watch_sizes[0] = strlen(b0) + 1; watch_sizes[1] = strlen(b1) + 1;
    watch_sizes[2] = strlen(b2) + 1; watch_sizes[3] = strlen(b3) + 1;
    watched = 0;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    watch_n = 0;
    CHECK(http.calls == calls && http.releases == releases && watched == 4);
    check_prior(&kept, &prior);

    /* Body allocation is the first owned step after finding creation. Failing
     * it on a nil context proves the form was requested before the drop. */
    fail_size = strlen(b0) + 1;
    fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory creating Mrticktock body"));
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[180];
    int n = snprintf(input, sizeof(input), "%s %s%*s mrticktock %s mrticktock %s",
                     email1, email2, 50, "", pass1, pass2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char b0[128], b1[128], b2[128], b3[128];
    expect_body(b0, sizeof(b0), email1, pass1);
    expect_body(b1, sizeof(b1), email1, pass2);
    expect_body(b2, sizeof(b2), email2, pass1);
    expect_body(b3, sizeof(b3), email2, pass2);
    const char *bodies[] = {b0, b1, b2, b3};
    expected e = {.bodies = bodies, .count = 4, .statuses = {200, 200, 200, 200},
                  .responses = {body_of(marker), body_of(marker), body_of(marker), body_of(marker)}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mrticktock-offline"};
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

    fail_size = strlen(email2) + 1; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_size = strlen(pass2) + 1; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Mrticktock result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    fail_size = strlen(b0) + 1; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory creating Mrticktock body"));
    CHECK(!http.calls && !http.releases && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Mrticktock result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live[0] && !e.live[1]);
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
    CHECK(!strcmp(error, "cannot retain Mrticktock response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live[0] && !e.live[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    e.count = 1;
    e.responses[0] = (br_slice){NULL, 8};
    e.body_errors[0] = NULL;
    char one[160];
    one_input(one, sizeof(one), email1, pass1);
    e.bodies = bodies;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, strlen(one)}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Mrticktock response body"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    CHECK(strlen(email1) == 20 && strlen(email2) == 11);
    CHECK(strlen(pass1) == 15 && strlen(pass2) == 12);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    product_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !watch_n);
    return test_finish("Mrticktock");
}
