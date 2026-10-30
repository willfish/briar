/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_monkeylearn_init(const br_detector **out, char **error);

/* Established named-test seams keep the compiled production factory while
 * observing absent setter calls and positive append failure. */
#define br_results_push monkeylearn_real_push
#define br_result_set_verification_error monkeylearn_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "0123456789abcdef0123456789abcdef01234567";
static const char other[] = "fedcba9876543210fedcba9876543210fedcba98";
static const char classifiers_url[] = "https://api.monkeylearn.com/v3/classifiers";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_request_after, setter_calls;
static bool fail_next_malloc, arm_headers;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) { fail_next_malloc = false; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key")) {
        if (fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
        if (arm_headers) { arm_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
    }
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return monkeylearn_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; return monkeylearn_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other) == 40);
    CHECK(br_monkeylearn_init(NULL, &error) == -1 && error && !strcmp(error, "invalid MonkeyLearn detector output")); free(error); error = NULL;
    CHECK(br_monkeylearn_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:monkeylearn)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_monkeylearn_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_monkeylearn_init(&d, &error) == 0 && d && !error);
    CHECK(br_monkeylearn_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 820 && d->version == 0 && !strcmp(d->name, "MonkeyLearn") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "MonkeyLearn is a machine learning platform that allows you to analyze text with custom machine learning "
        "models. API keys can be used to access and manage these models."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "monkeylearn"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 820, expected, "key"); CHECK(r->raw.len == 40 && r->verified == verified && !r->verification_error);
}

static void extraction_case(const br_detector *d, const void *data, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results r = test_scan(d, &ctx, false, data, len);
    CHECK(r.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&r.items[0], expected, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[41];
    snprintf(input, sizeof(input), "monkeylearn '%s'", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preMoNkEyLeArNsuffix:\r\n%s", other); extraction_case(d, input, strlen(input), other);
    extraction_case(d, key, strlen(key), NULL);
    memcpy(changed, key, 41); changed[12] = 'A'; snprintf(input, sizeof(input), "MONKEYLEARN %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 41); changed[12] = 'g'; snprintf(input, sizeof(input), "monkeylearn %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 41); changed[12] = '-'; snprintf(input, sizeof(input), "monkeylearn %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 41); changed[39] = '\0'; snprintf(input, sizeof(input), "monkeylearn %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "monkeylearn _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "monkeylearn %s_", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "monkeylearn %s0", key); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'f', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "monkeylearn %s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "monkeylearn \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 11; memcpy(input, "monkeylearn", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, 41); extraction_case(d, input, at + 40, gap == 40 ? key : NULL);
        at = 11; for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, 41); extraction_case(d, input, at + 40, gap == 40 ? key : NULL);
    }
    memcpy(input, "monkeylearn", 11); input[11] = '\0'; input[12] = '\r'; input[13] = '\n'; memcpy(input + 14, key, 41);
    extraction_case(d, input, 54, key); extraction_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "monkeylearn %s %s", key, other); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "monkeylearn %s\nmonkeylearn %s\nmonkeylearn %s", key, other, key);
    const char *keys[] = {key, other, key}; br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len); br_results_clear(&r);
    fail_request_after = 1; snprintf(input, sizeof(input), "monkeylearn %s", key);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && !fail_request_after && fail_next_malloc);
    fail_next_malloc = false; br_results_clear(&r);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    const int *codes;
    size_t count, initial_len, release_len, next_deferred, failed_sends;
    bool closing;
    const char *authorization[3], *urls[3];
    br_header markers[3];
} wire_case;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *w = http->user; size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http && i < w->count && w->count <= 3 && !w->closing);
    CHECK(w->published->len == w->initial_len + i && http->releases == w->failed_sends);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, classifiers_url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 820);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Token ", 6));
    CHECK(!strcmp(request->headers[1].value + 6, w->keys[i]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog monkeylearn-test" : "TruffleHog"));
    if (w->codes) { http->send_rc = w->codes[i]; http->send_error = http->send_rc ? "synthetic mixed Do failure" : NULL; }
    /* Retain original provider values only, never prepared request/header/UA
     * storage. Synthetic response headers identify release order, not body. */
    w->authorization[i] = request->headers[1].value; w->urls[i] = request->url;
    w->markers[i] = (br_header){"Fixture-Index", "synthetic"};
    http->response.headers = w->markers + i; http->response.nheaders = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; wire_case *w = http->user;
    if (!http->calls) {
        CHECK(!response->status && !response->body.data && !response->body.len && !response->headers);
        CHECK(w->published->len == w->initial_len);
    } else {
        size_t i = 0; while (i < http->calls && response->headers != w->markers + i) ++i;
        CHECK(i < http->calls && response->nheaders == 1);
        CHECK(!strcmp(w->authorization[i] + 6, w->keys[i]) && !strcmp(w->urls[i], classifiers_url));
        int code = w->codes ? w->codes[i] : http->send_rc;
        if (code) {
            CHECK(!w->closing && i + 1 == http->calls && w->published->len == w->initial_len + i); ++w->failed_sends;
        } else {
            if (!w->closing) { w->closing = true; w->next_deferred = http->calls; }
            while (w->next_deferred && w->codes && w->codes[w->next_deferred - 1]) --w->next_deferred;
            CHECK(w->next_deferred && --w->next_deferred == i && w->published->len == w->release_len);
            for (size_t j = 0; j <= i; ++j) if (!w->codes || !w->codes[j]) CHECK(!strcmp(w->authorization[j] + 6, w->keys[j]));
        }
    }
    test_http_release(http, response);
}

static br_transport wire_transport(wire_case *w)
{
    w->http.inspect = inspect_request; w->http.user = w;
    return (br_transport){&w->http, test_http_send, release_response};
}

static void scan_into(const br_detector *d, const br_scan_ctx *ctx, const char *input, br_results *r)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, r, &error) == 0 && !error);
}

static void http_policy(const br_detector *d)
{
    const char *keys[] = {key}; char input[96]; snprintf(input, sizeof(input), "monkeylearn %s", key);
    static const unsigned char binary[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    const struct { int status, code; const char *cause; } cases[] = {
        {199, 0, NULL}, {200, 0, NULL}, {201, 0, NULL}, {204, 0, NULL}, {299, 0, NULL},
        {300, 0, NULL}, {401, 0, NULL}, {403, 0, NULL}, {500, 0, NULL},
        {200, 1, "synthetic Do failure"}, {200, -1, "out of memory constructing HTTP headers"},
        {200, 7, "net/http: nil Context"}, {200, 1, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results r = {0};
        wire_case w = {.published = &r, .keys = keys, .count = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body = {binary, sizeof(binary)}, .body_error = i % 2 ? "" : "ignored read error"},
                     .send_rc = cases[i].code, .send_error = cases[i].cause}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport, .user_agent = i % 2 ? "monkeylearn-test" : NULL};
        scan_into(d, &ctx, input, &r); CHECK(r.len == 1 && w.http.calls == 1 && w.http.releases == 1);
        result_is(&r.items[0], key, !cases[i].code && cases[i].status >= 200 && cases[i].status < 300); br_results_clear(&r);
    }
    const char *multiple[] = {key, other, key}; const int mixed[] = {0, 1, 0};
    char repeated[192]; snprintf(repeated, sizeof(repeated), "monkeylearn %s\nmonkeylearn %s\nmonkeylearn %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        br_results r = {0}; wire_case w = {.published = &r, .keys = multiple, .count = 3, .release_len = 3,
            .codes = mode == 2 ? mixed : NULL,
            .http = {.response = {.status = 299, .body = {binary, sizeof(binary)}, .body_error = "ignored read error"},
                     .send_rc = mode == 1, .send_error = mode == 1 ? "synthetic Do failure" : NULL}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; scan_into(d, &ctx, repeated, &r);
        CHECK(r.len == 3 && w.http.calls == 3 && w.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], multiple[i], mode == 0 || (mode == 2 && !mixed[i]));
        br_results_clear(&r);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preparation_errors(const br_detector *d)
{
    const char *keys[] = {key}; char input[96]; snprintf(input, sizeof(input), "monkeylearn %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        br_results r = {0}; wire_case w = {.published = &r, .keys = keys, .count = 1};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        if (mode == 4) arm_headers = true;
        scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && !w.http.calls && w.http.releases == (mode == 2 ? 0u : 1u) && !arm_headers && !fail_after);
        result_is(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void owned_failures(const br_detector *d)
{
    const char *keys[] = {key, other}; char input[128]; snprintf(input, sizeof(input), "monkeylearn %s\nmonkeylearn %s", key, other);
    for (int mode = 0; mode < 7; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *prior_raw = sentinel.raw.data; char *prior_error = sentinel.verification_error;
        br_results r = {0}; CHECK(!br_results_push(&r, &sentinel));
        wire_case w = {.published = &r, .keys = keys, .count = 2, .initial_len = 1, .release_len = 2, .http = {.response = {.status = 200}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; const char *expected;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (mode == 1 || mode == 2 || mode == 6) { fail_part_after = mode == 2 ? 1 : 2; expected = "out of memory creating MonkeyLearn result"; }
        else if (mode == 3) { fail_push_after = 2; expected = "out of memory appending MonkeyLearn result"; }
        else { fail_request_after = mode == 4 ? 1 : 2; expected = "out of memory creating MonkeyLearn request"; }
        char *error = NULL;
        int rc = d->scan(d, mode == 2 ? NULL : &ctx, mode != 6, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_request_after && !fail_next_malloc);
        CHECK(r.len == 1 && r.items[0].detector_type == 12345 && r.items[0].verified);
        CHECK(r.items[0].raw.data == prior_raw && r.items[0].raw.len == 4 && !memcmp(prior_raw, "keep", 4));
        CHECK(r.items[0].verification_error == prior_error && !strcmp(prior_error, "caller-owned"));
        size_t calls = mode == 1 || mode == 5 ? 1u : mode == 3 ? 2u : 0u;
        CHECK(w.http.calls == calls && w.http.releases == calls); free(error); br_results_clear(&r);
    }
}

int main(void)
{
    const br_detector *d = descriptor(); extraction(d); http_policy(d); preparation_errors(d); owned_failures(d); CHECK(!setter_calls);
    return test_finish("MonkeyLearn lowerhex40, Token auth, ignored bodies, deferred LIFO and rollback");
}
