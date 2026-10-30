/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_mindmeister_init(const br_detector **out, char **error);

/* Established named-test seams observe real byte-search visitation, the absent
 * setter and positive append failure without changing shared production files. */
#define br_slice_find mindmeister_real_find
#include "../../src/bytes.c"
#undef br_slice_find
#define br_results_push mindmeister_real_push
#define br_result_set_verification_error mindmeister_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "Aa01234567Bb89cdef01Cc23456789Ddabcdef01Z9x";
static const char other[] = "Zz98765432Yy10fedcbaXx87654321Wwfedcba98Q2b";
static const char maps_url[] = "https://www.mindmeister.com/services/rest/oauth2?method=mm.maps.getList";
static const unsigned char marker[] = "\"stat\":\"ok\"";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_request_after, setter_calls, searches;
static bool fail_next_malloc;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) { fail_next_malloc = false; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key") && fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return mindmeister_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; return mindmeister_real_setter(result, cause, secrets, count);
}

size_t br_slice_find(br_slice input, br_slice needle, size_t start)
{
    ++searches;
    CHECK(start == 0 && needle.len == sizeof(marker) - 1 && !memcmp(needle.data, marker, needle.len));
    return mindmeister_real_find(input, needle, start);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other) == 43);
    CHECK(br_mindmeister_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Mindmeister detector output")); free(error); error = NULL;
    CHECK(br_mindmeister_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:mindmeister)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_mindmeister_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_mindmeister_init(&d, &error) == 0 && d && !error);
    CHECK(br_mindmeister_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 657 && d->version == 0 && !strcmp(d->name, "Mindmeister") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Mindmeister is a mind mapping tool that helps users organize and visualize their thoughts. "
        "Mindmeister API keys can be used to access and manipulate mind maps and other data within the platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mindmeister"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 657, expected, "key"); CHECK(r->raw.len == 43 && r->verified == verified && !r->verification_error);
}

static void extraction_case(const br_detector *d, const void *data, size_t len, const char *expected)
{
    size_t before = searches; test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results r = test_scan(d, &ctx, false, data, len);
    CHECK(r.len == (expected ? 1u : 0u) && !http.calls && !http.releases && searches == before);
    if (expected) result_is(&r.items[0], expected, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[44];
    snprintf(input, sizeof(input), "mindmeister '%s'", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preMiNdMeIsTeRsuffix:\r\n%s", other); extraction_case(d, input, strlen(input), other);
    extraction_case(d, key, strlen(key), NULL);
    memcpy(changed, key, 44); changed[12] = '-'; snprintf(input, sizeof(input), "mindmeister %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 44); changed[42] = '\0'; snprintf(input, sizeof(input), "mindmeister %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mindmeister _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mindmeister %s_", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mindmeister %s0", key); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'Z', 43); changed[43] = '\0'; snprintf(input, sizeof(input), "mindmeister %s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "mindmeister \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 11; memcpy(input, "mindmeister", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, 44); extraction_case(d, input, at + 43, gap == 40 ? key : NULL);
        at = 11; for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, 44); extraction_case(d, input, at + 43, gap == 40 ? key : NULL);
    }
    memcpy(input, "mindmeister", 11); input[11] = '\0'; input[12] = '\r'; input[13] = '\n'; memcpy(input + 14, key, 44);
    extraction_case(d, input, 57, key); extraction_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "mindmeister %s\nmindmeister %s\nmindmeister %s", key, other, key);
    const char *keys[] = {key, other, key}; size_t before = searches;
    br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && searches == before); br_results_clear(&r);
    fail_request_after = 1; snprintf(input, sizeof(input), "mindmeister %s", key);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && !fail_request_after && fail_next_malloc);
    fail_next_malloc = false; br_results_clear(&r);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    const int *codes;
    const char *const *read_errors;
    size_t count, initial_len, release_len, next_deferred, search_start, searches_before[3];
    bool closing, immediate[3], invalid_second;
    const char *authorization[3], *urls[3];
    br_header markers[3];
} wire_case;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *w = http->user; size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http && i < w->count && w->count <= 3 && !w->closing);
    CHECK(w->published->len == w->initial_len + i);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, maps_url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 657);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, w->keys[i]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog mindmeister-test" : "TruffleHog"));
    if (w->codes) { http->send_rc = w->codes[i]; http->send_error = http->send_rc ? "synthetic mixed Do failure" : NULL; }
    if (w->read_errors) http->response.body_error = w->read_errors[i];
    if (w->invalid_second && i == 1) http->response.body = (br_slice){NULL, sizeof(marker) - 1};
    w->immediate[i] = http->send_rc != 0 || http->response.body_error != NULL || (w->invalid_second && i == 1);
    w->searches_before[i] = searches;
    /* Only provider values are retained; prepared headers/UA/request expire
     * at send return. Response marker headers identify close order, not body. */
    w->authorization[i] = request->headers[0].value; w->urls[i] = request->url;
    w->markers[i] = (br_header){"Fixture-Index", "synthetic"};
    http->response.headers = w->markers + i; http->response.nheaders = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; wire_case *w = http->user;
    if (!http->calls) {
        CHECK(!response->status && !response->body.data && !response->body.len && !response->headers);
        CHECK(w->published->len == w->initial_len && searches == w->search_start);
    } else {
        size_t i = 0; while (i < http->calls && response->headers != w->markers + i) ++i;
        CHECK(i < http->calls && response->nheaders == 1);
        CHECK(!strcmp(w->authorization[i] + 7, w->keys[i]) && !strcmp(w->urls[i], maps_url));
        if (w->immediate[i]) {
            CHECK(!w->closing && i + 1 == http->calls && w->published->len == w->initial_len + i);
            CHECK(searches == w->searches_before[i]);
        } else {
            if (!w->closing) { w->closing = true; w->next_deferred = http->calls; }
            while (w->next_deferred && w->immediate[w->next_deferred - 1]) --w->next_deferred;
            CHECK(w->next_deferred && --w->next_deferred == i && w->published->len == w->release_len);
            for (size_t j = 0; j <= i; ++j) if (!w->immediate[j]) CHECK(!strcmp(w->authorization[j] + 7, w->keys[j]));
        }
    }
    test_http_release(http, response);
}

static br_transport wire_transport(wire_case *w)
{
    w->http.inspect = inspect_request; w->http.user = w; w->search_start = searches;
    return (br_transport){&w->http, test_http_send, release_response};
}

static void scan_into(const br_detector *d, const br_scan_ctx *ctx, const char *input, br_results *r)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, r, &error) == 0 && !error);
}

#define BODY(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
static void body_and_status(const br_detector *d)
{
    const char *keys[] = {key}; char input[96]; snprintf(input, sizeof(input), "mindmeister %s", key);
    static const unsigned char binary[] = {0, 0xff, '"', 's', 't', 'a', 't', '"', ':', '"', 'o', 'k', '"', 0xfe};
    const struct { int status, code; br_slice body; const char *read_error, *send_error; bool verified; } cases[] = {
        {200, 0, BODY("\"stat\":\"ok\""), NULL, NULL, true},
        {201, 0, BODY("{\"stat\":\"ok\"}"), NULL, NULL, true},
        {299, 0, BODY("not JSON: \"stat\":\"ok\" trailing"), NULL, NULL, true},
        {204, 0, {binary, sizeof(binary)}, NULL, NULL, true},
        {200, 0, BODY("{\"stat\": \"ok\"}"), NULL, NULL, false},
        {200, 0, BODY("{\"stat\":\"OK\"}"), NULL, NULL, false},
        {200, 0, BODY("{\"Stat\":\"ok\"}"), NULL, NULL, false},
        {200, 0, {NULL, 0}, NULL, NULL, false},
        {199, 0, BODY("\"stat\":\"ok\""), NULL, NULL, false},
        {300, 0, BODY("\"stat\":\"ok\""), NULL, NULL, false},
        {401, 0, BODY("\"stat\":\"ok\""), NULL, NULL, false},
        {503, 0, BODY("\"stat\":\"ok\""), NULL, NULL, false},
        {200, 0, BODY("{\"stat\":\"ok\"}"), "read failed", NULL, false},
        {299, 0, BODY("{\"stat\":\"ok\"}"), "", NULL, false},
        {403, 0, BODY("\"stat\":\"ok\""), "", NULL, false},
        {200, 0, {NULL, sizeof(marker) - 1}, "", NULL, false},
        {200, 1, BODY("\"stat\":\"ok\""), NULL, "synthetic Do failure", false},
        {200, -1, BODY("\"stat\":\"ok\""), NULL, "out of memory constructing HTTP headers", false},
        {200, 7, BODY("\"stat\":\"ok\""), NULL, "net/http: nil Context", false},
        {200, 1, BODY("\"stat\":\"ok\""), NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results r = {0}; size_t before = searches;
        wire_case w = {.published = &r, .keys = keys, .count = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error},
                     .send_rc = cases[i].code, .send_error = cases[i].send_error}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport, .user_agent = i % 2 ? "mindmeister-test" : NULL};
        scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && w.http.calls == 1 && w.http.releases == 1);
        CHECK(searches == before + (!cases[i].code && !cases[i].read_error));
        result_is(&r.items[0], key, cases[i].verified); br_results_clear(&r);
    }
}

static void release_order(const br_detector *d)
{
    const char *keys[] = {key, other, key}; const int codes[] = {0, 1, 0}; const char *read_errors[] = {NULL, "", NULL};
    char input[192]; snprintf(input, sizeof(input), "mindmeister %s\nmindmeister %s\nmindmeister %s", key, other, key);
    for (int mode = 0; mode < 4; ++mode) {
        br_results r = {0}; size_t before = searches;
        wire_case w = {.published = &r, .keys = keys, .count = 3, .release_len = 3,
            .codes = mode == 2 ? codes : NULL, .read_errors = mode == 1 ? read_errors : NULL,
            .http = {.response = {.status = mode == 3 ? 500 : 204, .body = BODY("\"stat\":\"ok\"")}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; scan_into(d, &ctx, input, &r);
        CHECK(r.len == 3 && w.http.calls == 3 && w.http.releases == 3 && searches == before + (mode == 1 || mode == 2 ? 2u : 3u));
        for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], mode != 3 && !((mode == 1 || mode == 2) && i == 1));
        br_results_clear(&r);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preparation_errors(const br_detector *d)
{
    const char *keys[] = {key}; char input[96]; snprintf(input, sizeof(input), "mindmeister %s", key);
    for (int mode = 0; mode < 4; ++mode) {
        br_results r = {0}; wire_case w = {.published = &r, .keys = keys, .count = 1}; size_t before = searches;
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && !w.http.calls && w.http.releases == (mode == 2 ? 0u : 1u) && searches == before);
        result_is(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void owned_failures(const br_detector *d)
{
    const char *keys[] = {key, other}; char input[128]; snprintf(input, sizeof(input), "mindmeister %s\nmindmeister %s", key, other);
    for (int mode = 0; mode < 8; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *prior_raw = sentinel.raw.data; char *prior_error = sentinel.verification_error;
        br_results r = {0}; CHECK(!br_results_push(&r, &sentinel)); size_t before = searches;
        wire_case w = {.published = &r, .keys = keys, .count = 2, .initial_len = 1, .release_len = 2,
            .invalid_second = mode == 7, .http = {.response = {.status = mode == 7 ? 500 : 200, .body = BODY("\"stat\":\"ok\"")}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; const char *expected;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (mode == 1 || mode == 2 || mode == 6) { fail_part_after = mode == 2 ? 1 : 2; expected = "out of memory creating Mindmeister result"; }
        else if (mode == 3) { fail_push_after = 2; expected = "out of memory appending Mindmeister result"; }
        else if (mode == 7) expected = "invalid Mindmeister response body slice";
        else { fail_request_after = mode == 4 ? 1 : 2; expected = "out of memory creating Mindmeister request"; }
        char *error = NULL;
        int rc = d->scan(d, mode == 2 ? NULL : &ctx, mode != 6, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_request_after && !fail_next_malloc);
        CHECK(r.len == 1 && r.items[0].detector_type == 12345 && r.items[0].verified);
        CHECK(r.items[0].raw.data == prior_raw && r.items[0].raw.len == 4 && !memcmp(prior_raw, "keep", 4));
        CHECK(r.items[0].verification_error == prior_error && !strcmp(prior_error, "caller-owned"));
        size_t calls = mode == 1 || mode == 5 ? 1u : mode == 3 || mode == 7 ? 2u : 0u;
        CHECK(w.http.calls == calls && w.http.releases == calls && searches == before + (mode == 7 ? 1u : calls));
        free(error); br_results_clear(&r);
    }
}

int main(void)
{
    const br_detector *d = descriptor(); extraction(d); body_and_status(d); release_order(d); preparation_errors(d); owned_failures(d);
    CHECK(!setter_calls);
    return test_finish("Mindmeister full-read binary substring, source-specific close order and owned rollback");
}
