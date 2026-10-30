/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

int br_mockaroo_init(const br_detector **out, char **error);

/* Established named-test seams retain actual parsing/ordered/numeric mechanics
 * and inject owned callback failures without a production hook or shared edit. */
#define br_json_first_document mockaroo_real_first
#define br_json_each_member mockaroo_real_member
#define br_json_each_element mockaroo_real_element
#define br_json_check_float64_numbers mockaroo_real_numbers
#include "../../src/detectors/json.c"
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_each_element
#undef br_json_check_float64_numbers
#define br_results_push mockaroo_real_push
#define br_result_set_verification_error mockaroo_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "g7h9j2k5", other[] = "z9y8x7w6";
static const char url_prefix[] = "https://api.mockaroo.com/api/types?key=";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_url_after;
static size_t fail_decoder_after, fail_member_after, fail_element_after, fail_number_after;
static size_t decodes, members, elements, numbers, overflows, setter_calls;
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
    if (!rc && !strcmp(name, "key") && fail_url_after && --fail_url_after == 0) fail_next_malloc = true;
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return mockaroo_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; return mockaroo_real_setter(result, cause, secrets, count);
}

int br_json_first_document(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    ++decodes;
    int rc = mockaroo_real_first(body, read_error, out, end, cause);
    /* Populate a real owned document before a resource failure, checking that
     * the provider frees it on every return rather than borrowing a getter. */
    if (!rc && fail_decoder_after && --fail_decoder_after == 0) return -1;
    return rc;
}

typedef struct { br_json_member_fn callback; void *user; } member_visit;
static int member_callback(void *user, br_slice name, br_json *value, br_slice encoded)
{
    member_visit *visit = user; ++members;
    if (fail_member_after && --fail_member_after == 0) return 1;
    return visit->callback(visit->user, name, value, encoded);
}

int br_json_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    member_visit visit = {callback, user}; return mockaroo_real_member(object, member_callback, &visit);
}

typedef struct { br_json_element_fn callback; void *user; } element_visit;
static int element_callback(void *user, size_t index, br_json *value, br_slice encoded)
{
    element_visit *visit = user; ++elements;
    if (fail_element_after && --fail_element_after == 0) return 1;
    return visit->callback(visit->user, index, value, encoded);
}

int br_json_each_element(br_slice array, br_json_element_fn callback, void *user)
{
    element_visit visit = {callback, user}; return mockaroo_real_element(array, element_callback, &visit);
}

int br_json_check_float64_numbers(br_slice scalar, char **cause)
{
    ++numbers;
    CHECK(scalar.len && (scalar.data[0] == '-' || (scalar.data[0] >= '0' && scalar.data[0] <= '9')));
    /* Never accept a whole object/array check that stops at its first overflow. */
    CHECK(!memchr(scalar.data, '{', scalar.len) && !memchr(scalar.data, '[', scalar.len));
    if (fail_number_after && --fail_number_after == 0) { *cause = NULL; return -1; }
    int rc = mockaroo_real_numbers(scalar, cause);
    if (rc == 1) ++overflows;
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 8 && strlen(other) == 8);
    CHECK(br_mockaroo_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Mockaroo detector output")); free(error); error = NULL;
    CHECK(br_mockaroo_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:mockaroo)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_mockaroo_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_mockaroo_init(&d, &error) == 0 && d && !error);
    CHECK(br_mockaroo_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 753 && d->version == 0 && !strcmp(d->name, "Mockaroo") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Mockaroo is a tool for generating realistic data for testing and development. Mockaroo API keys can be used to access and generate this data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mockaroo"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 753, expected, "key"); CHECK(r->raw.len == 8 && r->verified == verified && !r->verification_error);
}

static void extraction_case(const br_detector *d, const void *data, size_t len, const char *expected)
{
    size_t before = decodes; test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results r = test_scan(d, &ctx, false, data, len);
    CHECK(r.len == (expected ? 1u : 0u) && !http.calls && !http.releases && decodes == before);
    if (expected) result_is(&r.items[0], expected, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[9];
    snprintf(input, sizeof(input), "mockaroo '%s'", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preMoCkArOosuffix:\r\n%s", other); extraction_case(d, input, strlen(input), other);
    extraction_case(d, key, strlen(key), NULL);
    memcpy(changed, key, 9); changed[2] = 'A'; snprintf(input, sizeof(input), "MOCKAROO %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 9); changed[3] = '-'; snprintf(input, sizeof(input), "mockaroo %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 9); changed[7] = '\0'; snprintf(input, sizeof(input), "mockaroo %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mockaroo _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mockaroo %s_", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "mockaroo %s0", key); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'z', 8); changed[8] = '\0'; snprintf(input, sizeof(input), "mockaroo %s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "mockaroo \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 8; memcpy(input, "mockaroo", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, 9); extraction_case(d, input, at + 8, gap == 40 ? key : NULL);
        at = 8; for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, 9); extraction_case(d, input, at + 8, gap == 40 ? key : NULL);
    }
    memcpy(input, "mockaroo", 8); input[8] = '\0'; input[9] = '\r'; input[10] = '\n'; memcpy(input + 11, key, 9);
    extraction_case(d, input, 19, key); extraction_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "mockaroo %s\nmockaroo %s\nmockaroo %s", key, other, key);
    const char *keys[] = {key, other, key}; br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len); br_results_clear(&r);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    const int *codes;
    size_t count, initial_len, release_len, next_deferred, failed_sends;
    bool closing;
    const char *urls[3];
    br_header markers[3];
} wire_case;

static void check_url(const char *url, const char *expected)
{
    CHECK(!strncmp(url, url_prefix, sizeof(url_prefix) - 1) && !strcmp(url + sizeof(url_prefix) - 1, expected));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *w = http->user; size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http && i < w->count && w->count <= 3 && !w->closing);
    CHECK(w->published->len == w->initial_len + i && http->releases == w->failed_sends);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, w->keys[i]);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 753);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog mockaroo-test" : "TruffleHog"));
    if (w->codes) { http->send_rc = w->codes[i]; http->send_error = http->send_rc ? "synthetic mixed Do failure" : NULL; }
    /* Save only original provider URL bytes, never temporary prepared headers,
     * UA or effective request. Response headers identify close order. */
    w->urls[i] = request->url; w->markers[i] = (br_header){"Fixture-Index", "synthetic"};
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
        CHECK(i < http->calls && response->nheaders == 1); check_url(w->urls[i], w->keys[i]);
        int code = w->codes ? w->codes[i] : http->send_rc;
        if (code) {
            CHECK(!w->closing && i + 1 == http->calls && w->published->len == w->initial_len + i); ++w->failed_sends;
        } else {
            if (!w->closing) { w->closing = true; w->next_deferred = http->calls; }
            while (w->next_deferred && w->codes && w->codes[w->next_deferred - 1]) --w->next_deferred;
            CHECK(w->next_deferred && --w->next_deferred == i && w->published->len == w->release_len);
            for (size_t j = 0; j <= i; ++j) if (!w->codes || !w->codes[j]) check_url(w->urls[j], w->keys[j]);
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

static void json_cases(const br_detector *d)
{
    const char *keys[] = {key}; char input[40]; snprintf(input, sizeof(input), "mockaroo %s", key);
    const struct { const char *body, *read_error; bool verified; size_t number_count; } cases[] = {
        {"{\"types\":[{}]}", NULL, true, 0}, {"{\"types\":[null]}", NULL, true, 0},
        {"{\"types\":[]}", NULL, false, 0}, {"{\"types\":null}", NULL, false, 0},
        {"{}", NULL, false, 0}, {"null", NULL, false, 0}, {"[]", NULL, false, 0}, {"[1e400]", NULL, false, 0},
        {"{\"types\":[true]}", NULL, false, 0}, {"{\"types\":[1e400]}", NULL, false, 0},
        {"{\"types\":[{}]} trailing invalid", NULL, true, 0}, {"{\"types\":[{}]} [1e400]", NULL, true, 0},
        {"{\"types\":[{}]}", "terminal read error", true, 0}, {"{\"types\":[{}]}", "", true, 0},
        {"{\"types\":[{}]", "terminal read error", false, 0}, {"{\"types\":[{}]", "", false, 0},
        {"", NULL, false, 0}, {"{\"types\":[}", NULL, false, 0},
        {"{\"types\":[{}],\"types\":null}", NULL, false, 0},
        {"{\"types\":[{}],\"TYPES\":[]}", NULL, false, 0},
        {"{\"types\":[],\"Types\":[null]}", NULL, true, 0},
        {"{\"type\u017f\":[{}]}", NULL, true, 0},
        {"{\"types\":{},\"types\":[{}]}", NULL, false, 0},
        {"{\"types\":[{\"name\":false}],\"types\":[{}]}", NULL, false, 0},
        {"{\"unknown\":{\"n\":1e400},\"types\":[{}]}", NULL, true, 0},
        {"{\"types\":[{\"Name\":null,\"TYPE\":null,\"PARAMETERS\":null}]}", NULL, true, 0},
        {"{\"types\":[{\"name\":\"ok\",\"name\":null,\"type\":\"1e400\"}]}", NULL, true, 0},
        {"{\"types\":[{\"name\":{\"ignored\":1e400},\"parameters\":{\"ignored\":1e400}}]}", NULL, false, 0},
        {"{\"types\":[{\"name\":[1e400],\"type\":[1,2]}]}", NULL, false, 2},
        {"{\"types\":[{\"parameters\":3,\"parameters\":[]}]}", NULL, false, 0},
        {"{\"types\":[{\"type\":1e-9999}]}", NULL, true, 1},
        {"{\"types\":[{\"type\":184467440737095516160}]}", NULL, true, 1},
        {"{\"types\":[{\"type\":1e400}]}", NULL, false, 1},
        {"{\"types\":[{\"type\":1e400,\"type\":null}]}", NULL, false, 1},
        {"{\"types\":[{\"type\":{\"n\":1e400,\"n\":1},\"parameters\":[{\"v\":2,\"v\":3},[4],null]}]}", NULL, false, 5},
        {"{\"types\":[{\"parameters\":[null,true,\"text\",{\"n\":1,\"n\":2},[3]]}]}", NULL, true, 3},
        {"{\"types\":[{\"name\":\"first\",\"parameters\":[1]}],\"types\":[null]}", NULL, true, 1},
        {"{\"types\":[{\"name\":\"first\",\"type\":{},\"parameters\":[1]}],\"types\":[{}]}", NULL, true, 1},
        {"{\"types\":[{\"parameter\u017f\":[1]}]}", NULL, true, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results r = {0}; size_t before = numbers, decoded = decodes;
        wire_case w = {.published = &r, .keys = keys, .count = 1, .release_len = 1,
            .http = {.response = {.status = 200, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}, .body_error = cases[i].read_error}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport, .user_agent = "mockaroo-test"}; scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && w.http.calls == 1 && w.http.releases == 1 && decodes == decoded + 1 && numbers == before + cases[i].number_count);
        result_is(&r.items[0], key, cases[i].verified); br_results_clear(&r);
    }
}

static void http_policy(const br_detector *d)
{
    const char *keys[] = {key}; char input[40]; snprintf(input, sizeof(input), "mockaroo %s", key);
    const struct { int status, code; const char *cause; } cases[] = {
        {199, 0, NULL}, {200, 0, NULL}, {201, 0, NULL}, {204, 0, NULL}, {299, 0, NULL}, {300, 0, NULL},
        {401, 0, NULL}, {500, 0, NULL}, {200, 1, "synthetic Do failure"}, {200, -1, "out of memory constructing HTTP headers"},
        {200, 7, "net/http: nil Context"}, {200, 1, NULL},
    };
    static const unsigned char body[] = "{\"types\":[null]}";
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results r = {0}; size_t before = decodes;
        wire_case w = {.published = &r, .keys = keys, .count = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body = {body, sizeof(body) - 1}, .body_error = ""}, .send_rc = cases[i].code, .send_error = cases[i].cause}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport};
        bool expected = !cases[i].code && cases[i].status >= 200 && cases[i].status < 300;
        if (!expected) fail_decoder_after = 1; /* A non2xx/Do skip must not reach even owned decoder failure. */
        scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && w.http.calls == 1 && w.http.releases == 1 && decodes == before + expected);
        CHECK(expected ? !fail_decoder_after : fail_decoder_after == 1); fail_decoder_after = 0;
        result_is(&r.items[0], key, expected); br_results_clear(&r);
    }
    const char *multiple[] = {key, other, key}; const int mixed[] = {0, 1, 0};
    char repeated[80]; snprintf(repeated, sizeof(repeated), "mockaroo %s\nmockaroo %s\nmockaroo %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        br_results r = {0}; wire_case w = {.published = &r, .keys = multiple, .count = 3, .release_len = 3, .codes = mode == 2 ? mixed : NULL,
            .http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}, .send_rc = mode == 1, .send_error = mode == 1 ? "synthetic Do failure" : NULL}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; scan_into(d, &ctx, repeated, &r);
        CHECK(r.len == 3 && w.http.calls == 3 && w.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], multiple[i], mode == 0 || (mode == 2 && !mixed[i]));
        br_results_clear(&r);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preparation_errors(const br_detector *d)
{
    const char *keys[] = {key}; char input[40]; snprintf(input, sizeof(input), "mockaroo %s", key);
    for (int mode = 0; mode < 4; ++mode) {
        br_results r = {0}; wire_case w = {.published = &r, .keys = keys, .count = 1}; size_t before = decodes;
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && !w.http.calls && w.http.releases == (mode == 2 ? 0u : 1u) && decodes == before);
        result_is(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void owned_failures(const br_detector *d)
{
    const char *keys[] = {key, other}; char input[64]; snprintf(input, sizeof(input), "mockaroo %s\nmockaroo %s", key, other);
    static const unsigned char body[] = "{\"types\":[{}]}";
    for (int mode = 0; mode < 8; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *prior_raw = sentinel.raw.data; char *prior_error = sentinel.verification_error;
        br_results r = {0}; CHECK(!br_results_push(&r, &sentinel));
        wire_case w = {.published = &r, .keys = keys, .count = 2, .initial_len = 1, .release_len = 2, .http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport}; const char *expected;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (mode == 1 || mode == 2 || mode == 6) { fail_part_after = mode == 2 ? 1 : 2; expected = "out of memory creating Mockaroo result"; }
        else if (mode == 3) { fail_push_after = 2; expected = "out of memory appending Mockaroo result"; }
        else if (mode == 7) { fail_decoder_after = 2; expected = "cannot decode Mockaroo response"; }
        else { fail_url_after = mode == 4 ? 1 : 2; expected = "out of memory creating Mockaroo URL"; }
        char *error = NULL;
        int rc = d->scan(d, mode == 2 || mode == 4 ? NULL : &ctx, mode != 6,
            (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_url_after && !fail_next_malloc && !fail_decoder_after);
        CHECK(r.len == 1 && r.items[0].detector_type == 12345 && r.items[0].verified);
        CHECK(r.items[0].raw.data == prior_raw && r.items[0].raw.len == 4 && !memcmp(prior_raw, "keep", 4));
        CHECK(r.items[0].verification_error == prior_error && !strcmp(prior_error, "caller-owned"));
        size_t calls = mode == 1 || mode == 5 ? 1u : mode == 3 || mode == 7 ? 2u : 0u;
        CHECK(w.http.calls == calls && w.http.releases == calls); free(error); br_results_clear(&r);
    }
}

static void projection_failures(const br_detector *d)
{
    const char *keys[] = {key}; char input[40]; snprintf(input, sizeof(input), "mockaroo %s", key);
    const struct { const char *body; int fault; size_t nth, expected_numbers; } cases[] = {
        {"{\"types\":[{}]}", 0, 1, 0}, /* Decoder resource failure with an owned parsed document. */
        {"{\"types\":[{}]}", 1, 1, 0}, /* Positive root member callback is fatal, never decoder +1. */
        {"{\"types\":[{}]}", 2, 1, 0},
        {"{\"types\":[{\"type\":{\"bad\":1e400,\"later\":2}}]}", 1, 4, 1},
        {"{\"types\":[{\"parameters\":[1e400,2]}]}", 2, 3, 1},
        {"{\"types\":[{\"type\":[1e400,2]}]}", 3, 2, 2},
        {"{\"types\":[{\"name\":false,\"type\":{\"later\":1}}]}", 1, 4, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_result prior = {.detector_type = 12345, .verified = true};
        prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        unsigned char *saved = prior.raw.data; char *saved_error = prior.verification_error;
        br_results r = {0}; CHECK(!br_results_push(&r, &prior)); size_t before = numbers, overflow_before = overflows;
        wire_case w = {.published = &r, .keys = keys, .count = 1, .initial_len = 1, .release_len = 1,
            .http = {.response = {.status = 200, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}}}};
        br_transport transport = wire_transport(&w); br_scan_ctx ctx = {.transport = &transport};
        if (cases[i].fault == 0) fail_decoder_after = cases[i].nth;
        else if (cases[i].fault == 1) fail_member_after = cases[i].nth;
        else if (cases[i].fault == 2) fail_element_after = cases[i].nth;
        else fail_number_after = cases[i].nth;
        char *error = NULL;
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) == -1);
        CHECK(error && !strcmp(error, "cannot decode Mockaroo response") && !fail_decoder_after && !fail_member_after && !fail_element_after && !fail_number_after);
        CHECK(r.len == 1 && r.items[0].raw.data == saved && r.items[0].verification_error == saved_error && r.items[0].verified);
        CHECK(!memcmp(saved, "keep", 4) && !strcmp(saved_error, "caller-owned") && w.http.calls == 1 && w.http.releases == 1);
        CHECK(numbers == before + cases[i].expected_numbers);
        if (i >= 3 && i <= 5) CHECK(overflows == overflow_before + 1);
        free(error); br_results_clear(&r);
    }
}

int main(void)
{
    const br_detector *d = descriptor(); extraction(d); json_cases(d); http_policy(d); preparation_errors(d); owned_failures(d); projection_failures(d); CHECK(!setter_calls);
    return test_finish("Mockaroo ordered typed projection, scalar float visitation, deferred release and rollback");
}
