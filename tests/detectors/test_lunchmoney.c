/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_lunchmoney_init(const br_detector **out, char **error);

/* Established named-test seams; production extraction, findings and HTTP stay
 * linked. Observe forbidden setter calls and inject positive append failures. */
#define br_results_push lunchmoney_real_push
#define br_result_set_verification_error lunchmoney_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef01";
static const char other[] = "fedcba9876543210fedcba9876543210fedcba9876543210fe";
static const char categories_url[] = "https://dev.lunchmoney.app/v1/categories";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_request_after;
static size_t failed_allocations, setter_calls;
static bool fail_next_malloc, arm_headers;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false;
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "key")) {
        if (fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
        if (arm_headers) { arm_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1; }
    }
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return lunchmoney_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return lunchmoney_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 50 && strlen(other) == 50);
    CHECK(br_lunchmoney_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LunchMoney detector output")); free(error); error = NULL;
    CHECK(br_lunchmoney_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:lunchmoney)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_lunchmoney_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_lunchmoney_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_lunchmoney_init(&again, &error) == 0 && again == detector && !error);
    CHECK(br_lunchmoney_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 797 && detector->version == 0 && !strcmp(detector->name, "LunchMoney"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "LunchMoney is a personal finance tool that helps users manage their finances. "
        "LunchMoney API keys can be used to access and modify financial data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "lunchmoney"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 797, expected, "key");
    CHECK(result->raw.len == 50 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[384], changed[51];
    snprintf(input, sizeof(input), "lunchmoney = '%s'", key);
    extraction_case(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "preLuNcHmOnEysuffix:\r\n'%s'", key);
    extraction_case(detector, input, strlen(input), key);
    extraction_case(detector, key, strlen(key), NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = 'A';
    snprintf(input, sizeof(input), "LUNCHMONEY %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[20] = 'g';
    snprintf(input, sizeof(input), "lunchmoney %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[12] = '-';
    snprintf(input, sizeof(input), "lunchmoney %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[49] = '\0';
    snprintf(input, sizeof(input), "lunchmoney %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "lunchmoney _%s", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "lunchmoney %s_", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "lunchmoney %s0", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "lunchmoney \xc3\xa9%s\xc3\xa9", key);
    extraction_case(detector, input, strlen(input), key); /* ASCII word boundaries. */
    memset(changed, 'f', 50); changed[50] = '\0';
    snprintf(input, sizeof(input), "lunchmoney %s", changed);
    extraction_case(detector, input, strlen(input), changed); /* No local entropy filtering. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = sizeof("lunchmoney") - 1;
        memcpy(input, "lunchmoney", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, sizeof(key));
        extraction_case(detector, input, at + 50, gap == 40 ? key : NULL);
        at = sizeof("lunchmoney") - 1;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, sizeof(key));
        extraction_case(detector, input, at + 50, gap == 40 ? key : NULL);
    }
    memcpy(input, "lunchmoney", 10); input[10] = '\0'; input[11] = '\n'; input[12] = '\r';
    memcpy(input + 13, key, sizeof(key)); extraction_case(detector, input, 13 + 50, key);
    snprintf(input, sizeof(input), "lunchmoney %s %s", key, other);
    extraction_case(detector, input, strlen(input), key);
    extraction_case(detector, NULL, 0, NULL);

    snprintf(input, sizeof(input), "lunchmoney %s\nlunchmoney %s\nlunchmoney %s", key, other, key);
    const char *keys[] = {key, other, key};
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    const int *send_codes;
    size_t nkeys, initial_len, release_len, failed_sends, next_deferred;
    bool releasing_deferred;
    const char *authorization[3], *urls[3];
    unsigned char markers[3];
} wire_case;

static void authorization_is(const char *value, const char *expected)
{
    CHECK(value && !strncmp(value, "Bearer ", 7) && !strcmp(value + 7, expected));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *wire = http->user;
    size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(i < wire->nkeys && wire->nkeys <= 3 && !wire->releasing_deferred);
    CHECK(wire->published->len == wire->initial_len + i);
    CHECK(http->releases == wire->failed_sends);
    if (wire->send_codes) {
        http->send_rc = wire->send_codes[i];
        http->send_error = http->send_rc ? "synthetic mixed Do failure" : NULL;
    }
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, categories_url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 797);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization_is(request->headers[0].value, wire->keys[i]);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog lunchmoney-test" : "TruffleHog"));
    /* Keep provider values only. Prepared request/header arrays and the shared
     * synthesized UA expire on send return and must never be retained. */
    wire->authorization[i] = request->headers[0].value;
    wire->urls[i] = request->url;
    wire->markers[i] = (unsigned char)i;
    http->response.body = (br_slice){wire->markers + i, 1};
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; wire_case *wire = http->user;
    if (!http->calls) {
        CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
        CHECK(wire->published->len == wire->initial_len);
    } else {
        CHECK(response->body.len == 1 && response->body.data);
        size_t i = response->body.data[0]; CHECK(i < http->calls);
        int send_rc = wire->send_codes ? wire->send_codes[i] : http->send_rc;
        authorization_is(wire->authorization[i], wire->keys[i]);
        CHECK(!strcmp(wire->urls[i], categories_url));
        if (send_rc) {
            CHECK(!wire->releasing_deferred && i + 1 == http->calls);
            CHECK(wire->published->len == wire->initial_len + i);
            ++wire->failed_sends;
        } else {
            if (!wire->releasing_deferred) { wire->next_deferred = http->calls; wire->releasing_deferred = true; }
            while (wire->next_deferred && wire->send_codes && wire->send_codes[wire->next_deferred - 1])
                --wire->next_deferred;
            CHECK(wire->next_deferred && --wire->next_deferred == i);
            CHECK(wire->published->len == wire->release_len);
            for (size_t j = 0; j <= i; ++j) if (!wire->send_codes || !wire->send_codes[j])
                authorization_is(wire->authorization[j], wire->keys[j]);
        }
    }
    test_http_release(http, response);
}

static br_transport wire_transport(wire_case *wire)
{
    wire->http.inspect = inspect_request; wire->http.user = wire;
    return (br_transport){&wire->http, test_http_send, release_response};
}

static void scan_into(const br_detector *detector, const br_scan_ctx *ctx, const char *input, br_results *results)
{
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, results, &error) == 0);
    CHECK(!error);
}

static void http_policy(const br_detector *detector)
{
    const char *keys[] = {key}; char input[96], sensitive[160];
    snprintf(input, sizeof(input), "lunchmoney %s", key);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read failure for %s", key);
    const struct { int status, rc; const char *cause; } cases[] = {
        {199, 0, NULL}, {200, 0, NULL}, {201, 0, NULL}, {204, 0, NULL}, {299, 0, NULL},
        {300, 0, NULL}, {401, 0, NULL}, {403, 0, NULL}, {429, 0, NULL}, {500, 0, NULL},
        {200, 1, sensitive}, {200, -1, "context canceled"}, {200, 7, "net/http: nil Context"},
        {200, -1, "out of memory constructing HTTP headers"}, {200, 1, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = {0};
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body_error = sensitive},
                     .send_rc = cases[i].rc, .send_error = cases[i].cause}};
        br_transport transport = wire_transport(&wire);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = i % 2 ? "lunchmoney-test" : NULL};
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && wire.http.calls == 1 && wire.http.releases == 1);
        result_is(&results.items[0], key, !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&results);
    }
    const char *multiple[] = {key, other, key}; const int mixed[] = {0, 1, 0};
    char repeated[256];
    snprintf(repeated, sizeof(repeated), "lunchmoney %s\nlunchmoney %s\nlunchmoney %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = {0};
        wire_case wire = {.published = &results, .keys = multiple, .nkeys = 3, .release_len = 3,
            .send_codes = mode == 2 ? mixed : NULL,
            .http = {.response = {.status = 299, .body_error = "ignored read error"},
                     .send_rc = mode == 1, .send_error = mode == 1 ? sensitive : NULL}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport};
        scan_into(detector, &ctx, repeated, &results);
        CHECK(results.len == 3 && wire.http.calls == 3 && wire.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result_is(&results.items[i], multiple[i], mode == 0 || (mode == 2 && !mixed[i]));
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void preparation_errors(const br_detector *detector)
{
    const char *keys[] = {key}; char input[96]; snprintf(input, sizeof(input), "lunchmoney %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        br_results results = {0}; wire_case wire = {.published = &results, .keys = keys, .nkeys = 1};
        br_transport transport = wire_transport(&wire);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        if (mode == 4) arm_headers = true;
        size_t before = failed_allocations;
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && !wire.http.calls && wire.http.releases == (mode == 2 ? 0u : 1u));
        CHECK(!arm_headers && !fail_after && failed_allocations == before + (mode == 4));
        result_is(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void nil_before_authorization(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "lunchmoney %s", key);
    br_results results = {0}; char *error = NULL;
    size_t before = failed_allocations;
    /* Arm the next allocation only after real finding/map construction. The
     * fixed-URL nil-context skip must not reach Bearer/request allocation. */
    fail_request_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == 0);
    CHECK(!error && !results.len && !fail_request_after && fail_next_malloc);
    CHECK(failed_allocations == before);
    fail_next_malloc = false;
    br_results_clear(&results);
}

static void owned_failures(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "lunchmoney %s\nlunchmoney %s", key, other);
    const char *keys[] = {key, other};
    for (int mode = 0; mode < 7; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 2, .initial_len = 1, .release_len = 2,
                          .http = {.response = {.status = 200}}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport};
        const char *expected;
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span); fail_after = 1;
            expected = "out of memory iterating regex"; /* Actual positive regex/capture failure. */
        } else if (mode == 1 || mode == 2 || mode == 6) {
            fail_part_after = mode == 2 ? 1 : 2;
            expected = "out of memory creating LunchMoney result";
        } else if (mode == 3) {
            fail_push_after = 2; expected = "out of memory appending LunchMoney result";
        } else {
            fail_request_after = mode == 4 ? 1 : 2;
            expected = "out of memory creating LunchMoney request";
        }
        char *error = NULL;
        int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 6,
            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_next_malloc && !fail_request_after);
        CHECK(results.len == 1 && results.items[0].detector_type == 12345 && results.items[0].verified);
        CHECK(results.items[0].raw.data == original_raw && results.items[0].raw.len == 4 && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
        CHECK(wire.http.calls == (mode == 1 || mode == 5 ? 1u : mode == 3 ? 2u : 0u) && wire.http.releases == wire.http.calls);
        free(error); br_results_clear(&results);
    }
    br_results results = {0}; char *error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &results, &error) == -1 && error);
    free(error); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); http_policy(detector); preparation_errors(detector);
    nil_before_authorization(detector); owned_failures(detector);
    CHECK(!setter_calls);
    return test_finish("LunchMoney lowerhex50, nil/auth order, deferred LIFO release and owned rollback");
}
