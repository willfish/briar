/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_logzio_init(const br_detector **out, char **error);

/* Established named-test seams leave production extraction, findings and HTTP
 * linked while observing conditional setter order and positive owned failures. */
#define br_results_push logzio_real_push
#define br_result_set_verification_error logzio_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

/* Existing named-test inclusion seam makes formatter return faults observable:
 * GCC proves this fixed ASCII format cannot fail and removes builtin checks. */
static int checked_status_format(char *, size_t, const char *, ...);
#define snprintf checked_status_format
#define br_logzio_init observed_logzio_init
#include "../../src/detectors/logzio.c"
#undef snprintf
#undef br_logzio_init

static const char key[] = "g1234567-89az-cdef-g123-456789abcxyz";
static const char other[] = "z7654321-za98-fedc-z321-zyxcba987654";
static const char whoami_url[] = "https://api.logz.io/v2/whoami";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_request_after, fail_setter_after;
static size_t failed_allocations, setter_calls, null_setters;
static bool fail_next_malloc, arm_headers, fail_status_copy, fail_send_fallback;
static int fail_status_format;
static br_results *setter_published;
static test_http *setter_http;
static size_t setter_initial_len;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false; ++failed_allocations; return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if ((fail_status_copy && !strncmp(text, "unexpected HTTP response status ", 32)) ||
        (fail_send_fallback && !strcmp(text, "HTTP transport failed"))) {
        fail_status_copy = false; fail_send_fallback = false; ++failed_allocations; return NULL;
    }
    size_t size = strlen(text) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

static int checked_status_format(char *out, size_t size, const char *format, ...)
{
    CHECK(!strcmp(format, "unexpected HTTP response status %d"));
    if (fail_status_format) {
        int mode = fail_status_format; fail_status_format = 0;
        return mode == 1 ? -1 : (int)size;
    }
    va_list args; va_start(args, format); int rc = vsnprintf(out, size, format, args); va_end(args);
    return rc;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "key")) {
        if (fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
        if (arm_headers) { arm_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
    }
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return logzio_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls; if (!cause) ++null_setters;
    CHECK(!result->verified && result->raw.len == 36 && count == 1 && secrets && secrets[0].len == 36);
    CHECK(!memcmp(result->raw.data, secrets[0].data, 36));
    if (setter_published) {
        CHECK(setter_http);
        CHECK(setter_published->len == setter_initial_len + (setter_http->calls ? setter_http->calls - 1 : 0));
    }
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return logzio_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_logzio_init(NULL, &error) == -1 && error && !strcmp(error, "invalid LogzIO detector output"));
    free(error); error = NULL; CHECK(br_logzio_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:logz)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_logzio_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_logzio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_logzio_init(&again, &error) == 0 && again == detector && !error);
    CHECK(br_logzio_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 961 && detector->version == 0 && !strcmp(detector->name, "LogzIO"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Logz.io is a cloud observability platform for log analysis and monitoring. "
        "Logz.io API tokens can be used to access and manage log data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "logz"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result_is(const br_result *result, const char *expected, bool verified, const char *error)
{
    test_key_result(result, 961, expected, "key");
    CHECK(result->raw.len == 36 && result->verified == verified);
    CHECK(error ? result->verification_error && !strcmp(result->verification_error, error) : !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    size_t before = setter_calls;
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected) result_is(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], changed[37];
    snprintf(input, sizeof(input), "logz = '%s'", key); extraction_case(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "preLoGzsuffix:\r\n'%s'", key); extraction_case(detector, input, strlen(input), key);
    extraction_case(detector, key, strlen(key), NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = 'A';
    snprintf(input, sizeof(input), "LOGZ %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = '_';
    snprintf(input, sizeof(input), "logz %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[8] = 'a';
    snprintf(input, sizeof(input), "logz %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[35] = '\0';
    snprintf(input, sizeof(input), "logz %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "logz _%s", key); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "logz %s_", key); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "logz %s0", key); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "logz \xc3\xa9%s\xc3\xa9", key); extraction_case(detector, input, strlen(input), key);
    const char low[] = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
    snprintf(input, sizeof(input), "logz %s", low); extraction_case(detector, input, strlen(input), low);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 4; memcpy(input, "logz", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, sizeof(key)); extraction_case(detector, input, at + 36, gap == 40 ? key : NULL);
        at = 4;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, sizeof(key)); extraction_case(detector, input, at + 36, gap == 40 ? key : NULL);
    }
    memcpy(input, "logz", 4); input[4] = '\0'; input[5] = '\n'; input[6] = '\r';
    memcpy(input + 7, key, sizeof(key)); extraction_case(detector, input, 7 + 36, key);
    extraction_case(detector, NULL, 0, NULL);
    snprintf(input, sizeof(input), "logz %s\nlogz %s\nlogz %s", key, other, key);
    size_t before = setter_calls; const char *keys[] = {key, other, key};
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&results.items[i], keys[i], false, NULL);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && setter_calls == before); br_results_clear(&results);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    const int *send_codes, *statuses;
    size_t nkeys, initial_len, release_len, failed_sends, next_deferred, setter_start, setters_before[3];
    bool releasing_deferred;
    const char *tokens[3], *urls[3];
    unsigned char markers[3];
} wire_case;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *wire = http->user; size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(i < wire->nkeys && wire->nkeys <= 3 && !wire->releasing_deferred);
    CHECK(wire->published->len == wire->initial_len + i && http->releases == wire->failed_sends);
    if (wire->send_codes) {
        http->send_rc = wire->send_codes[i]; http->send_error = http->send_rc ? "synthetic mixed Do failure" : NULL;
    }
    if (wire->statuses) http->response.status = wire->statuses[i];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, whoami_url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 961);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "X-Api-Token"));
    CHECK(!strcmp(request->headers[0].value, wire->keys[i]));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog logzio-test" : "TruffleHog"));
    /* Only original provider values survive send return, not prepared headers,
     * synthesized UA or the effective request object. */
    wire->tokens[i] = request->headers[0].value; wire->urls[i] = request->url;
    wire->setters_before[i] = setter_calls; wire->markers[i] = (unsigned char)i;
    http->response.body = (br_slice){wire->markers + i, 1};
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; wire_case *wire = http->user;
    if (!http->calls) {
        CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
        CHECK(wire->published->len == wire->initial_len && setter_calls == wire->setter_start + 1);
    } else {
        CHECK(response->body.len == 1 && response->body.data);
        size_t i = response->body.data[0]; CHECK(i < http->calls);
        int send_rc = wire->send_codes ? wire->send_codes[i] : http->send_rc;
        CHECK(!strcmp(wire->tokens[i], wire->keys[i]) && !strcmp(wire->urls[i], whoami_url));
        if (send_rc) {
            CHECK(!wire->releasing_deferred && i + 1 == http->calls);
            CHECK(wire->published->len == wire->initial_len + i && setter_calls == wire->setters_before[i] + 1);
            ++wire->failed_sends;
        } else {
            if (!wire->releasing_deferred) { wire->next_deferred = http->calls; wire->releasing_deferred = true; }
            while (wire->next_deferred && wire->send_codes && wire->send_codes[wire->next_deferred - 1]) --wire->next_deferred;
            CHECK(wire->next_deferred && --wire->next_deferred == i);
            CHECK(wire->published->len == wire->release_len);
            for (size_t j = 0; j <= i; ++j) if (!wire->send_codes || !wire->send_codes[j])
                CHECK(!strcmp(wire->tokens[j], wire->keys[j]));
        }
    }
    test_http_release(http, response);
}

static br_transport wire_transport(wire_case *wire)
{
    wire->http.inspect = inspect_request; wire->http.user = wire; wire->setter_start = setter_calls;
    setter_published = wire->published; setter_http = &wire->http; setter_initial_len = wire->initial_len;
    return (br_transport){&wire->http, test_http_send, release_response};
}

static void scan_into(const br_detector *detector, const br_scan_ctx *ctx, const char *input, br_results *results)
{
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, results, &error) == 0 && !error);
    setter_published = NULL; setter_http = NULL;
}

static void http_policy(const br_detector *detector)
{
    const char *keys[] = {key}; char input[80], sensitive[192], redacted[192];
    snprintf(input, sizeof(input), "logz %s", key);
    snprintf(sensitive, sizeof(sensitive), "dial %s then %s other=%s", key, key, other);
    snprintf(redacted, sizeof(redacted), "dial [REDACTED] then [REDACTED] other=%s", other);
    const struct { int status, rc; const char *cause, *expected; } cases[] = {
        {199, 0, NULL, "unexpected HTTP response status 199"}, {200, 0, NULL, NULL}, {201, 0, NULL, NULL},
        {204, 0, NULL, NULL}, {299, 0, NULL, NULL}, {300, 0, NULL, "unexpected HTTP response status 300"},
        {401, 0, NULL, NULL}, {403, 0, NULL, "unexpected HTTP response status 403"},
        {500, 0, NULL, "unexpected HTTP response status 500"}, {200, 1, sensitive, redacted},
        {200, -1, "context canceled", "context canceled"}, {200, 7, "net/http: nil Context", "net/http: nil Context"},
        {200, -1, "out of memory constructing HTTP headers", "out of memory constructing HTTP headers"},
        {200, 1, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = {0}; size_t before = setter_calls;
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body_error = sensitive}, .send_rc = cases[i].rc, .send_error = cases[i].cause}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport, .user_agent = i % 2 ? "logzio-test" : NULL};
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && wire.http.calls == 1 && wire.http.releases == 1 && setter_calls == before + (cases[i].expected != NULL));
        result_is(&results.items[0], key, !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300, cases[i].expected);
        br_results_clear(&results);
    }
    br_results results = {0}; size_t before = setter_calls, null_before = null_setters;
    wire_case missing = {.published = &results, .keys = keys, .nkeys = 1, .http = {.send_rc = 1, .response = {.status = 200}}};
    br_transport transport = wire_transport(&missing); br_scan_ctx ctx = {.transport = &transport}; fail_send_fallback = true;
    scan_into(detector, &ctx, input, &results);
    CHECK(results.len == 1 && !fail_send_fallback && setter_calls == before + 1 && null_setters == null_before + 1);
    CHECK(missing.http.calls == 1 && missing.http.releases == 1); result_is(&results.items[0], key, false, NULL); br_results_clear(&results);

    const char *multiple[] = {key, other, key}; const int statuses[] = {200, 401, 503}, mixed[] = {0, 1, 0};
    char repeated[160]; snprintf(repeated, sizeof(repeated), "logz %s\nlogz %s\nlogz %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        results = (br_results){0}; before = setter_calls;
        wire_case wire = {.published = &results, .keys = multiple, .nkeys = 3, .release_len = 3,
            .statuses = statuses, .send_codes = mode == 2 ? mixed : NULL,
            .http = {.send_rc = mode == 1, .send_error = mode == 1 ? "synthetic Do failure" : NULL}};
        transport = wire_transport(&wire); ctx = (br_scan_ctx){.transport = &transport}; scan_into(detector, &ctx, repeated, &results);
        CHECK(results.len == 3 && wire.http.calls == 3 && wire.http.releases == 3 && setter_calls == before + (mode == 0 ? 1u : mode == 1 ? 3u : 2u));
        for (size_t i = 0; i < 3; ++i) {
            const char *expected = mode == 1 ? "synthetic Do failure" : mode == 2 && i == 1 ? "synthetic mixed Do failure" : i == 2 ? "unexpected HTTP response status 503" : NULL;
            result_is(&results.items[i], multiple[i], mode != 1 && i == 0, expected);
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preparation_errors(const br_detector *detector)
{
    const char *keys[] = {key}, *errors[] = {"context canceled", "context deadline exceeded", "HTTP transport not installed", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    char input[80]; snprintf(input, sizeof(input), "logz %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        br_results results = {0}; wire_case wire = {.published = &results, .keys = keys, .nkeys = 1}; size_t before = setter_calls;
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        if (mode == 4) arm_headers = true;
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && !wire.http.calls && wire.http.releases == (mode == 2 ? 0u : 1u) && setter_calls == before + 1);
        CHECK(!arm_headers && !fail_after); result_is(&results.items[0], key, false, errors[mode]); br_results_clear(&results);
    }
}

static void nil_before_headers(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "logz %s", key); br_results results = {0}; char *error = NULL;
    size_t before = setter_calls, allocations = failed_allocations; fail_request_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0);
    CHECK(!error && !results.len && !fail_request_after && fail_next_malloc && setter_calls == before && failed_allocations == allocations);
    fail_next_malloc = false; br_results_clear(&results);
}

static void owned_failures(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "logz %s\nlogz %s", key, other);
    const char *keys[] = {key, other}; const int statuses[] = {200, 503}, mixed[] = {0, 1};
    const br_detector *format_detector = NULL; char *format_error = NULL;
    CHECK(observed_logzio_init(&format_detector, &format_error) == 0 && format_detector && !format_error);
    for (int mode = 0; mode < 13; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); size_t before = setter_calls;
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 2, .initial_len = 1, .release_len = 2,
            .statuses = mode >= 7 && mode != 10 && mode != 11 ? statuses : NULL, .send_codes = mode == 10 ? mixed : NULL,
            .http = {.response = {.status = 200}, .send_rc = mode == 11}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport}; const char *expected;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (mode == 1 || mode == 2 || mode == 6) { fail_part_after = mode == 2 ? 1 : 2; expected = "out of memory creating LogzIO result"; }
        else if (mode == 3) { fail_push_after = 2; expected = "out of memory appending LogzIO result"; }
        else if (mode == 4 || mode == 5) { fail_request_after = mode == 4 ? 1 : 2; expected = "out of memory creating LogzIO request"; }
        else if (mode == 7 || mode == 12) { fail_status_format = mode == 7 ? 1 : 2; expected = "cannot format LogzIO HTTP status"; }
        else {
            expected = "cannot set LogzIO verification error";
            if (mode == 8) fail_status_copy = true; else fail_setter_after = 1;
            if (mode == 11) fail_send_fallback = true;
        }
        char *error = NULL;
        const br_detector *selected = mode == 7 || mode == 12 ? format_detector : detector;
        int rc = selected->scan(selected, mode == 2 ? NULL : &ctx, mode != 6,
            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        setter_published = NULL; setter_http = NULL;
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_next_malloc && !fail_request_after && !fail_setter_after);
        CHECK(!fail_status_copy && !fail_send_fallback && !fail_status_format);
        CHECK(results.len == 1 && results.items[0].detector_type == 12345 && results.items[0].verified);
        CHECK(results.items[0].raw.data == original_raw && results.items[0].raw.len == 4 && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
        size_t calls = mode == 1 || mode == 5 || mode == 11 ? 1u : mode == 3 || mode >= 7 ? 2u : 0u;
        CHECK(wire.http.calls == calls && wire.http.releases == calls);
        CHECK(setter_calls == before + (mode >= 8 && mode <= 11 ? 1u : 0u));
        free(error); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); http_policy(detector); preparation_errors(detector); nil_before_headers(detector); owned_failures(detector);
    return test_finish("LogzIO conditional setters, canonical headers, deferred LIFO and owned rollback");
}
