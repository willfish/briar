/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

int br_currencylayer_init(const br_detector **out, char **error);

static const char key[] = "g7h9j2k5m6n8p3q4r1s0t2u5v7w9x2y4";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7k6j5h4";
static const char url_prefix[] = "https://api.currencylayer.com/live?access_key=";
static const char success[] = "\"success\": true";
static const char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;
static size_t fail_format_after, format_failures, formatted_urls;
static bool truncate_format;

/* Interpose actual capture/finding/format boundaries, not a heap URL seam. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static bool fail_url_format(const char *format)
{
    if (strcmp(format, "https://api.currencylayer.com/live?access_key=%.*s")) return false;
    ++formatted_urls;
    if (!fail_format_after || --fail_format_after != 0) return false;
    ++format_failures;
    return true;
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
    if (fail_url_format(format)) return truncate_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buffer, size, format, args);
    va_end(args);
    return n;
}

#if defined(__GLIBC__) && defined(__USE_FORTIFY_LEVEL) && __USE_FORTIFY_LEVEL > 0
/* Nix hardening routes the same actual boundary through this fortified symbol. */
int __snprintf_chk(char *buffer, size_t size, int flag, size_t capacity, const char *format, ...)
{
    if (fail_url_format(format)) return truncate_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int n = __vsnprintf_chk(buffer, size, flag, capacity, format, args);
    va_end(args);
    return n;
}
#endif

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_currencylayer_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:currencylayer)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_currencylayer_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_currencylayer_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_currencylayer_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 354 && detector->version == 0 && !strcmp(detector->name, "Currencylayer"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "An API for converting and exchanging currencies. API keys can read currency data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "currencylayer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 354, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected, 32));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = formatted_urls;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && formatted_urls == before);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *accepted[] = {"currencylayer = '%s'", "CuRrEnCyLaYeR\r\n%s", "preCURRENCYLAYERsuffix:%s", "currencylayer\r%s", "currencylayer\n%s", "currencylayer-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s currencylayer", "currency layer %s", "currencylayer%s", "currencylayer _%s", "currencylayer %s_", "currencylayer x%s", "currencylayer %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "currencylayer%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "currencylayer %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0';
    snprintf(input, sizeof(input), "currencylayer %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "A_F-.:/";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = disallowed[i];
        snprintf(input, sizeof(input), "CURRENCYLAYER %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    const char low_entropy[] = {'a', 'z', '9'};
    for (size_t i = 0; i < sizeof(low_entropy); ++i) {
        memset(changed, low_entropy[i], 32); changed[32] = '\0';
        snprintf(input, sizeof(input), "currencylayer %s", changed); extraction_case(detector, input, strlen(input), changed);
    } /* Lower alphanumeric, not hex; no local FP/entropy filter. */
    snprintf(input, sizeof(input), "currencylayer %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches. */
    snprintf(input, sizeof(input), "currencylayer currencylayer %s", key);
    extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "currencylayer%c%s", 0, key);
    CHECK(n == 46); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
typedef struct {
    const char *key, *send_error, *read_error;
    int status, send_rc;
    br_slice body;
} reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[sizeof(url_prefix) + 32];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 354 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    size_t length = sizeof(url_prefix) - 1 + 32;
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "%s%s", url_prefix, step->key) == (int)length);
    CHECK(strlen(request->url) == length && !memcmp(request->url, steps->expected_url, length + 1));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog currencylayer-offline" : "TruffleHog"));
    /* Complete effective header set: no invented Auth, Type, Accept or CL. */
    steps->borrowed_url = request->url;
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == sizeof(url_prefix) - 1 + 32);
    CHECK(!strcmp(steps->borrowed_url, steps->expected_url));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void binary_markers_and_reads(const br_detector *detector)
{
    const struct { br_slice body; const char *read_error; bool verified; } cases[] = {
        {TEXT(success), NULL, true}, {TEXT(restricted), NULL, true},
        {TEXT("not JSON \"success\": true trailing"), NULL, true},
        {TEXT("\xff\0past NUL \"success\": true"), NULL, true},
        {TEXT("\0\xff\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, true},
        {TEXT("\"success\": trueish"), NULL, true},
        {{0}, NULL, false}, {TEXT(""), NULL, false},
        {TEXT("{\"success\":true}"), NULL, false}, {TEXT("{\"success\":  true}"), NULL, false},
        {TEXT("{\"success\":\ttrue}"), NULL, false}, {TEXT("{\"Success\": true}"), NULL, false},
        {TEXT("{\"success\": True}"), NULL, false}, {TEXT("\"success\": tru"), NULL, false},
        {TEXT("\"info\": \"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption\""), NULL, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support https Encryption.\""), NULL, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."), NULL, false},
        {TEXT(success), "read failure", false}, {TEXT(restricted), "", false},
        {TEXT(success), "", false}, {TEXT(""), "read failure", false},
    };
    char input[64]; snprintf(input, sizeof(input), "currencylayer %s", key);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .body = cases[i].body, .read_error = cases[i].read_error};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, cases[i].verified); br_results_clear(&results);
    }
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .body = status % 2 ? TEXT(restricted) : TEXT(success)};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i], .body = TEXT(success)};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    const char *keys[] = {key, other, key};
    unsigned char input[3 * 48 + 1]; size_t len = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, i == 1 ? "CURRENCYLAYER " : "currencylayer ", 14); len += 14;
        memcpy(input + len, keys[i], 32); len += 32;
        input[len++] = '\0'; input[len++] = i == 1 ? '\r' : '\n';
    }
    input[len++] = 0xff; /* Invalid bytes outside matches are not a global UTF-8 rejection. */
    br_slice data = {input, len};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "currencylayer-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .body = TEXT(success), .read_error = ""};
        steps.rows[1] = (reply){.key = other, .status = 204, .body = TEXT(restricted)};
        steps.rows[2] = (reply){.key = key, .status = 299, .body = TEXT(success)};
        br_results results = run(detector, data, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i != 0);
        br_results_clear(&results);
        size_t before = formatted_urls;
        results = test_scan(detector, NULL, verify, data.data, data.len);
        CHECK(results.len == (verify ? 0u : 3u) && formatted_urls == before + (verify ? 3u : 0u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
}

static void send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "currencylayer %s", key);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Currencylayer result", key, "unsupported native client configuration", "context canceled", "context deadline exceeded", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .body = TEXT(success), .read_error = i % 2 ? "" : NULL,
                                .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "currencylayer %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t before = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
    CHECK(results->items[0].secret_parts == parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "currencylayer %s\ncurrencylayer %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200, .body = TEXT(success)};
        steps.rows[1] = (reply){.key = other, .status = 200, .body = TEXT(restricted)};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        const char *expected[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create Currencylayer result", "cannot create Currencylayer result", "cannot format Currencylayer URL", "cannot format Currencylayer URL"};
        for (int failure = 0; failure < (mode == 0 ? 4 : 6); ++failure) {
            if (failure == 0) { fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; }
            if (failure == 1) { fail_alloc_size = 33; fail_alloc_after = 2; }
            /* Scratch spans are also 32 bytes; fail the second finding's Raw. */
            if (failure == 2) { fail_alloc_size = 32; fail_alloc_after = 3; }
            if (failure == 3) fail_part_after = 2;
            if (failure >= 4) { fail_format_after = 2; truncate_format = failure == 5; }
            size_t before = format_failures, before_urls = formatted_urls;
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_alloc_after && !fail_part_after && !fail_format_after);
            CHECK(!strcmp(error, expected[failure]) && format_failures == before + (failure >= 4 ? 1u : 0u));
            CHECK(formatted_urls == before_urls + (mode == 0 || failure < 2 ? 0u : failure < 4 ? 1u : 2u));
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* The actual append guard returns +1: normalize it to fatal -1. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append Currencylayer result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(results.len == 2); check_result(&results.items[0], key, false); check_result(&results.items[1], other, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); binary_markers_and_reads(detector); occurrences_and_nil_context(detector);
    send_errors(detector); combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("Currencylayer");
}
