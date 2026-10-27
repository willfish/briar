/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

int br_countrylayer_init(const br_detector **out, char **error);

static const char key[] = "g7h9j2k5m6n8p3q4r1s0t2u5v7w9x2y4";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7k6j5h4";
static const char url_prefix[] = "https://api.countrylayer.com/v2/all?access_key=";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;
static size_t fail_format_after, format_failures, formatted_urls;
static bool truncate_format;

/* Interpose real resource boundaries, not an invented URL allocation/API. */
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
    if (strcmp(format, "https://api.countrylayer.com/v2/all?access_key=%.*s")) return false;
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
/* Nix hardening routes the same real boundary through this fortified symbol. */
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
    CHECK(br_countrylayer_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:countrylayer)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_countrylayer_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_countrylayer_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_countrylayer_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 526 && detector->version == 0 && !strcmp(detector->name, "CountryLayer"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "CountryLayer is a service that provides information about countries. CountryLayer API keys can be used to access this information."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "countrylayer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 526, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected, 32));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *accepted[] = {"countrylayer = '%s'", "CoUnTrYlAyEr\r\n%s", "preCOUNTRYLAYERsuffix:%s", "countrylayer\r%s", "countrylayer\n%s", "countrylayer-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s countrylayer", "country layer %s", "countrylayer%s", "countrylayer _%s", "countrylayer %s_", "countrylayer x%s", "countrylayer %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "countrylayer%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "countrylayer %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0';
    snprintf(input, sizeof(input), "countrylayer %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "A_F-.:/";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = disallowed[i];
        snprintf(input, sizeof(input), "COUNTRYLAYER %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "countrylayer %s", changed); extraction_case(detector, input, strlen(input), changed); /* No local FP/entropy filter. */
    memset(changed, '9', 32);
    snprintf(input, sizeof(input), "countrylayer %s", changed); extraction_case(detector, input, strlen(input), changed);
    snprintf(input, sizeof(input), "countrylayer %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches, not all nearby keys. */
    snprintf(input, sizeof(input), "countrylayer countrylayer %s", key);
    extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "countrylayer%c%s", 0, key);
    CHECK(n == 45); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc, body_kind; } reply;
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
    CHECK(request->detector_type == 526 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    size_t length = sizeof(url_prefix) - 1 + 32;
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "%s%s", url_prefix, step->key) == (int)length);
    CHECK(strlen(request->url) == length && !memcmp(request->url, steps->expected_url, length + 1));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog countrylayer-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status,
        .body = step->body_kind == 0 ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->body_kind == 0 ? NULL : step->body_kind == 1 ? "" : "synthetic ignored body read error",
    };
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

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "countrylayer %s\nCOUNTRYLAYER %s\ncountrylayer %s", key, other, key);
    const char *keys[] = {key, other, key};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "countrylayer-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 204};
        steps.rows[2] = (reply){.key = key, .status = 299, .send_rc = -7, .send_error = "context canceled"};
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i == 1);
        br_results_clear(&results);
        size_t before = formatted_urls;
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == (verify ? 0u : 3u) && formatted_urls == before + (verify ? 3u : 0u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
    script steps = {.count = 3};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = 200};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], true); /* No cache/uniqueness. */
    br_results_clear(&results);
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "countrylayer %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .body_kind = status % 3};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i], .body_kind = 2};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create CountryLayer result", "synthetic access_key=g7h9j2k5m6n8p3q4r1s0t2u5v7w9x2y4", "unsupported native client configuration", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, input, true, &steps);
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
    char input[64]; snprintf(input, sizeof(input), "countrylayer %s", key);
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
    char input[128]; snprintf(input, sizeof(input), "countrylayer %s\ncountrylayer %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        const char *expected[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create CountryLayer result", "cannot create CountryLayer result", "cannot format CountryLayer URL", "cannot format CountryLayer URL"};
        for (int failure = 0; failure < (mode == 0 ? 4 : 6); ++failure) {
            if (failure == 0) { fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; }
            if (failure == 1) { fail_alloc_size = 33; fail_alloc_after = 2; }
            /* Scratch spans are also 32 bytes; fail the second finding's Raw. */
            if (failure == 2) { fail_alloc_size = 32; fail_alloc_after = 3; }
            if (failure == 3) fail_part_after = 2;
            if (failure >= 4) { fail_format_after = 2; truncate_format = failure == 5; }
            size_t before = format_failures;
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_alloc_after && !fail_part_after && !fail_format_after);
            CHECK(!strcmp(error, expected[failure]) && format_failures == before + (failure >= 4 ? 1u : 0u));
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* The real append guard returns positive +1: normalize to fatal -1. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append CountryLayer result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("CountryLayer");
}
