/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <limits.h>

static char key[49], other[49], case_key[49];
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Fail actual shared resources, not invented auth copies or formatting seams. */
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

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 48 && strlen(other) == 48 && strlen(case_key) == 48);
    CHECK(br_currentsapi_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:currentsapi)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_currentsapi_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_currentsapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_currentsapi_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 403 && detector->version == 0 && !strcmp(detector->name, "CurrentsAPI"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "CurrentsAPI provides access to the latest news and trends. CurrentsAPI keys can be used to authenticate requests and retrieve news data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "currentsapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *error)
{
    test_key_result(result, 403, expected, "key");
    CHECK(result->raw.len == 48 && result->verified == verified);
    CHECK(error ? result->verification_error && !strcmp(result->verification_error, error) : !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 48 && !memcmp(json_object_get_string(part), expected, 48));
}

static const br_result *find_result(const br_results *results, const char *expected)
{
    const br_result *found = NULL;
    for (size_t i = 0; i < results->len; ++i) {
        if (results->items[i].raw.len == 48 && !memcmp(results->items[i].raw.data, expected, 48)) {
            CHECK(!found); found = &results->items[i];
        }
    }
    CHECK(found); return found;
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[50];
    const char *accepted[] = {"currentsapi = '%s'", "CuRrEnTsApI\r\n%s", "precurrentsapisuffix:%s", "currentsapi\r%s", "currentsapi\n%s", "currentsapi%s", "currentsapi %sX", "currentsapi %s_", "currentsapi %s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s currentsapi", "currents-api %s", "currents api %s"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    /* No boundaries at either end. Valid leading bytes become part of the
     * capture; a longer valid run is truncated to its first 48 bytes. */
    const char leading[] = "X_-";
    for (size_t i = 0; i < sizeof(leading) - 1; ++i) {
        changed[0] = leading[i]; memcpy(changed + 1, key, 47); changed[48] = '\0';
        snprintf(input, sizeof(input), "currentsapi%c%s", leading[i], key);
        extraction_case(detector, input, strlen(input), changed);
    }
    memcpy(changed, key, sizeof(key)); changed[47] = '\0';
    snprintf(input, sizeof(input), "currentsapi %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[48] = '9'; changed[49] = '\0';
    snprintf(input, sizeof(input), "currentsapi %s", changed); extraction_case(detector, input, strlen(input), key);
    const char invalid[] = ".:/= ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[24] = invalid[i];
        snprintf(input, sizeof(input), "currentsapi %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = '-'; changed[47] = '_';
    snprintf(input, sizeof(input), "currentsapi %s", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, '-', 48); changed[48] = '\0';
    snprintf(input, sizeof(input), "currentsapi %s", changed); extraction_case(detector, input, strlen(input), changed); /* No trimming/entropy/FP filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "currentsapi%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
        memcpy(input, "currentsapi", 11);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 11 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 11 + 2 * gap, key, sizeof(key));
        extraction_case(detector, input, 11 + 2 * gap + 48, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "currentsapi %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* One non-overlapping whole match. */
    int n = snprintf(input, sizeof(input), "currentsapi%c%s", 0, key);
    CHECK(n == 60); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%ccurrentsapi %s%c", 0xff, key, 0xff);
    CHECK(n == 62); extraction_case(detector, input, (size_t)n, key); /* No whole-input UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error, *body_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    reply rows[3];
    size_t count, seen, current;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth, *agent_suffix;
    size_t fail_setter_on_call, setter_failure_size, failures_before;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(http->calls <= steps->count && ctx == steps->expected_ctx && http->releases == http->calls - 1);
    CHECK(request->detector_type == 403 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.currentsapi.services/v1/latest-news"));
    /* ABI1 proves only empty body bytes, not source http.NoBody identity. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 48);
    size_t row = 0;
    while (row < steps->count && strcmp(request->headers[0].value, steps->rows[row].key)) ++row;
    CHECK(row < steps->count && row < 3 && !(steps->seen & ((size_t)1 << row)));
    steps->seen |= (size_t)1 << row; steps->current = row;
    CHECK(!memcmp(request->headers[0].value, steps->rows[row].key, 49)); /* Token itself, no Bearer. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->agent_suffix ? "TruffleHog currentsapi-offline" : "TruffleHog"));
    /* The exact header count excludes invented Type, Accept and logical CL. */
    steps->borrowed_auth = request->headers[0].value;
    reply *step = &steps->rows[row];
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status, .body_error = step->body_error,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
    };
    http->send_rc = step->send_rc; http->send_error = step->send_error;
    if (steps->fail_setter_on_call == http->calls) {
        fail_alloc_size = steps->setter_failure_size; fail_alloc_after = 1;
        steps->failures_before = allocation_failures;
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && strlen(steps->borrowed_auth) == 48);
    CHECK(!memcmp(steps->borrowed_auth, steps->rows[steps->current].key, 49));
    if (steps->fail_setter_on_call == http->calls)
        CHECK(!fail_alloc_after && allocation_failures == steps->failures_before + 1); /* Setter before release. */
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    CHECK(steps->seen == ((size_t)1 << steps->count) - 1);
    return results;
}

static void unique_tokens_and_nil_context(const br_detector *detector)
{
    char input[320]; snprintf(input, sizeof(input), "currentsapi %s\nCURRENTSAPI %s\ncurrentsapi %s\ncurrentsapi %s", key, other, key, case_key);
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "currentsapi-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .body_error = "ignored read error"};
        steps.rows[1] = (reply){.key = other, .status = 401, .body_error = ""};
        steps.rows[2] = (reply){.key = case_key, .status = 503};
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3);
        check_result(find_result(&results, key), key, verify, NULL);
        check_result(find_result(&results, other), other, false, NULL);
        check_result(find_result(&results, case_key), case_key, false, verify ? "unexpected status code: 503" : NULL);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == 3);
        const char *tokens[] = {key, other, case_key};
        for (size_t i = 0; i < 3; ++i)
            check_result(find_result(&results, tokens[i]), tokens[i], false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&results);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[80], expected[64]; snprintf(input, sizeof(input), "currentsapi %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .body_error = status % 2 ? "" : "synthetic ignored read error", .nil_body = status % 3 == 0};
        snprintf(expected, sizeof(expected), "unexpected status code: %d", status);
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, status == 200, status == 200 ? NULL : expected);
        br_results_clear(&results);
    }
    const int others[] = {INT_MIN, -1, 0, 199, 300, 301, 400, 401, 403, 429, 500, 503, INT_MAX};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = others[i], .body_error = "ignored"};
        snprintf(expected, sizeof(expected), "unexpected status code: %d", others[i]);
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false, others[i] == 401 ? NULL : expected);
        br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create CurrentsAPI result", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i], .body_error = "ignored after failed send"};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false, causes[i] ? causes[i] : "HTTP transport failed");
        br_results_clear(&results);
    }
    /* Only the current token is redacted, not independent candidates or a
     * differently-cased token; all repeats of the current token are replaced. */
    char combined[160], cause[2][256], redacted[2][256];
    snprintf(combined, sizeof(combined), "currentsapi %s\ncurrentsapi %s", key, other);
    snprintf(cause[0], sizeof(cause[0]), "failed %s twice %s; other %s; case %s", key, key, other, case_key);
    snprintf(redacted[0], sizeof(redacted[0]), "failed [REDACTED] twice [REDACTED]; other %s; case %s", other, case_key);
    snprintf(cause[1], sizeof(cause[1]), "failed %s twice %s; other %s", other, other, key);
    snprintf(redacted[1], sizeof(redacted[1]), "failed [REDACTED] twice [REDACTED]; other %s", key);
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .send_rc = 1, .send_error = cause[0]};
    steps.rows[1] = (reply){.key = other, .send_rc = -1, .send_error = cause[1]};
    br_results results = run(detector, combined, true, &steps);
    CHECK(results.len == 2);
    check_result(find_result(&results, key), key, false, redacted[0]);
    check_result(find_result(&results, other), other, false, redacted[1]); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = 2 * sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "currentsapi %s", key);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
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
        check_result(&results.items[0], key, false, causes[mode]); br_results_clear(&results);
    }
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&results, &prior) == 0); return results;
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
    char input[160]; snprintf(input, sizeof(input), "currentsapi %s\ncurrentsapi %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, true, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = prior_result();
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) fail_part_after = 2; /* One finding already appended, even with nil context. */
            else {
                fail_alloc_size = failure == 1 ? 48 : failure == 2 ? 49 : failure == 3 ? 2 * sizeof(br_span) : 8 * sizeof(char *);
                fail_alloc_after = failure == 2 ? 2 : 1;
            }
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_part_after && !fail_alloc_after);
            const char *expected = failure < 2 ? "cannot create CurrentsAPI result" : failure == 2 ? "out of memory copying detector capture" : failure == 3 ? "out of memory iterating regex" : "out of memory collecting detector captures";
            CHECK(!strcmp(error, expected));
            CHECK(http.calls == (mode == 1 && failure == 0 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = steps.seen = 0;
        }
        size_t capacity = results.cap; results.cap = 0; /* Genuine positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append CurrentsAPI result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL; br_results_clear(&results);
    }
}

static void setter_failures(const br_detector *detector)
{
    char input[160], cause[2][192], redacted[192];
    snprintf(input, sizeof(input), "currentsapi %s\ncurrentsapi %s", key, other);
    snprintf(cause[0], sizeof(cause[0]), "failed %s twice %s; other %s", key, key, other);
    snprintf(cause[1], sizeof(cause[1]), "failed %s twice %s; other %s", other, other, key);
    snprintf(redacted, sizeof(redacted), "failed [REDACTED] twice [REDACTED]; other %s", other);
    br_result probe = {0}; br_slice token = {(const unsigned char *)key, 48};
    fail_alloc_size = strlen(redacted) + 1; fail_alloc_after = 1;
    CHECK(br_result_set_verification_error(&probe, cause[0], &token, 1) == 1 && !fail_alloc_after && !probe.verification_error);
    br_result_clear(&probe);
    for (int mode = 0; mode < 2; ++mode) {
        script steps = {.count = 2, .fail_setter_on_call = 2, .setter_failure_size = strlen(redacted) + 1};
        steps.rows[0] = (reply){.key = key, .send_rc = 1, .send_error = cause[0]};
        steps.rows[1] = (reply){.key = other, .send_rc = -1, .send_error = cause[1]};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = prior_result();
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        if (mode == 1) { /* The second nil-context cause-copy allocation fails after one append. */
            fail_alloc_size = sizeof("net/http: nil Context"); fail_alloc_after = 2;
        }
        char *error = NULL;
        CHECK(detector->scan(detector, mode ? NULL : &ctx, true,
                            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot sanitize CurrentsAPI verification error") && !fail_alloc_after);
        CHECK(http.calls == (mode ? 0u : 2u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, prior_error, parts);
        free(error); br_results_clear(&results);
    }
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 401};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2); check_result(find_result(&results, key), key, true, NULL);
    check_result(find_result(&results, other), other, false, NULL); br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 48, 0); test_secret(other, 48, 13);
    key[0] = 'G'; key[7] = '_'; key[17] = 'H'; key[29] = '-'; key[47] = 'T';
    other[5] = 'Z'; other[19] = '_'; other[35] = '-';
    memcpy(case_key, key, sizeof(key)); case_key[0] = 'g';
    const br_detector *detector = descriptor();
    extraction(detector); unique_tokens_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector); setter_failures(detector);
    return test_finish("CurrentsAPI");
}
