/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

#define SLICE(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
static const char key[] = "0123456789abcdef0123456789abcdef";
static const char other[] = "fedcba9876543210fedcba9876543210";
static const char id[] = "z9y8x7w6v5u4t3s2";
static const char other_id[] = "m0n1o2p3q4r5s6t7";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32 && strlen(id) == 16 && strlen(other_id) == 16);
    CHECK(br_braintreepayments_init(NULL, &error) == -1 && error && !strcmp(error, "invalid BraintreePayments detector output")); free(error); error = NULL;
    CHECK(!br_braintreepayments_init(&detector, &error) && detector && !error);
    CHECK(!br_braintreepayments_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 828 && detector->version == 0 && !strcmp(detector->name, "BraintreePayments"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Braintree is a full-stack payment platform that makes it easy to accept payments in your mobile app or website. Braintree API keys can be used to access and manage payment transactions, customer data, and other payment-related operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "braintree"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void input_for(char *out, size_t size, const char *const *keys, size_t nkeys, const char *const *ids, size_t nids)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < nkeys + nids; ++i) {
        const char *value = i < nkeys ? keys[i] : ids[i - nkeys];
        int n = snprintf(out + at, size - at, "braintree %s\n", value); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *private_key, const char *public_id, bool matched)
{
    char input[256]; const char *keys[] = {private_key}, *ids[] = {public_id};
    input_for(input, sizeof(input), keys, 1, ids, 1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (matched ? 1u : 0u));
    if (matched) { test_key_result(&results.items[0], 828, private_key, "key"); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    extraction_case(detector, key, id, true); /* Public ID is lower alphanumeric, not hex-only. */
    char changed[35]; memcpy(changed, key, sizeof(key)); changed[8] = 'A'; extraction_case(detector, changed, id, false);
    memcpy(changed, key, sizeof(key)); changed[8] = 'g'; extraction_case(detector, changed, id, false);
    memcpy(changed, key, sizeof(key)); changed[31] = '\0'; extraction_case(detector, changed, id, false);
    snprintf(changed, sizeof(changed), "%s0", key); extraction_case(detector, changed, id, false);
    char changed_id[18]; memcpy(changed_id, id, sizeof(id)); changed_id[0] = 'Z'; extraction_case(detector, key, changed_id, false);
    memcpy(changed_id, id, sizeof(id)); changed_id[8] = '_'; extraction_case(detector, key, changed_id, false);
    memcpy(changed_id, id, sizeof(id)); changed_id[15] = '\0'; extraction_case(detector, key, changed_id, false);
    snprintf(changed_id, sizeof(changed_id), "%s0", id); extraction_case(detector, key, changed_id, false);
    memset(changed, 'a', 32); changed[32] = '\0'; memset(changed_id, 'z', 16); changed_id[16] = '\0';
    extraction_case(detector, changed, changed_id, true); /* No entropy filter. */
    char input[1024]; const char *keys[] = {key}, *ids[] = {id};
    input_for(input, sizeof(input), keys, 1, NULL, 0); br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    input_for(input, sizeof(input), NULL, 0, ids, 1); results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "BRAINTREE%*s%s\n%80sbraintree %s", gap, "", key, "", id);
        results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (gap == 40 ? 1u : 0u)); br_results_clear(&results);
        snprintf(input, sizeof(input), "braintree %s\n%80sBRAINTREE%*s%s", key, "", gap, "", id);
        results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (gap == 40 ? 1u : 0u)); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "braintree _%s\nbraintree %s", key, id);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "braintree %s\nbraintree %s_", key, id);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    const char *many_keys[] = {key, other, key}, *many_ids[] = {id, id, other_id};
    input_for(input, sizeof(input), many_keys, 3, many_ids, 3);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[k * 3 + i], 828, many_keys[k], "key"); check_error(&results.items[k * 3 + i], false, NULL);
    }
    br_results_clear(&results);
}

typedef struct { const char *key, *id; int status, send_rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    reply replies[9]; size_t count, releases, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 9 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 828 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://payments.braintree-api.com/graphql"));
    static const unsigned char payload[] = "{\"query\": \"query { ping }\"}";
    CHECK(request->body.data && request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(!request->dedup_key.len && request->nheaders == 4);
    CHECK(header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/json"));
    CHECK(header(request, "Braintree-Version") && !strcmp(header(request, "Braintree-Version"), "2019-01-01"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && !strncmp(auth, "Basic ", 6) && strlen(auth) == 74);
    unsigned char decoded[64]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 68) == 51);
    CHECK(!strcmp(auth + 72, "=="));
    CHECK(!memcmp(decoded, step->id, 16) && decoded[16] == ':' && !memcmp(decoded + 17, step->key, 32));
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->releases); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    char input[128]; const char *keys[] = {step.key}, *ids[] = {step.id}; input_for(input, sizeof(input), keys, 1, ids, 1);
    script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); test_key_result(&results.items[0], 828, step.key, "key"); return results;
}

static void body_and_status(const br_detector *detector)
{
    const struct { br_slice body; bool verified; } cases[] = {
        {SLICE("{\"data\":{\"ping\":\"pong\"}}"), true},
        {SLICE("not JSON \"data\":{ trailing"), true},
        {SLICE("\0\"data\":{"), true},
        {SLICE("\xff\0\"data\":{"), true},
        {SLICE("{\"data\": {}}"), false}, {SLICE("{\"Data\":{}}"), false}, {SLICE("{}"), false}, {{NULL, 0}, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .id = id, .status = 200, .body = cases[i].body});
        check_error(&results.items[0], cases[i].verified, NULL); br_results_clear(&results);
    }
    const int codes[] = {201, 400, 401, 403, 500, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .id = id, .status = codes[i], .body = cases[3].body});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", codes[i]);
        check_error(&results.items[0], false, expected); br_results_clear(&results);
    }
    char cause[256], expected[256]; snprintf(cause, sizeof(cause), "read %s twice %s; public %s; keep %s", key, key, id, other);
    snprintf(expected, sizeof(expected), "read [REDACTED] twice [REDACTED]; public %s; keep %s", id, other);
    const int read_codes[] = {200, 401, 503};
    for (size_t i = 0; i < sizeof(read_codes) / sizeof(read_codes[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .id = id, .status = read_codes[i], .body = cases[3].body, .read_error = cause});
        check_error(&results.items[0], false, expected); br_results_clear(&results); /* Release still occurs on read failure. */
    }
}

static void products_and_transport(const br_detector *detector)
{
    const char *keys[] = {key, other, key}, *ids[] = {id, id, other_id}; char input[1024]; input_for(input, sizeof(input), keys, 3, ids, 3);
    script steps = {.count = 9, .releases = 9};
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i)
        steps.replies[k * 3 + i] = (reply){.key = keys[k], .id = ids[i], .status = 200, .body = SLICE("\"data\":{")};
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[k * 3 + i], 828, keys[k], "key"); check_error(&results.items[k * 3 + i], true, NULL);
    }
    br_results_clear(&results);
    char cause[192], expected[192]; snprintf(cause, sizeof(cause), "synthetic private %s; public %s", key, id);
    snprintf(expected, sizeof(expected), "synthetic private [REDACTED]; public %s", id);
    results = single(detector, (reply){.key = key, .id = id, .status = 200, .body = SLICE("\"data\":{"), .read_error = "ignored after Do failure", .send_error = cause});
    check_error(&results.items[0], false, expected); br_results_clear(&results);
    results = single(detector, (reply){.key = key, .id = id, .send_rc = -1}); check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
}

static void context_and_resource_failure(const br_detector *detector)
{
    const char *keys[] = {key}, *ids[] = {id, other_id}; char input[256]; input_for(input, sizeof(input), keys, 1, ids, 1);
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1);
    test_key_result(&results.items[0], 828, key, "key"); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls);
        check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    input_for(input, sizeof(input), keys, 1, ids, 2); script steps = {.count = 2, .releases = 2};
    steps.replies[0] = (reply){.key = key, .id = id, .status = 200, .body = SLICE("\"data\":{")};
    steps.replies[1] = (reply){.key = key, .id = other_id, .status = 503};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true; int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot verify BraintreePayments candidate"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_error(&results.items[0], true, NULL);
    check_error(&results.items[1], false, status_503); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = init();
    extraction(detector); body_and_status(detector); products_and_transport(detector); context_and_resource_failure(detector);
    return test_finish("BraintreePayments occurrence product + hidden public ID + read-first binary verification");
}
