/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <errno.h>
#include <strings.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SLICE(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
#define PREFIX "failed to verify Bitfinex API key, error: "
#define UNICODE_BODY "Snowman \xe2\x98\x83 replacement \xef\xbf\xbd globe \xf0\x9f\x8c\x8d controls:\x01\x7f\n\t\r"
static const char *const values[] = {
    "HYp6Lct_PgxCTk1GXo5Kbs9OfwBSj0FWn4Jar8NevAR",
    "Xo5Kbs9OfwBSj0FWn4Jar8NevARizEVm3IZq7Mdu-Qh",
    "n4Jar8NevARizEVm3IZq7Mdu-QhyDUl2HYp6Lct_Pgx",
};
/* Independent Python hmac/hashlib.sha384 goldens: ASCII keys, no decoding. */
static const char *const signatures[2][3] = {
    {"cc26461571e62f487a94641ceec21ba8c5f17be433c9d94bec4b58e3569be0f6eff471757a5eeb397d218c129194028b",
     "002aa39c246214d5b423bb6fd2654cb2c3c45dc37279d6770997b27b41140875129de42b7d51396c48b5cb1675e6b8b2",
     "025effc09ebc526bfab5e77b7588e7bfeabdb632308384c8dede0ccc8929158b4986f104749e3e8a2b1477fae217c8c1"},
    {"90682a196e0ac485b2d3c0b763249ad912f6449e90b8a80319156b38e2580a9a47e0ef66fe9b1b59f1089bff750132dd",
     "3c5fc477b61eafc73cd7fc6c183d2a2a932df8c8d5bcf32b038368b3b5f0da6299236c4bd008cbc7e45c844c86901a28",
     "af819b2db7dd06d172a32f038ab11866308c6a096550f4cd5e5a1abc2279723bb952e33cf67d175ca32d26470ded732b"},
};
static const struct timespec frozen[] = {{1704164645, 123456789}, {1706933106, 987654321}};
static const char *const nonces[] = {"1704164645123456", "1706933106987654"};
static const char unsupported[] = "unsupported: Bitfinex non-UTF-8 or NUL response body diagnostic";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy, fault_after_send;
static size_t frame, real_calls, monotonic_calls, sent_requests;
enum clock_fault { CLOCK_OK, CLOCK_FAILURE, CLOCK_NEGATIVE, CLOCK_OVERFLOW, CLOCK_BAD_NSEC };
static enum clock_fault clock_fault;

/* Freeze realtime only. Deadline checks still use the native monotonic clock;
 * this test-local Linux syscall delegation adds no production hook/runtime. */
int clock_gettime(clockid_t which, struct timespec *out)
{
    if (which != CLOCK_REALTIME) {
        if (which == CLOCK_MONOTONIC) ++monotonic_calls;
        return (int)syscall(SYS_clock_gettime, which, out);
    }
    ++real_calls; *out = frozen[frame];
    if (fault_after_send && !sent_requests) return 0;
    switch (clock_fault) {
    case CLOCK_OK: break;
    case CLOCK_FAILURE: errno = EIO; return -1;
    case CLOCK_NEGATIVE: out->tv_sec = -1; break;
    case CLOCK_OVERFLOW:
        out->tv_sec = (time_t)(INT64_MAX / INT64_C(1000000000));
        out->tv_nsec = (long)(INT64_MAX % INT64_C(1000000000)) + 1; break;
    case CLOCK_BAD_NSEC: out->tv_nsec = 1000000000L; break;
    }
    return 0;
}

/* Only the setter's copy of this one error fails, returning positive 1. */
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
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitfinex_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Bitfinex detector output")); free(error); error = NULL;
    CHECK(!br_bitfinex_init(&detector, &error) && detector && !error);
    CHECK(!br_bitfinex_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 56 && detector->version == 0 && !strcmp(detector->name, "Bitfinex"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Bitfinex is a cryptocurrency exchange offering various trading options. Bitfinex API keys can be used to access and manage trading accounts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bitfinex"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    for (size_t i = 0; i < 3; ++i) CHECK(strlen(values[i]) == 43);
    return detector;
}

static void input_for(char *out, size_t size, size_t count)
{
    size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        int n = snprintf(out + at, size - at, "bitfinex %s\n", values[i]); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
    if (!count) *out = '\0';
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) { CHECK(result->verification_error && strlen(result->verification_error) == strlen(error)); CHECK(!memcmp(result->verification_error, error, strlen(error))); }
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *prefix, int gap, const char *second, bool matches)
{
    char input[512]; snprintf(input, sizeof(input), "bitfinex %s\n%80s%s%*s%s", values[0], "", prefix, gap, "", second);
    size_t before = real_calls;
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(real_calls == before && results.len == (matches ? 2u : 0u));
    if (matches) { test_key_result(&results.items[0], 56, values[0], "key"); test_key_result(&results.items[1], 56, second, "key"); }
    br_results_clear(&results);
}

static void extraction_and_no_clock(const br_detector *detector)
{
    extraction_case(detector, "BITFINEX", 1, values[1], true);
    extraction_case(detector, "bitfinex", 40, values[1], true);
    extraction_case(detector, "bitfinex", 41, values[1], false);
    extraction_case(detector, "key", 1, values[1], false);
    char altered[48]; memcpy(altered, values[1], 44); altered[42] = '\0'; extraction_case(detector, "bitfinex", 1, altered, false);
    snprintf(altered, sizeof(altered), "%sx", values[1]); extraction_case(detector, "bitfinex", 1, altered, false);
    memcpy(altered, values[1], 44); altered[8] = '+'; extraction_case(detector, "bitfinex", 1, altered, false);
    memcpy(altered, values[1], 44); altered[8] = '/'; extraction_case(detector, "bitfinex", 1, altered, false);
    memset(altered, 'A', 43); altered[43] = '\0'; extraction_case(detector, "bitfinex", 1, altered, true); /* No entropy gate. */
    char input[512]; input_for(input, sizeof(input), 3);
    size_t at = strlen(input); snprintf(input + at, sizeof(input) - at, "bitfinex %s\nbitfinex %s", values[0], values[1]);
    size_t before = real_calls; clock_fault = CLOCK_FAILURE;
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 6 && real_calls == before);
    for (size_t i = 0; i < 3; ++i) for (size_t j = 0, seen = 0; j < 3; ++j) {
        if (i == j) continue;
        test_key_result(&results.items[i * 2 + seen], 56, values[i], "key"); check_error(&results.items[i * 2 + seen], false, NULL); ++seen;
    }
    br_results_clear(&results); clock_fault = CLOCK_OK;
    for (size_t count = 0; count <= 1; ++count) {
        input_for(input, sizeof(input), count); before = real_calls;
        results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && real_calls == before); br_results_clear(&results);
    }
}

typedef struct { size_t key, secret; int status, send_rc; br_slice body; const char *body_error, *send_error; } reply;
typedef struct {
    reply replies[6]; size_t count, cancel_calls, last_real; bool cancel, expired;
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
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 6 && http->releases == at && ctx == steps->expected_ctx);
    CHECK(real_calls > steps->last_real); steps->last_real = real_calls; /* Fresh realtime per pair. */
    reply *step = &steps->replies[at]; CHECK(step->key != step->secret && step->key < 3 && step->secret < 3);
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 56 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.bitfinex.com/v2/auth/r/wallets"));
    CHECK(request->body.data && request->body.len == 2 && !memcmp(request->body.data, "{}", 2) && !request->dedup_key.len);
    CHECK(request->nheaders == 6 && !strcmp(header(request, "Content-Type"), "application/json") && !strcmp(header(request, "Accept"), "application/json"));
    CHECK(!strcmp(header(request, "User-Agent"), "TruffleHog") && !header(request, "Content-Length") && !header(request, "Authorization"));
    CHECK(!strcmp(header(request, "bfx-apikey"), values[step->key]));
    CHECK(!strcmp(header(request, "bfx-nonce"), nonces[frame]));
    CHECK(!strcmp(header(request, "bfx-signature"), signatures[frame][step->secret]));
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->body_error};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc; ++sent_requests;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx; sent_requests = 0;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    size_t rejected = verify && (steps->cancel || steps->expired) ? results.len : 0;
    CHECK(http.calls == steps->count && http.releases == http.calls + rejected);
    return results;
}

static script pair_replies(reply common)
{
    script steps = {.count = 2}; steps.replies[0] = common; steps.replies[1] = common;
    steps.replies[0].key = 0; steps.replies[0].secret = 1; steps.replies[1].key = 1; steps.replies[1].secret = 0;
    return steps;
}

static br_results pair_case(const br_detector *detector, reply common)
{
    char input[128]; input_for(input, sizeof(input), 2); script steps = pair_replies(common);
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 2);
    test_key_result(&results.items[0], 56, values[0], "key"); test_key_result(&results.items[1], 56, values[1], "key"); return results;
}

static void goldens_and_all_pairs(const br_detector *detector)
{
    for (frame = 0; frame < 2; ++frame) {
        char input[192]; input_for(input, sizeof(input), 3); script steps = {.count = 6}; size_t at = 0;
        for (size_t key = 0; key < 3; ++key) for (size_t secret = 0; secret < 3; ++secret)
            if (key != secret) steps.replies[at++] = (reply){.key = key, .secret = secret, .status = 200, .body_error = "ignored read/drain/close error"};
        br_results results = scan(detector, input, true, &steps); CHECK(results.len == 6);
        for (size_t i = 0; i < 6; ++i) { test_key_result(&results.items[i], 56, values[i / 2], "key"); check_error(&results.items[i], true, NULL); }
        br_results_clear(&results);
    }
    frame = 0;
}

static void status_and_markers(const br_detector *detector)
{
    const int statuses[] = {200, 201, 400, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        br_results results = pair_case(detector, (reply){.status = statuses[i], .body = SLICE("\xff\0apikey: invalid"), .body_error = "ignored"});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", statuses[i]);
        for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], statuses[i] == 200, statuses[i] == 200 ? NULL : expected);
        br_results_clear(&results);
    }
    const br_slice markers[] = {SLICE("apikey: digest invalid"), SLICE("apikey: invalid"), SLICE("\xff\0apikey: digest invalid"), SLICE("\xff" "apikey: invalid")};
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
        br_results results = pair_case(detector, (reply){.status = 500, .body = markers[i]});
        for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], false, NULL);
        br_results_clear(&results);
    }
    char cause[192]; snprintf(cause, sizeof(cause), "unredacted read %s %s", values[0], values[1]);
    br_results results = pair_case(detector, (reply){.status = 500, .body = markers[2], .body_error = cause});
    for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], false, cause);
    br_results_clear(&results);
}

static void diagnostic_case(const br_detector *detector, br_slice body, const char *expected)
{
    br_results results = pair_case(detector, (reply){.status = 500, .body = body});
    for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], false, expected);
    br_results_clear(&results);
}

static void body_diagnostics_and_transport(const br_detector *detector)
{
    diagnostic_case(detector, SLICE("normal ASCII error"), PREFIX "normal ASCII error");
    diagnostic_case(detector, (br_slice){NULL, 0}, PREFIX);
    diagnostic_case(detector, SLICE(UNICODE_BODY), PREFIX UNICODE_BODY);
    diagnostic_case(detector, SLICE("APIKEY: invalid"), PREFIX "APIKEY: invalid");
    diagnostic_case(detector, SLICE("unknown\0suffix"), unsupported);
    diagnostic_case(detector, SLICE("\xff\nunknown"), unsupported);
    char body[160], expected[224]; snprintf(body, sizeof(body), "unredacted %s and %s", values[0], values[1]);
    snprintf(expected, sizeof(expected), PREFIX "%s", body);
    diagnostic_case(detector, (br_slice){(const unsigned char *)body, strlen(body)}, expected);
    size_t len = 8193; unsigned char *large = malloc(len); char *full = malloc(sizeof(PREFIX) + len); CHECK(large && full);
    memset(large, 'x', len); large[len - 1] = '!'; memcpy(full, PREFIX, sizeof(PREFIX) - 1); memcpy(full + sizeof(PREFIX) - 1, large, len);
    full[sizeof(PREFIX) - 1 + len] = '\0'; diagnostic_case(detector, (br_slice){large, len}, full); free(large); free(full);
    br_results results = pair_case(detector, (reply){.status = 200, .send_error = body, .body_error = "must not replace transport failure"});
    for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], false, body);
    br_results_clear(&results);
    results = pair_case(detector, (reply){.status = 200, .send_rc = -1});
    for (size_t j = 0; j < 2; ++j) check_error(&results.items[j], false, "HTTP transport failed");
    br_results_clear(&results);
    char input[128]; input_for(input, sizeof(input), 2); script steps = pair_replies((reply){.status = 200});
    steps.replies[0].status = 500; steps.replies[0].body = SLICE("unknown\0suffix");
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_error(&results.items[0], false, unsupported); check_error(&results.items[1], true, NULL); br_results_clear(&results);
}

static void context(const br_detector *detector)
{
    char input[128]; input_for(input, sizeof(input), 2);
    size_t before = real_calls; br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 2 && real_calls >= before + 2);
    for (size_t i = 0; i < 2; ++i) check_error(&results.items[i], false, "net/http: nil Context");
    br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline}; before = real_calls;
        results = scan(detector, input, false, &steps); CHECK(results.len == 2 && !steps.cancel_calls && real_calls == before); br_results_clear(&results);
        size_t mono_before = monotonic_calls;
        results = scan(detector, input, true, &steps); CHECK(results.len == 2 && steps.cancel_calls && real_calls >= before + 2);
        if (deadline) CHECK(monotonic_calls > mono_before);
        for (size_t i = 0; i < 2; ++i) check_error(&results.items[i], false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
}

static void rollback_guards(const br_detector *detector)
{
    char input[128]; input_for(input, sizeof(input), 2);
    for (enum clock_fault fault = CLOCK_FAILURE; fault <= CLOCK_BAD_NSEC; ++fault) {
        script steps = pair_replies((reply){.status = 200}); test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx; sent_requests = 0;
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
        clock_fault = fault; fault_after_send = true;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, fault == CLOCK_FAILURE ? "cannot read Bitfinex signing clock" : "unsupported: Bitfinex signing clock range"));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
        clock_fault = CLOCK_OK; fault_after_send = false;
    }
    script steps = pair_replies((reply){.status = 200}); steps.replies[1].status = 503;
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true; sent_requests = 0;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot store Bitfinex verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = init();
    extraction_and_no_clock(detector); goldens_and_all_pairs(detector); status_and_markers(detector);
    body_diagnostics_and_transport(detector); context(detector); rollback_guards(detector);
    return test_finish("Bitfinex unequal pairs + microsecond SHA384 + unredacted body policy");
}
