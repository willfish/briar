/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_lexigram_init(const br_detector **out, char **error);

static char key[302], other[302];
static const char url[] = "https://api.lexigram.io/v1/lexigraph/search?q=diabetes";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, fail_next_malloc;

void *malloc(size_t size)
{
    if (fail_next_malloc) { fail_next_malloc = false; ++allocation_failures; return NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_http_headers && !strcmp(name, "key")) {
        arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    if (!rc && arm_auth && !strcmp(name, "key")) {
        arm_auth = false; fail_size = 7 + 301 + 1; fail_after = 1;
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static br_slice bytes(const void *value, size_t len) { return (br_slice){value, len}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    memset(key, 'A', 301); key[301] = '\0'; memset(other, 'B', 301); other[301] = '\0';
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 301 && strlen(other) == 301 && strcmp(key, other));
    CHECK(!strcmp(url, "https://api.lexigram.io/v1/lexigraph/search?q=diabetes"));
    CHECK(strstr(url, "/lexigraph/") && !strstr(url, "/lexigram/"));
    CHECK(br_lexigram_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_lexigram_init(&d, &error) == 0 && d && !error);
    CHECK(br_lexigram_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 437 && d->version == 0 && !strcmp(d->name, "Lexigram"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Lexigram is a healthcare data service that provides an API for medical terminology and data. Lexigram API keys can be used to access and retrieve medical data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lexigram"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const void *expected, size_t n, bool verified)
{
    if (!n) {
        CHECK(result->detector_type == 437 && !result->raw.len && !result->verified == !verified);
        CHECK(!result->verification_error && result->secret_parts);
        br_json *part = NULL;
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
        CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), ""));
        return;
    }
    char copy[1024];
    CHECK(n < sizeof(copy));
    memcpy(copy, expected, n); copy[n] = '\0';
    if (!memchr(expected, '\0', n)) {
        test_key_result(result, 437, copy, "key");
        CHECK(result->verified == verified && !result->verification_error);
        return;
    }
    CHECK(result->detector_type == 437 && result->raw.len == n && !memcmp(result->raw.data, expected, n));
    CHECK(result->verified == verified && !result->verification_error && result->secret_parts);
    const char *printed = json_object_to_json_string(result->secret_parts);
    CHECK(printed && strstr(printed, "\\u0000"));
}

static void extraction_case(const br_detector *d, br_slice input, const void *expected, size_t n, bool present)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input.data, input.len);
    CHECK(out.len == (present ? 1u : 0u) && !http.calls && !http.releases);
    if (present) finding(&out.items[0], expected, n, false);
    br_results_clear(&out);
}

static void expect_text(const br_detector *d, const char *input, const char *expected)
{
    extraction_case(d, text(input), expected, expected ? strlen(expected) : 0, expected != NULL);
}

static void extraction(const br_detector *d)
{
    char input[2048], token[640], short_key[301], long_key[303];
    extraction_case(d, text(key), NULL, 0, false);
    snprintf(input, sizeof(input), "lexigram %s", key); expect_text(d, input, key);
    snprintf(input, sizeof(input), "LEXIGRAM='%s'", key); expect_text(d, input, key);
    snprintf(input, sizeof(input), "Lexigram\n%s", other); expect_text(d, input, other);
    snprintf(input, sizeof(input), "xlexigram: (%s)", key); expect_text(d, input, key);
    snprintf(input, sizeof(input), "lexigra %s", key); expect_text(d, input, NULL);
    snprintf(input, sizeof(input), "lexigram%s", key); expect_text(d, input, NULL);
    memset(short_key, 'A', 300); short_key[300] = '\0';
    snprintf(input, sizeof(input), "lexigram %s", short_key); expect_text(d, input, NULL);
    memset(long_key, 'A', 302); long_key[302] = '\0';
    snprintf(input, sizeof(input), "lexigram %s", long_key); expect_text(d, input, NULL);
    memcpy(token, key, 150); token[150] = ' '; memcpy(token + 151, key, 150); token[301] = '\0';
    snprintf(input, sizeof(input), "lexigram %s", token); expect_text(d, input, NULL);
    memcpy(token, key, 150); token[150] = '\v'; memcpy(token + 151, key, 150);
    extraction_case(d, bytes(input, (size_t)snprintf(input, sizeof(input), "lexigram ")), NULL, 0, false);
    memcpy(input + 9, token, 301);
    extraction_case(d, bytes(input, 310), token, 301, true); /* Interior VT is not PCRE2 \S and is retained. */
    memset(token, '\v', 301);
    memcpy(input, "lexigram", 8); memcpy(input + 8, token, 301); input[309] = 'Z';
    extraction_case(d, bytes(input, 310), "", 0, true);
    token[0] = '\v'; token[1] = '\v'; memset(token + 2, 'A', 299);
    memcpy(input, "lexigram", 8); memcpy(input + 8, token, 301);
    extraction_case(d, bytes(input, 309), token + 2, 299, true);
    unsigned char mixed[302];
    mixed[0] = '\v'; mixed[1] = 0xc2; mixed[2] = 0xa0; memset(mixed + 3, 'C', 299);
    memcpy(input, "lexigram", 8); memcpy(input + 8, mixed, 302);
    extraction_case(d, bytes(input, 310), mixed + 3, 299, true); /* VT and NBSP, more than one rune. */
    unsigned char nel[303];
    memset(nel, 'D', 300); nel[300] = 0xc2; nel[301] = 0x85;
    memcpy(input, "lexigram ", 9); memcpy(input + 9, nel, 302); input[311] = 'Z';
    extraction_case(d, bytes(input, 312), nel, 300, true);
    unsigned char ideographic[303];
    ideographic[0] = 0xe3; ideographic[1] = 0x80; ideographic[2] = 0x80; memset(ideographic + 3, 'E', 300);
    memcpy(input, "lexigram", 8); memcpy(input + 8, ideographic, 303);
    extraction_case(d, bytes(input, 311), ideographic + 3, 300, true);
    memset(token, '!', 301);
    memcpy(input, "lexigram", 8); memcpy(input + 8, token, 301); input[309] = 'Z';
    extraction_case(d, bytes(input, 310), token, 301, true);
    unsigned char accented[603];
    for (size_t i = 0; i < 301; ++i) { accented[i * 2] = 0xc3; accented[i * 2 + 1] = 0xa9; }
    memcpy(input, "lexigram", 8); memcpy(input + 8, accented, 602); input[610] = 'Z';
    extraction_case(d, bytes(input, 611), accented, 602, true); /* 301 runes, not 301 bytes. */
    extraction_case(d, bytes(input, 8 + 301), NULL, 0, false);
    char gap[1024];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "lexigram", 8); memcpy(gap + 48, key, 301);
    extraction_case(d, bytes(gap, 349), key, 301, true);
    memcpy(gap + 49, key, 301); gap[48] = ' ';
    extraction_case(d, bytes(gap, 350), NULL, 0, false);
    snprintf(input, sizeof(input), "lexigram %s %s", key, other); expect_text(d, input, key);
    snprintf(input, sizeof(input), "lexigram %s\nLEXIGRAM %s\nlexigram %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, 301, false); finding(&out.items[1], other, 301, false); finding(&out.items[2], key, 301, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
    unsigned char nulled[301];
    memset(nulled, 'A', 301); nulled[150] = '\0';
    memcpy(input, "lexigram ", 9); memcpy(input + 9, nulled, 301);
    extraction_case(d, bytes(input, 310), nulled, 301, true);
}

typedef struct { const void *key; size_t n; const char *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct {
    const char *auth; const void *key; size_t n;
} held;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth;
    size_t arm_call, arm_size, arm_after, arm_push;
    /* Successful Do stays here until scan return. Failed sends do not. */
    held deferred[3]; size_t deferred_len; size_t failed_sends;
    bool immediate, retain_fails;
    const char *immediate_auth; const void *immediate_key; size_t immediate_n;
    const void *released_keys[3]; size_t release_n;
} script;

static void authorization(const char *value, const void *expected, size_t n)
{
    CHECK(value && strlen(value) == 7 + n && !memcmp(value, "Bearer ", 7) && value[7 + n] == '\0');
    if (n) CHECK(!memcmp(value + 7, expected, n));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    /* Only earlier failed sends have released. Successful Bearers stay open. */
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        authorization(steps->deferred[i].auth, steps->deferred[i].key, steps->deferred[i].n);
        CHECK(steps->deferred[i].auth != request->headers[0].value);
        for (size_t j = 0; j < i; ++j) CHECK(steps->deferred[i].auth != steps->deferred[j].auth);
    }
    CHECK(request->detector_type == 437 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, reply->key, reply->n); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog lexigram-offline" : "TruffleHog"));
    http->response = (br_http_response){.status = reply->status, .body = reply->body, .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    row *reply = &steps->rows[http->calls - 1];
    bool failed = reply->rc != 0;
    bool retain_this = steps->retain_fails && !failed && http->calls == steps->count;
    if (failed || retain_this) {
        steps->immediate = true; steps->immediate_auth = steps->borrowed_auth;
        steps->immediate_key = reply->key; steps->immediate_n = reply->n;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 3);
        steps->deferred[steps->deferred_len++] = (held){.auth = steps->borrowed_auth, .key = reply->key, .n = reply->n};
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL; const void *expected = NULL; size_t n = 0;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected = steps->immediate_key; n = steps->immediate_n;
        steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth);
            authorization(steps->deferred[i].auth, steps->deferred[i].key, steps->deferred[i].n);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected = item.key; n = item.n;
    }
    /* This is the Bearer of the response being released, still complete. */
    authorization(auth, expected, n);
    if (steps->release_n < 3) steps->released_keys[steps->release_n++] = expected;
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "lexigram-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->deferred_len && !steps->immediate);
    return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})

static void status_read_and_send_policy(const br_detector *d)
{
    char input[512]; snprintf(input, sizeof(input), "lexigram %s", key);
    for (int status = 200; status < 300; ++status) {
        const char *read_error = status % 2 ? "read failed" : NULL;
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .n = 301, .status = status, .body = TEXT("not-json\0\xff"), .read_error = read_error};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, 301, true); br_results_clear(&out);
    }
    script empty = {.count = 1}; empty.rows[0] = (row){.key = key, .n = 301, .status = 200, .read_error = ""};
    br_results out = run(d, text(input), &empty); CHECK(out.len == 1);
    finding(&out.items[0], key, 301, true); br_results_clear(&out);
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .n = 301, .status = statuses[i], .body = TEXT("\xff"), .read_error = "ignored"};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, 301, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .n = 301, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, 301, false); br_results_clear(&out);
    }
    char blank[320];
    memcpy(blank, "lexigram", 8); memset(blank + 8, '\v', 301); blank[309] = 'Z';
    script bare = {.count = 1}; bare.rows[0] = (row){.key = "", .n = 0, .status = 204, .read_error = "read failed"};
    out = run(d, bytes(blank, 310), &bare); CHECK(out.len == 1);
    finding(&out.items[0], "", 0, true); br_results_clear(&out);
    unsigned char nulled[301]; memset(nulled, 'A', 301); nulled[150] = '\0';
    char nul_input[320]; memcpy(nul_input, "lexigram ", 9); memcpy(nul_input + 9, nulled, 301);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(d, &ctx, true, nul_input, 310); CHECK(!http.calls && !http.releases && out.len == 1);
    finding(&out.items[0], nulled, 301, false); br_results_clear(&out);
    char vt[312]; memcpy(vt, key, 150); vt[150] = '\v'; memcpy(vt + 151, key, 150);
    memcpy(nul_input, "lexigram ", 9); memcpy(nul_input + 9, vt, 301);
    http = (test_http){0};
    out = test_scan(d, &ctx, true, nul_input, 310); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], vt, 301, false); br_results_clear(&out);
    char occurrences[2048];
    snprintf(occurrences, sizeof(occurrences), "lexigram %s\nLEXIGRAM %s\nlexigram %s", key, other, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .n = 301, .status = 401, .read_error = "ignored"};
    steps.rows[1] = (row){.key = other, .n = 301, .status = 204};
    steps.rows[2] = (row){.key = key, .n = 301, .status = 200, .rc = 1, .send_error = "later Do"};
    out = run(d, text(occurrences), &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, 301, false); finding(&out.items[1], other, 301, true); finding(&out.items[2], key, 301, false);
    /* Failed send released immediately, then successes last-success-first. */
    CHECK(steps.failed_sends == 1 && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "lexigram %s\nlexigram %s", key, other);
    script early = {.count = 2};
    early.rows[0] = (row){.key = key, .n = 301, .rc = 1, .send_error = "early Do"};
    early.rows[1] = (row){.key = other, .n = 301, .status = 201, .read_error = "ignored"};
    out = run(d, text(occurrences), &early); CHECK(out.len == 2);
    finding(&out.items[0], key, 301, false); finding(&out.items[1], other, 301, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key && early.released_keys[1] == other);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[512]; snprintf(input, sizeof(input), "lexigram %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, 301, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, 301, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, 301, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, 301, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key"); br_results_clear(&caller);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(out);
}

static void own_failure_rollback(const br_detector *d)
{
    char input[768]; snprintf(input, sizeof(input), "lexigram %s", key);
    const size_t sizes[] = {302, 301};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_auth = true;
    rc = d->scan(d, &ctx, true, text(input), &out, &error);
    CHECK(!arm_auth && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "authorization")); rolled_back(&out, rc, error);
    unsigned char nulled[301]; memset(nulled, 'A', 301); nulled[150] = '\0';
    char nul_input[320]; memcpy(nul_input, "lexigram ", 9); memcpy(nul_input + 9, nulled, 301);
    http = (test_http){0}; out = caller_owned(); error = NULL; before = allocation_failures; arm_auth = true;
    rc = d->scan(d, &ctx, true, bytes(nul_input, 310), &out, &error);
    CHECK(!arm_auth && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "authorization")); rolled_back(&out, rc, error);
    http = (test_http){0};
    out = test_scan(d, &ctx, true, nul_input, 310); CHECK(!http.calls && !http.releases && out.len == 1);
    finding(&out.items[0], nulled, 301, false); br_results_clear(&out);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .n = 301, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "lexigram %s\nlexigram %s", key, other);
    steps = (script){.count = 2, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .n = 301, .status = 200};
    steps.rows[1] = (row){.key = other, .n = 301, .status = 204};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 2 && steps.released_keys[0] == other && steps.released_keys[1] == key);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "lexigram %s\nlexigram %s", key, key);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 301, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .n = 301, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(input), &out, NULL) == -1);
    error = NULL; CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_read_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !fail_next_malloc && !arm_http_headers && !arm_auth);
    return test_finish("Lexigram");
}
