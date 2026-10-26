/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <errno.h>
#include <inttypes.h>
#include <strings.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char uid[] = "ab123456789", other_uid[] = "xy987654321";
static const char a[] = "AbCd0123EfGh4567IjKl8901", b[] = "ZyXw9876VuTs5432RqPo1098Nml";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
/* Synthetic OpenSSL CLI SHA256-HMAC goldens. Message=nonce+UID+key;
 * secret bytes unchanged. */
static const char *const signatures[] = {
    "96D7B753995D5DD96F90479465DE349524F8E2FA45A8516E5D0801E89CD23D28",
    "D87CE20B4417C9426F3F4B78E234321583B0D65DCD0D2EBC22EA1EF84E725105",
    "3B92857F7878C9BF6722698696D7A9088715D5E600A54E7FC6E2A39742185206",
    "21A937328EE547AFF945ADA60F9A521D0DAB5521221AD313FC61A8997460F60A",
    "3C4A5E26F555CB91E6DB9C1D53868B9D703B63C539BFB58D2EA57BC0E7FFC415",
    "54FD040E6F4DA955B4BDAF8627D244D030FC976804CD743A33EC6DB3813B6270",
    "DB4BAD25527E1B8A39207B774111BC5693622DAC318D44C7D370C264CA505B33",
};
static const struct timespec ticks[] = {{1704164645, 123456789}, {1704164645, 987654321}, {1704164646, 0}, {1704164646, 999999999}};
static const struct timespec *clock_ticks = ticks;
static size_t clock_len = 1, real_calls, fail_clock_at, fail_uid_add_after;

int clock_gettime(clockid_t which, struct timespec *out)
{
    if (which != CLOCK_REALTIME) return (int)syscall(SYS_clock_gettime, which, out);
    size_t at = real_calls++; if (fail_clock_at && real_calls == fail_clock_at) { errno = EIO; return -1; }
    *out = clock_ticks[at < clock_len ? at : clock_len - 1]; return 0;
}

/* A positive failure of the provider's third-part addition. Forward every
 * other call unchanged; do not alter JSON parser strings, UTF-8 or NUL bytes. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "user_id") && fail_uid_add_after && --fail_uid_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void reset_clock(const struct timespec *frames, size_t count, size_t fail_at)
{
    clock_ticks = frames ? frames : ticks; clock_len = frames ? count : 1; CHECK(clock_len); real_calls = 0; fail_clock_at = fail_at;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(uid) == 11 && strlen(a) == 24 && strlen(b) == 27);
    CHECK(br_cexio_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CexIO detector output")); free(error); error = NULL;
    CHECK(!br_cexio_init(&detector, &error) && detector && !error);
    CHECK(!br_cexio_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 739 && detector->version == 0 && !strcmp(detector->name, "CexIO") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "CexIO is a cryptocurrency exchange platform. CexIO API keys can be used to access and manage cryptocurrency accounts and transactions."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "cexio") && !strcmp(detector->keywords[1], "cex.io"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void text_part(br_json *object, const char *name, const char *text)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(text) && !memcmp(json_object_get_string(value), text, strlen(text)));
}

static void check_result(const br_result *result, const char *user, const char *key, const char *secret, bool verified)
{
    CHECK(result->detector_type == 739 && !result->detector_name && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(result->raw_v2.len == 11 + strlen(secret) && result->raw_v2.data != result->raw.data);
    CHECK(!memcmp(result->raw_v2.data, user, 11) && !memcmp(result->raw_v2.data + 11, secret, strlen(secret)));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    text_part(result->secret_parts, "key", key); text_part(result->secret_parts, "secret", secret); text_part(result->secret_parts, "user_id", user);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static void input_for(char *out, size_t size, const char *const *users, size_t nu, const char *const *values, size_t nv)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < nu + nv; ++i) {
        int n = snprintf(out + at, size - at, "cexio %s\n", i < nu ? users[i] : values[i - nu]); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void expect_one(const br_detector *detector, const char *input, const char *user, const char *value)
{
    reset_clock(NULL, 0, 0); br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!real_calls && results.len == (user ? 1u : 0u)); if (user) check_result(&results.items[0], user, value, value, false); br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[30];
    snprintf(input, sizeof(input), "CEXIO %s\n%s\nCeX.Io %s", uid, isolation, a); expect_one(detector, input, uid, a);
    snprintf(input, sizeof(input), "cexXio %s\n%s\ncexYio %s", uid, isolation, b); expect_one(detector, input, uid, b); /* Regex dots remain wildcards; dispatch keywords remain literal. */
    snprintf(input, sizeof(input), "cexio %s", uid); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cexio %s", a); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cexio Ab123456789\n%s\ncexio %s", isolation, a); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cexio ab12345678\n%s\ncexio %s", isolation, a); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cexio ab1234567890\n%s\ncexio %s", isolation, a); expect_one(detector, input, NULL, NULL);
    memcpy(changed, a, sizeof(a)); changed[23] = 0; snprintf(input, sizeof(input), "cexio %s\n%s\ncexio %s", uid, isolation, changed); expect_one(detector, input, NULL, NULL);
    snprintf(changed, sizeof(changed), "%sZ", b); snprintf(input, sizeof(input), "cexio %s\n%s\ncexio %s", uid, isolation, changed); expect_one(detector, input, NULL, NULL);
    memcpy(changed, a, sizeof(a)); changed[10] = '_'; snprintf(input, sizeof(input), "cexio %s\n%s\ncexio %s", uid, isolation, changed); expect_one(detector, input, NULL, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "cexio%*s%s\n%s\ncexio %s", gap, "", uid, isolation, a); expect_one(detector, input, gap == 40 ? uid : NULL, a);
        snprintf(input, sizeof(input), "cexio %s\n%s\ncexio%*s%s", uid, isolation, gap, "", a); expect_one(detector, input, gap == 40 ? uid : NULL, a);
    }
    snprintf(input, sizeof(input), "cexio _%s\n%s\ncexio %s", uid, isolation, a); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cexio %s\n%s\ncexio %s_", uid, isolation, a); expect_one(detector, input, NULL, NULL);
    memset(changed, 'A', 24); changed[24] = 0; snprintf(input, sizeof(input), "cexio ab000000000\n%s\ncexio %s", isolation, changed); expect_one(detector, input, "ab000000000", changed);
}

typedef struct {
    const char *uid, *key, *secret, *nonce, *signature;
    int status, send_rc; br_slice body; const char *read_error, *send_error;
} reply;
typedef struct {
    reply rows[18]; size_t count; const struct timespec *frames; size_t nframes;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 18 && real_calls == at + 1 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at]; const char *nonce = step->nonce ? step->nonce : "1704164645000";
    CHECK(request->detector_type == 739 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://cex.io/api/balance/") && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/x-www-form-urlencoded"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Authorization") && !header(request, "Content-Length"));
    char expected[160]; int n = snprintf(expected, sizeof(expected), "key=%s&nonce=%s&signature=", step->key, nonce); CHECK(n > 0 && (size_t)n + 64 < sizeof(expected));
    CHECK(request->body.data && request->body.len == (size_t)n + 64 && !memcmp(request->body.data, expected, (size_t)n));
    const unsigned char *signature = request->body.data + n;
    for (size_t i = 0; i < 64; ++i) CHECK((signature[i] >= '0' && signature[i] <= '9') || (signature[i] >= 'A' && signature[i] <= 'F'));
    if (step->signature) CHECK(!memcmp(signature, step->signature, 64));
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    reset_clock(steps->frames, steps->nframes, 0); br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(real_calls == (verify ? steps->count : 0) && http.calls == steps->count && http.releases == steps->count); return results;
}

static br_results single_at(const br_detector *detector, reply step, const struct timespec *frame)
{
    if (!step.uid) step.uid = uid;
    step.key = step.secret = a;
    if (!step.signature) step.signature = signatures[0];
    const char *users[] = {step.uid}, *values[] = {a}; char input[128]; input_for(input, sizeof(input), users, 1, values, 1);
    script steps = {.count = 1, .frames = frame, .nframes = frame ? 1 : 0}; steps.rows[0] = step; return run(detector, input, true, &steps);
}

static void products_and_goldens(const br_detector *detector)
{
    const char *users[] = {uid}, *values[] = {a, b}; char input[256]; input_for(input, sizeof(input), users, 1, values, 2);
    script steps = {.count = 4, .frames = ticks, .nframes = 4};
    for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) {
        size_t at = k * 2 + s; steps.rows[at] = (reply){.uid = uid, .key = values[k], .secret = values[s], .status = 201, .body = TEXT("{\"error\":\"timestamp\"}"), .signature = signatures[at], .nonce = at < 2 ? "1704164645000" : "1704164646000"};
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 4);
    for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) check_result(&results.items[k * 2 + s], uid, values[k], values[s], true);
    br_results_clear(&results);
    const char *dup_users[] = {uid, other_uid}, *dup_values[] = {a, b, a}; input_for(input, sizeof(input), dup_users, 2, dup_values, 3);
    steps = (script){.count = 18};
    for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s)
        steps.rows[u * 9 + k * 3 + s] = (reply){.uid = dup_users[u], .key = dup_values[k], .secret = dup_values[s], .status = 200, .body = TEXT("{\"timestamp\":1}")};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 18);
        for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) check_result(&results.items[u * 9 + k * 3 + s], dup_users[u], dup_values[k], dup_values[s], verify);
        br_results_clear(&results);
    }
    results = single_at(detector, (reply){.uid = other_uid, .signature = signatures[6], .status = 200, .body = TEXT("{\"timestamp\":1}")}, NULL); CHECK(results.len == 1); check_result(&results.items[0], other_uid, a, a, true); br_results_clear(&results);
}

static void responses(const br_detector *detector)
{
    const int statuses[] = {199, 200, 201, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        br_results results = single_at(detector, (reply){.status = statuses[i], .body = TEXT("{\"timestamp\":1}")}, NULL); CHECK(results.len == 1); check_result(&results.items[0], uid, a, a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const struct { br_slice body; int status, expected; } cases[] = {
        {TEXT("{}"), 200, 0}, {TEXT("{\"Error\":null,\"stamp\":\"timestamp\"}"), 299, 1},
        {TEXT("{\"ErRoR\":true,\"timestamp\":1}"), 200, -1}, {TEXT("{\"error\":1,\"error\":\"timestamp\"}"), 401, -1},
        {TEXT("{\"unused\":1e9999,\"timestamp\":1}"), 200, 1}, {TEXT("{\"timestamp\":999999999999999999999999999999999999999}"), 200, 1},
        {TEXT("\"timestamp\""), 200, -1}, {TEXT("[]"), 401, -1}, {TEXT("null"), 401, 0},
        {TEXT("{\"timestamp\":1} {\"x\":2}"), 200, -1}, {TEXT("{\"timestamp\":1} broken"), 503, -1},
        {TEXT("{\"TIMESTAMP\":1}"), 200, 0}, {TEXT("{\"\\u0074imestamp\":1}"), 200, 0},
        {TEXT("{\"unknown\":\"\xff" "timestamp\"}"), 204, 1}, {TEXT("{\"unknown\":\"\\u0000timestamp\"}"), 200, 1},
        {TEXT("{\"unknown\":\"\0timestamp\"}"), 200, -1}, {TEXT("{\"timestamp\":1}\0"), 200, -1},
        {TEXT("{\n\"unknown\":\"\xff" "timestamp\"}\n"), 200, 1}, {TEXT("{\"unknown\":\"\xff\0timestamp\"}"), 200, -1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = single_at(detector, (reply){.status = cases[i].status, .body = cases[i].body}, NULL);
        if (results.len != (cases[i].expected < 0 ? 0u : 1u)) fprintf(stderr, "response fixture %zu: expected %d, got %zu findings\n", i, cases[i].expected, results.len);
        CHECK(results.len == (cases[i].expected < 0 ? 0u : 1u));
        if (results.len) check_result(&results.items[0], uid, a, a, cases[i].expected == 1);
        br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        br_results results = single_at(detector, (reply){.status = 200, .body = TEXT("bad JSON"), .read_error = "read error", .send_error = causes[i], .send_rc = 1}, NULL);
        CHECK(results.len == 1); check_result(&results.items[0], uid, a, a, false); br_results_clear(&results);
    }
}

static void skip_continues(const br_detector *detector)
{
    const char *users[] = {uid}, *values[] = {a, b}; char input[256]; input_for(input, sizeof(input), users, 1, values, 2); script steps = {.count = 4};
    for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) steps.rows[k * 2 + s] = (reply){.uid = uid, .key = values[k], .secret = values[s], .status = 200, .body = TEXT("{\"timestamp\":1}")};
    steps.rows[0].status = 401; steps.rows[0].read_error = ""; /* Even empty error text wins over complete JSON/marker for 401. */
    steps.rows[1].status = 503; steps.rows[1].body = TEXT("{\"error\":false,\"error\":\"timestamp\"}");
    steps.rows[2].body = TEXT("{\"error\":\"timestamp\"}"); steps.rows[3].status = 401; steps.rows[3].body = TEXT("null");
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], uid, b, a, true); check_result(&results.items[1], uid, b, b, false); br_results_clear(&results);
    br_results skipped = single_at(detector, (reply){.status = 200, .body = TEXT("{\"timestamp\":1}"), .read_error = "non-EOF read failure"}, NULL); CHECK(!skipped.len); br_results_clear(&skipped);
}

static void nil_zero_negative(const br_detector *detector)
{
    const char *users[] = {uid}, *values[] = {a, b}; char input[256]; input_for(input, sizeof(input), users, 1, values, 2);
    reset_clock(NULL, 0, 0); br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && real_calls == 4); br_results_clear(&results);
    reset_clock(NULL, 0, 0); results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 4 && !real_calls); br_results_clear(&results);
    const struct timespec special[] = {{0, 999999999}, {-1, 500000000}}; const char *nonces[] = {"0", "-1000"};
    for (size_t i = 0; i < 2; ++i) {
        results = single_at(detector, (reply){.status = 200, .body = TEXT("{\"timestamp\":1}"), .nonce = nonces[i], .signature = signatures[i + 4]}, &special[i]);
        CHECK(results.len == 1); check_result(&results.items[0], uid, a, a, true); br_results_clear(&results);
    }
    reset_clock(NULL, 0, 1); char *error = NULL; int rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && real_calls == 1 && !results.len && error && !strcmp(error, "cannot read CexIO signing clock")); free(error); br_results_clear(&results); /* Signing really precedes nil-context skipping. */
}

static void resource_boundaries(const br_detector *detector)
{
    const char *users[] = {uid}, *values[] = {a, b}; char input[256]; input_for(input, sizeof(input), users, 1, values, 2);
    for (int mode = 0; mode < 4; ++mode) {
        script steps = {.count = 4};
        for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) steps.rows[k * 2 + s] = (reply){.uid = uid, .key = values[k], .secret = values[s], .status = 200, .body = TEXT("{\"timestamp\":1}")};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        struct timespec frames[2] = {ticks[0], ticks[0]};
        if (mode == 2) frames[1].tv_sec = (time_t)(INT64_MAX / INT64_C(1000)) + 1;
        if (mode == 3) frames[1].tv_sec = (time_t)(INT64_MIN / INT64_C(1000)) - 1;
        reset_clock(frames, 2, mode == 1 ? 2 : 0); if (mode == 0) fail_uid_add_after = 2;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && !fail_uid_add_after && error && !strcmp(error, mode == 0 ? "cannot create CexIO result" : mode == 1 ? "cannot read CexIO signing clock" : "unsupported: CexIO signing clock range"));
        CHECK(http.calls == 1 && http.releases == 1 && real_calls == (mode == 0 ? 1u : 2u));
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); text_part(results.items[0].secret_parts, "key", "prior");
        free(error); br_results_clear(&results); results = run(detector, input, true, &steps); CHECK(results.len == 4);
        for (size_t k = 0; k < 2; ++k) {
            for (size_t s = 0; s < 2; ++s) check_result(&results.items[k * 2 + s], uid, values[k], values[s], true);
        }
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    br_json *probe = json_object_new_object(), *part = json_object_new_string("probe"); CHECK(probe && part); fail_uid_add_after = 1; CHECK(json_object_object_add(probe, "user_id", part) == 1 && !fail_uid_add_after && !json_object_object_length(probe)); json_object_put(part); json_object_put(probe);
    extraction(detector); products_and_goldens(detector); responses(detector); skip_continues(detector); nil_zero_negative(detector); resource_boundaries(detector);
    return test_finish("CexIO occurrence triples + UID-secret RawV2 + whole-second HMAC + typed JSON tri-state");
}
