/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <openssl/rand.h>

static const char key[] = "g7h9j2k5m6n8p3q4r1s0t2u5v7w9x2y4z6a8";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7k6j5h4g3f2";
static size_t random_calls, fail_random_on;
static int fail_random_value;
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Process-local interposition of the existing crypto API. Never a production
 * seed/boundary option, real credential, service call or Go runtime wrapper. */
int RAND_bytes(unsigned char *out, int count)
{
    CHECK(out && count == 30);
    size_t draw = random_calls++;
    for (int i = 0; i < count; ++i) out[i] = (unsigned char)(draw + (size_t)i);
    if (fail_random_on == random_calls) {
        fail_random_on = 0;
        return fail_random_value;
    }
    return 1;
}

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
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_deepai_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:deepai)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_deepai_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    free(error); error = NULL;
    CHECK(br_deepai_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_deepai_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 621 && detector->version == 0 && !strcmp(detector->name, "DeepAI"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DeepAI is an AI service provider offering various machine learning APIs. DeepAI API keys can be used to access and utilize these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "deepai"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint && !random_calls);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 621, expected, "key");
    CHECK(result->raw.len == 36 && result->verified == verified && !result->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 36 && !memcmp(json_object_get_string(part), expected, 36));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = random_calls;
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && random_calls == before);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[38];
    const char *accepted[] = {"deepai '%s'", "DeEpAi\r\n%s", "preDEEPAIsuffix:%s", "deepai\r%s", "deepai\n%s", "deepai-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s deepai", "deep ai %s", "deepai%s", "deepai _%s", "deepai %s_", "deepai x%s", "deepai %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "deepai%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[35] = '\0';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[36] = 'a'; changed[37] = '\0';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "A_./+";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "DEEPAI %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[3] = changed[11] = changed[20] = '-';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not UUID validation. */
    memset(changed, 'z', 36); changed[36] = '\0';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not hex/entropy validation. */
    memset(changed, '9', 36);
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "deepai X%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[35] = '-';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "deepai %sZ", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, '-', 36); changed[36] = '\0';
    snprintf(input, sizeof(input), "deepai %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "deepaiX%sY", changed); extraction_case(detector, input, strlen(input), changed); /* Both source word-boundary quirks. */
    snprintf(input, sizeof(input), "deepai %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "deepai%c%s", 0, key);
    CHECK(n == 43); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, rc, body_kind; } reply;
typedef struct {
    reply rows[3]; size_t count, random_start;
    const br_scan_ctx *ctx;
    const char *borrowed_type, *borrowed_key;
    br_slice borrowed_body;
    size_t borrowed_draw;
    bool suffix;
} script;

static void check_form(const char *type, br_slice body, const char *actual_key, const char *expected_key, size_t draw)
{
    char boundary[61], expected_type[91], expected_body[184];
    for (size_t i = 0; i < 30; ++i)
        CHECK(snprintf(boundary + 2 * i, 3, "%02x", (unsigned int)(unsigned char)(draw + i)) == 2);
    if (!draw) CHECK(!strcmp(boundary, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"));
    CHECK(snprintf(expected_type, sizeof(expected_type), "multipart/form-data; boundary=%s", boundary) == 90);
    CHECK(type && strlen(type) == 90 && !memcmp(type, expected_type, sizeof(expected_type)));
    CHECK(snprintf(expected_body, sizeof(expected_body), "--%s\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\ntest\r\n--%s--\r\n", boundary, boundary) == 183);
    CHECK(body.data && body.len == 183 && !memcmp(body.data, expected_body, 183));
    CHECK(actual_key && strlen(actual_key) == 36 && !memcmp(actual_key, expected_key, 37));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(random_calls == steps->random_start + http->calls); /* One fresh 30-byte draw per occurrence. */
    reply *row = &steps->rows[at];
    CHECK(request->detector_type == 621 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.deepai.org/api/text-tagging"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[1].name, "Api-Key"));
    check_form(request->headers[0].value, request->body, request->headers[1].value, row->key, steps->random_start + at);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog deepai-offline" : "TruffleHog"));
    /* Logical Content-Length is body.len=183, supplied by shared framing. No
     * manual CL, Accept or Authorization header, extra form field or dedup key. */
    steps->borrowed_type = request->headers[0].value; steps->borrowed_key = request->headers[1].value;
    steps->borrowed_body = request->body; steps->borrowed_draw = steps->random_start + at;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){body, sizeof(body)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "synthetic ignored read error"};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    check_form(steps->borrowed_type, steps->borrowed_body, steps->borrowed_key,
               steps->rows[http->calls - 1].key, steps->borrowed_draw);
    steps->borrowed_type = steps->borrowed_key = NULL; steps->borrowed_body = (br_slice){0};
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "deepai-offline" : NULL}; steps->ctx = &ctx;
    steps->random_start = random_calls;
    br_results out = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_type && !steps->borrowed_body.data);
    CHECK(random_calls == steps->random_start + steps->count);
    return out;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    const char *keys[] = {key, other, key};
    unsigned char input[3 * 45 + 1]; size_t len = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, "DeEpAi ", 7); len += 7; memcpy(input + len, keys[i], 36); len += 36;
        input[len++] = '\0'; input[len++] = i == 1 ? '\r' : '\n';
    }
    input[len++] = 0xff; br_slice data = {input, len};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .suffix = true};
        steps.rows[0] = (reply){.key = key, .status = 200, .rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 204, .body_kind = 1};
        steps.rows[2] = (reply){.key = key, .status = 299, .body_kind = 2};
        br_results out = run(detector, data, verify, &steps); CHECK(out.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify && i != 0);
        br_results_clear(&out);
        size_t before = random_calls;
        out = test_scan(detector, NULL, verify, data.data, data.len);
        CHECK(out.len == (verify ? 0u : 3u) && random_calls == before + (verify ? 3u : 0u));
        for (size_t i = 0; i < out.len; ++i) check_result(&out.items[i], keys[i], false);
        br_results_clear(&out);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "deepai %s", key); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = status, .body_kind = status % 3};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1); check_result(&out.items[0], key, true); br_results_clear(&out);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i], .body_kind = 2};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1); check_result(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot generate DeepAI multipart boundary", key, "unsupported native POST configuration", "context canceled", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1); check_result(&out.items[0], key, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user; fail_alloc_size = 3 * sizeof(br_header); fail_alloc_after = 1; return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "deepai %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = allocation_failures, before_random = random_calls;
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(random_calls == before_random + 1 && !fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&out.items[0], key, false); br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static void resources_and_rng_failures(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "deepai %s\ndeepai %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2}; steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 299};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = {&http, test_http_send, release_reply};
        br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
        br_result prior = {0}; br_results out = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
        const char *errors[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create DeepAI result", "cannot create DeepAI result"};
        for (int f = 0; f < 4; ++f) {
            if (f == 0) { fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; }
            if (f == 1) { fail_alloc_size = 37; fail_alloc_after = 2; }
            if (f == 2) { fail_alloc_size = 36; fail_alloc_after = 2; }
            if (f == 3) fail_part_after = 2;
            steps.random_start = random_calls;
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1 && error && !strcmp(error, errors[f]));
            CHECK(!fail_alloc_after && !fail_part_after && random_calls == steps.random_start + (mode != 0 && f >= 2 ? 1u : 0u));
            CHECK(http.calls == (mode == 1 && f >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_type);
            check_prior(&out, raw, saved, parts); free(error); error = NULL; http.calls = http.releases = 0;
        }
        if (mode != 0) {
            const int failures[] = {0, -1, 2};
            for (size_t f = 0; f < 3; ++f) {
                steps.random_start = random_calls; fail_random_on = random_calls + 2; fail_random_value = failures[f];
                CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot generate DeepAI multipart boundary"));
                CHECK(random_calls == steps.random_start + 2 && !fail_random_on);
                CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_type);
                check_prior(&out, raw, saved, parts); free(error); error = NULL; http.calls = http.releases = 0;
            }
        }
        size_t capacity = out.cap; out.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot append DeepAI result"));
        out.cap = capacity; check_prior(&out, raw, saved, parts); free(error); error = NULL;
        steps.random_start = random_calls;
        CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error && random_calls == steps.random_start + 2);
        check_prior(&out, raw, saved, parts); br_results_clear(&out);
    }
    size_t before = random_calls; fail_random_on = before + 1; fail_random_value = 0;
    br_results out = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(out.len == 2 && random_calls == before && fail_random_on == before + 1); fail_random_on = 0;
    check_result(&out.items[0], key, false); check_result(&out.items[1], other, false); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rng_failures(detector);
    return test_finish("DeepAI");
}
