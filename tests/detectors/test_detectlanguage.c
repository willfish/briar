/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "g7h9j2k5m6n8p3q4r1s0t2u5v7w9x2y4";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7k6j5h4";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Existing native resource boundaries, never a heap Authorization seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_detectlanguage_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:detectlanguage)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_detectlanguage_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_detectlanguage_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_detectlanguage_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 434 && detector->version == 0 && !strcmp(detector->name, "DetectLanguage"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DetectLanguage is a language detection API service. The API key can be used to access the language detection functionalities provided by DetectLanguage."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "detectlanguage"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result(const br_result *value, const char *expected, bool verified)
{
    test_key_result(value, 434, expected, "key");
    CHECK(value->raw.len == 32 && value->verified == verified && !value->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(value->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected, 32));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *accepted[] = {"detectlanguage = '%s'", "DeTeCtLaNgUaGe\r\n%s", "preDETECTLANGUAGEsuffix:%s", "detectlanguage\r%s", "detectlanguage\n%s", "detectlanguage-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s detectlanguage", "detect language %s", "detectlanguage%s", "detectlanguage _%s", "detectlanguage %s_", "detectlanguage x%s", "detectlanguage %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "detectlanguage%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "detectlanguage %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0';
    snprintf(input, sizeof(input), "detectlanguage %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "A_-/+";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[12] = invalid[i];
        snprintf(input, sizeof(input), "DETECTLANGUAGE %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "detectlanguage %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not hex-only or entropy filtered. */
    memset(changed, '9', 32);
    snprintf(input, sizeof(input), "detectlanguage %s", changed); extraction_case(detector, input, strlen(input), changed);
    snprintf(input, sizeof(input), "detectlanguage %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Whole-match non-overlap, not all nearby words. */
    int n = snprintf(input, sizeof(input), "detectlanguage%c%s", 0, key);
    CHECK(n == 47); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, rc, body_kind; } reply;
typedef struct {
    reply rows[3]; size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth;
    bool suffix;
} script;

static void authorization(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 39 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, expected, 33));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    reply *row = &steps->rows[at];
    CHECK(request->detector_type == 434 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://ws.detectlanguage.com/0.2/user/status"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, row->key); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog detectlanguage-offline" : "TruffleHog"));
    /* Full logical header set: no Content-Type, Accept or manual Content-Length. */
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){body, sizeof(body)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "ignored synthetic read failure"};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key);
    steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "detectlanguage-offline" : NULL}; steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_auth);
    return out;
}

static void verification_and_occurrences(const br_detector *detector)
{
    unsigned char input[3 * 49 + 1]; size_t len = 0; const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, "DetectLanguage ", 15); len += 15; memcpy(input + len, keys[i], 32); len += 32;
        input[len++] = '\0'; input[len++] = i == 1 ? '\r' : '\n';
    }
    input[len++] = 0xff; br_slice data = {input, len};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .suffix = true};
        steps.rows[0] = (reply){.key = key, .status = 200, .rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 201, .body_kind = 1};
        steps.rows[2] = (reply){.key = key, .status = 299, .body_kind = 2};
        br_results out = run(detector, data, verify, &steps); CHECK(out.len == 3);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], verify && i != 0);
        br_results_clear(&out);
        out = test_scan(detector, NULL, verify, data.data, data.len); CHECK(out.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < out.len; ++i) result(&out.items[i], keys[i], false);
        br_results_clear(&out);
    }
    char single[64]; snprintf(single, sizeof(single), "detectlanguage %s", key); data = (br_slice){(const unsigned char *)single, strlen(single)};
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 301, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = statuses[i], .body_kind = (int)(i % 3)};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1);
        result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create DetectLanguage result", key, "context canceled", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1);
        result(&out.items[0], key, false); br_results_clear(&out); /* Whole mixed domain is suppressed, never classified by text. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_failures(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "detectlanguage %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = allocation_failures;
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], key, false); br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static void owned_failures_and_skip(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "detectlanguage %s\ndetectlanguage %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    script steps = {.count = 2}; steps.rows[0] = (reply){.key = key, .status = 204}; steps.rows[1] = (reply){.key = other, .status = 299};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = {&http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
    br_result prior = {0}; br_results out = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;

    fail_size = 2 * sizeof(br_span); fail_after = 1; /* Native regex helper returns positive +1. */
    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    fail_size = 33; fail_after = 2; /* Capture failure precedes the known nil-context skip. */
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    for (int nil_context = 0; nil_context < 2; ++nil_context) {
        fail_part_after = 2; /* After first candidate was appended, or constructor-skipped. */
        CHECK(detector->scan(detector, nil_context ? NULL : &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create DetectLanguage result") && !fail_part_after);
        CHECK(http.calls == (nil_context ? 0u : 1u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&out, raw, saved, parts); free(error); error = NULL; http.calls = http.releases = 0;
    }
    size_t capacity = out.cap; out.cap = 0; /* Real +1 append guard, not a synthetic auth allocation. */
    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot append DetectLanguage result"));
    out.cap = capacity; check_prior(&out, raw, saved, parts); free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error && !http.calls);
    check_prior(&out, raw, saved, parts); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification_and_occurrences(detector); shared_setup_failures(detector); owned_failures_and_skip(detector);
    return test_finish("DetectLanguage");
}
