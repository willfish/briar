/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "G7h9J2k5M6n8P3q4" "R1s0T2u5V7w9X2y4" "Z6a8B3c1D5e7F9g2" "H4j6K8m0N3p5Q7r9";
static const char other[] = "Z9y8X7w6V5u4T3s2" "R1q0P9n8M7k6J5h4" "G3f2E1d0C9b8A7z6" "Y5x4W3v2U1t0S9r8";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Actual native resource boundaries, never an invented URL allocation seam. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64);
    CHECK(br_disqus_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:disqus)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_disqus_init(&detector, &error) == -1 && !detector && error && !fail_after);
    free(error); error = NULL;
    CHECK(br_disqus_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_disqus_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 789 && detector->version == 0 && !strcmp(detector->name, "Disqus"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Disqus is a networked community platform used for web comments and discussions. Disqus API keys can be used to access and manage comments and user data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "disqus"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result(const br_result *value, const char *expected, bool verified)
{
    test_key_result(value, 789, expected, "key");
    CHECK(value->raw.len == 64 && value->verified == verified && !value->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(value->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 64 && !memcmp(json_object_get_string(part), expected, 64));
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
    char input[256], changed[66];
    const char *accepted[] = {"disqus = '%s'", "DiSqUs\r\n%s", "preDISQUSsuffix:%s", "disqus\r%s", "disqus\n%s", "disqus-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *bad[] = {"%s", "%s disqus", "dis qus %s", "disqus%s", "disqus _%s", "disqus %s_", "disqus X%s", "disqus %s9"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "disqus%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[63] = '\0';
    snprintf(input, sizeof(input), "disqus %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[64] = 'A'; changed[65] = '\0';
    snprintf(input, sizeof(input), "disqus %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "_-./+";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[32] = invalid[i];
        snprintf(input, sizeof(input), "DISQUS %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    const char low_entropy[] = {'A', 'z', '9'};
    for (size_t i = 0; i < sizeof(low_entropy); ++i) {
        memset(changed, low_entropy[i], 64); changed[64] = '\0';
        snprintf(input, sizeof(input), "disqus %s", changed); extraction_case(detector, input, strlen(input), changed);
    } /* Both cases/nonhex letters accepted; no local entropy filtering. */
    snprintf(input, sizeof(input), "disqus %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Whole-match non-overlap. */
    int len = snprintf(input, sizeof(input), "disqus%c%s", 0, key);
    CHECK(len == 71); extraction_case(detector, input, (size_t)len, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, rc, body_kind; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; bool suffix; } script;

static void url_value(const char *url, const char *expected_key)
{
    char expected[124];
    CHECK(snprintf(expected, sizeof(expected), "https://disqus.com/api/3.0/trends/listThreads.json?api_key=%s", expected_key) == 123);
    CHECK(url && strlen(url) == 123 && !memcmp(url, expected, sizeof(expected)));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    reply *row = &steps->rows[at];
    CHECK(request->detector_type == 789 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET")); url_value(request->url, row->key);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->suffix ? "TruffleHog disqus-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    /* No Auth/Type/Accept/CL header; the .json endpoint never implies parsing. */
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){body, sizeof(body)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "ignored synthetic read failure"};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    url_value(steps->borrowed_url, steps->rows[http->calls - 1].key);
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "disqus-offline" : NULL}; steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_url);
    return out;
}

static void verification_and_occurrences(const br_detector *detector)
{
    unsigned char input[3 * 73 + 1]; size_t len = 0; const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, "DiSqUs ", 7); len += 7; memcpy(input + len, keys[i], 64); len += 64;
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
    char single[80]; snprintf(single, sizeof(single), "disqus %s", key); data = (br_slice){(const unsigned char *)single, strlen(single)};
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 301, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = statuses[i], .body_kind = (int)(i % 3)};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1);
        result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Disqus result", key, "context canceled", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results out = run(detector, data, true, &steps); CHECK(out.len == 1);
        result(&out.items[0], key, false); br_results_clear(&out); /* No diagnostic-stage classifier or setter. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_failures(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "disqus %s", key);
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
    char input[160]; snprintf(input, sizeof(input), "disqus %s\ndisqus %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    script steps = {.count = 2}; steps.rows[0] = (reply){.key = key, .status = 204}; steps.rows[1] = (reply){.key = other, .status = 299};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = {&http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
    br_result prior = {0}; br_results out = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
    fail_size = 2 * sizeof(br_span); fail_after = 1;
    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    fail_size = 65; fail_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    for (int nil_context = 0; nil_context < 2; ++nil_context) {
        fail_part_after = 2; /* After first candidate was appended, or constructor-skipped. */
        CHECK(detector->scan(detector, nil_context ? NULL : &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Disqus result") && !fail_part_after);
        CHECK(http.calls == (nil_context ? 0u : 1u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&out, raw, saved, parts); free(error); error = NULL; http.calls = http.releases = 0;
    }
    size_t capacity = out.cap; out.cap = 0; /* Actual positive +1 append rejection. */
    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Disqus result"));
    out.cap = capacity; check_prior(&out, raw, saved, parts); free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error && !http.calls);
    check_prior(&out, raw, saved, parts); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification_and_occurrences(detector); shared_setup_failures(detector); owned_failures_and_skip(detector);
    return test_finish("Disqus");
}
