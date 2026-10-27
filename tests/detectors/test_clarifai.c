/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[33], other_key[33];
static size_t fail_finding_after;

/* One targeted provider-finding allocation failure, not a probe/Do error. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[33]; memcpy(copy, value, 32); copy[32] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other_key) == 32);
    CHECK(br_clarifai_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Clarifai detector output")); free(error); error = NULL;
    CHECK(!br_clarifai_init(&detector, &error) && detector && !error);
    CHECK(!br_clarifai_init(&again, NULL) && again == detector);
    CHECK(detector->type == 57 && detector->version == 0 && !strcmp(detector->name, "Clarifai"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Clarifai is an AI platform for visual recognition. Clarifai API keys can be used to access and manage visual recognition models and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clarifai"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 57, secret, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[33];
    const char *formats[] = {"clarifai %s", "CLARIFAI '%s'", "prefixClArIfAiSuffix=%s", "clarifai\r\n%s", "clarifai \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key); /* Mixed case/digits/nonhex remain unchanged. */
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"clarifai _%s", "clarifai %s_", "clarifai X%s", "clarifai %sA", "clarifai %.31s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = '_';
    snprintf(input, sizeof(input), "clarifai %s", changed);
    extraction_case(detector, input, NULL);
    memset(changed, 'Z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "clarifai %s", changed);
    extraction_case(detector, input, changed); /* No entropy or hex validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "clarifai", 8); memset(input + 8, '.', gap);
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "clarifai %s %s", key, key);
    extraction_case(detector, input, key); /* First match consumes the only keyword. */
}

typedef struct { const char *key; bool fallback; int status, send_rc; const char *send_error; } reply;
typedef struct { reply rows[6]; size_t len; uint32_t timeout_limit; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->len && http->releases + 1 == http->calls);
    const reply *step = &steps->rows[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, step->fallback ? "https://api.clarifai.com/v2/users/me" : "https://api.clarifai.com/v2/inputs"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 57);
    if (steps->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= steps->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Literal Key + shared UA; no Content-Type/Accept/manual Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 36 && !memcmp(request->headers[0].value, "Key ", 4));
    CHECK(!strcmp(request->headers[0].value + 4, step->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored read/close error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
    /* Counts assert ABI1's eager release, NOT source holding the first
     * successful Do response through fallback and scan-deferred Close-only. */
}

static void run_pair(const br_detector *detector, reply first, const reply *second, bool verified)
{
    char input[64]; snprintf(input, sizeof(input), "clarifai %s", key);
    script steps = {.rows = {first}, .len = second ? 2 : 1};
    if (second) steps.rows[1] = *second;
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == steps.len && http.releases == steps.len);
    check_result(&results.items[0], key, verified); br_results_clear(&results);
}

static void ordered_probes(const br_detector *detector)
{
    const int successes[] = {200, 201, 204, 299};
    for (size_t i = 0; i < sizeof(successes) / sizeof(successes[0]); ++i)
        run_pair(detector, (reply){.key = key, .status = successes[i]}, NULL, true); /* Body error does not trigger fallback. */
    const int first_failures[] = {199, 300, 401, 403, 500};
    reply second = {.key = key, .fallback = true, .status = 299};
    for (size_t i = 0; i < sizeof(first_failures) / sizeof(first_failures[0]); ++i)
        run_pair(detector, (reply){.key = key, .status = first_failures[i]}, &second, true);
    const int second_failures[] = {199, 300, 401, 503};
    for (size_t i = 0; i < sizeof(second_failures) / sizeof(second_failures[0]); ++i) {
        second.status = second_failures[i];
        run_pair(detector, (reply){.key = key, .status = 401}, &second, false);
    }
    char sensitive[128]; snprintf(sensitive, sizeof(sensitive), "synthetic Do error Key %s", key);
    const char *errors[] = {"no such host", "net/http: nil Context", "out of memory constructing HTTP headers", "out of memory creating Clarifai result", sensitive, NULL};
    second.status = 200;
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i)
        run_pair(detector, (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = errors[i]}, &second, true);
    second.send_rc = 9; second.send_error = sensitive;
    run_pair(detector, (reply){.key = key, .status = 200, .send_rc = 1, .send_error = "unsupported: native SANE policy"}, &second, false);
    /* Error text never identifies constructor/provider-resource stages. The
     * shared adapter setup/Do domain remains an explicit, unproved stage gap. */
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "clarifai %s\nCLARIFAI %s\nclarifai %s", key, other_key, key);
    const char *keys[] = {key, other_key, key}; script steps = {.len = 6};
    for (size_t i = 0; i < 3; ++i) {
        steps.rows[i * 2] = (reply){.key = keys[i], .status = 401};
        steps.rows[i * 2 + 1] = (reply){.key = keys[i], .fallback = true, .status = 204};
    }
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 6 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0); br_results_clear(&results); /* No probe, including fallback, on known constructor failure. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "clarifai %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], key, false); br_results_clear(&results);
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 2u));
        check_result(&results.items[0], key, false); br_results_clear(&results); /* Both Do attempts fail; finding stays. */
    }
    script steps = {.rows = {{.key = key, .status = 401}, {.key = key, .fallback = true, .status = 299}}, .len = 2, .timeout_limit = 2000};
    test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = test_transport(&http);
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + steps.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2 && http.releases == 2 && ctx.deadline_monotonic_ms == deadline);
    check_result(&results.items[0], key, true); br_results_clear(&results);
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 57, (br_slice){(const unsigned char *)key, 32}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Core errors need not be negative. */
    char input[128]; snprintf(input, sizeof(input), "clarifai %s\nclarifai %s", key, other_key);
    script steps = {.rows = {{.key = key, .status = 401}, {.key = key, .fallback = true, .status = 200},
        {.key = other_key, .status = 401}, {.key = other_key, .fallback = true, .status = 200}}, .len = 4};
    test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    unsigned char *saved_raw = prior.raw.data; char *saved_error = prior.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0);
    char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_finding_after && rc == -1 && error && !strcmp(error, "out of memory creating Clarifai result"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == saved_raw && !memcmp(saved_raw, "keep", 4));
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == saved_raw);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 4 && http.releases == 4);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0); key[0] = 'G'; key[20] = 'Z';
    test_secret(other_key, 32, 7); other_key[0] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector);
    ordered_probes(detector);
    occurrences_and_nil_context(detector);
    context(detector);
    resource_rollback(detector);
    return test_finish("Clarifai");
}
