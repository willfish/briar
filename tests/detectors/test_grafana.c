/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static size_t fail_size, fail_after, fail_add_after, allocation_failures;
static test_http *watch_http;
static const char *watch_text;
static size_t watch_copies;

/* Target real helper allocations, including their positive failure returns. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (watch_http && !strcmp(text, watch_text)) {
        CHECK(watch_http->calls == watch_copies / 2 + 1);
        CHECK(watch_http->releases == (watch_copies + 1) / 2);
        ++watch_copies;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *detector;
static char key[168], maximum[168], input[512];

static void result_check(const br_result *r, const char *expected, bool verified, const char *cause)
{
    test_key_result(r, 830, expected, "key");
    CHECK(r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}

static void extraction(const void *text, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, text, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_check(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}

static void grammar_and_metadata(void)
{
    char *error = NULL; const br_detector *again = NULL;
    CHECK(br_grafana_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_grafana_init(&detector, &error) == 0 && !error);
    CHECK(br_grafana_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 830 && detector->version == 0 && !strcmp(detector->name, "Grafana"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Grafana is an open-source platform for monitoring and observability. Grafana API keys can be used to access and manage Grafana resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "glc_eyJ"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    memcpy(key, "glc_eyJ", 7); test_secret(key + 7, 60, 1);
    key[12] = '+'; key[23] = '/'; key[31] = '='; key[44] = 'Q';
    memcpy(maximum, "glc_eyJ", 7); test_secret(maximum + 7, 160, 2);
    maximum[166] = '=';
    extraction(key, 67, key); extraction(maximum, 167, maximum);
    extraction(key, 66, NULL); extraction(NULL, 0, NULL);
    const char *accepted[] = {"%s_", "%s-", "(%s)", "\r\n%s", "grafana %s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), accepted[i], key); extraction(input, strlen(input), key); }
    const char *rejected[] = {"x%s", "_%s", "9%s"};
    for (size_t i = 0; i < 3; ++i) { snprintf(input, sizeof(input), rejected[i], key); extraction(input, strlen(input), NULL); }
    memcpy(input, key, 68); input[6] = 'j'; extraction(input, 67, NULL);
    memcpy(input, key, 68); input[0] = 'G'; extraction(input, 67, NULL);
    memcpy(input, key, 68); input[20] = '_'; extraction(input, 67, NULL);
    memcpy(input, maximum, 167); input[167] = 'A'; extraction(input, 168, maximum);
    /* Greedy capture has no end boundary, including when a word byte follows. */
    memcpy(input, maximum, 167); input[167] = '_'; extraction(input, 168, maximum);
    memcpy(input, key, 67); input[67] = 0; input[68] = (char)0xff; extraction(input, 69, key);
    snprintf(input, sizeof(input), "%s\n%s\n%s", key, maximum, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    result_check(&out.items[0], key, false, NULL); result_check(&out.items[1], maximum, false, NULL); result_check(&out.items[2], key, false, NULL);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
}

typedef struct {
    const char *expected_key, *borrowed_auth;
    char read_cause[512];
    bool poison_read, fail_setter;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx && http->releases + 1 == http->calls && !s->borrowed_auth);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://grafana.com/api/v1/tokens?region=us"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 830);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, s->expected_key));
    CHECK(strlen(request->headers[0].value) == 7 + strlen(s->expected_key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog grafana-offline"));
    s->borrowed_auth = request->headers[0].value;
    if (s->fail_setter && http->calls == 2) { fail_size = strlen(http->send_error) + 1; fail_after = 2; }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(!strncmp(s->borrowed_auth, "Bearer ", 7) && !strcmp(s->borrowed_auth + 7, s->expected_key));
        s->borrowed_auth = NULL;
    } else CHECK(!response->status && !response->body.data && !response->body_error);
    if (watch_http == http) CHECK(watch_copies == http->calls * 2 - 1);
    if (s->poison_read) memset(s->read_cause, '!', strlen(s->read_cause));
    test_http_release(user, response);
}

static void outcome(int status, const void *body, size_t len, const char *read_error,
                    int send_rc, const char *send_error, bool valid, const char *cause,
                    const char *token)
{
    script s = {.expected_key = token, .poison_read = read_error != NULL};
    if (read_error) snprintf(s.read_cause, sizeof(s.read_cause), "%s", read_error);
    test_http http = {.user = &s, .inspect = inspect, .send_rc = send_rc, .send_error = send_error,
        .response = {.status = status, .body = {body, len}, .body_error = read_error ? s.read_cause : NULL}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "grafana-offline"};
    br_results out = test_scan(detector, &ctx, true, token, strlen(token));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
    result_check(&out.items[0], token, valid, cause); br_results_clear(&out);
}

static void verification(void)
{
    const unsigned char binary[] = {0, 0xff, 'r','e','q','u','i','r','e','d',' ','s','c','o','p','e'};
    outcome(200, NULL, 0, "ignored read error", 0, NULL, true, NULL, maximum);
    outcome(403, NULL, 0, "", 0, NULL, true, NULL, key);
    const char *positive[] = {"invalid permission", "required scope", "not JSON: invalid permission!", "InvalidCredentials required scope", "Unauthorized invalid permission"};
    for (size_t i = 0; i < 5; ++i) outcome(401, positive[i], strlen(positive[i]), NULL, 0, NULL, true, NULL, key);
    outcome(401, binary, sizeof(binary), NULL, 0, NULL, true, NULL, key);
    const char *negative[] = {"", "Unauthorized", "InvalidCredentials", "Invalid Permission", "Required Scope", "required  scope"};
    for (size_t i = 0; i < 6; ++i) outcome(401, negative[i], strlen(negative[i]), NULL, 0, NULL, false, NULL, key);
    outcome(401, "required scope", 14, "", 0, NULL, false, "", key);
    char cause[512]; snprintf(cause, sizeof(cause), "read %s Bearer %s", key, key);
    outcome(401, "invalid permission", 18, cause, 0, NULL, false, "read [REDACTED] Bearer [REDACTED]", key);
    const int statuses[] = {201, 204, 299, 400, 429, 500};
    for (size_t i = 0; i < 6; ++i) {
        char expected[64]; snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        outcome(statuses[i], "required scope", 14, "ignored", 0, NULL, false, expected, key);
    }
    const char *errors[] = {cause, "context deadline exceeded", "failed to create request", "cannot create Grafana result", "", NULL};
    for (size_t i = 0; i < 6; ++i) outcome(200, NULL, 0, NULL, i % 2 ? -7 : 1, errors[i], false,
        i == 0 ? "read [REDACTED] Bearer [REDACTED]" : errors[i] ? errors[i] : "HTTP transport failed", key);
    br_results out = test_scan(detector, NULL, true, key, 67); CHECK(out.len == 1);
    result_check(&out.items[0], key, false, "net/http: nil Context"); br_results_clear(&out);
    /* The borrowed read cause is copied before release; setter copies after it. */
    script s = {.expected_key = key, .poison_read = true}; strcpy(s.read_cause, "synthetic borrowed read cause");
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 401, .body_error = s.read_cause}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "grafana-offline"};
    watch_http = &http; watch_text = "synthetic borrowed read cause"; watch_copies = 0;
    out = test_scan(detector, &ctx, true, key, 67); CHECK(watch_copies == 2 && http.releases == 1);
    result_check(&out.items[0], key, false, watch_text); watch_http = NULL; br_results_clear(&out);
    /* Identical occurrences still make separate requests. */
    http.calls = http.releases = 0; http.response = (br_http_response){.status = 200}; s.poison_read = false;
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    out = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(out.len == 2 && http.calls == 2 && http.releases == 2); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }

static void setup_and_resources(void)
{
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        script s = {.expected_key = key}; test_http http = {.user = &s}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, key, 67);
        CHECK(out.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u) && !fail_after);
        result_check(&out.items[0], key, false, causes[mode]); br_results_clear(&out);
    }
    br_results out = {0}; br_result seed = {0}; CHECK(br_finding_key(&seed, 777, "caller", "key") == 0);
    seed.verified = true; CHECK(br_results_push(&out, &seed) == 0);
    unsigned char *saved = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts;
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    const char *expected[] = {"out of memory copying detector capture", "cannot create Grafana result", "cannot create Grafana result", "cannot copy Grafana read error", "cannot store Grafana verification error", "cannot store Grafana verification error", "cannot append Grafana result"};
    for (int mode = 0; mode < 7; ++mode) {
        script s = {.expected_key = key}; test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "grafana-offline"};
        size_t cap = out.cap, before = allocation_failures; char *error = NULL;
        switch (mode) {
        case 0: fail_size = 68; fail_after = 2; break;
        case 1: fail_size = 67; fail_after = 2; break;
        case 2: fail_add_after = 2; break;
        case 3: http.response = (br_http_response){.status = 401, .body_error = "borrowed read allocation"}; fail_size = sizeof("borrowed read allocation"); fail_after = 1; break;
        case 4: fail_size = sizeof("net/http: nil Context"); fail_after = 1; break;
        case 5: http.response = (br_http_response){.status = 401, .body_error = "borrowed setter allocation deliberately distinct"}; fail_size = sizeof("borrowed setter allocation deliberately distinct"); fail_after = 2; break;
        case 6: out.cap = 0; break;
        }
        CHECK(detector->scan(detector, mode == 1 || mode == 4 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
        out.cap = cap;
        CHECK(error && !strcmp(error, expected[mode]) && !fail_after && !fail_add_after);
        CHECK(out.len == 1 && out.items[0].raw.data == saved && out.items[0].secret_parts == parts && out.items[0].verified && !memcmp(saved, "caller", 6));
        CHECK(http.calls == http.releases && !s.borrowed_auth);
        if (mode != 2 && mode != 6) CHECK(allocation_failures == before + 1);
        free(error);
    }
    /* A late positive setter failure rolls back an earlier appended finding. */
    script s = {.expected_key = key, .fail_setter = true};
    test_http http = {.user = &s, .inspect = inspect, .send_rc = 1, .send_error = "synthetic send setter allocation"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "grafana-offline"}; char *error = NULL;
    watch_http = &http; watch_text = http.send_error; watch_copies = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot store Grafana verification error") && watch_copies == 4 && !fail_after && http.calls == 2 && http.releases == 2);
    CHECK(out.len == 1 && out.items[0].raw.data == saved && out.items[0].secret_parts == parts);
    watch_http = NULL; free(error); br_results_clear(&out);
    br_result probe = {0}; probe.verification_error = strdup("keep"); char *original = probe.verification_error;
    CHECK(br_result_set_verification_error(&probe, NULL, NULL, 0) == 0 && probe.verification_error == original); br_result_clear(&probe);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    grammar_and_metadata(); verification(); setup_and_resources();
    return test_finish("Grafana");
}
