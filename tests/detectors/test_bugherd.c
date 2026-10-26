/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

static char key[23], other[23];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* Exercise the real core setter's positive-1 allocation failure. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 22 && strlen(other) == 22);
    CHECK(br_bugherd_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Bugherd detector output")); free(error); error = NULL;
    CHECK(!br_bugherd_init(&detector, &error) && detector && !error);
    CHECK(!br_bugherd_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 602 && detector->version == 0 && !strcmp(detector->name, "Bugherd"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Bugherd is a visual feedback and bug tracking tool for websites. Bugherd API keys can be used to access and manage projects, tasks, and feedback data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bugherd"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) { test_key_result(&results.items[0], 602, expected, "key"); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[24];
    snprintf(input, sizeof(input), "bugherd %s", key); extraction_case(detector, input, key); CHECK(key[0] == 'z'); /* Not hex-only. */
    snprintf(input, sizeof(input), "preBUGHERDpost\r\n(%s)", key); extraction_case(detector, input, key);
    extraction_case(detector, key, NULL); extraction_case(detector, "", NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "bugherd%*s%s", gap, "", key); extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'Z'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[9] = '-'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, NULL);
    changed[9] = '_'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, NULL);
    changed[9] = '.'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[21] = '\0'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "bugherd %s0", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "bugherd _%s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "bugherd %s_", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "bugherd%s", key); extraction_case(detector, input, NULL);
    memset(changed, 'a', 22); changed[22] = '\0'; snprintf(input, sizeof(input), "bugherd %s", changed); extraction_case(detector, input, changed); /* No entropy gate. */
    snprintf(input, sizeof(input), "bugherd %s\nBUGHERD %s\nbugherd %s", key, key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    test_key_result(&results.items[0], 602, key, "key"); test_key_result(&results.items[1], 602, key, "key"); test_key_result(&results.items[2], 602, other, "key");
    br_results_clear(&results);
}

typedef struct { const char *key; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply replies[3]; size_t count, releases, cancel_calls; bool cancel, expired;
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
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 602 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.bugherd.com/api_v2/projects.json"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/json"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && !strncmp(auth, "Basic ", 6) && strlen(auth) == 38);
    unsigned char decoded[32]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 32) == 24);
    CHECK(!memcmp(decoded, step->key, 22) && decoded[22] == ':' && decoded[23] == 'x');
    static const unsigned char body[] = "\xff\0not JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close failure"};
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
    char input[64]; snprintf(input, sizeof(input), "bugherd %s", step.key); script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); test_key_result(&results.items[0], 602, step.key, "key"); return results;
}

static void verification(const br_detector *detector)
{
    const int codes[] = {200, 401, 201, 400, 403, 429, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = codes[i]});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]);
        check_error(&results.items[0], codes[i] == 200, codes[i] == 200 || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char plain[25], auth[40], cause[256]; snprintf(plain, sizeof(plain), "%s:x", key); memcpy(auth, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)auth + 6, (const unsigned char *)plain, 24) == 32);
    snprintf(cause, sizeof(cause), "unredacted token=%s auth=%s repeat=%s other=%s", key, auth, key, other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .send_error = cause});
    check_error(&results.items[0], false, cause); CHECK(strstr(results.items[0].verification_error, key) && strstr(results.items[0].verification_error, auth)); br_results_clear(&results);
    results = single(detector, (reply){.key = key, .send_rc = -1}); check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
    char input[256]; snprintf(input, sizeof(input), "bugherd %s\nbugherd %s\nbugherd %s", key, key, other);
    script steps = {.count = 3, .releases = 3};
    steps.replies[0] = (reply){.key = key, .status = 200}; steps.replies[1] = (reply){.key = key, .status = 200}; steps.replies[2] = (reply){.key = other, .status = 200};
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 602, steps.replies[i].key, "key"); check_error(&results.items[i], true, NULL); }
    br_results_clear(&results);
}

static void context_and_resource_failure(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "bugherd %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "bugherd %s\nbugherd %s", key, other); script steps = {.count = 2, .releases = 2};
    steps.replies[0] = (reply){.key = key, .status = 200}; steps.replies[1] = (reply){.key = other, .status = 503};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true; int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && *error && http.calls == 2 && http.releases == 2);
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_error(&results.items[0], true, NULL); check_error(&results.items[1], false, status_503); br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 22, 1); test_secret(other, 22, 13); key[0] = 'z'; other[0] = 'q';
    const br_detector *detector = init();
    extraction(detector); verification(detector); context_and_resource_failure(detector);
    return test_finish("Bugherd lowercase occurrences + Basic key:x + unredacted verification errors");
}
