/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

static char key[29], other[29];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* One targeted core-setter +1 resource failure, not a provider outcome. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 28 && strlen(other) == 28);
    CHECK(br_browshot_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Browshot detector output")); free(error); error = NULL;
    CHECK(!br_browshot_init(&detector, &error) && detector && !error);
    CHECK(!br_browshot_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 448 && detector->version == 0 && !strcmp(detector->name, "Browshot"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Browshot is a service that allows you to take screenshots of web pages from different browsers and devices. Browshot API keys can be used to automate and manage these screenshots."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "browshot"));
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
    if (expected) { test_key_result(&results.items[0], 448, expected, "key"); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[30];
    snprintf(input, sizeof(input), "browshot %s", key); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "preBROWSHOTpost\r\n(%s)", key); extraction_case(detector, input, key);
    extraction_case(detector, key, NULL); extraction_case(detector, "", NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "browshot%*s%s", gap, "", key); extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[9] = '-'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, changed);
    memcpy(changed, key, sizeof(key)); changed[9] = '_'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    changed[9] = ':'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    changed[9] = '.'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[27] = '\0'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "browshot %sX", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "browshot _%s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "browshot %s_", key); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "browshot%s", changed); extraction_case(detector, input, changed); /* Word-to-hyphen left boundary. */
    memcpy(changed, key, sizeof(key)); changed[27] = '-';
    snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "browshot %sX", changed); extraction_case(detector, input, changed); /* Hyphen-to-word right boundary. */
    memset(changed, '-', 28); changed[28] = '\0'; snprintf(input, sizeof(input), "browshot%sX", changed); extraction_case(detector, input, changed);
    memset(changed, 'A', 28); changed[28] = '\0'; snprintf(input, sizeof(input), "browshot %s", changed); extraction_case(detector, input, changed); /* No entropy gate. */
    snprintf(input, sizeof(input), "browshot %s\nBROWSHOT %s\nbrowshot %s", key, key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    test_key_result(&results.items[0], 448, key, "key"); test_key_result(&results.items[1], 448, key, "key"); test_key_result(&results.items[2], 448, other, "key");
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
    reply *step = &steps->replies[at]; char url[128]; snprintf(url, sizeof(url), "https://api.browshot.com/api/v1/instance/list?key=%s", step->key);
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 448 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Authorization") && !header(request, "Accept") && !header(request, "Content-Type") && !header(request, "Content-Length"));
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
    char input[64]; snprintf(input, sizeof(input), "browshot %s", step.key); script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); test_key_result(&results.items[0], 448, step.key, "key"); return results;
}

static void verification(const br_detector *detector)
{
    const int codes[] = {200, 400, 401, 201, 403, 429, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = codes[i]});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]);
        check_error(&results.items[0], codes[i] == 200, codes[i] == 200 || codes[i] == 400 || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[256]; snprintf(cause, sizeof(cause), "synthetic https://api.browshot.com/api/v1/instance/list?key=%s echo %s keep %s", key, key, other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .send_error = cause});
    check_error(&results.items[0], false, cause); CHECK(strstr(results.items[0].verification_error, key)); br_results_clear(&results);
    results = single(detector, (reply){.key = key, .send_rc = -1}); check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
    char dashed[29]; memcpy(dashed, key, sizeof(key)); dashed[9] = '-';
    results = single(detector, (reply){.key = dashed, .status = 200}); check_error(&results.items[0], true, NULL); br_results_clear(&results);
    char input[256]; snprintf(input, sizeof(input), "browshot %s\nbrowshot %s\nbrowshot %s", key, key, other);
    script steps = {.count = 3, .releases = 3}; steps.replies[0] = (reply){.key = key, .status = 200};
    steps.replies[1] = (reply){.key = key, .status = 400}; steps.replies[2] = (reply){.key = other, .status = 503};
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    test_key_result(&results.items[0], 448, key, "key"); test_key_result(&results.items[1], 448, key, "key"); test_key_result(&results.items[2], 448, other, "key");
    check_error(&results.items[0], true, NULL); check_error(&results.items[1], false, NULL); check_error(&results.items[2], false, status_503); br_results_clear(&results);
}

static void context_and_resource_failure(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "browshot %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "browshot %s\nbrowshot %s", key, other); script steps = {.count = 2, .releases = 2};
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
    test_secret(key, 28, 1); test_secret(other, 28, 13); key[0] = 'A'; key[9] = 'Z'; other[0] = 'Q';
    const br_detector *detector = init();
    extraction(detector); verification(detector); context_and_resource_failure(detector);
    return test_finish("Browshot literal-hyphen occurrences + status-only GET + unredacted query errors");
}
