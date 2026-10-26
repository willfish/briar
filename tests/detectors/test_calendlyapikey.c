/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static size_t fail_finding_after;

/* Same targeted finding-allocation seam as Calendarific. All fixture tokens
 * are NUL-free ASCII; forward the complete bytes through the string constructor. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    CHECK(len >= 0 && (!len || !memchr(value, 0, (size_t)len)));
    char *copy = malloc((size_t)len + 1); CHECK(copy);
    if (len) memcpy(copy, value, (size_t)len);
    copy[len] = '\0'; struct json_object *out = json_object_new_string(copy); free(copy); return out;
}

static char *make_token(size_t first, size_t second, size_t signature)
{
    size_t len = 3 + first + 1 + 3 + second + 1 + signature;
    char *out = malloc(len + 1); CHECK(out); size_t at = 0;
    memcpy(out + at, "eyJ", 3); at += 3;
    const char a[] = "Ab7_-Q", b[] = "Bc8-_R", c[] = "Cd9_-S3";
    for (size_t i = 0; i < first; ++i) out[at++] = a[i % (sizeof(a) - 1)];
    out[at++] = '.'; memcpy(out + at, "eyJ", 3); at += 3;
    for (size_t i = 0; i < second; ++i) out[at++] = b[i % (sizeof(b) - 1)];
    out[at++] = '.';
    for (size_t i = 0; i < signature; ++i) out[at++] = c[i % (sizeof(c) - 1)];
    if (signature) out[at - 1] = 'Z';
    out[at] = '\0'; CHECK(at == len); return out;
}

static char *input_for(const char *prefix, size_t gap, const char *const *tokens, size_t count)
{
    size_t size = 1, plen = strlen(prefix);
    for (size_t i = 0; i < count; ++i) size += plen + gap + strlen(tokens[i]) + 1;
    char *out = malloc(size); CHECK(out); size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t len = strlen(tokens[i]); memcpy(out + at, prefix, plen); at += plen;
        memset(out + at, ' ', gap); at += gap; memcpy(out + at, tokens[i], len); at += len; out[at++] = '\n';
    }
    out[at] = '\0'; return out;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_calendlyapikey_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CalendlyApiKey detector output")); free(error); error = NULL;
    CHECK(!br_calendlyapikey_init(&detector, &error) && detector && !error);
    CHECK(!br_calendlyapikey_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 44 && detector->version == 0 && !strcmp(detector->name, "CalendlyApiKey"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Calendly is an online scheduling tool that allows users to schedule meetings and appointments. Calendly API keys can be used to access and manage Calendly accounts and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "calendly"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, bool verified)
{
    test_key_result(result, 44, token, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *prefix, size_t gap, const char *token, const char *expected)
{
    const char *tokens[] = {token}; char *input = input_for(prefix, gap, tokens, 1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results); free(input);
}

static void extraction(const br_detector *detector, const char *token)
{
    extraction_case(detector, "calendly", 1, token, token);
    extraction_case(detector, "CaLeNdLy", 1, token, token);
    extraction_case(detector, "calendly", 40, token, token);
    extraction_case(detector, "calendly", 41, token, NULL);
    extraction_case(detector, "calendar", 1, token, NULL);
    extraction_case(detector, "", 0, token, NULL);
    char *changed = strdup(token); CHECK(changed); changed[0] = 'E'; extraction_case(detector, "calendly", 1, changed, NULL);
    memcpy(changed, token, strlen(token) + 1); changed[2] = 'j'; extraction_case(detector, "calendly", 1, changed, NULL);
    memcpy(changed, token, strlen(token) + 1); changed[104] = 'E'; extraction_case(detector, "calendly", 1, changed, NULL);
    memcpy(changed, token, strlen(token) + 1); changed[103] = '#'; extraction_case(detector, "calendly", 1, changed, NULL);
    memcpy(changed, token, strlen(token) + 1); changed[207] = '@'; extraction_case(detector, "calendly", 1, changed, NULL);
    memcpy(changed, token, strlen(token) + 1); changed[5] = '+'; extraction_case(detector, "calendly", 1, changed, NULL); free(changed);
    const size_t lengths[][2] = {{99,100}, {100,99}, {100,100}, {300,300}, {301,100}, {100,301}};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        char *value = make_token(lengths[i][0], lengths[i][1], 1);
        bool valid = lengths[i][0] >= 100 && lengths[i][0] <= 300 && lengths[i][1] >= 100 && lengths[i][1] <= 300;
        extraction_case(detector, "calendly", 1, value, valid ? value : NULL); free(value);
    }
    char *value = make_token(100, 100, 0); extraction_case(detector, "calendly", 1, value, NULL); free(value);
    value = make_token(100, 100, 1); value[strlen(value) - 1] = '_'; extraction_case(detector, "calendly", 1, value, value);
    value[strlen(value) - 1] = '-'; extraction_case(detector, "calendly", 1, value, NULL); free(value);
    value = make_token(100, 100, 8); size_t len = strlen(value); value[len - 2] = value[len - 1] = '-';
    char *trimmed = strdup(value); CHECK(trimmed); trimmed[len - 2] = '\0';
    extraction_case(detector, "calendly", 1, value, trimmed); free(value); free(trimmed); /* Word-boundary regex backtracking, not JWT validation. */
}

typedef struct { const char *token; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply replies[3]; size_t count, releases, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 44 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.calendly.com/users/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Type") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); size_t len = strlen(step->token);
    CHECK(auth && strlen(auth) == 7 + len && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, step->token, len));
    static const unsigned char body[] = "\xff\0not JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close error"};
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
    const char *tokens[] = {step.token}; char *input = input_for("calendly", 1, tokens, 1);
    script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); free(input); CHECK(results.len == 1);
    check_result(&results.items[0], step.token, !step.send_error && !step.send_rc && step.status >= 200 && step.status < 300); return results;
}

static void verification(const br_detector *detector, const char *token)
{
    const int codes[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.token = token, .status = codes[i]}); br_results_clear(&results);
    }
    const char *causes[] = {"synthetic credential exchange error", "net/http: nil Context", "out of memory constructing HTTP headers", "context canceled", "unsupported: native SANE policy", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        br_results results = single(detector, (reply){.token = token, .status = 200, .send_rc = 1, .send_error = causes[i]}); br_results_clear(&results);
    }
    char *long_token = make_token(300, 300, 8193); CHECK(strlen(long_token) == 8801);
    br_results results = single(detector, (reply){.token = long_token, .status = 299}); br_results_clear(&results); free(long_token);
}

static void occurrences_and_context(const br_detector *detector, const char *token, const char *other)
{
    const char *tokens[] = {token, token, other}; char *input = input_for("CALENDLY", 1, tokens, 3);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results); /* Known constructor failure skips, not an unverified finding. */
    script steps = {.count = 3, .releases = 3};
    for (size_t i = 0; i < 3; ++i) steps.replies[i] = (reply){.token = tokens[i], .status = 204};
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], true);
    br_results_clear(&results); free(input);
    input = input_for("calendly", 1, tokens, 1);
    for (int deadline = 0; deadline < 2; ++deadline) {
        steps = (script){.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_result(&results.items[0], token, false); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls); check_result(&results.items[0], token, false); br_results_clear(&results);
    }
    br_scan_ctx empty = {0}; results = test_scan(detector, &empty, true, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], token, false); br_results_clear(&results); free(input); /* Configured adapter/setup errors also share the suppressed domain. */
}

static void resource_rollback(const br_detector *detector, const char *token, const char *other)
{
    const char *tokens[] = {token, other, token}; char *input = input_for("calendly", 1, tokens, 3);
    script steps = {.count = 3, .releases = 3}; for (size_t i = 0; i < 3; ++i) steps.replies[i] = (reply){.token = tokens[i], .status = 200};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; br_results results = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    CHECK(br_results_push(NULL, &prior) == 1); /* Core resource domains are not uniformly negative. */
    fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_finding_after && rc == -1 && error && !strcmp(error, "cannot create CalendlyApiKey result"));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); error = NULL;
    CHECK(!detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) && !error && results.len == 1 && results.items[0].raw.data == saved);
    br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], true);
    br_results_clear(&results); free(input);
}

int main(void)
{
    char *token = make_token(100, 100, 1), *other = make_token(100, 100, 7); CHECK(strlen(token) == 209);
    const br_detector *detector = init();
    extraction(detector, token); verification(detector, token); occurrences_and_context(detector, token, other); resource_rollback(detector, token, other);
    free(token); free(other);
    return test_finish("CalendlyApiKey exact JWT-shaped captures + unbounded Bearer + suppressed Do errors");
}
