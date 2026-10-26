/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

static const char project[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other_project[] = "fedcba98-7654-3210-fedc-ba9876543210";
static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char other_key[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;
static size_t fail_part_after;

/* Target the setter's initial strdup and the real finding helper's part
 * allocations. These are provider resources, not synthetic Client.Do errors. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_part_after && --fail_part_after == 0) return NULL;
    CHECK(len >= 0 && (!len || !memchr(value, 0, (size_t)len)));
    char *copy = malloc((size_t)len + 1); CHECK(copy); if (len) memcpy(copy, value, (size_t)len); copy[len] = '\0';
    struct json_object *out = json_object_new_string(copy); free(copy); return out;
}

static void descriptors(const br_detector **v1, const br_detector **v2)
{
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(project) == 36 && strlen(other_project) == 36 && strlen(key) == 64 && strlen(other_key) == 64);
    CHECK(br_captaindata_v1_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CaptainData v1 detector output")); free(error); error = NULL;
    CHECK(br_captaindata_v2_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CaptainData v2 detector output")); free(error); error = NULL;
    CHECK(!br_captaindata_v2_init(v2, &error) && *v2 && !error); /* Either factory can initialize the shared patterns first. */
    CHECK(!br_captaindata_v1_init(v1, &error) && *v1 && !error);
    CHECK(!br_captaindata_v1_init(&again, &error) && again == *v1 && !error);
    CHECK(!br_captaindata_v2_init(&again, &error) && again == *v2 && !error);
    const br_detector *versions[] = {*v1, *v2};
    for (size_t i = 0; i < 2; ++i) {
        const br_detector *d = versions[i]; CHECK(d->type == 708 && d->version == (int)i + 1 && !strcmp(d->name, "CaptainData"));
        CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, "CaptainData is a service for automating data extraction and processing. The API keys can be used to access and control these automation processes."));
        CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "captaindata"));
        CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == (i ? -1 : 1024));
        CHECK(d->scan && d->state && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    }
    CHECK((*v1)->state == (*v2)->state && (*v1)->scan == (*v2)->scan && (*v1)->description == (*v2)->description);
}

static void check_text(br_json *object, const char *name, const char *text)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(text) && !memcmp(json_object_get_string(value), text, strlen(text)));
}

static void check_result(const br_result *result, const char *expected_project, const char *expected_key)
{
    CHECK(result->detector_type == 708 && !result->detector_name);
    CHECK(result->raw.len == 64 && !memcmp(result->raw.data, expected_key, 64));
    CHECK(result->raw_v2.len == 100 && result->raw_v2.data != result->raw.data);
    CHECK(!memcmp(result->raw_v2.data, expected_project, 36) && !memcmp(result->raw_v2.data + 36, expected_key, 64));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "key", expected_key); check_text(result->secret_parts, "project_id", expected_project);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void input_for(char *out, size_t size, const char *const *projects, size_t np, const char *const *keys, size_t nk)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < np + nk; ++i) {
        const char *value = i < np ? projects[i] : keys[i - np];
        int n = snprintf(out + at, size - at, "captaindata %s\n", value); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void expect_one(const br_detector *detector, const char *input, const char *p, const char *k)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (p ? 1u : 0u));
    if (p) { check_result(&results.items[0], p, k); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[1024], p[38], k[66]; const char *projects[] = {project}, *keys[] = {key};
    input_for(input, sizeof(input), projects, 1, keys, 1); expect_one(detector, input, project, key);
    snprintf(input, sizeof(input), "CAPTAINDATA -%s-\n%s\nCaPtAiNdAtA -%s-", project, isolation, key); expect_one(detector, input, project, key);
    input_for(input, sizeof(input), projects, 1, NULL, 0); expect_one(detector, input, NULL, NULL);
    input_for(input, sizeof(input), NULL, 0, keys, 1); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "%s\n%s\ncaptaindata %s", project, isolation, key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "captaindata %s\n%s\n%s", project, isolation, key); expect_one(detector, input, NULL, NULL);
    memcpy(p, project, sizeof(project)); p[9] = 'A'; snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", p, key); expect_one(detector, input, NULL, NULL);
    memcpy(p, project, sizeof(project)); p[8] = '_'; snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", p, key); expect_one(detector, input, NULL, NULL);
    memcpy(p, project, sizeof(project)); p[35] = '\0'; snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", p, key); expect_one(detector, input, NULL, NULL);
    snprintf(p, sizeof(p), "%sa", project); snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", p, key); expect_one(detector, input, NULL, NULL);
    memcpy(k, key, sizeof(key)); k[10] = 'A'; snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", project, k); expect_one(detector, input, NULL, NULL);
    memcpy(k, key, sizeof(key)); k[63] = '\0'; snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", project, k); expect_one(detector, input, NULL, NULL);
    snprintf(k, sizeof(k), "%sa", key); snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", project, k); expect_one(detector, input, NULL, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "captaindata%*s%s\n%s\ncaptaindata %s", gap, "", project, isolation, key); expect_one(detector, input, gap == 40 ? project : NULL, key);
        snprintf(input, sizeof(input), "captaindata %s\n%s\ncaptaindata%*s%s", project, isolation, gap, "", key); expect_one(detector, input, gap == 40 ? project : NULL, key);
    }
    snprintf(input, sizeof(input), "captaindata _%s\n%s\ncaptaindata %s", project, isolation, key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "captaindata %s\n%s\ncaptaindata %s_", project, isolation, key); expect_one(detector, input, NULL, NULL);
    memset(k, '0', 64); k[64] = '\0'; const char *zero = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "captaindata %s\ncaptaindata %s", zero, k); expect_one(detector, input, zero, k); /* No entropy, UUID-version or UUID false-positive policy. */
}

typedef struct { const char *project, *key; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply replies[9]; size_t count, releases, cancel_calls; int version; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 9 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 708 && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    if (steps->version == 1) {
        char expected[128]; snprintf(expected, sizeof(expected), "https://api.captaindata.co/v2/%s", step->project);
        CHECK(!strcmp(request->url, expected) && request->nheaders == 2);
        CHECK(header(request, "x-api-key") && !strcmp(header(request, "x-api-key"), step->key));
        CHECK(!header(request, "Authorization") && !header(request, "x-project-id"));
    } else {
        CHECK(!strcmp(request->url, "https://api.captaindata.co/v3/workspace") && request->nheaders == 3);
        const char *auth = header(request, "Authorization"); CHECK(auth && strlen(auth) == 74 && !memcmp(auth, "x-api-key ", 10) && !memcmp(auth + 10, step->key, 64));
        CHECK(header(request, "x-project-id") && !strcmp(header(request, "x-project-id"), step->project) && !header(request, "x-api-key"));
    }
    static const unsigned char body[] = "\xff\0ignored body";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps, .deadline_monotonic_ms = steps->expired ? 1 : 0};
    steps->expected_ctx = &ctx; steps->version = detector->version;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->releases); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    char input[160]; const char *projects[] = {step.project}, *keys[] = {step.key}; input_for(input, sizeof(input), projects, 1, keys, 1);
    script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], step.project, step.key); return results;
}

static void products(const br_detector *detector)
{
    const char *projects[] = {project, other_project, project}, *keys[] = {key, other_key, key}; char input[512]; input_for(input, sizeof(input), projects, 3, keys, 3);
    size_t width = detector->version == 1 ? 3 : 2; script steps = {.count = width * width, .releases = width * width};
    for (size_t p = 0; p < width; ++p) for (size_t k = 0; k < width; ++k) steps.replies[p * width + k] = (reply){.project = projects[p], .key = keys[k], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; br_results results = scan(detector, input, verify, verify ? &steps : &none); CHECK(results.len == width * width);
        for (size_t p = 0; p < width; ++p) for (size_t k = 0; k < width; ++k) { check_result(&results.items[p * width + k], projects[p], keys[k]); check_error(&results.items[p * width + k], verify, NULL); }
        br_results_clear(&results);
    }
}

static void verification(const br_detector *detector)
{
    const int codes[] = {199, 200, 201, 204, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        int code = codes[i]; br_results results = single(detector, (reply){.project = project, .key = key, .status = code});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", code);
        bool v1 = detector->version == 1; check_error(&results.items[0], v1 ? code >= 200 && code < 300 : code == 200, v1 || code == 200 || code == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[320], redacted[240]; snprintf(cause, sizeof(cause), "project=%s key=%s Authorization=x-api-key %s", project, key, key);
    snprintf(redacted, sizeof(redacted), "project=%s key=[REDACTED] Authorization=x-api-key [REDACTED]", project);
    const char *causes[] = {cause, "net/http: nil Context", "out of memory constructing HTTP headers", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        br_results results = single(detector, (reply){.project = project, .key = key, .status = 200, .send_rc = 1, .send_error = causes[i]});
        const char *expected = detector->version == 1 ? NULL : i == 0 ? redacted : causes[i] ? causes[i] : "HTTP transport failed";
        check_error(&results.items[0], false, expected); br_results_clear(&results);
    }
}

static void contexts(const br_detector *detector)
{
    char input[160]; const char *projects[] = {project}, *keys[] = {key}; input_for(input, sizeof(input), projects, 1, keys, 1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1); check_result(&results.items[0], project, key); check_error(&results.items[0], false, NULL); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == (detector->version == 1 ? 0u : 1u));
    if (results.len) { check_result(&results.items[0], project, key); check_error(&results.items[0], false, "net/http: nil Context"); } br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline}; results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, detector->version == 1 ? NULL : deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
}

static unsigned char *prior_result(br_results *results)
{
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(results, &prior)); return results->items[0].raw.data;
}

static void check_prior(const br_results *results, unsigned char *saved, char *saved_error)
{
    CHECK(results->len == 1 && results->items[0].raw.data == saved && results->items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    CHECK(results->items[0].detector_type == 777 && results->items[0].verified && results->items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    check_text(results->items[0].secret_parts, "key", "prior");
}

static void resource_boundary(const br_detector *detector, bool setter_failure)
{
    char input[256]; const char *projects[] = {project}, *keys[] = {key, other_key}; input_for(input, sizeof(input), projects, 1, keys, 2);
    script steps = {.count = 2, .releases = 2, .version = detector->version};
    steps.replies[0] = (reply){.project = project, .key = key, .status = 200}; steps.replies[1] = (reply){.project = project, .key = other_key, .status = setter_failure ? 503 : 200};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; unsigned char *saved = prior_result(&results); char *saved_error = results.items[0].verification_error, *error = NULL;
    if (setter_failure) fail_status_copy = true;
    else fail_part_after = 4; /* Second pair's project part, after RawV2 was allocated. */
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, setter_failure ? "cannot verify CaptainData candidate" : "cannot create CaptainData result"));
    CHECK(!fail_status_copy && !fail_part_after && http.calls == (setter_failure ? 2u : 1u) && http.releases == http.calls); check_prior(&results, saved, saved_error); free(error); error = NULL;
    if (detector->version == 1) {
        CHECK(!detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) && !error); check_prior(&results, saved, saved_error);
    }
    br_results_clear(&results); results = scan(detector, input, true, &steps); CHECK(results.len == 2);
    for (size_t k = 0; k < 2; ++k) { check_result(&results.items[k], project, keys[k]); check_error(&results.items[k], !setter_failure || k == 0, setter_failure && k == 1 ? status_503 : NULL); }
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *v1 = NULL, *v2 = NULL; descriptors(&v1, &v2);
    const br_detector *versions[] = {v1, v2};
    for (size_t i = 0; i < 2; ++i) { extraction(versions[i]); products(versions[i]); verification(versions[i]); contexts(versions[i]); resource_boundary(versions[i], false); }
    br_result probe = {0}; fail_status_copy = true; CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    resource_boundary(v2, true);
    fail_status_copy = true; br_results results = single(v1, (reply){.project = project, .key = key, .status = 503}); CHECK(fail_status_copy); fail_status_copy = false; check_error(&results.items[0], false, NULL); br_results_clear(&results);
    return test_finish("CaptainData v1/v2 multiplicity + project-key RawV2 + explicit verifier/resource policies");
}
