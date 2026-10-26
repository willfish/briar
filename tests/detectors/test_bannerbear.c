/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

static const char v1_key[] = "Ab9Cd8Ef7Gh6Ij5Kl4Mn3Ptt";
static const char v1_other[] = "Qw1Er2Ty3Ui4Op5As6Df7Gtt";
static const char project[] = "bb_pr_0123456789abcdef0123456789abcd";
static const char master[] = "bb_ma_fedcba9876543210fedcba98765432";
static const char unsupported[] = "unsupported: Bannerbear v2 non-marker 400 diagnostic";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* Target only the core setter's positive-1 allocation failure. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected));
    CHECK(!memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *key, const char *version, const char *key_type)
{
    CHECK(result->detector_type == 430 && !result->detector_name);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    check_text(result->secret_parts, "key", key);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    if (!version) CHECK(!result->extra_data);
    else {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == (key_type ? 2 : 1));
        check_text(result->extra_data, "version", version);
        if (key_type) check_text(result->extra_data, "key_type", key_type);
    }
}

static const br_detector *init(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_bannerbear_v1_init : br_bannerbear_v2_init;
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, version == 1 ? "invalid Bannerbear v1 detector output" : "invalid Bannerbear v2 detector output"));
    free(error); error = NULL;
    CHECK(!factory(&detector, &error) && detector && !error);
    CHECK(!factory(&again, &error) && again == detector && !error);
    CHECK(detector->type == 430 && detector->version == version && !strcmp(detector->name, "Bannerbear"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Bannerbear is an API for generating dynamic images, videos, and GIFs. Bannerbear API keys can be used to access and manipulate these resources."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(detector->nkeywords == (version == 1 ? 1u : 2u));
    CHECK(!strcmp(detector->keywords[0], version == 1 ? "bannerbear" : "bb_pr_"));
    if (version == 2) CHECK(!strcmp(detector->keywords[1], "bb_ma_"));
    return detector;
}

static void input_for(char *out, size_t size, int version, const char *key)
{
    int n = snprintf(out, size, "%s%s", version == 1 ? "bannerbear " : "", key);
    CHECK(n >= 0 && (size_t)n < size);
}

static void extraction_case(const br_detector *detector, const char *input, const char *key)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (key ? 1u : 0u));
    if (key) {
        check_result(&results.items[0], key, detector->version == 1 ? "1" : "2", NULL);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[512], value[80];
    CHECK(strlen(v1_key) == 24 && strlen(v1_other) == 24 && strlen(project) == 36 && strlen(master) == 36);
    input_for(input, sizeof(input), 1, v1_key); extraction_case(v1, input, v1_key);
    snprintf(input, sizeof(input), "BANNERBEAR\r\n(%s)", v1_key); extraction_case(v1, input, v1_key);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "bannerbear%*s%s", gap, "", v1_key);
        extraction_case(v1, input, gap == 40 ? v1_key : NULL);
    }
    extraction_case(v1, v1_key, NULL); extraction_case(v1, "", NULL);
    memcpy(value, v1_key, sizeof(v1_key)); value[23] = 'T'; input_for(input, sizeof(input), 1, value); extraction_case(v1, input, NULL);
    value[22] = 'T'; value[23] = 't'; input_for(input, sizeof(input), 1, value); extraction_case(v1, input, NULL);
    snprintf(value, sizeof(value), "x%s", v1_key); input_for(input, sizeof(input), 1, value); extraction_case(v1, input, NULL);
    snprintf(value, sizeof(value), "%s_", v1_key); input_for(input, sizeof(input), 1, value); extraction_case(v1, input, NULL);
    snprintf(value, sizeof(value), "_%s", v1_key); input_for(input, sizeof(input), 1, value); extraction_case(v1, input, NULL);
    input_for(input, sizeof(input), 1, v1_key + 1); extraction_case(v1, input, NULL);
    memset(value, 'A', 22); memcpy(value + 22, "tt", 3); input_for(input, sizeof(input), 1, value); extraction_case(v1, input, value);
    extraction_case(v2, project, project); extraction_case(v2, master, master); extraction_case(v2, "", NULL);
    snprintf(input, sizeof(input), "(%s)", master); extraction_case(v2, input, master);
    memcpy(value, project, sizeof(project)); value[0] = 'B'; extraction_case(v2, value, NULL);
    memcpy(value, project, sizeof(project)); value[3] = 'P'; extraction_case(v2, value, NULL);
    memcpy(value, project, sizeof(project)); value[8] = 'A'; extraction_case(v2, value, NULL);
    memcpy(value, project, sizeof(project)); value[8] = 'g'; extraction_case(v2, value, NULL);
    memcpy(value, project, sizeof(project)); value[35] = '\0'; extraction_case(v2, value, NULL);
    snprintf(value, sizeof(value), "%s0", project); extraction_case(v2, value, NULL);
    snprintf(value, sizeof(value), "x%s", project); extraction_case(v2, value, NULL);
    snprintf(value, sizeof(value), "_%s", project); extraction_case(v2, value, NULL);
    snprintf(value, sizeof(value), "%s_", project); extraction_case(v2, value, NULL);
    snprintf(input, sizeof(input), "bannerbear %s\nbannerbear %s\nbannerbear %s", v1_key, v1_key, v1_other);
    br_results results = test_scan(v1, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    check_result(&results.items[0], v1_key, "1", NULL); check_result(&results.items[1], v1_key, "1", NULL);
    check_result(&results.items[2], v1_other, "1", NULL); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s\n%s", project, master, project);
    results = test_scan(v2, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], project, "2", NULL); check_result(&results.items[1], master, "2", NULL); br_results_clear(&results);
}

typedef struct {
    const char *key, *send_error, *body_error;
    br_slice body;
    int status, send_rc;
} reply;
typedef struct {
    reply replies[4]; br_header tags[4]; size_t count, calls, releases, empty_releases, cancel_calls;
    bool released[4], cancel, expired;
    const br_scan_ctx *expected_ctx;
} fake_http;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static int send_fake(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    fake_http *fake = user; size_t at = fake->calls++;
    CHECK(ctx == fake->expected_ctx && at < fake->count && at < 4 && fake->releases == at);
    reply *step = &fake->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 430 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.bannerbear.com/v2/auth"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Type") && !header(request, "Content-Length"));
    char auth[64]; snprintf(auth, sizeof(auth), "Bearer %s", step->key);
    CHECK(header(request, "Authorization") && !strcmp(header(request, "Authorization"), auth));
    fake->tags[at] = (br_header){"fixture", "synthetic"};
    *response = (br_http_response){.status = step->status, .headers = &fake->tags[at], .nheaders = 1,
                                   .body = step->body, .body_error = step->body_error};
    *error = step->send_error ? strdup(step->send_error) : NULL; CHECK(!step->send_error || *error);
    return step->send_error ? -1 : step->send_rc;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user;
    if (!response->headers) { ++fake->empty_releases; return; }
    size_t at = 0; while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]); fake->released[at] = true; ++fake->releases;
}

static bool cancelled(void *user) { fake_http *fake = user; ++fake->cancel_calls; return fake->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake};
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = fake,
                       .deadline_monotonic_ms = fake->expired ? 1 : 0};
    fake->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(fake->calls == fake->count && fake->releases == fake->calls);
    return results;
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void statuses(const br_detector *detector)
{
    const int codes[] = {200, 401, 201, 403, 503};
    const char *key = detector->version == 1 ? v1_key : master;
    char input[96]; input_for(input, sizeof(input), detector->version, key);
    static const unsigned char body[] = "When using a Master API Key\0ignored";
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        fake_http fake = {.count = 1}; fake.replies[0] = (reply){.key = key, .status = codes[i],
            .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close failure"};
        br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1);
        check_result(&results.items[0], key, detector->version == 1 ? "1" : "2",
                      detector->version == 2 && codes[i] == 200 ? "Project API Key" : NULL);
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]);
        check_error(&results.items[0], codes[i] == 200, codes[i] == 200 || codes[i] == 401 ? NULL : expected);
        br_results_clear(&results);
    }
}

static void transport_and_context(const br_detector *detector)
{
    const char *key = detector->version == 1 ? v1_key : project;
    const char *other = detector->version == 1 ? v1_other : master;
    char input[96], cause[256], redacted[256]; input_for(input, sizeof(input), detector->version, key);
    snprintf(cause, sizeof(cause), "synthetic %s / %s; keep %s and https://api.bannerbear.com/v2/auth", key, key, other);
    snprintf(redacted, sizeof(redacted), "synthetic [REDACTED] / [REDACTED]; keep %s and https://api.bannerbear.com/v2/auth", other);
    for (int missing_cause = 0; missing_cause < 2; ++missing_cause) {
        fake_http fake = {.count = 1}; fake.replies[0] = (reply){.key = key, .status = 200, .send_rc = -1,
            .send_error = missing_cause ? NULL : cause, .body_error = "must not replace transport error"};
        br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1);
        check_result(&results.items[0], key, detector->version == 1 ? "1" : NULL, NULL);
        check_error(&results.items[0], false, missing_cause ? "HTTP transport failed" : redacted); br_results_clear(&results);
    }
    for (int deadline = 0; deadline < 2; ++deadline) {
        fake_http fake = {.cancel = !deadline, .expired = deadline};
        br_results results = scan(detector, input, false, &fake); CHECK(results.len == 1 && !fake.cancel_calls && !fake.empty_releases);
        check_result(&results.items[0], key, detector->version == 1 ? "1" : "2", NULL); check_error(&results.items[0], false, NULL);
        br_results_clear(&results);
        results = scan(detector, input, true, &fake); CHECK(results.len == 1 && fake.empty_releases == 1 && fake.cancel_calls);
        check_result(&results.items[0], key, detector->version == 1 ? "1" : NULL, NULL);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], key, detector->version == 1 ? "1" : NULL, NULL);
    check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
}

static void bad_request(const br_detector *v1, const br_detector *v2)
{
    static const unsigned char full[] = "prefix\0When using a Master API Key you must set a project_id parameter";
    static const unsigned char limited[] = "Error: this Master Key is Limited Access only";
    static const unsigned char ordinary[] = "ordinary non-marker diagnostic";
    static const unsigned char binary[] = "no marker\0nor after NUL";
    static const unsigned char wrong_case[] = "when using a master api key";
    const br_slice bodies[] = {{full, sizeof(full) - 1}, {limited, sizeof(limited) - 1},
        {ordinary, sizeof(ordinary) - 1}, {binary, sizeof(binary) - 1}, {wrong_case, sizeof(wrong_case) - 1}, {NULL, 0}};
    char input[96]; input_for(input, sizeof(input), 2, project);
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        fake_http fake = {.count = 1}; fake.replies[0] = (reply){.key = project, .status = 400, .body = bodies[i]};
        br_results results = scan(v2, input, true, &fake); CHECK(results.len == 1);
        check_result(&results.items[0], project, "2", i < 2 ? "Master API Key" : NULL);
        check_error(&results.items[0], i < 2, i < 2 ? NULL : unsupported); br_results_clear(&results);
    }
    char read_error[128]; snprintf(read_error, sizeof(read_error), "body read failure: %s", project);
    fake_http fake = {.count = 1}; fake.replies[0] = (reply){.key = project, .status = 400,
        .body = bodies[0], .body_error = read_error};
    br_results results = scan(v2, input, true, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], project, "2", NULL); check_error(&results.items[0], false, "body read failure: [REDACTED]"); br_results_clear(&results);
    input_for(input, sizeof(input), 1, v1_key);
    fake = (fake_http){.count = 1}; fake.replies[0] = (reply){.key = v1_key, .status = 400, .body = bodies[0], .body_error = "ignored"};
    results = scan(v1, input, true, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], v1_key, "1", NULL); check_error(&results.items[0], false, "unexpected status code: 400"); br_results_clear(&results);
}

static void multiple_keys(const br_detector *v1, const br_detector *v2)
{
    char input[256]; snprintf(input, sizeof(input), "bannerbear %s\nbannerbear %s", v1_key, v1_key);
    fake_http fake = {.count = 2}; fake.replies[0] = (reply){.key = v1_key, .status = 200};
    fake.replies[1] = (reply){.key = v1_key, .status = 401};
    br_results results = scan(v1, input, true, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], v1_key, "1", NULL); check_result(&results.items[1], v1_key, "1", NULL);
    check_error(&results.items[0], true, NULL); check_error(&results.items[1], false, NULL); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s\n%s", project, master, project);
    fake = (fake_http){.count = 2}; fake.replies[0] = (reply){.key = project, .status = 400};
    fake.replies[1] = (reply){.key = master, .status = 200};
    results = scan(v2, input, true, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], project, "2", NULL); check_error(&results.items[0], false, unsupported);
    check_result(&results.items[1], master, "2", "Project API Key"); check_error(&results.items[1], true, NULL); br_results_clear(&results);
}

static void setter_resource_failure(const br_detector *v2)
{
    char input[128]; snprintf(input, sizeof(input), "%s\n%s", project, master);
    fake_http fake = {.count = 2}; fake.replies[0] = (reply){.key = project, .status = 200};
    fake.replies[1] = (reply){.key = master, .status = 503};
    br_transport transport = {&fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport}; fake.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; fail_status_copy = true;
    int rc = v2->scan(v2, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot verify Bannerbear candidate"));
    CHECK(fake.calls == 2 && fake.releases == 2);
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    memset(fake.released, 0, sizeof(fake.released)); fake.calls = fake.releases = 0;
    results = scan(v2, input, true, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], project, "2", "Project API Key"); check_error(&results.items[0], true, NULL);
    check_result(&results.items[1], master, "2", NULL); check_error(&results.items[1], false, status_503); br_results_clear(&results);
}

int main(void)
{
    const br_detector *v1 = init(1), *v2 = init(2);
    extraction(v1, v2); statuses(v1); statuses(v2); transport_and_context(v1); transport_and_context(v2);
    bad_request(v1, v2); multiple_keys(v1, v2); setter_resource_failure(v2);
    return test_finish("Bannerbear v1/v2 extraction + replacement metadata + binary master markers");
}
