/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[37], other[37];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Exercise existing resource failures, not an artificial body-write seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
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
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_dfuse_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_dfuse_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dfuse_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 567 && detector->version == 0 && !strcmp(detector->name, "Dfuse"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Dfuse is a blockchain API company providing access to blockchain data and infrastructure. Dfuse API keys can be used to access and interact with blockchain data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "dfuse"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 567, expected, "key");
    CHECK(result->raw.len == 36 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 36);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[38];
    /* The dfuse keyword belongs to dispatch, NOT this direct extraction regex. */
    const char *accepted[] = {"%s", "'%s'", "%s dfuse", "DFUSE\r\n%s", "-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, key);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dfuse%*s%s", gap, "", key);
        extraction_case(detector, input, key);
    }
    const char *rejected[] = {"x%s", "_%s", "%s_", "%s9", "dfuse%s", "%sdfuse"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[35] = '\0';
    extraction_case(detector, changed, NULL);
    memcpy(changed, key, sizeof(key)); changed[36] = 'a'; changed[37] = '\0';
    extraction_case(detector, changed, NULL);
    const size_t positions[] = {0, 3, 12, 12};
    const char invalid[] = {'W', '-', 'A', '_'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[positions[i]] = invalid[i];
        extraction_case(detector, changed, NULL);
    }
    memcpy(changed, "web_", 4); memset(changed + 4, '0', 32); changed[36] = '\0';
    extraction_case(detector, changed, changed); /* No local FP/entropy filter. */
    extraction_case(detector, "dfuse", NULL);
    extraction_case(detector, "", NULL);
}

typedef struct { const char *key; int status, send_rc; const char *send_error; int body_kind; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    br_slice borrowed_body;
    char expected_body[51];
    bool suffix;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 567 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://auth.dfuse.io/v1/auth/issue"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->suffix ? "TruffleHog dfuse-offline" : "TruffleHog"));
    /* Exact count excludes auth/Accept/manual Content-Length headers. Shared
     * framing uses body.len=50; this is an auth-issuing POST, never live tested. */
    memcpy(steps->expected_body, "{\"api_key\":\"", 12);
    memcpy(steps->expected_body + 12, row->key, 36);
    memcpy(steps->expected_body + 48, "\"}", 3);
    CHECK(request->body.data && request->body.len == 50);
    CHECK(!memcmp(request->body.data, steps->expected_body, 50) && request->body.data[50] == '\0');
    steps->borrowed_body = request->body;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){junk, sizeof(junk)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "synthetic ignored read failure"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_body.data && steps->borrowed_body.len == 50);
    CHECK(!memcmp(steps->borrowed_body.data, steps->expected_body, 51));
    steps->borrowed_body = (br_slice){0};
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "dfuse-offline" : NULL};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_body.data);
    return out;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    unsigned char input[112];
    memcpy(input, key, 36); input[36] = '\0';
    memcpy(input + 37, other, 36); input[73] = '\r'; input[74] = '\n';
    memcpy(input + 75, key, 36); input[111] = '\n';
    br_slice data = {input, sizeof(input)};
    const char *keys[] = {key, other, key};
    const reply rows[] = {{key, 401, 0, NULL, 0}, {other, 204, 0, NULL, 1}, {key, 299, 0, NULL, 2}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u, .suffix = true};
        br_results out = run(detector, data, verify, &steps);
        CHECK(out.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify && i != 0);
        br_results_clear(&out);
        out = test_scan(detector, NULL, verify, data.data, data.len);
        CHECK(out.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < out.len; ++i) check_result(&out.items[i], keys[i], false);
        br_results_clear(&out);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    br_slice data = {(const unsigned char *)key, 36};
    const int statuses[] = {199, 200, 204, 299, 300, 302, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .body_kind = (int)(i % 3)};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, data, true, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers",
        "cannot format Dfuse request body", "unsupported: redirects for native HTTP POST", key, NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {.key = key, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i], .body_kind = 2};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, data, true, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, false); /* Suppressed, not classified as local fatal/SKIP. */
        br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_send_domain(const br_detector *detector)
{
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_shared_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = allocation_failures;
        br_results out = test_scan(detector, &ctx, true, key, 36);
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static void resource_failures(const br_detector *detector)
{
    char input[74];
    CHECK(snprintf(input, sizeof(input), "%s\n%s", key, other) == 73);
    br_slice data = {(const unsigned char *)input, 73};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results out = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&out, &prior) == 0);
        unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error;
        br_json *parts = out.items[0].secret_parts;
        const reply rows[] = {{key, 200, 0, NULL, 0}, {other, 299, 0, NULL, 0}};
        script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
        const char *errors[] = {"out of memory iterating regex", "out of memory copying detector capture",
            "cannot create Dfuse result", "cannot create Dfuse result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 capture failure. */
            if (failure == 1) { fail_size = 37; fail_after = 2; }
            if (failure == 2) { fail_size = 36; fail_after = 2; }
            if (failure == 3) fail_part_after = 2; /* Actual +1 JSON failure, after one append or nil-context skip. */
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, errors[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_body.data);
            check_prior(&out, raw, saved, parts);
            free(error); error = NULL; http.calls = http.releases = 0;
        }
        size_t capacity = out.cap; out.cap = 0; /* Actual +1 push guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Dfuse result"));
        out.cap = capacity;
        check_prior(&out, raw, saved, parts);
        free(error); error = NULL;
        /* Normal constructor SKIP also preserves preexisting caller results. */
        CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
        check_prior(&out, raw, saved, parts);
        br_results_clear(&out);
    }
}

int main(void)
{
    memcpy(key, "web_", 4); test_secret(key + 4, 32, 0);
    memcpy(other, "web_", 4); test_secret(other + 4, 32, 11);
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences_and_nil_context(detector);
    statuses_and_send_errors(detector);
    shared_send_domain(detector);
    resource_failures(detector);
    return test_finish("Dfuse");
}
