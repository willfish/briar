/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[78], other[78];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Exercise existing allocation/JSON APIs, without an auth-format failure seam. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 77 && strlen(other) == 77);
    CHECK(br_ditto_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    fail_size = sizeof("(?i:ditto)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_ditto_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_ditto_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_ditto_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 666 && detector->version == 0 && !strcmp(detector->name, "Ditto"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Ditto is a service that provides API access to various word variants. Ditto API keys can be used to access this service and retrieve word variants."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ditto"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 666, expected, "key");
    CHECK(result->raw.len == 77 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 77);
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
    char input[224], changed[79];
    const char *accepted[] = {"ditto '%s'", "DiTtO=%s", "predittosuffix:%s",
        "ditto\r\n%s", "ditto\r%s", "ditto\n%s", "ditto %s.ignored"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, key);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "ditto%*s%s", gap, "", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    const char *rejected[] = {"%s", "%s ditto", "dit to %s", "ditto%s",
        "ditto _%s", "ditto %s_", "ditto x%s", "ditto %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[76] = '\0';
    snprintf(input, sizeof(input), "ditto %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[77] = 'a'; changed[78] = '\0';
    snprintf(input, sizeof(input), "ditto %s", changed); extraction_case(detector, input, NULL);
    /* Case folding applies only to the keyword. All four hyphens and the dot
     * are literal; the UUID-shaped prefix is NOT parsed as a UUID. */
    const size_t positions[] = {0, 37, 13, 36};
    const char invalid[] = {'A', 'A', '_', 'x'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[positions[i]] = invalid[i];
        snprintf(input, sizeof(input), "DITTO %s", changed); extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[8] = 'q'; changed[9] = '-';
    snprintf(input, sizeof(input), "ditto %s", changed); extraction_case(detector, input, NULL); /* Wrong 9-3 group shape. */
    memset(changed, '0', 77); changed[77] = '\0';
    changed[8] = changed[13] = changed[18] = changed[23] = '-'; changed[36] = '.';
    snprintf(input, sizeof(input), "ditto %s", changed); extraction_case(detector, input, changed); /* No UUID/version/variant, local FP or entropy check. */
    char bare[41]; test_secret(bare, 40, 0);
    snprintf(input, sizeof(input), "ditto %s", bare); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "ditto %.36s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "ditto %s %s", key, other);
    extraction_case(detector, input, key); /* One prefix match cannot be reused for another key. */
    extraction_case(detector, "ditto", NULL);
    extraction_case(detector, "", NULL);
}

typedef struct { const char *key; int status, send_rc; const char *send_error; int body_kind; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth;
    char expected_auth[84];
    bool suffix;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 666 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.dittowords.com/variants"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    memcpy(steps->expected_auth, "token ", 6);
    memcpy(steps->expected_auth + 6, row->key, 77); steps->expected_auth[83] = '\0';
    CHECK(strlen(request->headers[0].value) == 83 && !memcmp(request->headers[0].value, steps->expected_auth, 84));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->suffix ? "TruffleHog ditto-offline" : "TruffleHog"));
    /* Exact case/count excludes Token/Bearer, Accept, Content-Type and extras. */
    steps->borrowed_auth = request->headers[0].value;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){junk, sizeof(junk)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "synthetic ignored read failure"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 84));
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "ditto-offline" : NULL};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_auth);
    return out;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    unsigned char input[252]; size_t len = 0;
    const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, "ditto ", 6); len += 6;
        memcpy(input + len, keys[i], 77); len += 77;
        input[len++] = i == 0 ? '\0' : i == 1 ? '\r' : '\n';
    }
    CHECK(len == sizeof(input));
    br_slice data = {input, len};
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
    char input[84]; CHECK(snprintf(input, sizeof(input), "ditto %s", key) == 83);
    br_slice data = {(const unsigned char *)input, 83};
    const int statuses[] = {199, 200, 201, 204, 299, 300, 302, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .body_kind = (int)(i % 3)};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, data, true, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers",
        "cannot format Ditto authorization", "context deadline exceeded", key, NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {.key = key, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i], .body_kind = 2};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, data, true, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, false); /* Suppressed, never text-classified as local fatal/SKIP. */
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
    char input[84]; CHECK(snprintf(input, sizeof(input), "ditto %s", key) == 83);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_shared_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = allocation_failures;
        br_results out = test_scan(detector, &ctx, true, input, 83);
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
    char input[168]; CHECK(snprintf(input, sizeof(input), "ditto %s\nditto %s", key, other) == 167);
    br_slice data = {(const unsigned char *)input, 167};
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
            "cannot create Ditto result", "cannot create Ditto result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Genuine +1 capture failure. */
            if (failure == 1) { fail_size = 78; fail_after = 2; }
            if (failure == 2) { fail_size = 77; fail_after = 2; }
            if (failure == 3) fail_part_after = 2; /* Genuine +1 JSON failure, after one append or nil-context skip. */
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, errors[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
            check_prior(&out, raw, saved, parts);
            free(error); error = NULL; http.calls = http.releases = 0;
        }
        size_t capacity = out.cap; out.cap = 0; /* Genuine +1 append guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Ditto result"));
        out.cap = capacity; check_prior(&out, raw, saved, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
        check_prior(&out, raw, saved, parts); /* Normal constructor skip preserves caller findings too. */
        br_results_clear(&out);
    }
}

int main(void)
{
    test_secret(key, 77, 0); test_secret(other, 77, 11);
    const size_t hyphens[] = {8, 13, 18, 23};
    for (size_t i = 0; i < sizeof(hyphens) / sizeof(hyphens[0]); ++i)
        key[hyphens[i]] = other[hyphens[i]] = '-';
    key[36] = other[36] = '.';
    key[14] = key[19] = 'z'; /* Valid lowercase alnum, invalid UUID version/variant and non-hex. */
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences_and_nil_context(detector);
    statuses_and_send_errors(detector);
    shared_send_domain(detector);
    resource_failures(detector);
    return test_finish("Ditto");
}
