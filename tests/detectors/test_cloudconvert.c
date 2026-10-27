/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static bool track_raw;
static size_t raw_allocations, fail_raw_after;

/* Fail a real 836-byte Raw allocation for the minimum ASCII capture. This is
 * not an authorization copy or an attempt to emulate Go allocation failure. */
void *malloc(size_t size)
{
    if (track_raw && size == 836) {
        ++raw_allocations;
        if (fail_raw_after && --fail_raw_after == 0) return NULL;
    }
    return calloc(1, size);
}

typedef struct { unsigned char data[1300]; size_t len; } token;
typedef struct { unsigned char data[4096]; size_t len; } subject;
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})

/* A fixed source-shaped synthetic fixture, not a JWT encoder/validator. */
static token make_token(size_t first, size_t second, size_t third, br_slice separator1, br_slice separator2)
{
    token value = {0};
    CHECK(4 + first + second + third + separator1.len + separator2.len <= sizeof(value.data));
    memcpy(value.data, "ey", 2); value.len = 2;
    memset(value.data + value.len, 'a', first); value.len += first;
    memcpy(value.data + value.len, separator1.data, separator1.len); value.len += separator1.len;
    memcpy(value.data + value.len, "ey", 2); value.len += 2;
    memset(value.data + value.len, 'B', second); value.len += second;
    memcpy(value.data + value.len, separator2.data, separator2.len); value.len += separator2.len;
    memset(value.data + value.len, 'c', third); value.len += third;
    return value;
}

static void append(subject *input, const void *data, size_t len)
{
    CHECK(input->len + len <= sizeof(input->data));
    memcpy(input->data + input->len, data, len); input->len += len;
}

static subject wrapped(const token *value, const char *prefix, const char *suffix)
{
    subject input = {0}; append(&input, prefix, strlen(prefix)); append(&input, value->data, value->len); append(&input, suffix, strlen(suffix));
    return input;
}

static subject candidates(const token *const *values, size_t count)
{
    subject input = {0};
    for (size_t i = 0; i < count; ++i) {
        append(&input, "cloudconvert ", 13); append(&input, values[i]->data, values[i]->len); append(&input, "\n", 1);
    }
    return input;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_cloudconvert_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CloudConvert detector output")); free(error); error = NULL;
    CHECK(!br_cloudconvert_init(&detector, &error) && detector && !error);
    CHECK(!br_cloudconvert_init(&again, NULL) && again == detector);
    CHECK(detector->type == 829 && detector->version == 0 && !strcmp(detector->name, "CloudConvert") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "CloudConvert is a file conversion service. CloudConvert API keys can be used to access and manage file conversion operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloudconvert"));
    CHECK(detector->max_secret_size == 1300 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const token *expected, bool verified)
{
    CHECK(result->detector_type == 829 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == expected->len && !memcmp(result->raw.data, expected->data, expected->len));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len && !result->redacted);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == expected->len && !memcmp(json_object_get_string(part), expected->data, expected->len));
}

static void extraction_case(const br_detector *detector, subject input, const token *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    token minimum = make_token(30, 200, 600, TEXT("."), TEXT("."));
    token maximum = make_token(34, 500, 700, TEXT("."), TEXT("."));
    CHECK(minimum.len == 836 && maximum.len == 1240 && minimum.data[2] != 'J');
    extraction_case(detector, wrapped(&minimum, "CLOUDCONVERT '", "'"), &minimum);
    extraction_case(detector, wrapped(&maximum, "prefixClOuDcOnVeRtsuffix\r\n", "\n"), &maximum);
    extraction_case(detector, wrapped(&minimum, "", ""), NULL);
    extraction_case(detector, wrapped(&minimum, "cloud convert ", ""), NULL);
    extraction_case(detector, wrapped(&minimum, "cloudconvert _", ""), NULL);
    extraction_case(detector, wrapped(&maximum, "cloudconvert ", "X"), NULL); /* 701 word bytes cannot end at a boundary at 700. */
    const size_t outside[][3] = {{29, 200, 600}, {35, 200, 600}, {30, 199, 600}, {30, 501, 600}, {30, 200, 599}, {30, 200, 701}};
    for (size_t i = 0; i < sizeof(outside) / sizeof(outside[0]); ++i) {
        token changed = make_token(outside[i][0], outside[i][1], outside[i][2], TEXT("."), TEXT("."));
        extraction_case(detector, wrapped(&changed, "cloudconvert ", ""), NULL);
    }
    token changed = minimum; changed.data[0] = 'E'; extraction_case(detector, wrapped(&changed, "CLOUDCONVERT ", ""), NULL);
    changed = minimum; changed.data[33] = 'E'; extraction_case(detector, wrapped(&changed, "CLOUDCONVERT ", ""), NULL);
    changed = minimum; changed.data[4] = '_'; extraction_case(detector, wrapped(&changed, "cloudconvert ", ""), NULL); /* Header class excludes punctuation. */
    changed = make_token(30, 200, 600, TEXT("!"), TEXT(":"));
    memcpy(changed.data + 35, "/-_", 3); memcpy(changed.data + 236, "/-_", 3);
    extraction_case(detector, wrapped(&changed, "cloudconvert ", ""), &changed); /* Not literal dots, JWT or Base64 validation. */
    changed = make_token(30, 200, 600, TEXT("\n"), TEXT("."));
    extraction_case(detector, wrapped(&changed, "cloudconvert ", ""), NULL); /* Dot is not DOTALL outside PrefixRegex. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        subject input = {0}; append(&input, "cloudconvert", 12);
        unsigned char spaces[41]; memset(spaces, ' ', sizeof(spaces)); append(&input, spaces, gap); append(&input, minimum.data, minimum.len);
        extraction_case(detector, input, gap == 40 ? &minimum : NULL);
    }
}

typedef struct { const token *key; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply rows[4]; size_t count; const br_scan_ctx *expected_ctx;
    const char *authorization;
} script;

static void check_authorization(const char *value, const token *key)
{
    CHECK(value && strlen(value) == 7 + key->len && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, key->data, key->len)); /* All bytes, including both four-byte separators and the final byte. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 4 && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 829 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.cloudconvert.com/v2/users/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/vnd.cloudconvert+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    steps->authorization = request->headers[1].value; check_authorization(steps->authorization, step->key);
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->authorization) {
        CHECK(http->calls && http->calls <= steps->count);
        check_authorization(steps->authorization, steps->rows[http->calls - 1].key); /* Borrowed stack value remains live through release. */
        steps->authorization = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, subject input, bool verify, script *steps, size_t releases)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == (verify ? releases : 0) && !steps->authorization);
    return results;
}

static void wildcard_bytes(const br_detector *detector)
{
    token nul1 = make_token(30, 200, 600, TEXT("\0"), TEXT("."));
    token nul2 = make_token(30, 200, 600, TEXT("."), TEXT("\0"));
    token control = make_token(30, 200, 600, TEXT("\x01"), TEXT("\r"));
    token tab = make_token(30, 200, 600, TEXT("\t"), TEXT(":"));
    token wide = make_token(34, 500, 700, TEXT("\xf0\x9f\x8c\x9f"), TEXT("\xf0\x9f\x9a\x80"));
    CHECK(nul1.len == 836 && nul2.len == 836 && wide.len == 1246);
    extraction_case(detector, wrapped(&nul1, "cloudconvert ", ""), &nul1);
    extraction_case(detector, wrapped(&nul2, "cloudconvert ", ""), &nul2);
    extraction_case(detector, wrapped(&wide, "cloudconvert ", ""), &wide);
    const token *all[] = {&nul1, &control, &tab, &wide}; subject input = candidates(all, 4);
    script steps = {.count = 2, .rows = {{&tab, 201, 0, NULL}, {&wide, 299, 0, NULL}}};
    br_results results = run(detector, input, false, &steps, 0); CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&results.items[i], all[i], false);
    br_results_clear(&results);
    results = run(detector, input, true, &steps, 3); CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&results.items[i], all[i], i >= 2);
    br_results_clear(&results);
    /* NUL performs no send/release; invalid C0 header is suppressed; later TAB
     * and full 1246-byte non-ASCII candidates still reach the injected adapter. */
    const token *nulls_then_valid[] = {&nul1, &nul2, &tab}; input = candidates(nulls_then_valid, 3);
    steps = (script){.count = 1, .rows = {{&tab, 200, 0, NULL}}};
    results = run(detector, input, true, &steps, 1); CHECK(results.len == 3);
    check_result(&results.items[0], &nul1, false); check_result(&results.items[1], &nul2, false); check_result(&results.items[2], &tab, true); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input.data, input.len); CHECK(!results.len); br_results_clear(&results); /* Constructor SKIP comes BEFORE NUL gate. */
    results = test_scan(detector, NULL, false, input.data, input.len); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], nulls_then_valid[i], false);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    token key = make_token(30, 200, 600, TEXT("!"), TEXT(":"));
    token other = make_token(34, 500, 700, TEXT("."), TEXT("."));
    const token *duplicates[] = {&key, &key, &other}; subject input = candidates(duplicates, 3);
    script steps = {.count = 3, .rows = {{&key, 200, 0, NULL}, {&key, 201, 0, NULL}, {&other, 401, 0, NULL}}};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = run(detector, input, verify, &steps, 3); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], duplicates[i], verify && i < 2);
        br_results_clear(&results);
    }
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){duplicates[i], 200, 1, "no such host"};
    for (int retry = 0; retry < 2; ++retry) {
        br_results results = run(detector, input, true, &steps, 3); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], duplicates[i], false);
        br_results_clear(&results);
    }
    input = wrapped(&key, "cloudconvert ", "");
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{&key, statuses[i], 0, NULL}}};
        br_results results = run(detector, input, true, &steps, 1); CHECK(results.len == 1);
        check_result(&results.items[0], &key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "unsupported: native SANE policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{&key, 200, i % 2 ? 1 : -1, errors[i]}}};
        br_results results = run(detector, input, true, &steps, 1); CHECK(results.len == 1);
        check_result(&results.items[0], &key, false); br_results_clear(&results);
    }
    br_scan_ctx missing = {0}; br_results results = test_scan(detector, &missing, true, input.data, input.len);
    CHECK(results.len == 1); check_result(&results.items[0], &key, false); br_results_clear(&results);
}

static void resource_rollback(const br_detector *detector)
{
    token key = make_token(30, 200, 600, TEXT("."), TEXT("."));
    const token *duplicates[] = {&key, &key}; subject input = candidates(duplicates, 2);
    script steps = {.count = 2, .rows = {{&key, 200, 0, NULL}, {&key, 201, 0, NULL}}};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
    raw_allocations = 0; fail_raw_after = 2; track_raw = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){input.data, input.len}, &results, &error); track_raw = false;
    CHECK(rc == -1 && error && !strcmp(error, "cannot create CloudConvert result"));
    CHECK(!fail_raw_after && raw_allocations == 2 && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input.data, input.len); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], &key, true); check_result(&results.items[1], &key, true); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); wildcard_bytes(detector); verification(detector); resource_rollback(detector);
    return test_finish("CloudConvert");
}
