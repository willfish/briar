/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define BYTES(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char key[] = "0123456789abcdef0123456789abcdef";
static const char second_key[] = "abcdef0123456789abcdef0123456789";
static const char third_key[] = "fedcba9876543210fedcba9876543210";
static bool fail_503_dup;

char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, "unexpected status code: 503")) {
        fail_503_dup = false; return NULL;
    }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

typedef struct { const char *key, *id; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; const br_http_response *responses; } expected_requests;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_billomat_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(!br_billomat_init(&detector, &error) && detector && !error);
    CHECK(!br_billomat_init(&again, NULL) && again == detector);
    CHECK(detector->type == 385 && detector->version == 0 && !strcmp(detector->name, "Billomat"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Billomat is an online invoicing software. Billomat API keys can be used to access and manage invoices, clients, and other related data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "billomat"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair, bool verified, const char *error)
{
    size_t n = strlen(pair.id);
    CHECK(result->detector_type == 385 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 32 && !memcmp(result->raw.data, pair.key, 32));
    CHECK(result->raw_v2.data && result->raw_v2.len == 32 + n);
    CHECK(!memcmp(result->raw_v2.data, pair.key, 32) && !memcmp(result->raw_v2.data + 32, pair.id, n));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), pair.key, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == n && !strcmp(json_object_get_string(part), pair.id));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

/* Isolate ordinary fixtures. Without this gap, the ID regex may legitimately
 * capture a later provider/context word while looking past a 32-byte key. */
static void add_record(char *input, size_t capacity, size_t *at, const char *value)
{
    int n = snprintf(input + *at, capacity - *at, "billomat %s", value);
    CHECK(n >= 0 && (size_t)n + 51 < capacity - *at);
    *at += (size_t)n;
    memset(input + *at, '\n', 50); *at += 50; input[*at] = '\0';
}

static void single_input(char *input, size_t capacity, const char *id, const char *secret)
{
    size_t at = 0; input[0] = '\0';
    if (id) add_record(input, capacity, &at, id);
    if (secret) add_record(input, capacity, &at, secret);
}

static void expect_extract(const br_detector *detector, const char *input, const char *id, const char *secret)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (id ? 1 : 0) && !http.calls && !http.releases);
    if (id) check_pair(&results.items[0], (expected_pair){secret, id}, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], value[34], id20[22];
    single_input(input, sizeof(input), "zxyw", key);
    expect_extract(detector, input, "zxyw", key); /* IDs are lower ALNUM, not hex. */
    memcpy(input, "BILLOMAT", 8);
    expect_extract(detector, input, "zxyw", key);
    const char *bad_ids[] = {"abc", "Acctone", "_acctone", "acctone_"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); ++i) {
        single_input(input, sizeof(input), bad_ids[i], key);
        expect_extract(detector, input, NULL, NULL);
    }
    memset(id20, 'z', 20); id20[20] = '\0';
    single_input(input, sizeof(input), id20, key);
    expect_extract(detector, input, id20, key);
    id20[20] = 'z'; id20[21] = '\0';
    single_input(input, sizeof(input), id20, key);
    expect_extract(detector, input, NULL, NULL);
    single_input(input, sizeof(input), "acct-tail", key);
    expect_extract(detector, input, "acct", key); /* Source boundary allows the prefix before '-'. */
    const char *bad_keys[] = {"0123456789abcdef0123456789abcdef0", "0123456789abcdef0123456789abcde",
        "0123456789abcdeF0123456789abcdef", "0123456789abcdeg0123456789abcdef", "_0123456789abcdef0123456789abcdef"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        single_input(input, sizeof(input), "acctone", bad_keys[i]);
        expect_extract(detector, input, NULL, NULL);
    }
    memset(value, 'a', 32); value[32] = '\0';
    single_input(input, sizeof(input), "acctone", value);
    expect_extract(detector, input, "acctone", value); /* No entropy filtering. */
    single_input(input, sizeof(input), NULL, key);
    expect_extract(detector, input, NULL, NULL); /* No ID fallback. */
    single_input(input, sizeof(input), "acctone", NULL);
    expect_extract(detector, input, NULL, NULL);
    expect_extract(detector, "", NULL, NULL);
    snprintf(input, sizeof(input), "billomat %s\nbillomat acctone", key);
    expect_extract(detector, input, "billomat", key); /* Actual ID match consumes the second provider word. */
    size_t at = 0;
    add_record(input, sizeof(input), &at, "account actualid");
    add_record(input, sizeof(input), &at, key);
    expect_extract(detector, input, "account", key); /* Do not heuristically discard a context label. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "billomat", 8); memset(input + 8, '.', gap);
        size_t pos = 8 + gap;
        memcpy(input + pos, "acctone", 7); pos += 7;
        memset(input + pos, '\n', 50); pos += 50; input[pos] = '\0';
        add_record(input, sizeof(input), &pos, key);
        expect_extract(detector, input, gap == 40 ? "acctone" : NULL, key);
        pos = 0; add_record(input, sizeof(input), &pos, "acctone");
        int n = snprintf(input + pos, sizeof(input) - pos, "billomat%.*s%s", (int)gap, ".........................................", key);
        CHECK(n > 0 && (size_t)n < sizeof(input) - pos);
        expect_extract(detector, input, gap == 40 ? "acctone" : NULL, key);
    }
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    expected_pair pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 385 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    char url[96]; snprintf(url, sizeof(url), "https://%s.billomat.net/api/v2/clients/myself", pair.id);
    CHECK(!strcmp(request->url, url));
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-BillomatApiKey") && !strcmp(request->headers[1].value, pair.key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog billomat-test"));
    if (expected->responses) http->response = expected->responses[http->calls - 1];
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error, bool removed)
{
    char input[256]; single_input(input, sizeof(input), "acctone", key);
    expected_pair pair = {key, "acctone"}; expected_requests expected = {&pair, 1, NULL};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "billomat-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == (removed ? 0 : 1) && http->calls == 1 && http->releases == 1);
    if (!removed) check_pair(&results.items[0], pair, verified, error);
    br_results_clear(&results);
}

static void status_and_errors(const br_detector *detector)
{
    const struct { int status; br_slice body; const char *read_error, *error; bool verified, removed; } cases[] = {
        {200, BYTES("account not found"), "ignored", NULL, true, false},
        {401, BYTES("account not found"), "ignored", NULL, false, false},
        {404, BYTES("prefix\0account not found"), NULL, NULL, false, true},
        {404, BYTES("prefix\0account not found"), "partial read failed", NULL, false, false},
        {404, BYTES("Account not found"), NULL, NULL, false, false},
        {404, BYTES("account id not found"), NULL, NULL, false, false},
        {404, {0}, NULL, NULL, false, false},
        {201, BYTES("account not found"), "ignored", "unexpected status code: 201", false, false},
        {403, BYTES("account not found"), "ignored", "unexpected status code: 403", false, false},
        {500, {0}, "ignored", "unexpected status code: 500", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error}};
        verify_case(detector, &http, cases[i].verified, cases[i].error, cases[i].removed);
    }
    test_http dns = {.send_rc = 1, .send_error = "no such host"};
    verify_case(detector, &dns, false, dns.send_error, false);
    verify_case(detector, &dns, false, dns.send_error, false); /* No global DNS cache. */
    dns.send_error = NULL;
    verify_case(detector, &dns, false, "HTTP transport failed", false);
    char cause[256], redacted[256];
    snprintf(cause, sizeof(cause), "id=acctone key=%s again=%s other=%s", key, key, second_key);
    snprintf(redacted, sizeof(redacted), "id=acctone key=[REDACTED] again=[REDACTED] other=%s", second_key);
    dns.send_error = cause;
    verify_case(detector, &dns, false, redacted, false);
}

static void products_and_deletion(const br_detector *detector)
{
    char input[1024]; size_t at = 0;
    add_record(input, sizeof(input), &at, "acctone"); add_record(input, sizeof(input), &at, "accttwo");
    add_record(input, sizeof(input), &at, "acctone");
    add_record(input, sizeof(input), &at, key); add_record(input, sizeof(input), &at, second_key);
    add_record(input, sizeof(input), &at, third_key); add_record(input, sizeof(input), &at, key);
    const expected_pair all[] = {{key, "acctone"}, {key, "accttwo"}, {second_key, "acctone"}, {second_key, "accttwo"}, {third_key, "acctone"}, {third_key, "accttwo"}};
    expected_requests expected = {all, 6, NULL};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "billomat-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < 6; ++i) check_pair(&results.items[i], all[i], true, NULL);
    br_results_clear(&results); /* Independent uniqueness; success never breaks or consumes. */
    const expected_pair attempted[] = {{key, "acctone"}, {key, "accttwo"}, {second_key, "acctone"}, {second_key, "accttwo"}, {third_key, "accttwo"}};
    const br_http_response responses[] = {{.status = 200}, {.status = 200}, {.status = 404, .body = BYTES("prefix\0account not found")}, {.status = 200}, {.status = 200}};
    expected = (expected_requests){attempted, 5, responses};
    for (int scan = 0; scan < 2; ++scan) {
        http = (test_http){.inspect = inspect_request, .user = &expected};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 5 && http.releases == 5);
        check_pair(&results.items[0], all[0], true, NULL); /* Earlier finding for deleted ID STAYS. */
        check_pair(&results.items[1], all[1], true, NULL);
        check_pair(&results.items[2], all[3], true, NULL);
        check_pair(&results.items[3], all[5], true, NULL);
        br_results_clear(&results);
    } /* The next invocation attempts acctone again: deletion is LOCAL, not a TTL cache. */
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 6 && !http.calls && !http.releases);
    for (size_t i = 0; i < 6; ++i) check_pair(&results.items[i], all[i], false, NULL);
    br_results_clear(&results);
    expected = (expected_requests){all, 6, NULL};
    http = (test_http){.send_rc = 1, .send_error = "account id not found", .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < 6; ++i) check_pair(&results.items[i], all[i], false, "account id not found");
    br_results_clear(&results); /* Text equal to errAccountIDNotFound is NOT sentinel identity. */
    http = (test_http){.response = {.status = 404, .body = BYTES("account not found"), .body_error = "failed after marker"},
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < 6; ++i) check_pair(&results.items[i], all[i], false, NULL);
    br_results_clear(&results); /* ReadAll errors cannot delete IDs for later keys. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[256]; single_input(input, sizeof(input), "acctone", key);
    expected_pair pair = {key, "acctone"};
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], pair, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], pair, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_pair(&results.items[0], pair, false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
    expected_requests expected = {&pair, 1, NULL};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "billomat-test"};
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory recording Billomat verification error"));
    CHECK(!fail_503_dup && results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    CHECK(http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, &http, false, "unexpected status code: 503", false); /* Resource failure never becomes ID deletion. */
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    status_and_errors(detector);
    products_and_deletion(detector);
    context_and_resource(detector);
    return test_finish("Billomat");
}
