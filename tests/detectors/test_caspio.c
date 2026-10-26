/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char credential1[51], credential2[51];
static const char domain1[] = "region01", domain2[] = "zone0002";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_part_after;
typedef struct { const char *const *keys, *const *ids, *const *domains; size_t len; } expected_requests;

/* Target provider-owned finding allocation, outside the adapter/Do error
 * domain. Every fixture part is a complete non-NUL ASCII capture. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 50 || len == 8);
    if (fail_part_after && --fail_part_after == 0) return NULL;
    char copy[51]; memcpy(copy, value, (size_t)len); copy[len] = 0;
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_caspio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_caspio_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 648 && detector->version == 0 && !strcmp(detector->name, "Caspio"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Caspio is a cloud platform for building custom database applications. Caspio credentials can be used to access and manage these applications."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "caspio"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_caspio_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void triple_result(const br_result *result, const char *key, const char *id, const char *domain)
{
    CHECK(result->detector_type == 648 && result->raw.len == 50 && !memcmp(result->raw.data, key, 50));
    CHECK(result->raw_v2.len == 108 && !memcmp(result->raw_v2.data, key, 50));
    CHECK(!memcmp(result->raw_v2.data + 50, id, 50) && !memcmp(result->raw_v2.data + 100, domain, 8));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    const char *names[] = {"key", "id", "domain"}, *values[] = {key, id, domain};
    const size_t lengths[] = {50, 50, 8};
    for (size_t i = 0; i < 3; ++i) {
        br_json *part = NULL;
        CHECK(json_object_object_get_ex(result->secret_parts, names[i], &part) && json_object_is_type(part, json_type_string));
        CHECK((size_t)json_object_get_string_len(part) == lengths[i] && !memcmp(json_object_get_string(part), values[i], lengths[i]));
    }
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static size_t single_input(char *out, size_t cap, const char *credential, const char *domain)
{
    int len = snprintf(out, cap, "caspio %s\n%s\nCASPIO %s", credential, isolation, domain);
    CHECK(len > 0 && (size_t)len < cap); return (size_t)len;
}

static void expect_single(const br_detector *detector, const void *input, size_t len, const char *credential, const char *domain, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    if (count) {
        triple_result(&results.items[0], credential, credential, domain); /* A self-pair MUST exist. */
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[52]; size_t len = single_input(input, sizeof(input), credential1, domain1);
    expect_single(detector, input, len, credential1, domain1, 1);
    for (size_t n = 49; n <= 51; n += 2) {
        test_secret(changed, n, 0); len = single_input(input, sizeof(input), changed, domain1);
        expect_single(detector, input, len, NULL, NULL, 0);
    }
    memcpy(changed, credential1, sizeof(credential1)); changed[0] = 'B';
    len = single_input(input, sizeof(input), changed, domain1); expect_single(detector, input, len, NULL, NULL, 0);
    memcpy(changed, credential1, sizeof(credential1)); changed[25] = '-';
    len = single_input(input, sizeof(input), changed, domain1); expect_single(detector, input, len, NULL, NULL, 0);
    const char *bad_domains[] = {"region0", "region011", "Region01", "_region01", "region01_"};
    for (size_t i = 0; i < sizeof(bad_domains) / sizeof(bad_domains[0]); ++i) {
        len = single_input(input, sizeof(input), credential1, bad_domains[i]); expect_single(detector, input, len, NULL, NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, ':', gap); padding[gap] = 0;
        int n = snprintf(input, sizeof(input), "caspio%s%s\n%s\ncaspio %s", padding, credential1, isolation, domain1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_single(detector, input, (size_t)n, credential1, domain1, gap == 40 ? 1 : 0);
        n = snprintf(input, sizeof(input), "caspio %s\n%s\ncaspio%s%s", credential1, isolation, padding, domain1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_single(detector, input, (size_t)n, credential1, domain1, gap == 40 ? 1 : 0);
    }
    int n = snprintf(input, sizeof(input), "CaSpIo domainid %s", credential1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_single(detector, input, (size_t)n, credential1, "domainid", 1); /* Independent domain regex captures context. */
    memset(changed, 'a', 50); changed[50] = 0;
    len = single_input(input, sizeof(input), changed, "00000000");
    expect_single(detector, input, len, changed, "00000000", 1); /* No local entropy/FP filtering. */
    n = snprintf(input, sizeof(input), "caspio %s", credential1); CHECK(n > 0);
    expect_single(detector, input, (size_t)n, NULL, NULL, 0);
    expect_single(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 648);
    char url[80], body[192]; size_t at = http->calls - 1;
    snprintf(url, sizeof(url), "https://%s.caspio.com/oauth/token", expected->domains[at]);
    int n = snprintf(body, sizeof(body), "grant_type=client_credentials&client_id=%s&client_secret=%s", expected->ids[at], expected->keys[at]);
    CHECK(n == 155 && !strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->body.data && request->body.len == 155 && !memcmp(request->body.data, body, 155));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "text/plain"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog caspio-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source's scan-deferred close-only lifecycle. */
}

static void products(const br_detector *detector)
{
    char input[1024];
    int n = snprintf(input, sizeof(input), "caspio %s\n%s\ncaspio %s\n%s\ncaspio %s\n%s\ncaspio %s\n%s\ncaspio %s\n%s\ncaspio %s",
                     credential1, isolation, credential2, isolation, credential1, isolation, domain1, isolation, domain2, isolation, domain1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *credentials[] = {credential1, credential2, credential1}, *domains[] = {domain1, domain2, domain1};
    const char *keys[27], *ids[27], *hosts[27];
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) for (size_t d = 0; d < 3; ++d) {
        size_t at = k * 9 + i * 3 + d; keys[at] = credentials[k]; ids[at] = credentials[i]; hosts[at] = domains[d];
    }
    expected_requests expected = {keys, ids, hosts, 27};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 27 && http.calls == (mode ? 27u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 27; ++i) {
            triple_result(&results.items[i], keys[i], ids[i], hosts[i]);
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, (size_t)n);
        CHECK(results.len == (verify ? 0u : 27u));
        for (size_t i = 0; i < results.len; ++i) { triple_result(&results.items[i], keys[i], ids[i], hosts[i]); CHECK(!results.items[i].verification_error); }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[256], sensitive[160]; size_t len = single_input(input, sizeof(input), credential1, domain1);
    snprintf(sensitive, sizeof(sensitive), "synthetic secret=%s id=%s domain=%s", credential1, credential1, domain1);
    const char *keys[] = {credential1}, *ids[] = {credential1}, *domains[] = {domain1}; expected_requests expected = {keys, ids, domains, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {302, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "out of memory constructing HTTP headers", false},
        {200, 1, "unsupported: native curl HTTP client profile", false},
        {200, 1, "dialing local IP addresses is not allowed", false}, {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "caspio-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        triple_result(&results.items[0], credential1, credential1, domain1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preflight_errors(const br_detector *detector)
{
    char input[256]; size_t len = single_input(input, sizeof(input), credential1, domain1);
    const char *keys[] = {credential1}, *ids[] = {credential1}, *domains[] = {domain1}; expected_requests expected = {keys, ids, domains, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u));
        triple_result(&results.items[0], credential1, credential1, domain1); CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_part_after = 1;
    CHECK(br_finding_key_bytes(&probe, 648, (br_slice){(const unsigned char *)credential1, 50}, "key") != 0);
    CHECK(!fail_part_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1);
    char input[512]; int n = snprintf(input, sizeof(input), "caspio %s\n%s\ncaspio %s\n%s\ncaspio %s", credential1, isolation, domain1, isolation, domain2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {credential1, credential1}, *ids[] = {credential1, credential1}, *domains[] = {domain1, domain2};
    expected_requests expected = {keys, ids, domains, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_part_after = 4; /* Three parts in first triple, then fail the next key part. */
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Caspio result"));
    CHECK(!fail_part_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { triple_result(&results.items[i], keys[i], ids[i], domains[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    test_secret(credential1, 50, 0); test_secret(credential2, 50, 7);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); statuses_and_errors(detector); preflight_errors(detector); resource_rollback(detector);
    return test_finish("Caspio");
}
