/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <openssl/evp.h>

static const char key1[] = "G7H8IJKL-M9N0-OPQR-STUV-WXYZ1234ABCD";
static const char key2[] = "12345678-90AB-CDEF-GHIJ-KLMNOPQRSTUV";
static size_t fail_add_after;
typedef struct { const char *key; br_slice id; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; } expected_requests;

/* Return a real positive +1 object-add failure for a provider finding. Forward
 * normally through add_ex, preserving embedded NUL in the owned JSON value. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_clicksendsms_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_clicksendsms_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 209 && detector->version == 0 && !strcmp(detector->name, "ClickSendsms"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "ClickSend is a global leader in business communication solutions, providing a range of services including SMS, email, and voice. ClickSend API keys can be used to access and manage these communication services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clicksendsms"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_clicksendsms_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void pair_result(const br_result *result, const expected_pair *expected)
{
    CHECK(result->detector_type == 209 && result->raw.len == 36 && !memcmp(result->raw.data, expected->key, 36));
    CHECK(result->raw_v2.len == 36 + expected->id.len && !memcmp(result->raw_v2.data, expected->key, 36));
    CHECK(!memcmp(result->raw_v2.data + 36, expected->id.data, expected->id.len));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 36 && !memcmp(json_object_get_string(part), expected->key, 36));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == expected->id.len && !memcmp(json_object_get_string(part), expected->id.data, expected->id.len));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static size_t pair_input(unsigned char *out, size_t cap, const char *key, br_slice email_input)
{
    CHECK(cap >= 37 + email_input.len);
    memcpy(out, key, 36); out[36] = '\n'; memcpy(out + 37, email_input.data, email_input.len);
    return 37 + email_input.len;
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 209);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://rest.clicksend.com/v3/account"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog clicksendsms-test" : "TruffleHog"));
    const char *auth = request->headers[0].value; CHECK(!strncmp(auth, "Basic ", 6));
    size_t encoded = strlen(auth + 6);
    CHECK(encoded == 4 * ((pair->id.len + 1 + 36 + 2) / 3) && encoded <= INT_MAX);
    unsigned char *decoded = malloc(encoded / 4 * 3 + 1); CHECK(decoded);
    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, (int)encoded); CHECK(decoded_len >= 0);
    if (auth[6 + encoded - 1] == '=') --decoded_len;
    if (auth[6 + encoded - 2] == '=') --decoded_len;
    CHECK((size_t)decoded_len == pair->id.len + 1 + 36 && decoded[pair->id.len] == ':');
    CHECK(!memcmp(decoded, pair->id.data, pair->id.len)); /* Full binary ID, not strlen(ID). */
    CHECK(!memcmp(decoded + pair->id.len + 1, pair->key, 36));
    free(decoded);
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source's scan-deferred close-only lifecycle. */
}

static void projection_case(const br_detector *detector, br_slice email_input, br_slice id)
{
    size_t cap = 37 + email_input.len;
    unsigned char *input = malloc(cap); CHECK(input);
    size_t len = pair_input(input, cap, key1, email_input);
    expected_pair pair = {key1, id}; expected_requests expected = {&pair, 1};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, len);
        CHECK(results.len == 1 && http.calls == (verify ? 1u : 0u) && http.releases == http.calls);
        pair_result(&results.items[0], &pair);
        CHECK(results.items[0].verified == (bool)verify && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    free(input);
}

static void projections(const br_detector *detector)
{
    projection_case(detector, text("sms first@example.invalid"), text("first@example.invalid"));
    projection_case(detector, text("SMS\tCase.User@EXAMPLE.INVALID"), text("SMS\tCase.User@EXAMPLE.INVALID"));
    static const unsigned char nul[] = "sms\0nul@example.invalid";
    projection_case(detector, (br_slice){nul, sizeof(nul) - 1}, (br_slice){nul, sizeof(nul) - 1});
    static const unsigned char nul_tail[] = "sms \0nul@example.invalid";
    projection_case(detector, (br_slice){nul_tail, sizeof(nul_tail) - 1}, (br_slice){nul_tail + 4, sizeof(nul_tail) - 5});
    projection_case(detector, text("sms X\"a\\ b\"@example.invalid"), text("b\"@example.invalid")); /* Last space is INSIDE quoted local. */
    static const unsigned char whitespace[] =
        "sms \t\n\r\v\f\xc2\x85\xc2\xa0\xe1\x9a\x80\xe2\x80\x80\xe2\x80\xa8\xe2\x80\xaf\xe2\x81\x9f\xe3\x80\x80trim@example.invalid";
    projection_case(detector, (br_slice){whitespace, sizeof(whitespace) - 1}, text("trim@example.invalid"));
    const size_t local_len = 8192;
    unsigned char *email = malloc(local_len + 64); CHECK(email);
    memcpy(email, "sms ", 4); memset(email + 4, 'a', local_len);
    static const char suffix[] = "@example.invalid";
    memcpy(email + 4 + local_len, suffix, sizeof(suffix) - 1);
    size_t len = 4 + local_len + sizeof(suffix) - 1;
    projection_case(detector, (br_slice){email, len}, (br_slice){email + 4, len - 4});
    free(email);
}

static void key_and_prefix_rules(const br_detector *detector)
{
    unsigned char input[256];
    const br_slice email = {(const unsigned char *)"sms first@example.invalid", sizeof("sms first@example.invalid") - 1};
    size_t len = pair_input(input, sizeof(input), key1, email);
    CHECK(!br_slice_find((br_slice){input, len}, text(key1), 0)); /* Direct key needs no dispatch keyword. */
    CHECK(br_slice_find((br_slice){input, len}, text("clicksendsms"), 0) == SIZE_MAX);
    br_results results = test_scan(detector, NULL, false, input, len); CHECK(results.len == 1); br_results_clear(&results);
    const char *bad_keys[] = {"g7h8ijkl-m9n0-opqr-stuv-wxyz1234abcd", "G7H8IJK-M9N0-OPQR-STUV-WXYZ1234ABCD",
                              "G7H8IJKL_M9N0-OPQR-STUV-WXYZ1234ABCD", "G7H8IJKL-M9N0-OPQR-STUV-WXYZ1234ABCDA"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        int n = snprintf((char *)input, sizeof(input), "%s\nsms first@example.invalid", bad_keys[i]); CHECK(n > 0);
        results = test_scan(detector, NULL, false, input, (size_t)n); CHECK(!results.len); br_results_clear(&results);
    }
    len = pair_input(input, sizeof(input), "00000000-0000-0000-0000-000000000000", email);
    results = test_scan(detector, NULL, false, input, len); CHECK(results.len == 1); br_results_clear(&results);
    len = pair_input(input, sizeof(input), key1, text("notice first@example.invalid"));
    results = test_scan(detector, NULL, false, input, len); CHECK(!results.len); br_results_clear(&results);
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, ':', gap); padding[gap] = 0;
        int n = snprintf((char *)input, sizeof(input), "%s\nsms%sfirst@example.invalid", key1, padding); CHECK(n > 0);
        results = test_scan(detector, NULL, false, input, (size_t)n); CHECK(results.len == (gap == 40 ? 1u : 0u));
        if (results.len) {
            expected_pair expected = {key1, (br_slice){input + 37, (size_t)n - 37}}; pair_result(&results.items[0], &expected);
        }
        br_results_clear(&results);
    }
}

static void products(const br_detector *detector)
{
    char input[512];
    int n = snprintf(input, sizeof(input), "%s\n%s\n%s\nsms first@example.invalid\nSMS second@example.invalid\nsms first@example.invalid", key1, key2, key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key2, key1}; br_slice ids[] = {text("first@example.invalid"), text("second@example.invalid"), text("first@example.invalid")};
    expected_pair pairs[9];
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) pairs[k * 3 + i] = (expected_pair){keys[k], ids[i]};
    expected_requests expected = {pairs, 9};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) { pair_result(&results.items[i], &pairs[i]); CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error); }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, (size_t)n); CHECK(results.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < results.len; ++i) pair_result(&results.items[i], &pairs[i]);
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    unsigned char input[256]; size_t len = pair_input(input, sizeof(input), key1, text("sms first@example.invalid"));
    expected_pair pair = {key1, text("first@example.invalid")}; expected_requests expected = {&pair, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false},
        {200, 9, "synthetic Do failure", false}, {200, 1, "out of memory constructing HTTP headers", false},
        {302, 1, "unsupported: redirects with sensitive HTTP headers", false}, {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored read error"},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "clicksendsms-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); pair_result(&results.items[0], &pair);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preflight_errors(const br_detector *detector)
{
    unsigned char input[256]; size_t len = pair_input(input, sizeof(input), key1, text("sms first@example.invalid"));
    expected_pair pair = {key1, text("first@example.invalid")}; expected_requests expected = {&pair, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); pair_result(&results.items[0], &pair);
        CHECK(!results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_add_after = 1;
    CHECK(br_finding_pair_bytes(&probe, 209, text(key1), "key", text("first@example.invalid"), "id", (br_slice){0}) != 0);
    CHECK(!fail_add_after && !probe.raw.data && !probe.raw_v2.data && !probe.secret_parts); br_result_clear(&probe);
    char *auth = NULL; CHECK(br_http_basic_auth((br_slice){NULL, 1}, text(key1), &auth, NULL) == 1 && !auth);
    CHECK(br_results_push(NULL, &probe) == 1);
    char input[256]; int n = snprintf(input, sizeof(input), "%s\nsms first@example.invalid\nsms second@example.invalid", key1); CHECK(n > 0);
    expected_pair pairs[] = {{key1, text("first@example.invalid")}, {key1, text("second@example.invalid")}};
    expected_requests expected = {pairs, 2}; test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_add_after = 3;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating ClickSendsms result"));
    CHECK(!fail_add_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    fail_add_after = 1;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !fail_add_after && results.len == 1); /* Owned failures are not masked by nil-context skips. */
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { pair_result(&results.items[i], &pairs[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 36 && strlen(key2) == 36);
    const br_detector *detector = descriptor();
    projections(detector); key_and_prefix_rules(detector); products(detector); statuses_and_errors(detector); preflight_errors(detector); resource_rollback(detector);
    return test_finish("ClickSendsms");
}
