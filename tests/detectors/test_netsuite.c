/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>
#include <stdint.h>

static int ns_intercept_setter(br_result *result, const char *cause, const br_slice *secrets,
                               size_t nsecrets);
static int ns_intercept_send(const br_scan_ctx *ctx, const br_http_request *request,
                             br_http_response *response, char **error);
static int ns_intercept_captures(const br_regex *regex, br_slice input, br_captures *values,
                                 bool unique, char **error);
static int ns_test_snprintf(char *buf, size_t n, const char *fmt, ...);
static int (*ns_real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *,
                           char **) = br_http_send;
static int (*ns_real_captures)(const br_regex *, br_slice, br_captures *, bool, char **) =
    br_captures_find;

#define br_result_set_verification_error ns_intercept_setter
#define br_http_send ns_intercept_send
#define br_captures_find ns_intercept_captures
#define snprintf ns_test_snprintf
#include "../../src/detectors/netsuite.c"
#undef snprintf
#undef br_captures_find
#undef br_http_send
#undef br_result_set_verification_error

static const char *A = "3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15";
static const char *B = "5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD";
static const char *C = "KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WDa5iGvLIvVBqZj5rMkaWFmzkp4bveJa74";
static const char *D = "GGQUdyYOGDfDImJWCz4Kufk2GevaIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2";
static const char *account = "x1L2_BXo";
static const char *url =
    "https://x1l2-bxo.suitetalk.api.netsuite.com/services/rest/record/v1/metadata-catalog/check";
static const char *headers_expected[4] = {
    "OAuth realm=\"x1L2_BXo\",oauth_consumer_key=\"3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15\",oauth_token=\"KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WDa5iGvLIvVBqZj5rMkaWFmzkp4bveJa74\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"1700000000\",oauth_nonce=\"abcdefghijk\",oauth_version=\"1.0\",oauth_signature=\"8UmEvujqrUuHy8JKCOghcGFpV4goNZs4GxQeSWBT67g%3D\"",
    "OAuth realm=\"x1L2_BXo\",oauth_consumer_key=\"3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15\",oauth_token=\"GGQUdyYOGDfDImJWCz4Kufk2GevaIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"1700000000\",oauth_nonce=\"abcdefghijk\",oauth_version=\"1.0\",oauth_signature=\"HkvkzZR2JeA1tofnkcQLLhc3r8LwfPHXQ8yyrJkVBmE%3D\"",
    "OAuth realm=\"x1L2_BXo\",oauth_consumer_key=\"5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD\",oauth_token=\"KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WDa5iGvLIvVBqZj5rMkaWFmzkp4bveJa74\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"1700000000\",oauth_nonce=\"abcdefghijk\",oauth_version=\"1.0\",oauth_signature=\"P8GMwxvaNp2M6zObfaFAyLH8gwpyToEop%2Fk4yhoxjIU%3D\"",
    "OAuth realm=\"x1L2_BXo\",oauth_consumer_key=\"5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD\",oauth_token=\"GGQUdyYOGDfDImJWCz4Kufk2GevaIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"1700000000\",oauth_nonce=\"abcdefghijk\",oauth_version=\"1.0\",oauth_signature=\"sOhG0J%2Bhyd7A7U%2FliuGCDqJTOlmkgdjqzUZSXE%2FNwjE%3D\"",
};

static int setter_fail_at, format_rc, captures_inject, null_cause;
static size_t setter_calls, fail_part_after;
static size_t setter_counts[8], releases_at_setter[8];
static char setter_causes[8][320], setter_secrets[8][80];
static test_http *seam_http;
static char seen_url[8][160], seen_auth[8][768];
static size_t seen_count;
static int script_status[4], script_rc[4];
static const char *script_error[4], *script_body[4];
static bool use_script;

static int fixed_nonce(char *out, char **error)
{
    (void)error;
    memcpy(out, "abcdefghijk", 12);
    return 0;
}

static int fixed_unix(int64_t *seconds, char **error)
{
    (void)error;
    *seconds = 1700000000;
    return 0;
}

static int failing_nonce(char *out, char **error)
{
    (void)out;
    if (error) *error = strdup("nonce failed 3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15");
    return -1;
}

static int counting_nonce(char *out, char **error)
{
    (void)out;
    if (error) *error = strdup("nonce should not run");
    return -1;
}

static int failing_clock(int64_t *seconds, char **error)
{
    (void)seconds;
    if (error) *error = strdup("injected Netsuite clock failure");
    return -1;
}

static bool always_cancelled(void *user)
{
    (void)user;
    return true;
}

static void reset_seam(void)
{
    setter_fail_at = format_rc = captures_inject = null_cause = 0;
    setter_calls = fail_part_after = seen_count = 0;
    use_script = false;
    memset(setter_counts, 0, sizeof(setter_counts));
    memset(releases_at_setter, 0, sizeof(releases_at_setter));
    memset(setter_causes, 0, sizeof(setter_causes));
    memset(setter_secrets, 0, sizeof(setter_secrets));
    memset(script_status, 0, sizeof(script_status));
    memset(script_rc, 0, sizeof(script_rc));
    memset(script_error, 0, sizeof(script_error));
    memset(script_body, 0, sizeof(script_body));
    seam_http = NULL;
    netsuite_nonce_fn = NULL;
    netsuite_unix_fn = NULL;
}

static int ns_intercept_setter(br_result *result, const char *cause, const br_slice *secrets,
                               size_t nsecrets)
{
    size_t i = setter_calls++;
    if (i < 8) {
        setter_counts[i] = nsecrets;
        releases_at_setter[i] = seam_http ? seam_http->releases : 0;
        setter_causes[i][0] = '\0';
        setter_secrets[i][0] = '\0';
        if (cause) snprintf(setter_causes[i], sizeof(setter_causes[i]), "%s", cause);
        if (nsecrets == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(setter_secrets[i])) {
            memcpy(setter_secrets[i], secrets[0].data, secrets[0].len);
            setter_secrets[i][secrets[0].len] = '\0';
        }
    }
    if (setter_fail_at && setter_calls == (size_t)setter_fail_at) return 1;
    return br_result_set_verification_error(result, cause, secrets, nsecrets);
}

static int ns_intercept_send(const br_scan_ctx *ctx, const br_http_request *request,
                             br_http_response *response, char **error)
{
    if (null_cause) {
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return ns_real_send(ctx, request, response, error);
}

static int ns_intercept_captures(const br_regex *regex, br_slice input, br_captures *values,
                                 bool unique, char **error)
{
    if (captures_inject) {
        int rc = captures_inject;
        captures_inject = 0;
        if (error) *error = strdup("injected Netsuite capture failure");
        return rc;
    }
    return ns_real_captures(regex, input, values, unique, error);
}

static int ns_test_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    if (format_rc && fmt && strstr(fmt, "unexpected HTTP response status")) {
        int rc = format_rc;
        format_rc = 0;
        return rc;
    }
    va_list ap;
    va_start(ap, fmt);
    int wrote = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return wrote;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    if (use_script) {
        size_t i = http->calls - 1;
        http->send_rc = script_rc[i];
        http->send_error = script_error[i];
        http->response.status = script_status[i];
        http->response.body_error = script_body[i];
    }
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 995);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    if (seen_count < 8) {
        snprintf(seen_url[seen_count], sizeof(seen_url[seen_count]), "%s", request->url);
        snprintf(seen_auth[seen_count], sizeof(seen_auth[seen_count]), "%s", request->headers[1].value);
        ++seen_count;
    }
}

static int fixture(char *out, size_t cap, const char *id)
{
    return snprintf(out, cap, "netsuite id - '%s'\nconsumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'",
                    id, A, B, C, D);
}

static void expect_pair(const br_result *result, const char *key, const char *secret)
{
    char raw_v2[129];
    CHECK(result->detector_type == 995);
    CHECK(result->raw.len == 64 && !memcmp(result->raw.data, key, 64));
    CHECK(result->raw_v2.len == 128);
    memcpy(raw_v2, key, 64);
    memcpy(raw_v2 + 64, secret, 64);
    CHECK(!memcmp(result->raw_v2.data, raw_v2, 128));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "consumer_key", &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(result->secret_parts, "consumer_secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    CHECK(!json_object_object_get_ex(result->secret_parts, "token_key", &part));
    CHECK(!json_object_object_get_ex(result->secret_parts, "account_id", &part));
    CHECK(!result->extra_data && !result->structured_data && !result->redacted);
    CHECK(!result->detector_name && !result->verification_from_cache);
}

static void expect_order(const br_results *results)
{
    CHECK(results->len == 4);
    expect_pair(&results->items[0], A, B);
    expect_pair(&results->items[1], A, B);
    expect_pair(&results->items[2], B, A);
    expect_pair(&results->items[3], B, A);
}

static void plant(br_results *out, unsigned char **raw, char **saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "caller-secret", "key") == 0);
    prior.verification_error = strdup("caller-error");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *raw = out->items[0].raw.data;
    *saved = out->items[0].verification_error;
}

static void check_prior(const br_results *out, unsigned char *raw, char *saved)
{
    CHECK(out->len == 1 && out->items[0].raw.data == raw && out->items[0].verification_error == saved);
    CHECK(!strcmp(saved, "caller-error") && !strcmp((char *)raw, "caller-secret"));
}

typedef struct { const uint32_t *values; size_t len, at; } u32_script;

static int next_u32(uint32_t *out, void *user, char **error)
{
    u32_script *script = user;
    if (script->at >= script->len) return fail(error, "rng exhausted");
    *out = script->values[script->at++];
    return 0;
}

static int failing_u32(uint32_t *out, void *user, char **error)
{
    (void)out;
    (void)user;
    return fail(error, "rng failed");
}

static void escape_and_nonce(void)
{
    char *escaped = NULL, *error = NULL;
    size_t n = 0;
    CHECK(netsuite_query_escape((const unsigned char *)"a b~./_", 7, &escaped, &n, &error) == 0);
    CHECK(!error && n == 11 && !strcmp(escaped, "a+b%7E.%2F_"));
    free(escaped);
    unsigned char raw[] = {0x00, 0xff, '~', ' ', '=', '&', '+'};
    CHECK(netsuite_query_escape(raw, sizeof(raw), &escaped, &n, &error) == 0);
    CHECK(!strcmp(escaped, "%00%FF%7E+%3D%26%2B"));
    free(escaped);
    CHECK(netsuite_query_escape((const unsigned char *)"A-Z_a.z9", 8, &escaped, &n, &error) == 0);
    CHECK(!strcmp(escaped, "A-Z_a.z9"));
    free(escaped);
    CHECK(netsuite_query_escape(NULL, 0, &escaped, &n, &error) == 0 && n == 0 && !escaped[0]);
    free(escaped);
    unsigned char be[4] = {0x01, 0x02, 0x03, 0x04};
    CHECK(netsuite_be32(be) == 0x01020304u);
    CHECK(sizeof(netsuite_nonce_charset) - 1 == 62 && netsuite_nonce_limit == 4294967292u);
    uint32_t rejected[] = {4294967292u, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    u32_script script = {rejected, 12, 0};
    char nonce[12];
    CHECK(netsuite_sample_nonce(next_u32, &script, nonce, &error) == 0 && !error);
    CHECK(script.at == 12 && nonce[0] == 'a' && nonce[1] == 'b' && !nonce[11]);
    uint32_t boundary[] = {4294967291u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    script = (u32_script){boundary, 11, 0};
    CHECK(netsuite_sample_nonce(next_u32, &script, nonce, &error) == 0);
    CHECK(nonce[0] == '9' && nonce[1] == 'a');
    CHECK(netsuite_sample_nonce(failing_u32, NULL, nonce, &error) == -1);
    CHECK(error && !strcmp(error, "rng failed"));
    free(error);
    error = NULL;
    netsuite_nonce_fn = NULL;
    CHECK(netsuite_make_nonce(nonce, &error) == 0 && !error && !nonce[11]);
    for (int i = 0; i < 11; ++i) CHECK(strchr(netsuite_nonce_charset, nonce[i]));
}

static const br_detector *ready(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_netsuite_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Netsuite detector output"));
    free(error);
    error = NULL;
    CHECK(br_netsuite_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_netsuite_init(&again, &error) == 0 && again == detector);
    CHECK(detector->type == 995 && detector->version == 0 && !strcmp(detector->name, "Netsuite"));
    CHECK(!strcmp(detector->description, "Netsuite is a cloud business management suite. These credentials can be used to access and modify data within Netsuite."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "netsuite"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(!detector->false_positive && !detector->clean);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[512];
    CHECK(fixture(input, sizeof(input), account) > 0);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    expect_order(&results);
    br_results_clear(&results);

    CHECK(snprintf(input, sizeof(input), "CONSUMER - '%s' CONSUMER - '%s'\nTOKEN - '%s' TOKEN - '%s'\nID - '%s'",
                   A, B, C, D, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    expect_order(&results);
    br_results_clear(&results);

    CHECK(snprintf(input, sizeof(input), "consumer - '%s' consumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'\nid - '%s'",
                   A, A, B, C, D, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    expect_order(&results);
    br_results_clear(&results);

    char padded[1700];
    memset(padded, 'q', 1100);
    padded[1100] = '\n';
    CHECK(fixture(padded + 1101, sizeof(padded) - 1101, account) > 0);
    results = test_scan(detector, NULL, false, padded, strlen(padded));
    expect_order(&results);
    br_results_clear(&results);

    char gap[64];
    memset(gap, ' ', 40);
    gap[20] = '\v';
    gap[40] = '\0';
    CHECK(snprintf(input, sizeof(input), "id - '%s'\nconsumer%s%s consumer%s%s\ntoken - '%s' token - '%s'",
                   account, gap, A, gap, B, C, D) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    expect_order(&results);
    br_results_clear(&results);
    memset(gap, ' ', 41);
    gap[41] = '\0';
    CHECK(snprintf(input, sizeof(input), "id - '%s'\nconsumer%s%s consumer%s%s\ntoken - '%s' token - '%s'",
                   account, gap, A, gap, B, C, D) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    /* Keep the account keyword more than 40 bytes from the word consumer. */
    char far[48];
    memset(far, ' ', 41);
    far[41] = '\0';
    const char *accounts[] = {"abcde", "abcdef", "abcdefghijklmno", "abcdefghijklmnop", "ab?def"};
    const size_t expect_accounts[] = {0, 4, 4, 0, 0};
    for (size_t i = 0; i < 5; ++i) {
        CHECK(snprintf(input, sizeof(input), "id - '%s'%sconsumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'",
                       accounts[i], far, A, B, C, D) > 0);
        results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == expect_accounts[i]);
        br_results_clear(&results);
    }

    char broken[65];
    memcpy(broken, A, 64);
    broken[10] = '?';
    broken[64] = '\0';
    CHECK(snprintf(input, sizeof(input), "consumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'\nid - '%s'",
                   broken, B, C, D, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    CHECK(snprintf(input, sizeof(input), "consumer - 'x%s' consumer - '%s'\ntoken - '%s' token - '%s'\nid - '%s'",
                   A, B, C, D, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    CHECK(snprintf(input, sizeof(input), "consumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'\nid - '%s'",
                   A, A, C, D, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    CHECK(snprintf(input, sizeof(input), "consumer - '%s' consumer - '%s'\ntoken - '%s' token - '%s'\nid - '%s'",
                   A, B, C, C, account) > 0);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, "", 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static br_scan_ctx http_ctx(test_http *http, br_transport *transport)
{
    *transport = test_transport(http);
    seam_http = http;
    return (br_scan_ctx){.transport = transport};
}

static void verification(const br_detector *detector)
{
    char input[512];
    CHECK(fixture(input, sizeof(input), account) > 0);
    netsuite_nonce_fn = fixed_nonce;
    netsuite_unix_fn = fixed_unix;
    test_http http = {.response = {.status = 200, .body_error = "read failed"}, .inspect = inspect};
    br_transport transport;
    br_scan_ctx ctx = http_ctx(&http, &transport);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_order(&results);
    CHECK(http.calls == 4 && http.releases == 4 && setter_calls == 0 && seen_count == 4);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(results.items[i].verified && !results.items[i].verification_error);
        CHECK(!strcmp(seen_url[i], url));
        CHECK(!strcmp(seen_auth[i], headers_expected[i]));
    }
    br_results_clear(&results);

    reset_seam();
    netsuite_nonce_fn = fixed_nonce;
    netsuite_unix_fn = fixed_unix;
    http = (test_http){.response = {.status = 200}, .inspect = inspect};
    ctx = http_ctx(&http, &transport);
    CHECK(fixture(input, sizeof(input), "Ab_C-dE") > 0);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && seen_count == 4);
    CHECK(!strcmp(seen_url[0], "https://ab-c-de.suitetalk.api.netsuite.com/services/rest/record/v1/metadata-catalog/check"));
    CHECK(!strncmp(seen_auth[0], "OAuth realm=\"Ab_C-dE\",", 22));
    CHECK(!strstr(seen_auth[0], "realm=\"ab-c-de\""));
    br_results_clear(&results);

    reset_seam();
    http = (test_http){.inspect = inspect};
    ctx = http_ctx(&http, &transport);
    use_script = true;
    script_status[0] = 200; script_status[1] = 401; script_status[2] = 500; script_status[3] = 200;
    script_body[0] = "ignored"; script_body[1] = "ignored"; script_body[2] = "ignored";
    script_error[3] = "lookup failed: no such host";
    script_rc[3] = 1;
    CHECK(fixture(input, sizeof(input), account) > 0);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_order(&results);
    CHECK(http.calls == 4 && http.releases == 4 && setter_calls == 1);
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    CHECK(!results.items[1].verified && !results.items[1].verification_error);
    CHECK(!results.items[2].verified && results.items[2].verification_error);
    CHECK(!strcmp(results.items[2].verification_error, "unexpected HTTP response status 500"));
    CHECK(releases_at_setter[0] == 3 && setter_counts[0] == 1 && !strcmp(setter_secrets[0], B));
    CHECK(!results.items[3].verified && !results.items[3].verification_error);
    br_results_clear(&results);

    reset_seam();
    http = (test_http){.send_rc = 1, .send_error = "No such host", .inspect = inspect};
    ctx = http_ctx(&http, &transport);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && setter_calls == 4 && http.releases == 4);
    CHECK(!strcmp(results.items[0].verification_error, "No such host"));
    br_results_clear(&results);

    reset_seam();
    http = (test_http){.send_rc = 1, .send_error = "failed 3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15 and 5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"};
    ctx = http_ctx(&http, &transport);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(setter_calls == 4 && http.releases == 4 && releases_at_setter[0] == 1);
    CHECK(!strcmp(results.items[0].verification_error, "failed [REDACTED] and 5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"));
    CHECK(!strcmp(results.items[2].verification_error, "failed 3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15 and [REDACTED]"));
    br_results_clear(&results);

    reset_seam();
    http = (test_http){.send_rc = 1};
    ctx = http_ctx(&http, &transport);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(setter_calls == 4 && !strcmp(results.items[0].verification_error, "HTTP transport failed"));
    br_results_clear(&results);

    reset_seam();
    null_cause = 1;
    http = (test_http){0};
    ctx = http_ctx(&http, &transport);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 0 && http.releases == 4 && setter_calls == 4);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        CHECK(!setter_causes[i][0] && setter_counts[i] == 1 && releases_at_setter[i] == i + 1);
    }
    br_results_clear(&results);
}

static void boundaries(const br_detector *detector)
{
    char input[512], *error = NULL;
    CHECK(fixture(input, sizeof(input), account) > 0);
    reset_seam();
    netsuite_nonce_fn = counting_nonce;
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    expect_order(&results);
    CHECK(setter_calls == 0);
    br_results_clear(&results);

    reset_seam();
    netsuite_nonce_fn = counting_nonce;
    test_http http = {.inspect = inspect};
    br_transport transport;
    br_scan_ctx ctx = http_ctx(&http, &transport);
    CHECK(snprintf(input, sizeof(input), "consumer - '%s'\ntoken - '%s'\nid - '%s'", A, C, account) > 0);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0 && setter_calls == 0);
    br_results_clear(&results);

    reset_seam();
    netsuite_nonce_fn = failing_nonce;
    CHECK(fixture(input, sizeof(input), account) > 0);
    ctx = http_ctx(&http, &transport);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_order(&results);
    CHECK(http.calls == 0 && http.releases == 0 && setter_calls == 4);
    CHECK(!strcmp(results.items[0].verification_error, "nonce failed [REDACTED]"));
    CHECK(!strcmp(results.items[2].verification_error, "nonce failed 3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15"));
    CHECK(!strcmp(setter_secrets[0], A) && setter_counts[0] == 1 && releases_at_setter[0] == 0);
    br_results_clear(&results);

    reset_seam();
    results = test_scan(detector, NULL, true, input, strlen(input));
    expect_order(&results);
    for (size_t i = 0; i < 4; ++i)
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    CHECK(setter_calls == 4 && setter_counts[0] == 1 && !strcmp(setter_secrets[0], A));
    br_results_clear(&results);

    unsigned char *raw = NULL;
    char *saved = NULL;
    br_results prior = {0};
    plant(&prior, &raw, &saved);
    setter_calls = 0;
    setter_fail_at = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot store Netsuite verification error"));
    CHECK(setter_calls == 1);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    http = (test_http){.response = {.status = 201}, .inspect = inspect};
    ctx = http_ctx(&http, &transport);
    setter_fail_at = 2;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot store Netsuite verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && setter_calls == 2 && prior.len == 1);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    http = (test_http){.response = {.status = 500}, .inspect = inspect};
    ctx = http_ctx(&http, &transport);
    format_rc = -1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot format Netsuite status"));
    CHECK(http.calls == 1 && http.releases == 1 && setter_calls == 0);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    format_rc = 64;
    http.calls = http.releases = 0;
    ctx = http_ctx(&http, &transport);
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot format Netsuite status") && setter_calls == 0 && http.releases == 1);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    ctx.cancelled = always_cancelled;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 0 && http.releases == 4);
    CHECK(!strcmp(results.items[0].verification_error, "context canceled"));
    br_results_clear(&results);

    reset_seam();
    ctx = (br_scan_ctx){.deadline_monotonic_ms = 1, .transport = &transport};
    seam_http = &http;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!strcmp(results.items[0].verification_error, "context deadline exceeded") && http.releases == 4);
    br_results_clear(&results);

    reset_seam();
    ctx = (br_scan_ctx){0};
    ctx.transport = NULL;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);

    reset_seam();
    netsuite_unix_fn = failing_clock;
    http = (test_http){.inspect = inspect};
    ctx = http_ctx(&http, &transport);
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "injected Netsuite clock failure"));
    CHECK(http.calls == 0 && http.releases == 0 && setter_calls == 0);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    captures_inject = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "injected Netsuite capture failure"));
    CHECK(http.calls == 0 && setter_calls == 0);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    fail_part_after = 1;
    http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Netsuite result") && http.calls == 0);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    reset_seam();
    http = (test_http){.response = {.status = 200}, .inspect = inspect};
    ctx = http_ctx(&http, &transport);
    prior.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Netsuite result"));
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&prior, raw, saved);
    free(error);
    br_results_clear(&prior);

    CHECK(detector->scan(NULL, &ctx, false, (br_slice){NULL, 1}, &results, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized Netsuite scan"));
    free(error);
}

int main(void)
{
    escape_and_nonce();
    const br_detector *detector = ready();
    grammar(detector);
    verification(detector);
    boundaries(detector);
    return test_finish("Netsuite");
}
