/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/azure_shared_key.h"
#include "../support/detector_test.h"
#include <strings.h>
#include <time.h>

static const char host1[] = "MiXeD-Store.azconfig.io", host2[] = "other-store.azconfig.io";
static const char id1[] = "Id+/==A";
static const char key1[] = "AP8QU3ludGhldGljLUtleQCA", key2[] = "c3ludGhldGljLW5vdC1yZWFs";
static const char hash[] = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
static time_t fixed_time = 1704164645;
time_t time(time_t *out) { if (out) *out = fixed_time; return fixed_time; }

static char *connection(const char *host, const char *id, const char *key)
{
    size_t cap = strlen(host) + strlen(id) + strlen(key) + 40;
    char *out = malloc(cap); CHECK(out);
    snprintf(out, cap, "Endpoint=https://%s;Id=%s;Secret=%s", host, id, key);
    return out;
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected));
    CHECK(!memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *whole, const char *host, const char *id, const char *key)
{
    CHECK(result->detector_type == 1025 && !result->detector_name);
    CHECK(result->raw.len == strlen(id) && !memcmp(result->raw.data, id, strlen(id)));
    CHECK(result->raw_v2.len == strlen(whole) && !memcmp(result->raw_v2.data, whole, strlen(whole)));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    check_text(result->secret_parts, "id", id); check_text(result->secret_parts, "secret", key);
    size_t cap = strlen(host) + 9; char *endpoint = malloc(cap); CHECK(endpoint);
    snprintf(endpoint, cap, "https://%s", host); check_text(result->secret_parts, "endpoint", endpoint); free(endpoint);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azureappconfigconnectionstring_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid AzureAppConfigConnectionString detector output")); free(error); error = NULL;
    CHECK(!br_azureappconfigconnectionstring_init(&detector, &error) && detector && !error);
    CHECK(!br_azureappconfigconnectionstring_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1025 && detector->version == 0 && !strcmp(detector->name, "AzureAppConfigConnectionString"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Azure App Configuration is a managed service that centralizes application settings and feature flags, enabling dynamic updates without redeploying applications. Its connection string, which includes the endpoint URL and an access key, securely connects applications to the configuration store."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".azconfig.io"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

typedef struct {
    const char *host, *id, *date, *signature, *send_error;
    int status, send_rc;
} expected_request;
typedef struct {
    expected_request requests[8]; br_header tags[8];
    size_t count, calls, releases, cancellation_calls;
    bool released[8], ignore_scan_context;
    const br_transport *transport;
    const char *suffix;
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
    CHECK(at < fake->count && at < 8 && ctx && ctx->transport == fake->transport);
    CHECK(!ctx->cancelled && !ctx->cancel_user && !ctx->deadline_monotonic_ms);
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1025 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len && !request->dedup_key.len);
    expected_request *expected = &fake->requests[at];
    size_t cap = strlen(expected->host) + 40; char *url = malloc(cap); CHECK(url);
    snprintf(url, cap, "https://%s/kv?api-version=1.0", expected->host);
    CHECK(!strcmp(request->url, url)); free(url);
    CHECK(request->nheaders == 5 && !strcmp(header(request, "Host"), expected->host));
    CHECK(!strcmp(header(request, "Date"), expected->date ? expected->date : "Tue, 02 Jan 2024 03:04:05 GMT"));
    CHECK(!strcmp(header(request, "x-ms-content-sha256"), hash));
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    CHECK(!header(request, "x-ms-date") && !header(request, "x-ms-version"));
    char agent[128]; snprintf(agent, sizeof(agent), "TruffleHog%s%s", fake->suffix ? " " : "", fake->suffix ? fake->suffix : "");
    CHECK(!strcmp(header(request, "User-Agent"), agent));
    cap = strlen(expected->id) + 160; char *auth = malloc(cap); CHECK(auth);
    int prefix = snprintf(auth, cap, "HMAC-SHA256 Credential=%s&SignedHeaders=date;host;x-ms-content-sha256&Signature=", expected->id);
    const char *actual = header(request, "Authorization");
    CHECK(prefix > 0 && actual && strlen(actual) == (size_t)prefix + 44 && !memcmp(actual, auth, (size_t)prefix));
    if (expected->signature) CHECK(!strcmp(actual + prefix, expected->signature));
    free(auth);
    CHECK(fake->releases == at);
    static const unsigned char body[] = {'n', 'o', 't', '-', 'J', 'S', 'O', 'N', 0, 'b', 'o', 'd', 'y'};
    *response = (br_http_response){.status = expected->status, .headers = &fake->tags[at], .nheaders = 1,
        .body = {body, sizeof(body)}, .body_error = "ignored response body failure"};
    *error = expected->send_error ? strdup(expected->send_error) : NULL;
    CHECK(!expected->send_error || *error);
    return expected->send_error ? -1 : expected->send_rc;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user; size_t at = 0;
    while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]); fake->released[at] = true; ++fake->releases;
}

static bool cancelled(void *user)
{
    fake_http *fake = user; ++fake->cancellation_calls; return true;
}

static br_results scan_bytes(const br_detector *detector, br_slice input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake}; fake->transport = &transport;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    if (fake->ignore_scan_context) {
        ctx.deadline_monotonic_ms = 1; ctx.cancelled = cancelled; ctx.cancel_user = fake;
    }
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    if (fake->count != fake->calls || fake->calls != fake->releases)
        fprintf(stderr, "expected=%zu requests=%zu releases=%zu\n", fake->count, fake->calls, fake->releases);
    CHECK(fake->calls == fake->count && fake->releases == fake->calls && !fake->cancellation_calls);
    return results;
}

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    return scan_bytes(detector, (br_slice){(const unsigned char *)input, strlen(input)}, verify, fake);
}

static void extraction(const br_detector *detector)
{
    char *whole = connection(host1, id1, key1); fake_http fake = {0};
    br_results results = scan(detector, whole, false, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_result(&results.items[0], whole, host1, id1, key1); br_results_clear(&results);
    size_t cap = strlen(whole) + 32; char *decorated = malloc(cap); CHECK(decorated);
    snprintf(decorated, cap, "\t arbitrary%s \r\n", whole); /* No leading boundary requirement. */
    results = scan(detector, decorated, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], whole, host1, id1, key1); br_results_clear(&results); free(decorated);
    const char *bad[] = {
        "endpoint=https://a.azconfig.io;Id=I;Secret=AA==", "Endpoint=HTTPS://a.azconfig.io;Id=I;Secret=AA==",
        "Endpoint=http://a.azconfig.io;Id=I;Secret=AA==", "Endpoint=https://a.azconfig.io;id=I;Secret=AA==",
        "Endpoint=https://a.azconfig.io;Id=I;secret=AA==", "Endpoint=https://a.azconfig.io; Id=I;Secret=AA==",
        "Endpoint=https://a.azconfig.io;Id=;Secret=AA==", "Endpoint=https://a.azconfig.io;Id=I;Secret=",
        "Endpoint=https://aXazconfigYio;Id=I;Secret=AA==", "Endpoint=https://a.azconfigXio;Id=I;Secret=AA==",
        "Endpoint=https://a_b.azconfig.io;Id=I;Secret=AA==", "Endpoint=https://a.b.azconfig.io;Id=I;Secret=AA==",
        "Endpoint=https://a.AZCONFIG.io;Id=I;Secret=AA==", "Endpoint=https://a.azconfig.io:443;Id=I;Secret=AA==",
        "Endpoint=https://a.azconfig.io/;Id=I;Secret=AA==", "Endpoint=https://a.azconfig.io.evil;Id=I;Secret=AA==",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        results = scan(detector, bad[i], false, &fake); CHECK(!results.len); br_results_clear(&results);
    }
    char *invalid_key = connection(host1, "====", "=");
    results = scan(detector, invalid_key, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], invalid_key, host1, "====", "="); br_results_clear(&results); free(invalid_key);
    char *prefix = connection(host1, id1, "AA==");
    cap = strlen(prefix) + 20; decorated = malloc(cap); CHECK(decorated); snprintf(decorated, cap, "%s_more-text", prefix);
    results = scan(detector, decorated, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], prefix, host1, id1, "AA=="); br_results_clear(&results); free(prefix); free(decorated); free(whole);
}

static void whole_uniqueness(const br_detector *detector)
{
    char *a = connection(host1, id1, key1), *b = connection(host1, id1, key2), *c = connection(host2, id1, key1);
    size_t cap = strlen(a) * 2 + strlen(b) + strlen(c) + 8;
    char *input = malloc(cap); CHECK(input); snprintf(input, cap, "%s\n%s\n%s\n%s", a, b, a, c);
    fake_http fake = {.count = 3};
    fake.requests[0] = (expected_request){.host = host1, .id = id1, .status = 200};
    fake.requests[1] = (expected_request){.host = host1, .id = id1, .status = 401};
    fake.requests[2] = (expected_request){.host = host2, .id = id1, .status = 200};
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 3);
    check_result(&results.items[0], a, host1, id1, key1); check_result(&results.items[1], b, host1, id1, key2);
    check_result(&results.items[2], c, host2, id1, key1);
    CHECK(results.items[0].verified && !results.items[1].verified && results.items[2].verified);
    br_results_clear(&results); free(input); free(a); free(b); free(c);
}

static void signing_goldens(const br_detector *detector)
{
    /* Independent Python hashlib/hmac vectors: opaque binary key (including
     * NUL), host case, non-Base64 ID and a second UTC date. */
    char *whole = connection(host1, id1, key1);
    fake_http fake = {.count = 1};
    fake.requests[0] = (expected_request){.host = host1, .id = id1, .status = 200,
        .signature = "O6LiV3hsE5aRO6e1dRn0NEB/8c4QNDYprk5ML0B5c2s="};
    br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results); free(whole);
    fixed_time = 1706933106;
    whole = connection(host2, "=", key2); fake = (fake_http){.count = 1};
    fake.requests[0] = (expected_request){.host = host2, .id = "=", .status = 200, .date = "Sat, 03 Feb 2024 04:05:06 GMT",
        .signature = "hrpnYv+Dm1eB92E1bK8XoVk8TpTKm/ww6hK+FVON6Wk="};
    results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_result(&results.items[0], whole, host2, "=", key2); br_results_clear(&results); free(whole); fixed_time = 1704164645;
    /* Empty secrets cannot be extracted by '+', but generateHMACSignature's
     * pure primitive accepts an empty decoded key; do not add a length gate. */
    br_bytes decoded = {0}; size_t bad = SIZE_MAX;
    CHECK(!br_azure_base64_std_decode((br_slice){(const unsigned char *)"", 0}, &decoded, &bad) && !decoded.len && bad == SIZE_MAX);
    static const char canonical[] = "GET\n/kv?api-version=1.0\nTue, 02 Jan 2024 03:04:05 GMT;MiXeD-Store.azconfig.io;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    char signature[45];
    CHECK(!br_azure_hmac_sha256_base64((br_slice){decoded.data, decoded.len}, (br_slice){(const unsigned char *)canonical, sizeof(canonical) - 1}, signature));
    CHECK(!strcmp(signature, "YlgRY4L3N2yUE8eV1rLvyZOh7wpkdwDUl7C+mSXYyNY=")); free(decoded.data);
}

static void corrupt_keys(const br_detector *detector)
{
    const struct { const char *key; size_t offset; } cases[] = {
        {"A", 0}, {"AA", 0}, {"AAA", 0}, {"=", 0}, {"AA=", 3}, {"AA=A", 2},
        {"AAAA=", 4}, {"AAAAA", 4}, {"AA==AAAA", 4}, {"AA===", 4}, {"====", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char *whole = connection(host1, id1, cases[i].key); fake_http fake = {0};
        br_results results = scan(detector, whole, true, &fake);
        CHECK(results.len == 1 && !results.items[0].verified);
        char expected[96]; snprintf(expected, sizeof(expected), "illegal base64 data at input byte %zu", cases[i].offset);
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, expected));
        check_result(&results.items[0], whole, host1, id1, cases[i].key);
        br_results_clear(&results); free(whole);
    }
    /* Standard Base64 is non-strict: unused pad bits are not rejection. */
    char *whole = connection(host1, id1, "AB=="); fake_http fake = {.count = 1};
    fake.requests[0] = (expected_request){.host = host1, .id = id1, .status = 200,
        .signature = "YlgRY4L3N2yUE8eV1rLvyZOh7wpkdwDUl7C+mSXYyNY="};
    br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results); free(whole);
}

static void statuses_context_and_errors(const br_detector *detector)
{
    char *whole = connection(host1, id1, key1);
    const int statuses[] = {200, 401, 201, 204, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake_http fake = {.count = 1, .ignore_scan_context = true, .suffix = "Synthetic/fixture"};
        fake.requests[0] = (expected_request){.host = host1, .id = id1, .status = statuses[i]};
        br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1);
        CHECK(results.items[0].verified == (statuses[i] == 200));
        if (statuses[i] == 200 || statuses[i] == 401) CHECK(!results.items[0].verification_error);
        else {
            char expected[80]; snprintf(expected, sizeof(expected), "got unexpected status code: %d", statuses[i]);
            CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, expected));
        }
        br_results_clear(&results);
    }
    const char *errors[] = {"synthetic no such host", "synthetic No such host", "synthetic transport failed"};
    for (size_t i = 0; i < 3; ++i) {
        fake_http fake = {.count = 1}; fake.requests[0] = (expected_request){.host = host1, .id = id1, .send_error = errors[i]};
        br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && !results.items[0].verified);
        if (!i) CHECK(!results.items[0].verification_error);
        else CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, errors[i]));
        br_results_clear(&results);
    }
    size_t cap = strlen(whole) * 2 + 512;
    char *error = malloc(cap), *expected = malloc(cap); CHECK(error && expected);
    snprintf(error, cap, "synthetic %s %s id=%s secret=%s host=%s", whole, whole, id1, key1, host1);
    snprintf(expected, cap, "synthetic [REDACTED] [REDACTED] id=%s secret=%s host=%s", id1, key1, host1);
    fake_http fake = {.count = 1}; fake.requests[0] = (expected_request){.host = host1, .id = id1, .send_error = error};
    br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, expected));
    br_results_clear(&results); free(error); free(expected);
    fake = (fake_http){.count = 1}; fake.requests[0] = (expected_request){.host = host1, .id = id1, .send_rc = -1};
    results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "HTTP transport failed"));
    br_results_clear(&results); free(whole);
}

static void no_host_cache(const br_detector *detector)
{
    char *a = connection(host1, id1, key1), *b = connection(host1, id1, key2);
    size_t cap = strlen(a) + strlen(b) + 2; char *input = malloc(cap); CHECK(input); snprintf(input, cap, "%s\n%s", a, b);
    fake_http fake = {.count = 2};
    fake.requests[0] = (expected_request){.host = host1, .id = id1, .send_error = "synthetic no such host"};
    fake.requests[1] = (expected_request){.host = host1, .id = id1, .status = 200};
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && results.items[1].verified);
    check_result(&results.items[0], a, host1, id1, key1); check_result(&results.items[1], b, host1, id1, key2);
    br_results_clear(&results); free(input); free(a); free(b);
}

static void unbounded_fields(const br_detector *detector)
{
    size_t label_len = 4096, id_len = 8193, key_len = 16384;
    char *host = malloc(label_len + sizeof(".azconfig.io")), *id = malloc(id_len + 1), *key = malloc(key_len + 1);
    CHECK(host && id && key);
    memset(host, 'A', label_len); memcpy(host + label_len, ".azconfig.io", sizeof(".azconfig.io"));
    static const char id_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    for (size_t i = 0; i < id_len; ++i) id[i] = id_alphabet[i % (sizeof(id_alphabet) - 1)];
    id[id_len] = '\0';
    for (size_t i = 0; i < key_len; i += 4) memcpy(key + i, "QUJD", 4);
    key[key_len] = '\0';
    char *whole = connection(host, id, key); fake_http fake = {.count = 1};
    fake.requests[0] = (expected_request){.host = host, .id = id, .status = 200};
    br_results results = scan(detector, whole, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_result(&results.items[0], whole, host, id, key); br_results_clear(&results);
    free(whole); free(host); free(id); free(key);
}

int main(void)
{
    const br_detector *detector = init();
    extraction(detector); whole_uniqueness(detector); signing_goldens(detector); corrupt_keys(detector);
    statuses_context_and_errors(detector); no_host_cache(detector); unbounded_fields(detector);
    return test_finish("Azure App Configuration connection capture + strict decode + HMAC");
}
