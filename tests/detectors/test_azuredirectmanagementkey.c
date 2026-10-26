/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>
#include <time.h>

static char key1[89], key2[89];
static const char base1[] = "https://example.management.azure-api.net";
static const char base2[] = "https://second-service.management.azure-api.net";
static const char signature1[] = "+lhyEgy/GgQAsJgFUnErOWC8KYm1H2raHWu2HBPqVeDw0FXNSPXkXwQ99CRbA9vOzPkS4/3QtvJ7Uk+YEQBH+w==";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;
static time_t fixed_time = 1704164645;
static size_t cache_clock_calls;

time_t time(time_t *out) { if (out) *out = fixed_time; return fixed_time; }
int timespec_get(struct timespec *out, int base)
{
    if (base != TIME_UTC) return 0;
    ++cache_clock_calls; *out = (struct timespec){1704164645, 0}; return TIME_UTC;
}

/* One targeted reproduction of positive setter OOM being mistaken for the
 * source DNS sentinel. No other allocation is fault-injected. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *out = malloc(len);
    if (out) memcpy(out, text, len);
    return out;
}

static void make_key(char *out, size_t len, unsigned shift)
{
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    CHECK(len >= 85 && len <= 89);
    for (size_t i = 0; i < len - 3; ++i) out[i] = alphabet[(i * 17 + shift) % 64];
    out[len - 3] = 'Z'; out[len - 2] = out[len - 1] = '='; out[len] = '\0';
}

static void input_for(char *out, size_t size, const char *url, const char *prefix, size_t gap, const char *key)
{
    int n = snprintf(out, size, "%s", url); CHECK(n >= 0 && (size_t)n + 80 < size);
    size_t at = (size_t)n; memset(out + at, '\n', 80); at += 80;
    n = snprintf(out + at, size - at, "%s%*s%s", prefix, (int)gap, "", key);
    CHECK(n >= 0 && (size_t)n < size - at);
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, name, &value)); CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected)); CHECK(!memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_detector *detector, const br_result *result, const char *url, const char *key)
{
    size_t url_len = strlen(url), key_len = strlen(key);
    CHECK(result->detector_type == 1024 && !result->detector_name);
    CHECK(result->raw.len == url_len && !memcmp(result->raw.data, url, url_len));
    CHECK(result->raw_v2.len == url_len + 1 + key_len && !memcmp(result->raw_v2.data, url, url_len));
    CHECK(result->raw_v2.data[url_len] == ':' && !memcmp(result->raw_v2.data + url_len + 1, key, key_len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "url", url); check_text(result->secret_parts, "key", key);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, result, &reason)); CHECK(reason && !strcmp(reason, "")); free(reason);
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azuredirectmanagementkey_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid AzureDirectManagementKey detector output")); free(error); error = NULL;
    CHECK(!br_azuredirectmanagementkey_init(&detector, &error) && detector && !error);
    CHECK(!br_azuredirectmanagementkey_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1024 && detector->version == 0 && !strcmp(detector->name, "AzureDirectManagementKey"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".management.azure-api.net"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    char *reason = NULL; CHECK(!detector->false_positive(detector, NULL, &reason)); CHECK(reason && !*reason); free(reason);
    CHECK(!detector->false_positive(detector, NULL, NULL));
    return detector;
}

typedef struct {
    const char *base, *service, *expiry, *signature, *send_error;
    int status, send_rc;
} expected_request;
typedef struct {
    expected_request requests[8]; br_header tags[8]; size_t count, calls, releases, empty_releases;
    bool released[8], cancel, expired; size_t cancel_calls;
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
    CHECK(ctx && at < fake->count && at < 8);
    expected_request *expected = &fake->requests[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1024 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len && !request->dedup_key.len);
    char url[384]; snprintf(url, sizeof(url), "%s/subscriptions/default/resourceGroups/default/providers/Microsoft.ApiManagement/service/%s/apis?api-version=2024-05-01", expected->base, expected->service);
    CHECK(!strcmp(request->url, url));
    CHECK(request->nheaders == 3 && !strcmp(header(request, "Content-Type"), "application/json"));
    CHECK(!strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Date") && !header(request, "x-ms-date") && !header(request, "Content-Length"));
    char prefix[128]; snprintf(prefix, sizeof(prefix), "SharedAccessSignature uid=integration&ex=%s&sn=",
                               expected->expiry ? expected->expiry : "2024-01-02T03:04:10.0000000Z");
    const char *auth = header(request, "Authorization");
    CHECK(auth && strlen(auth) == strlen(prefix) + 88 && !memcmp(auth, prefix, strlen(prefix)));
    CHECK(!strcmp(auth + strlen(auth) - 2, "=="));
    if (expected->signature) CHECK(!strcmp(auth + strlen(prefix), expected->signature));
    CHECK(fake->releases == at);
    static const unsigned char body[] = {'n', 'o', 't', '-', 'J', 'S', 'O', 'N', 0, 'b', 'o', 'd', 'y'};
    *response = (br_http_response){.status = expected->status, .headers = &fake->tags[at], .nheaders = 1,
        .body = {body, sizeof(body)}, .body_error = "ignored body/close failure"};
    *error = expected->send_error ? strdup(expected->send_error) : NULL;
    CHECK(!expected->send_error || *error);
    return expected->send_error ? -1 : expected->send_rc;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user;
    if (!response->headers) { ++fake->empty_releases; return; } /* Pre-send context rejection. */
    size_t at = 0; while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]); fake->released[at] = true; ++fake->releases;
}

static bool cancelled(void *user) { fake_http *fake = user; ++fake->cancel_calls; return true; }

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport};
    if (fake->cancel) { ctx.cancelled = cancelled; ctx.cancel_user = fake; }
    if (fake->expired) ctx.deadline_monotonic_ms = 1;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    if (fake->calls != fake->count || fake->calls != fake->releases)
        fprintf(stderr, "expected=%zu sends=%zu releases=%zu\n", fake->count, fake->calls, fake->releases);
    CHECK(fake->calls == fake->count && fake->releases == fake->calls);
    return results;
}

static void extraction_case(const br_detector *detector, const char *input, const char *url, const char *key)
{
    fake_http fake = {0}; size_t before = cache_clock_calls;
    br_results results = scan(detector, input, false, &fake);
    CHECK(results.len == (url ? 1u : 0u) && cache_clock_calls == before);
    if (url) { check_result(detector, &results.items[0], url, key); CHECK(!results.items[0].verified && !results.items[0].verification_error); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[1024], value[128], key[92];
    input_for(input, sizeof(input), base1, "azure", 1, key1); extraction_case(detector, input, base1, key1);
    input_for(input, sizeof(input), base1, "AZURE", 1, key1); extraction_case(detector, input, base1, key1);
    /* All three prefix dots are regex wildcards. The embedded azure alternative
     * ends >40 bytes from the key, so only the full wildcard prefix can match. */
    input_for(input, sizeof(input), base1, "QmanagementXazure-apiYnet", 40, key1); extraction_case(detector, input, base1, key1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        input_for(input, sizeof(input), base1, "azure", gap, key1);
        extraction_case(detector, input, gap == 40 ? base1 : NULL, key1);
    }
    input_for(input, sizeof(input), base1, "azure\r\n", 0, key1); extraction_case(detector, input, base1, key1);
    input_for(input, sizeof(input), base1, "key", 1, key1); extraction_case(detector, input, NULL, NULL);
    extraction_case(detector, "", NULL, NULL); extraction_case(detector, base1, NULL, NULL);
    snprintf(input, sizeof(input), "azure %s", key1); extraction_case(detector, input, NULL, NULL);
    const char *urls[] = {
        "https://ab.management.azure-api.net", "https://a--9.management.azure-api.net", "https://00.management.azure-api.net",
        "https://a.management.azure-api.net", "HTTPS://ab.management.azure-api.net", "http://ab.management.azure-api.net",
        "https://Ab.management.azure-api.net", "https://ab.Management.azure-api.net", "https://ab.management.azure-api.NET",
        "https://-ab.management.azure-api.net", "https://ab-.management.azure-api.net", "https://a_b.management.azure-api.net",
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i) {
        input_for(input, sizeof(input), urls[i], "azure", 1, key1); extraction_case(detector, input, i < 3 ? urls[i] : NULL, key1);
    }
    for (size_t label = 50; label <= 51; ++label) {
        memcpy(value, "https://", 8); memset(value + 8, 'a', label);
        memcpy(value + 8 + label, ".management.azure-api.net", sizeof(".management.azure-api.net"));
        input_for(input, sizeof(input), value, "azure", 1, key1); extraction_case(detector, input, label == 50 ? value : NULL, key1);
    }
    const char *suffixes[] = {".evil", "z", "/path?query=yes", ":8443"};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(value, sizeof(value), "%s%s", base1, suffixes[i]); input_for(input, sizeof(input), value, "azure", 1, key1);
        extraction_case(detector, input, base1, key1); /* No added right boundary. */
    }
    snprintf(value, sizeof(value), "prefix%s", base1); input_for(input, sizeof(input), value, "azure", 1, key1);
    extraction_case(detector, input, base1, key1);
    for (size_t len = 85; len <= 88; ++len) {
        make_key(key, len, 11); input_for(input, sizeof(input), base1, "azure", 1, key);
        extraction_case(detector, input, len >= 86 ? base1 : NULL, key);
    }
    /* No left boundary: PrefixRegex can consume one byte of an overlong key,
     * leaving its last 88 bytes as the source capture. */
    make_key(key, 89, 11); input_for(input, sizeof(input), base1, "azure", 1, key);
    extraction_case(detector, input, base1, key + 1);
    make_key(key, 86, 11); key[83] = '+'; input_for(input, sizeof(input), base1, "azure", 1, key);
    extraction_case(detector, input, NULL, NULL); /* Last pre-padding byte must be alphanumeric. */
    memcpy(key, key1, 87); key[30] = '_'; input_for(input, sizeof(input), base1, "azure", 1, key); extraction_case(detector, input, NULL, NULL);
    memset(key, 'a', 84); memcpy(key + 84, "==", 3); input_for(input, sizeof(input), base1, "azure", 1, key);
    extraction_case(detector, input, base1, key); /* No Base64 validity or entropy gate. */
}

static void signing_goldens(const br_detector *detector)
{
    char input[512]; input_for(input, sizeof(input), base1, "azure", 1, key1);
    fake_http fake = {.count = 1}; fake.requests[0] = (expected_request){.base = base1, .service = "example", .status = 200, .signature = signature1};
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    /* Python hashlib/hmac SHA512 goldens, keyed by the ASCII ENCODED key.
     * key1's 86 bytes cannot even be a complete standard-Base64 input. */
    CHECK(strlen(key1) == 86 && strlen(key1) % 4 != 0);
    fixed_time = 1735689598; /* +5 seconds crosses the UTC year boundary. */
    input_for(input, sizeof(input), base2, "azure", 1, key2);
    fake = (fake_http){.count = 1}; fake.requests[0] = (expected_request){.base = base2, .service = "second-service", .status = 200,
        .expiry = "2025-01-01T00:00:03.0000000Z",
        .signature = "ctrEqk62/BwjeymVdcY/mbxR0tsJ1Y/OgjCa5s3PmdBezkHQs1dhsxU7yTJBmyLHu9JCGsGmKo7QxV/oIJaqWQ=="};
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results); fixed_time = 1704164645;
}

static void products(const br_detector *detector)
{
    char input[1024]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%80sazure %s\nazure %s\nazure %s", base1, base2, base1, "", key1, key2, key1);
    fake_http fake = {.count = 4};
    fake.requests[0] = (expected_request){.base = base1, .service = "example", .status = 200, .signature = signature1};
    fake.requests[1] = (expected_request){.base = base1, .service = "example", .status = 200};
    fake.requests[2] = (expected_request){.base = base2, .service = "second-service", .status = 200, .signature = signature1};
    fake.requests[3] = (expected_request){.base = base2, .service = "second-service", .status = 200};
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 4);
    const char *urls[] = {base1, base2}, *keys[] = {key1, key2};
    for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 2; ++k) {
        check_result(detector, &results.items[u * 2 + k], urls[u], keys[k]); CHECK(results.items[u * 2 + k].verified);
    }
    br_results_clear(&results);
    fake = (fake_http){.count = 4};
    for (size_t u = 0; u < 2; ++u) for (size_t k = 0; k < 2; ++k)
        fake.requests[u * 2 + k] = (expected_request){.base = urls[u], .service = u ? "second-service" : "example", .send_error = "lookup synthetic: no such host"};
    results = scan(detector, input, true, &fake); CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) CHECK(!results.items[i].verified && !results.items[i].verification_error);
    br_results_clear(&results);
    /* Literal DNS errors never populate a cache, even across invocations. */
    memset(fake.released, 0, sizeof(fake.released)); fake.calls = fake.releases = 0;
    results = scan(detector, input, true, &fake); CHECK(results.len == 4); br_results_clear(&results);
}

static void status_and_context(const br_detector *detector)
{
    char input[512]; input_for(input, sizeof(input), base1, "azure", 1, key1);
    const int statuses[] = {200, 401, 201, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake_http fake = {.count = 1}; fake.requests[0] = (expected_request){.base = base1, .service = "example", .status = statuses[i]};
        br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified == (statuses[i] == 200));
        if (statuses[i] == 200 || statuses[i] == 401) CHECK(!results.items[0].verification_error);
        else { char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", statuses[i]); CHECK(!strcmp(results.items[0].verification_error, expected)); }
        br_results_clear(&results);
    }
    const char *errors[] = {"no such host", "No such host", "context canceled", "context deadline exceeded", "synthetic transport failure", NULL};
    for (size_t i = 0; i < 6; ++i) {
        fake_http fake = {.count = 1}; fake.requests[0] = (expected_request){.base = base1, .service = "example", .send_error = errors[i], .send_rc = -1};
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
    fake_http fake = {.cancel = true}; size_t before = cache_clock_calls;
    br_results results = scan(detector, input, false, &fake);
    CHECK(results.len == 1 && !fake.cancel_calls && cache_clock_calls == before && !fake.empty_releases); br_results_clear(&results);
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && fake.cancel_calls && fake.empty_releases == 1);
    br_results_clear(&results);
    fake = (fake_http){.expired = true}; results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && fake.empty_releases == 1); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    check_result(detector, &results.items[0], base1, key1); br_results_clear(&results);
}

static void setter_failure_is_not_dns(const br_detector *detector)
{
    const char url[] = "https://setter-oom.management.azure-api.net";
    char input[768]; snprintf(input, sizeof(input), "%s\n%80sazure %s\nazure %s", url, "", key1, key2);
    fake_http fake = {.count = 2};
    fake.requests[0] = (expected_request){.base = url, .service = "setter-oom", .status = 200};
    fake.requests[1] = (expected_request){.base = url, .service = "setter-oom", .status = 503};
    br_transport transport = {&fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error);
    CHECK(fake.calls == 2 && fake.releases == 2);
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    /* No DNS sentinel, no poisoned cache, and no lost first/second pair. */
    memset(fake.released, 0, sizeof(fake.released)); fake.calls = fake.releases = 0;
    results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    CHECK(results.items[0].verified && !results.items[1].verified && !strcmp(results.items[1].verification_error, status_503));
    check_result(detector, &results.items[0], url, key1); check_result(detector, &results.items[1], url, key2); br_results_clear(&results);
}

int main(void)
{
    make_key(key1, 86, 7); make_key(key2, 88, 23);
    const br_detector *detector = init();
    extraction(detector); signing_goldens(detector); products(detector); status_and_context(detector); setter_failure_is_not_dns(detector);
    return test_finish("Azure direct management ASCII-key SHA512 + extraction/status policy");
}
