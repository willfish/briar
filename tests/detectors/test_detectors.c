/* SPDX-License-Identifier: AGPL-3.0-only */
/* Synthetic offline acceptance for the three pinned, detector-local ports. */
#include "briar.h"
#include "../../src/detectors/first_batch.h"
#include "../../src/detectors/second_batch.h"
#include "../../src/detectors/third_batch.h"
#include "../../src/detectors/fourth_batch.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static size_t assertions, cases;
static const char *current_case;

#define CHECK(expr) do { \
    ++assertions; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s at %s:%d: %s\n", \
                current_case ? current_case : "setup", __FILE__, __LINE__, #expr); \
        fprintf(stderr, "%zu cases completed, 1 failure\n", cases); \
        exit(1); \
    } \
} while (0)

typedef struct {
    int32_t type;
    const char *name, *keyword, *description;
    size_t key_len;
    bool enabled;
    int rejected;
    const char *url, *header;
} specification;

static const specification specs[] = {
    {384, "Abstract", "abstract",
     "Abstract API provides various services including exchange rates. The API keys can be used to access these services and retrieve data.",
     32, false, 401, NULL, "Content-Type"},
    {521, "AbuseIPDB", "abuseipdb",
     "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses for abusive activities.",
     80, true, 401, "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", "Key"},
    {239, "Abyssale", "abyssale",
     "Abyssale is a service offering various API functionalities for marketing automation and services such as images and ad campaigns. Abyssale API keys can be used to access and interact with this data.",
     40, true, 403, "https://api.abyssale.com/ready", "x-api-key"},
};

static char *copy_string(const char *text)
{
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    CHECK(copy != NULL);
    memcpy(copy, text, len);
    return copy;
}

static void synthetic_key(char key[82], size_t len, unsigned int shift)
{
    static const char alphabet[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6";
    for (size_t i = 0; i < len; ++i)
        key[i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    key[len] = '\0';
}

static br_results scan(const br_detector *detector, const br_scan_ctx *ctx,
                       bool verify, const void *input, size_t len)
{
    br_results results = {0};
    char *error = NULL;
    int rc = detector->scan(detector, ctx, verify, (br_slice){input, len}, &results, &error);
    if (rc != 0 || error) fprintf(stderr, "scan error: %s\n", error ? error : "(none)");
    CHECK(rc == 0);
    CHECK(error == NULL);
    return results;
}

static void check_result(const br_result *result, const specification *spec, const char *key)
{
    CHECK(result->detector_type == spec->type);
    CHECK(result->detector_name == NULL);
    CHECK(result->raw.len == spec->key_len);
    CHECK(result->raw.data != NULL);
    CHECK(memcmp(result->raw.data, key, spec->key_len) == 0);
    CHECK(result->raw_v2.data == NULL && result->raw_v2.len == 0);
    CHECK(result->redacted == NULL);
    CHECK(result->extra_data == NULL);
    CHECK(result->structured_data == NULL);
    CHECK(result->secret_parts != NULL);
    CHECK(json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)spec->key_len);
    CHECK(strcmp(json_object_get_string(part), key) == 0);
    CHECK(!result->verification_from_cache);
    CHECK(result->primary_secret.data == NULL && result->primary_secret.len == 0);
    CHECK(result->primary_line == 0);
    CHECK(result->chunk_offset == 0 && !result->chunk_offset_set);
}

typedef struct {
    const specification *spec;
    const char *key;
    int status;
    br_slice body;
    const char *body_error, *send_error;
    bool send_fails;
    size_t calls, releases;
    const char *suffix;
} fake_http;

static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                     br_http_response *response, char **error)
{
    fake_http *fake = user;
    CHECK(ctx != NULL && ctx->transport != NULL && ctx->transport->user == fake);
    ++fake->calls;
    CHECK(strcmp(request->method, "GET") == 0);
    char abstract_url[160];
    const char *url = fake->spec->url;
    if (fake->spec->type == 384) {
        snprintf(abstract_url, sizeof(abstract_url),
                 "https://exchange-rates.abstractapi.com/v1/live/?api_key=%s&base=USD", fake->key);
        url = abstract_url;
    }
    CHECK(strcmp(request->url, url) == 0);
    CHECK(request->detector_type == fake->spec->type);
    CHECK(request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(request->body.data == NULL && request->body.len == 0);
    CHECK(request->dedup_key.data == NULL && request->dedup_key.len == 0);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    char expected_agent[80];
    snprintf(expected_agent, sizeof(expected_agent), "TruffleHog%s%s",
             fake->suffix ? " " : "", fake->suffix ? fake->suffix : "");
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (strcasecmp(header->name, fake->spec->header) == 0) {
            ++auth;
            const char *value = fake->spec->type == 384 ? "application/json" : fake->key;
            CHECK(strcmp(header->value, value) == 0);
        } else if (strcasecmp(header->name, "User-Agent") == 0) {
            ++agent;
            CHECK(strcmp(header->value, expected_agent) == 0);
        } else {
            CHECK(!"unexpected request header");
        }
    }
    CHECK(auth == 1 && agent == 1);
    /* Populate even failed sends to check the mandatory release-on-error path. */
    *response = (br_http_response){
        .status = fake->status, .body = fake->body, .body_error = fake->body_error,
    };
    *error = fake->send_error ? copy_string(fake->send_error) : NULL;
    return fake->send_fails ? 1 : 0;
}

static void fake_release(void *user, br_http_response *response)
{
    fake_http *fake = user;
    CHECK(response != NULL);
    ++fake->releases;
}

static void extraction_case(const br_detector *detector, const specification *spec,
                            const char *label, const void *input, size_t len,
                            const char *const *expected, size_t nexpected)
{
    current_case = label;
    fake_http fake = {.spec = spec};
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan(detector, &ctx, false, input, len);
    CHECK(results.len == nexpected);
    CHECK(fake.calls == 0 && fake.releases == 0);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], spec, expected[i]);
        CHECK(!results.items[i].verified);
        CHECK(results.items[i].verification_error == NULL);
    }
    br_results_clear(&results);
    CHECK(results.items == NULL && results.len == 0 && results.cap == 0);
    ++cases;
}

static void extraction_tests(const br_detector *detector, const specification *spec)
{
    char key[82], second[82], input[512], changed[82];
    synthetic_key(key, spec->key_len, 0);
    synthetic_key(second, spec->key_len, 9);
    const char *one[] = {key};
    const char *two[] = {key, second};
    const char *twice[] = {key, key};
    size_t prefix_len = strlen(spec->keyword);

#define EXTRACT(label, count, expected) \
    extraction_case(detector, spec, label, input, strlen(input), expected, count)
    snprintf(input, sizeof(input), "%s = '%s'", spec->keyword, key);
    EXTRACT("basic extraction and all result defaults", 1, one);
    extraction_case(detector, spec, "empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("no provider keyword", 0, NULL);
    snprintf(input, sizeof(input), "%s %s", key, spec->keyword);
    EXTRACT("keyword must precede key", 0, NULL);
    for (size_t i = 0; i < prefix_len; ++i)
        input[i] = (char)toupper((unsigned char)spec->keyword[i]);
    snprintf(input + prefix_len, sizeof(input) - prefix_len, " = %s", key);
    EXTRACT("scoped case-insensitive keyword", 1, one);
    snprintf(input, sizeof(input), "pre%ssuffix:%s", spec->keyword, key);
    EXTRACT("keyword has no word boundaries", 1, one);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, spec->keyword, prefix_len);
        memset(input + prefix_len, '-', gap);
        memcpy(input + prefix_len + gap, key, spec->key_len + 1);
        EXTRACT(gap == 40 ? "prefix distance 40" : "prefix distance 41",
                gap == 40 ? 1 : 0, one);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s%s", spec->keyword, separators[i], key);
        EXTRACT("prefix crosses CR/LF", 1, one);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, spec->keyword, prefix_len);
        memset(input + prefix_len, '-', gap - 2);
        memcpy(input + prefix_len + gap - 2, "\r\n", 2);
        memcpy(input + prefix_len + gap, key, spec->key_len + 1);
        EXTRACT(gap == 40 ? "CR/LF distance 40" : "CR/LF distance 41",
                gap == 40 ? 1 : 0, one);
    }
    /* PrefixRegex counts runes, while all ABI offsets remain byte-based. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = prefix_len;
        memcpy(input, spec->keyword, prefix_len);
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, spec->key_len + 1);
        EXTRACT(gap == 40 ? "Unicode prefix distance 40" : "Unicode prefix distance 41",
                gap == 40 ? 1 : 0, one);
    }

    snprintf(input, sizeof(input), "%s%s", spec->keyword, key);
    EXTRACT("zero gap fails capture boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s _%s", spec->keyword, key);
    EXTRACT("underscore before capture fails boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s %s_", spec->keyword, key);
    EXTRACT("underscore after capture fails boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s '%s'", spec->keyword, key);
    EXTRACT("punctuation boundaries", 1, one);
    snprintf(input, sizeof(input), "%s \xc3\xa9%s\xc3\xa9", spec->keyword, key);
    EXTRACT("word boundaries remain ASCII", 1, one);
    snprintf(input, sizeof(input), "%s %.*s", spec->keyword, (int)spec->key_len - 1, key);
    EXTRACT("short capture rejected", 0, NULL);
    snprintf(input, sizeof(input), "%s %sq", spec->keyword, key);
    EXTRACT("long capture rejected", 0, NULL);
    memcpy(changed, key, spec->key_len + 1);
    changed[spec->key_len / 2] = '_';
    snprintf(input, sizeof(input), "%s %s", spec->keyword, changed);
    EXTRACT("nonalphabet character rejected", 0, NULL);
    for (size_t i = 0; i < spec->key_len; ++i)
        changed[i] = (char)toupper((unsigned char)key[i]);
    changed[spec->key_len] = '\0';
    snprintf(input, sizeof(input), "%s %s", spec->keyword, changed);
    const char *upper[] = {changed};
    EXTRACT("capture case remains detector-specific", spec->type == 239 ? 1 : 0, upper);

    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, second);
    EXTRACT("multiple findings preserve source order", 2, two);
    snprintf(input, sizeof(input), "%s %s %s", spec->keyword, key, second);
    EXTRACT("one prefix is not reused for a second finding", 1, one);
    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, key);
    EXTRACT("detector does not clean duplicate findings", 2, twice);
    memset(changed, 'a', spec->key_len);
    changed[spec->key_len] = '\0';
    snprintf(input, sizeof(input), "%s %s", spec->keyword, changed);
    const char *low_entropy[] = {changed};
    EXTRACT("no detector-local false-positive filtering", 1, low_entropy);

    memcpy(input, spec->keyword, prefix_len);
    input[prefix_len] = '\0';
    memcpy(input + prefix_len + 1, key, spec->key_len);
    extraction_case(detector, spec, "binary NUL separator", input,
                    prefix_len + 1 + spec->key_len, one, 1);
#undef EXTRACT
    printf("PASS %s extraction\n", spec->name);
}

static void verification_case(const br_detector *detector, const specification *spec,
                              const char *label, fake_http *fake,
                              bool verified, const char *expected_error)
{
    current_case = label;
    char key[82], input[128];
    synthetic_key(key, spec->key_len, 0);
    fake->key = key;
    fake->spec = spec;
    fake->calls = fake->releases = 0;
    br_transport transport = {fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    snprintf(input, sizeof(input), "%s %s", spec->keyword, key);
    br_results results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(fake->calls == 1 && fake->releases == 1);
    check_result(&results.items[0], spec, key);
    CHECK(results.items[0].verified == verified);
    if (expected_error) {
        CHECK(results.items[0].verification_error != NULL);
        CHECK(strcmp(results.items[0].verification_error, expected_error) == 0);
        CHECK(strstr(results.items[0].verification_error, key) == NULL);
    } else {
        CHECK(results.items[0].verification_error == NULL);
    }
    br_results_clear(&results);
    ++cases;
}

static bool always_cancelled(void *user)
{
    size_t *checks = user;
    ++*checks;
    return true;
}

static void context_tests(const br_detector *detector, const specification *spec)
{
    char key[82], input[128];
    synthetic_key(key, spec->key_len, 0);
    snprintf(input, sizeof(input), "%s %s", spec->keyword, key);
    size_t checks = 0;
    for (int mode = 0; mode < 3; ++mode) {
        current_case = mode == 0 ? "missing transport fails closed" :
                       mode == 1 ? "cancelled context retains candidate" :
                                   "expired deadline retains candidate";
        fake_http fake = {.spec = spec, .key = key};
        br_transport transport = {&fake, fake_send, fake_release};
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? always_cancelled : NULL,
            .cancel_user = &checks,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
        };
        br_results results = scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1);
        check_result(&results.items[0], spec, key);
        CHECK(!results.items[0].verified);
        CHECK(results.items[0].verification_error != NULL);
        CHECK(results.items[0].verification_error[0] != '\0');
        CHECK(strstr(results.items[0].verification_error, key) == NULL);
        CHECK(fake.calls == 0);
        CHECK(fake.releases == (mode == 0 ? 0u : 1u));
        br_results_clear(&results);
        ++cases;
    }
    CHECK(checks > 0);
}

static void verification_tests(const br_detector *detector, const specification *spec)
{
    static const unsigned char good[] = "{\"data\":{\"ipAddress\":\"8.8.8.8\"}}";
    fake_http fake = {.status = 200, .body = {good, sizeof(good) - 1}};
    verification_case(detector, spec, "successful verification", &fake, true, NULL);
    fake.suffix = "detector-tests";
    verification_case(detector, spec, "effective User-Agent suffix", &fake, true, NULL);
    fake.status = spec->rejected;
    fake.body_error = "ignored rejected response body failure";
    verification_case(detector, spec, "explicit credential rejection", &fake, false, NULL);
    const int statuses[] = {201, 204, 400, spec->rejected == 401 ? 403 : 401, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake.status = statuses[i];
        char expected[80];
        snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", fake.status);
        verification_case(detector, spec, "unexpected status ignores body failure", &fake, false, expected);
    }
    fake.status = 200;
    fake.body_error = NULL;
    const char *transport_errors[] = {"context deadline exceeded", "context canceled"};
    fake.send_fails = true;
    for (size_t i = 0; i < sizeof(transport_errors) / sizeof(transport_errors[0]); ++i) {
        fake.send_error = transport_errors[i];
        verification_case(detector, spec, "transport timeout/cancellation retains candidate", &fake,
                          false, transport_errors[i]);
    }
    char key[82], sensitive_error[220];
    synthetic_key(key, spec->key_len, 0);
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s failed: %s", key, key);
    fake.send_error = sensitive_error;
    verification_case(detector, spec, "all credential occurrences are redacted", &fake, false,
                      "request [REDACTED] failed: [REDACTED]");
    fake.send_error = NULL;
    verification_case(detector, spec, "transport failure without cause is indeterminate", &fake,
                      false, "HTTP transport failed");
    fake.send_fails = false;
    fake.body_error = sensitive_error;
    verification_case(detector, spec, "body read error is consumed only by AbuseIPDB", &fake,
                      spec->type != 521,
                      spec->type == 521 ? "request [REDACTED] failed: [REDACTED]" : NULL);
    fake.body_error = NULL;

    static const unsigned char malformed[] = "not JSON: ipAddress!!!";
    static const unsigned char binary[] = {0, 'i', 'p', 'A', 'd', 'd', 'r', 'e', 's', 's', 0, 0xff};
    static const unsigned char no_marker[] = "{\"data\":{\"address\":\"8.8.8.8\"}}";
    static const unsigned char wrong_case[] = "ipaddress IPADDRESS ipAddres";
    const br_slice bodies[] = {
        {NULL, 0}, {no_marker, sizeof(no_marker) - 1},
        {wrong_case, sizeof(wrong_case) - 1},
        {malformed, sizeof(malformed) - 1}, {binary, sizeof(binary)},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        fake.body = bodies[i];
        verification_case(detector, spec, "literal byte substring, not JSON or C string", &fake,
                          spec->type != 521 || i >= 3, NULL);
    }
    context_tests(detector, spec);

    current_case = "no candidate means no verification I/O";
    fake.key = key;
    fake.spec = spec;
    fake.calls = fake.releases = 0;
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake.suffix};
    br_results results = scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 0 && fake.calls == 0 && fake.releases == 0);
    br_results_clear(&results);
    ++cases;

    current_case = "multiple verified findings are not cleaned or coalesced in scan";
    char input[256];
    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, key);
    fake.body = (br_slice){good, sizeof(good) - 1};
    results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && fake.calls == 2 && fake.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], spec, key);
        CHECK(results.items[i].verified && results.items[i].verification_error == NULL);
    }
    br_results_clear(&results);
    ++cases;
    printf("PASS %s verification/status/body/error/request paths\n", spec->name);
}

static void registry_handler_test(const br_detector *detector, const specification *spec)
{
    current_case = "each registry identity executes its actual initialized handler";
    char key[128], secondary_buffer[82], input[512];
    synthetic_key(key, spec->key_len, 0);
    if (detector->type == 303 && detector->version == 1) key[7] = '%';
    if (detector->type == 390) memcpy(key, "aio_", 4);
    const char *secondary = NULL, *secondary_name = NULL;
    switch (detector->type) {
    case 125: secondary = "004207"; secondary_name = "id"; break;
    case 136: secondary = "C7d8E9f0.G1H"; secondary_name = "id"; break;
    case 1014: strcpy(key, "Native7.v1.Synthetic_-Payload.1a2b3c"); break;
    case 431: secondary = "c7d8e9f0"; secondary_name = "id"; break;
    case 693: secondary = "00042"; secondary_name = "id"; break;
    case 197:
        synthetic_key(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 802:
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[64] = '\0';
        secondary = "synthetic.aha.io";
        secondary_name = "url";
        break;
    }
    if (detector->type == 197)
        snprintf(input, sizeof(input), "token %s\nsecret %s", key, secondary);
    else if (detector->type == 802)
        snprintf(input, sizeof(input), "aha %s\n%s", key, secondary);
    else if (secondary)
        snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, secondary);
    else if (detector->type == 390) snprintf(input, sizeof(input), "%s", key);
    else snprintf(input, sizeof(input), "%s %s", spec->keyword, key);
    br_results results = scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    const br_result *result = &results.items[0];
    CHECK(result->detector_type == detector->type);
    CHECK(result->raw.len == spec->key_len && result->raw.data != NULL);
    CHECK(memcmp(result->raw.data, key, spec->key_len) == 0);
    CHECK(!result->verified && result->verification_error == NULL);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, detector->type == 1014 ? "token" : "key", &part));
    CHECK(strcmp(json_object_get_string(part), key) == 0);
    CHECK(json_object_object_length(result->secret_parts) == (secondary ? 2 : 1));
    if (secondary) {
        CHECK(json_object_object_get_ex(result->secret_parts, secondary_name, &part));
        CHECK(strcmp(json_object_get_string(part), secondary) == 0);
        CHECK(result->raw_v2.len == spec->key_len + strlen(secondary) && result->raw_v2.data != NULL);
        CHECK(memcmp(result->raw_v2.data, key, spec->key_len) == 0);
        CHECK(memcmp(result->raw_v2.data + spec->key_len, secondary, strlen(secondary)) == 0);
    } else CHECK(result->raw_v2.len == 0 && result->raw_v2.data == NULL);
    br_results_clear(&results);
    ++cases;
}

static void registry_tests(const br_detector *const *detectors, size_t count)
{
    static const specification second_specs[] = {
        {.type = 303, .name = "Accuweather", .keyword = "accuweather", .key_len = 35, .enabled = true,
         .description = "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts."},
        {.type = 303, .name = "Accuweather", .keyword = "accuweather", .key_len = 32, .enabled = true,
         .description = "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts."},
        {.type = 390, .name = "AdafruitIO", .keyword = "aio_", .key_len = 32, .enabled = true,
         .description = "Adafruit IO is a cloud service used for IoT applications. Adafruit IO keys can be used to access and control data and devices connected to the platform."},
        {.type = 136, .name = "AdobeIO", .keyword = "adobe", .key_len = 32, .enabled = false,
         .description = "AdobeIO provides APIs for integrating with Adobe services. These credentials can be used to access Adobe services and data."},
    };
    static const specification third_specs[] = {
        {.type = 431, .name = "Adzuna", .keyword = "adzuna", .key_len = 32, .enabled = true,
         .description = "Adzuna is a job search engine used to find job listings. Adzuna API keys can be used to access job listing data."},
        {.type = 693, .name = "Aeroworkflow", .keyword = "aeroworkflow", .key_len = 20, .enabled = true,
         .description = "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys and Account IDs can be used to access and manage workflows."},
        {.type = 197, .name = "Agora", .keyword = "agora", .key_len = 32, .enabled = true,
         .description = "Agora is a real-time engagement platform providing APIs for voice, video, and messaging. Agora API keys can be used to access and manage these services."},
        {.type = 802, .name = "Aha", .keyword = "aha.io", .key_len = 64, .enabled = true,
         .description = "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows."},
    };
    static const specification fourth_specs[] = {
        {.type = 125, .name = "AirbrakeProjectKey", .keyword = "airbrake", .key_len = 32, .enabled = true,
         .description = "Airbrake is an error and performance monitoring service for web applications. Airbrake project keys can be used to report and track errors in applications."},
        {.type = 126, .name = "AirbrakeUserKey", .keyword = "airbrake", .key_len = 40, .enabled = true,
         .description = "Airbrake is an error and performance monitoring service. Airbrake User Keys can be used to access and manage error reports and performance data."},
        {.type = 277, .name = "Airship", .keyword = "airship", .key_len = 91, .enabled = true,
         .description = "Airship is a customer engagement platform that provides tools for mobile app messaging, in-app messaging, and web notifications. Airship API keys can be used to access and manage these messaging services."},
        {.type = 1014, .name = "AirtableOAuth", .keyword = "airtable", .key_len = sizeof("Native7.v1.Synthetic_-Payload.1a2b3c") - 1, .enabled = true,
         .description = "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases."},
    };
    const struct {
        const specification *spec;
        int32_t version;
        int64_t credential_span;
    } expected[] = {
        {&specs[2], 0, -1}, {&specs[0], 0, -1}, {&specs[1], 0, -1},
        {&second_specs[0], 1, -1}, {&second_specs[1], 2, -1},
        {&second_specs[2], 0, -1}, {&second_specs[3], 0, 1024},
        {&third_specs[0], 0, 1024}, {&third_specs[1], 0, 1024},
        {&third_specs[2], 0, 1024}, {&third_specs[3], 0, 1024},
        {&fourth_specs[0], 0, 1024}, {&fourth_specs[1], 0, -1},
        {&fourth_specs[2], 0, -1}, {&fourth_specs[3], 0, -1},
    };
    current_case = "exact compiled registry identities/order/defaults";
    CHECK(BR_ABI_REVISION == 1);
    CHECK(count == 15 && count == sizeof(expected) / sizeof(expected[0]));
    const br_detector *const *first = NULL, *const *second = NULL;
    const br_detector *const *third = NULL, *const *fourth = NULL;
    size_t nfirst = 0, nsecond = 0, nthird = 0, nfourth = 0;
    char *batch_error = NULL;
    CHECK(br_first_batch(&first, &nfirst, &batch_error) == 0 && batch_error == NULL);
    CHECK(br_second_batch(&second, &nsecond, &batch_error) == 0 && batch_error == NULL);
    CHECK(br_third_batch(&third, &nthird, &batch_error) == 0 && batch_error == NULL);
    CHECK(br_fourth_batch(&fourth, &nfourth, &batch_error) == 0 && batch_error == NULL);
    CHECK(nfirst == 3 && nsecond == 4 && nthird == 4 && nfourth == 4);
    CHECK(br_detector_type_name(-1) == NULL);
    CHECK(br_detector_type_name(0) == NULL);
    CHECK(br_detector_type_name(1) == NULL); /* Not a metadata-only AWS descriptor. */
    CHECK(!br_detector_is_default(NULL, NULL));
    br_detector unimplemented = {.type = 1};
    CHECK(!br_detector_is_default(&unimplemented, NULL));
    br_json *flags = json_object_new_object();
    CHECK(flags != NULL);
    CHECK(json_object_object_add(flags, "all", json_object_new_boolean(true)) == 0);
    size_t enabled = 0;
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        const specification *spec = expected[i].spec;
        CHECK(detector == (i < nfirst ? first[i] :
              i < nfirst + nsecond ? second[i - nfirst] :
              i < nfirst + nsecond + nthird ? third[i - nfirst - nsecond] :
              fourth[i - nfirst - nsecond - nthird]));
        CHECK(detector->type == spec->type);
        CHECK(strcmp(detector->name, spec->name) == 0);
        CHECK(strcmp(br_detector_type_name(detector->type), spec->name) == 0);
        CHECK(strcmp(detector->description, spec->description) == 0);
        CHECK(detector->version == expected[i].version);
        CHECK(detector->custom_name != NULL && detector->custom_name[0] == '\0');
        CHECK(detector->nkeywords == 1);
        CHECK(strcmp(detector->keywords[0], spec->keyword) == 0);
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
              detector->max_credential_span == expected[i].credential_span);
        CHECK(detector->state != NULL && detector->scan != NULL);
        CHECK(detector->clean == NULL && !detector->clean_always);
        CHECK(detector->false_positive == NULL);
        CHECK(detector->validate_endpoints == NULL && detector->cloud_endpoint == NULL);
        CHECK(br_detector_is_default(detector, NULL) == spec->enabled);
        CHECK(br_detector_is_default(detector, flags) == spec->enabled);
        br_detector copied = *detector;
        CHECK(br_detector_is_default(&copied, NULL) == spec->enabled);
        copied.version = 77;
        CHECK(!br_detector_is_default(&copied, NULL));
        copied.version = detector->version;
        copied.custom_name = "custom";
        CHECK(!br_detector_is_default(&copied, NULL));
        enabled += br_detector_is_default(detector, NULL);
        for (size_t j = 0; j < i; ++j) {
            CHECK(detector != detectors[j]);
            CHECK(detector->type != detectors[j]->type || detector->version != detectors[j]->version);
        }
        registry_handler_test(detector, spec);
    }
    CHECK(enabled == 13);
    json_object_put(flags);
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    char *error = NULL;
    CHECK(br_registry(&again, &nagain, &error) == 0);
    CHECK(error == NULL && again == detectors && nagain == count);
    CHECK(br_registry(NULL, &nagain, &error) != 0);
    CHECK(error != NULL && nagain == 0);
    free(error);
    error = NULL;
    CHECK(br_registry(&again, NULL, &error) != 0);
    CHECK(error != NULL && again == NULL);
    free(error);
    ++cases;
    printf("PASS registry: fifteen actual handlers in upstream order; Abstract/AdobeIO disabled; Accuweather v1/v2 distinct\n");
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_registry(&detectors, &count, &error) == 0);
    CHECK(error == NULL);
    registry_tests(detectors, count);
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i) {
        const br_detector *detector = NULL;
        for (size_t j = 0; j < count; ++j)
            if (detectors[j]->type == specs[i].type) detector = detectors[j];
        CHECK(detector != NULL);
        extraction_tests(detector, &specs[i]);
        verification_tests(detector, &specs[i]);
    }
    printf("PASS: %zu cases, %zu assertions, 0 failures; injected transport only\n", cases, assertions);
    return 0;
}
