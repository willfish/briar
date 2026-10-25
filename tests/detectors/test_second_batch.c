/* SPDX-License-Identifier: AGPL-3.0-only */
/* Offline, synthetic acceptance for the private second-batch wiring boundary. */
#include "../../src/detectors/second_batch.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static size_t cases, assertions;
static const char *current_case = "initialization";
#define CHECK(expr) do { \
    ++assertions; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s at %s:%d: %s\n", current_case, __FILE__, __LINE__, #expr); \
        fprintf(stderr, "%zu cases completed, 1 failure\n", cases); \
        exit(1); \
    } \
} while (0)

typedef struct {
    int32_t type, version;
    const char *name, *keyword, *description;
    size_t key_len;
} specification;
static const specification specs[] = {
    {303, 1, "Accuweather", "accuweather",
     "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts.", 35},
    {303, 2, "Accuweather", "accuweather",
     "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts.", 32},
    {390, 0, "AdafruitIO", "aio_",
     "Adafruit IO is a cloud service used for IoT applications. Adafruit IO keys can be used to access and control data and devices connected to the platform.", 32},
    {136, 0, "AdobeIO", "adobe",
     "AdobeIO provides APIs for integrating with Adobe services. These credentials can be used to access Adobe services and data.", 32},
};
static const char adobe_id[] = "C7d8E9f0.G1H";
static const char adobe_second_id[] = "M2n3P4q5.R6S";

typedef struct { const char *key, *id; } expected_result;

static void make_key(const specification *spec, char key[64], size_t shift)
{
    static const char mixed[] = "a0B1c2D3e4F5g6H7i8J9kLmNoPqRsTuVwXyZ";
    static const char lower[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6";
    const char *alphabet = spec->type == 136 ? lower : mixed;
    size_t start = spec->type == 390 ? 4 : 0;
    if (start) memcpy(key, "aio_", start);
    for (size_t i = start; i < spec->key_len; ++i)
        key[i] = alphabet[(i - start + shift) % strlen(alphabet)];
    key[spec->key_len] = '\0';
    if (spec->type == 303 && spec->version == 1) key[7] = '%';
}

static char *copy_string(const char *text)
{
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    CHECK(copy != NULL);
    memcpy(copy, text, len);
    return copy;
}

static br_results scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const void *input, size_t len)
{
    br_results results = {0};
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, verify, (br_slice){input, len}, &results, &error) == 0);
    CHECK(error == NULL);
    return results;
}

static bool same_result(const br_result *result, const expected_result *expected)
{
    br_json *key = NULL, *id = NULL;
    if (!json_object_object_get_ex(result->secret_parts, "key", &key) ||
        strcmp(json_object_get_string(key), expected->key)) return false;
    if (!expected->id) return !json_object_object_get_ex(result->secret_parts, "id", &id);
    return json_object_object_get_ex(result->secret_parts, "id", &id) &&
           !strcmp(json_object_get_string(id), expected->id);
}

static void check_result(const br_result *result, const specification *spec,
                          const expected_result *expected)
{
    CHECK(result->detector_type == spec->type);
    CHECK(result->detector_name == NULL && result->redacted == NULL);
    CHECK(result->raw.data != NULL && result->raw.len == strlen(expected->key));
    CHECK(memcmp(result->raw.data, expected->key, result->raw.len) == 0);
    CHECK(result->secret_parts != NULL && json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == (expected->id ? 2 : 1));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(strcmp(json_object_get_string(part), expected->key) == 0);
    if (expected->id) {
        CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
        CHECK(json_object_is_type(part, json_type_string));
        CHECK(strcmp(json_object_get_string(part), expected->id) == 0);
        CHECK(result->raw_v2.data != NULL);
        CHECK(result->raw_v2.len == strlen(expected->key) + strlen(expected->id));
        CHECK(memcmp(result->raw_v2.data, expected->key, strlen(expected->key)) == 0);
        CHECK(memcmp(result->raw_v2.data + strlen(expected->key), expected->id, strlen(expected->id)) == 0);
    } else {
        CHECK(result->raw_v2.data == NULL && result->raw_v2.len == 0);
    }
    CHECK(result->extra_data == NULL && result->structured_data == NULL);
    CHECK(!result->verification_from_cache);
    CHECK(result->primary_secret.data == NULL && result->primary_secret.len == 0);
    CHECK(result->primary_line == 0 && result->chunk_offset == 0 && !result->chunk_offset_set);
}

typedef struct {
    const specification *spec;
    const char *key, *id, *error, *body_error, *suffix;
    int status;
    bool send_fails;
    br_slice body;
    size_t calls, releases;
} fake_http;

static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    fake_http *fake = user;
    ++fake->calls;
    CHECK(ctx != NULL && ctx->transport != NULL && ctx->transport->user == fake);
    CHECK(strcmp(request->method, "GET") == 0);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == fake->spec->type);
    CHECK(request->body.data == NULL && request->body.len == 0);
    CHECK(request->dedup_key.data == NULL && request->dedup_key.len == 0);
    char url[256];
    if (fake->spec->type == 303) {
        snprintf(url, sizeof(url), "https://dataservice.accuweather.com/locations/v1/cities/autocomplete?apikey=%s&q=----&language=en-us", fake->key);
    } else if (fake->spec->type == 390) {
        snprintf(url, sizeof(url), "https://io.adafruit.com/api/v2/ladybugtest/feeds/?x-aio-key=%s", fake->key);
    } else {
        snprintf(url, sizeof(url), "https://stock.adobe.io/Rest/Media/1/Search/Files?locale=en_US%%2526search_parameters%%255Bwords%%255D=kittens");
    }
    CHECK(strcmp(request->url, url) == 0);
    CHECK(request->nheaders == (fake->spec->type == 136 ? 3u : 1u));
    size_t agent = 0, key = 0, product = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcasecmp(header->name, "User-Agent")) {
            char value[80];
            snprintf(value, sizeof(value), "TruffleHog%s%s", fake->suffix ? " " : "",
                     fake->suffix ? fake->suffix : "");
            CHECK(strcmp(header->value, value) == 0);
            ++agent;
        } else if (!strcasecmp(header->name, "x-api-key")) {
            CHECK(fake->spec->type == 136 && strcmp(header->value, fake->key) == 0);
            ++key;
        } else if (!strcasecmp(header->name, "x-product")) {
            CHECK(fake->spec->type == 136 && strcmp(header->value, fake->id) == 0);
            ++product;
        } else CHECK(!"unexpected header");
    }
    CHECK(agent == 1);
    CHECK(key == (fake->spec->type == 136 ? 1u : 0u));
    CHECK(product == (fake->spec->type == 136 ? 1u : 0u));
    *response = (br_http_response){.status = fake->status, .body = fake->body, .body_error = fake->body_error};
    *error = fake->error ? copy_string(fake->error) : NULL;
    return fake->send_fails ? 1 : 0;
}

static void fake_release(void *user, br_http_response *response)
{
    fake_http *fake = user;
    CHECK(response != NULL);
    ++fake->releases;
}

static void extraction(const br_detector *detector, const specification *spec,
                        const char *label, const void *input, size_t len,
                        const expected_result *expected, size_t count)
{
    current_case = label;
    fake_http fake = {.spec = spec};
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan(detector, &ctx, false, input, len);
    CHECK(results.len == count);
    CHECK(fake.calls == 0 && fake.releases == 0);
    bool *seen = calloc(count ? count : 1, sizeof(*seen));
    CHECK(seen != NULL);
    for (size_t i = 0; i < results.len; ++i) {
        size_t j;
        /* Upstream maps make Accuweather/AdobeIO order unspecified. */
        for (j = 0; j < count; ++j)
            if (!seen[j] && same_result(&results.items[i], &expected[j])) break;
        CHECK(j < count);
        seen[j] = true;
        check_result(&results.items[i], spec, &expected[j]);
        if (spec->type == 390) CHECK(same_result(&results.items[i], &expected[i]));
        CHECK(!results.items[i].verified && results.items[i].verification_error == NULL);
    }
    free(seen);
    br_results_clear(&results);
    CHECK(results.items == NULL && results.len == 0 && results.cap == 0);
    ++cases;
}

static void accuweather_extraction(const br_detector *detector, const specification *spec)
{
    char key[64], second[64], changed[64], input[512];
    make_key(spec, key, 0);
    make_key(spec, second, 9);
    expected_result one[] = {{key, NULL}}, two[] = {{key, NULL}, {second, NULL}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    snprintf(input, sizeof(input), "accuweather = '%s'", key);
    EXTRACT("Accuweather baseline and exact fields", 1, one);
    extraction(detector, spec, "Accuweather empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("Accuweather needs preceding keyword", 0, NULL);
    snprintf(input, sizeof(input), "%s accuweather", key);
    EXTRACT("Accuweather keyword after key is insufficient", 0, NULL);
    snprintf(input, sizeof(input), "prefixACCUWEATHERsuffix:%s", key);
    EXTRACT("Accuweather case-insensitive unbounded keyword", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen("accuweather");
        memcpy(input, "accuweather", at);
        memset(input + at, '-', gap);
        memcpy(input + at + gap, key, spec->key_len + 1);
        EXTRACT(gap == 40 ? "Accuweather prefix 40" : "Accuweather prefix 41", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "accuweather\r\n%s", key);
    EXTRACT("Accuweather CR/LF prefix", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen("accuweather");
        memcpy(input, "accuweather", at);
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, spec->key_len + 1);
        EXTRACT(gap == 40 ? "Accuweather rune prefix 40" : "Accuweather rune prefix 41", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "accuweather%s", key);
    EXTRACT("Accuweather v1 has no leading capture boundary", spec->version == 1 ? 1 : 0, one);
    snprintf(input, sizeof(input), "accuweather _%s", key);
    EXTRACT("Accuweather version-specific left underscore boundary", spec->version == 1 ? 1 : 0, one);
    snprintf(input, sizeof(input), "accuweather %s_", key);
    EXTRACT("Accuweather right underscore boundary", 0, NULL);
    snprintf(input, sizeof(input), "accuweather %.*s", (int)spec->key_len - 1, key);
    EXTRACT("Accuweather short key rejected", 0, NULL);
    snprintf(input, sizeof(input), "accuweather X%s", key);
    EXTRACT("Accuweather v1 captures a longer token suffix", spec->version == 1 ? 1 : 0, one);
    memcpy(changed, key, spec->key_len + 1);
    changed[spec->key_len / 2] = '$';
    snprintf(input, sizeof(input), "accuweather %s", changed);
    EXTRACT("Accuweather invalid alphabet", 0, NULL);
    if (spec->version == 1) {
        memcpy(changed, key, spec->key_len + 1);
        changed[0] = '%';
        expected_result percent[] = {{changed, NULL}};
        snprintf(input, sizeof(input), "accuweather %s", changed);
        EXTRACT("Accuweather v1 accepts initial percent", 1, percent);
        changed[spec->key_len - 1] = '%';
        snprintf(input, sizeof(input), "accuweather %s", changed);
        EXTRACT("Accuweather v1 final percent needs word boundary", 0, NULL);
        snprintf(input, sizeof(input), "accuweather %sX", changed);
        EXTRACT("Accuweather v1 final percent before word is captured", 1, percent);
    } else {
        memcpy(changed, key, spec->key_len + 1);
        changed[7] = '%';
        snprintf(input, sizeof(input), "accuweather %s", changed);
        EXTRACT("Accuweather v2 rejects percent", 0, NULL);
    }
    memset(changed, 'a', spec->key_len);
    changed[spec->key_len] = '\0';
    snprintf(input, sizeof(input), "accuweather %s", changed);
    EXTRACT("Accuweather rejects low entropy", 0, NULL);
    const char *below = spec->version == 1 ? "0123456789abcdef" : "0123456789abcde";
    for (size_t i = 0; i < spec->key_len; ++i) changed[i] = below[i % strlen(below)];
    snprintf(input, sizeof(input), "accuweather %s", changed);
    EXTRACT("Accuweather just below entropy threshold", 0, NULL);
    const char *above = spec->version == 1 ? "0123456789abcdefg" : "0123456789abcdef";
    for (size_t i = 0; i < spec->key_len; ++i) changed[i] = above[i % strlen(above)];
    snprintf(input, sizeof(input), "accuweather %s", changed);
    expected_result threshold[] = {{changed, NULL}};
    EXTRACT(spec->version == 1 ? "Accuweather just above four bits" : "Accuweather exactly four bits is accepted", 1, threshold);
    snprintf(input, sizeof(input), "accuweather %s\naccuweather %s", key, key);
    EXTRACT("Accuweather unique-match map removes duplicate keys", 1, one);
    snprintf(input, sizeof(input), "accuweather %s\naccuweather %s", key, second);
    EXTRACT("Accuweather retains distinct keys", 2, two);
    size_t at = strlen("accuweather");
    memcpy(input, "accuweather", at);
    input[at++] = '\0';
    memcpy(input + at, key, spec->key_len);
    extraction(detector, spec, "Accuweather binary NUL prefix", input, at + spec->key_len, one, 1);
#undef EXTRACT
    printf("PASS Accuweather v%d extraction/entropy/uniqueness\n", spec->version);
}

static void adafruit_extraction(const br_detector *detector, const specification *spec)
{
    char key[64], second[64], input[256], changed[64];
    make_key(spec, key, 0);
    make_key(spec, second, 11);
    expected_result one[] = {{key, NULL}}, two[] = {{key, NULL}, {second, NULL}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("AdafruitIO captures complete aio_ key with no provider prefix", 1, one);
    extraction(detector, spec, "AdafruitIO empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "  '%s'\r\n", key);
    EXTRACT("AdafruitIO whitespace outside capture", 1, one);
    snprintf(input, sizeof(input), "x%s", key);
    EXTRACT("AdafruitIO left word boundary", 0, NULL);
    snprintf(input, sizeof(input), "_%s", key);
    EXTRACT("AdafruitIO left underscore boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s_", key);
    EXTRACT("AdafruitIO right underscore boundary", 0, NULL);
    snprintf(input, sizeof(input), "%sq", key);
    EXTRACT("AdafruitIO long key rejected", 0, NULL);
    snprintf(input, sizeof(input), "%.*s", (int)spec->key_len - 1, key);
    EXTRACT("AdafruitIO short key rejected", 0, NULL);
    memcpy(changed, key, spec->key_len + 1);
    changed[0] = 'A';
    snprintf(input, sizeof(input), "%s", changed);
    EXTRACT("AdafruitIO literal prefix remains case-sensitive", 0, NULL);
    memcpy(changed, key, spec->key_len + 1);
    changed[15] = '_';
    snprintf(input, sizeof(input), "%s", changed);
    EXTRACT("AdafruitIO payload alphabet", 0, NULL);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    expected_result duplicates[] = {{key, NULL}, {key, NULL}};
    EXTRACT("AdafruitIO does not deduplicate", 2, duplicates);
    snprintf(input, sizeof(input), "%s\n%s", key, second);
    EXTRACT("AdafruitIO source order", 2, two);
    memcpy(changed, "aio_", 4);
    memset(changed + 4, 'a', 28);
    changed[32] = '\0';
    expected_result low[] = {{changed, NULL}};
    snprintf(input, sizeof(input), "%s", changed);
    EXTRACT("AdafruitIO has no local entropy or false-positive filter", 1, low);
    snprintf(input, sizeof(input), "\xc3\xa9%s\xc3\xa9", key);
    EXTRACT("AdafruitIO ASCII boundaries", 1, one);
#undef EXTRACT
    printf("PASS AdafruitIO extraction/order/duplicates\n");
}

static void adobe_extraction(const br_detector *detector, const specification *spec)
{
    char key[64], second[64], input[4096], changed[64], id[32];
    make_key(spec, key, 0);
    make_key(spec, second, 8);
    expected_result one[] = {{key, adobe_id}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, adobe_id);
    EXTRACT("AdobeIO exact Raw/RawV2/SecretParts", 1, one);
    extraction(detector, spec, "AdobeIO empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "adobe %s", key);
    EXTRACT("AdobeIO key alone is not a credential", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s", adobe_id);
    EXTRACT("AdobeIO ID alone is not a credential", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", adobe_id, key);
    EXTRACT("AdobeIO pairs IDs before keys", 1, one);
    snprintf(input, sizeof(input), "adobe %s %s", key, adobe_id);
    EXTRACT("AdobeIO patterns independently reuse one prefix", 1, one);
    snprintf(input, sizeof(input), "preADOBEsuffix:%s\radobe\n%s", key, adobe_id);
    EXTRACT("AdobeIO prefix case/substrings/CR/LF", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "adobe%.*s%s\nadobe %s", (int)gap,
                 "-----------------------------------------", key, adobe_id);
        EXTRACT("AdobeIO key prefix distance 40/41", gap == 40 ? 1 : 0, one);
        snprintf(input, sizeof(input), "adobe %s\nadobe%.*s%s", key, (int)gap,
                 "-----------------------------------------", adobe_id);
        EXTRACT("AdobeIO ID prefix distance 40/41", gap == 40 ? 1 : 0, one);
    }
    size_t at = (size_t)snprintf(input, sizeof(input), "adobe %s\n", key);
    memset(input + at, '-', 2048);
    at += 2048;
    snprintf(input + at, sizeof(input) - at, "\nadobe %s", adobe_id);
    EXTRACT("AdobeIO does not impose engine credential span inside scanner", 1, one);
    snprintf(input, sizeof(input), "adobe %s\nadobe %s\nadobe %s\nadobe %s",
             key, key, adobe_id, adobe_id);
    EXTRACT("AdobeIO deduplicates both component sets", 1, one);
    snprintf(input, sizeof(input), "adobe %s\nadobe %s\nadobe %s\nadobe %s",
             key, second, adobe_id, adobe_second_id);
    expected_result product[] = {
        {key, adobe_id}, {key, adobe_second_id}, {second, adobe_id}, {second, adobe_second_id},
    };
    EXTRACT("AdobeIO full Cartesian product, not positional pairing", 4, product);
    memcpy(changed, key, 33);
    changed[0] = (char)toupper((unsigned char)changed[0]);
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", changed, adobe_id);
    EXTRACT("AdobeIO key capture remains lowercase", 0, NULL);
    snprintf(input, sizeof(input), "adobe _%s\nadobe %s", key, adobe_id);
    EXTRACT("AdobeIO key left boundary", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s_\nadobe %s", key, adobe_id);
    EXTRACT("AdobeIO key right boundary", 0, NULL);
    snprintf(input, sizeof(input), "adobe %.*s\nadobe %s", 31, key, adobe_id);
    EXTRACT("AdobeIO short key rejected", 0, NULL);
    snprintf(input, sizeof(input), "adobe %sq\nadobe %s", key, adobe_id);
    EXTRACT("AdobeIO long key rejected", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe ABCD0123wxy", key);
    EXTRACT("AdobeIO short ID rejected", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe ABCD0123wxyzq", key);
    EXTRACT("AdobeIO long ID rejected", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe ABCD_123wxyz", key);
    EXTRACT("AdobeIO invalid ID alphabet", 0, NULL);
    snprintf(id, sizeof(id), ".ABCDEFGHIJK");
    expected_result dotted[] = {{key, id}};
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, id);
    EXTRACT("AdobeIO leading dot after nonword fails boundary", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe q%s", key, id);
    EXTRACT("AdobeIO leading dot after word satisfies boundary", 1, dotted);
    snprintf(id, sizeof(id), "ABCDEFGHIJK.");
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, id);
    EXTRACT("AdobeIO trailing dot before end fails boundary", 0, NULL);
    snprintf(input, sizeof(input), "adobe %s\nadobe %sX", key, id);
    EXTRACT("AdobeIO trailing dot before word satisfies boundary", 1, dotted);
    memset(changed, 'a', 32);
    changed[32] = '\0';
    expected_result low[] = {{changed, "BBBBBBBBBBBB"}};
    snprintf(input, sizeof(input), "adobe %s\nadobe BBBBBBBBBBBB", changed);
    EXTRACT("AdobeIO has no local entropy or false-positive filter", 1, low);
#undef EXTRACT
    printf("PASS AdobeIO extraction/component sets/Cartesian pairing\n");
}

static void verification_case(const br_detector *detector, const specification *spec,
                               const char *label, fake_http *fake,
                               bool verified, const char *error)
{
    current_case = label;
    char key[64], input[256];
    make_key(spec, key, 0);
    fake->spec = spec;
    fake->key = key;
    fake->id = spec->type == 136 ? adobe_id : NULL;
    fake->calls = fake->releases = 0;
    br_transport transport = {fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    if (spec->type == 136)
        snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, adobe_id);
    else if (spec->type == 303)
        snprintf(input, sizeof(input), "accuweather %s", key);
    else snprintf(input, sizeof(input), "%s", key);
    br_results results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && fake->calls == 1 && fake->releases == 1);
    expected_result expected = {key, fake->id};
    check_result(&results.items[0], spec, &expected);
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error != NULL);
        CHECK(strcmp(results.items[0].verification_error, error) == 0);
    } else CHECK(results.items[0].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
}

static bool cancelled(void *user)
{
    size_t *calls = user;
    ++*calls;
    return true;
}

static void verification_tests(const br_detector *detector, const specification *spec)
{
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    fake_http fake = {.status = 200, .body = {junk, sizeof(junk)}};
    verification_case(detector, spec, "successful status ignores malformed body", &fake, true, NULL);
    fake.suffix = "second-batch-tests";
    fake.body_error = "body read failed";
    const int statuses[] = {200, 401, 403, 201, 204, 400, 404, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake.status = statuses[i];
        bool success = fake.status == 200 || (spec->type == 303 && fake.status == 403);
        bool rejected = fake.status == 401 || (spec->type == 136 && fake.status == 403);
        char error[80];
        snprintf(error, sizeof(error), spec->type == 136 ? "unexpected status code: %d" :
                 "unexpected HTTP response status %d", fake.status);
        verification_case(detector, spec, "all status branches ignore body errors", &fake,
                          success, success || rejected ? NULL : error);
    }
    fake.status = 200;
    fake.send_fails = true;
    fake.body_error = NULL;
    const char *errors[] = {"context deadline exceeded", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fake.error = errors[i];
        verification_case(detector, spec, "transport error retains candidate and releases response", &fake,
                          false, fake.error ? fake.error : "HTTP transport failed");
    }
    char key[64], sensitive_error[256];
    make_key(spec, key, 0);
    snprintf(sensitive_error, sizeof(sensitive_error), "failure %s %s %s", key, key, adobe_id);
    fake.error = sensitive_error;
    char redacted[128];
    snprintf(redacted, sizeof(redacted), "failure [REDACTED] [REDACTED] %s", adobe_id);
    verification_case(detector, spec, "exact upstream secret-redaction arguments", &fake, false,
                      spec->type == 136 ? sensitive_error : redacted);
    fake.error = NULL;
    fake.send_fails = false;

    char input[256];
    if (spec->type == 136)
        snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, adobe_id);
    else if (spec->type == 303)
        snprintf(input, sizeof(input), "accuweather %s", key);
    else snprintf(input, sizeof(input), "%s", key);
    for (int mode = 0; mode < 3; ++mode) {
        current_case = "missing transport/cancelled context/expired deadline fails closed";
        fake.calls = fake.releases = 0;
        size_t checks = 0;
        br_transport transport = {&fake, fake_send, fake_release};
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL, .cancel_user = &checks,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
        };
        br_results results = scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error != NULL && results.items[0].verification_error[0]);
        CHECK(fake.calls == 0 && fake.releases == (mode == 0 ? 0u : 1u));
        CHECK(mode != 1 || checks > 0);
        expected_result expected = {key, spec->type == 136 ? adobe_id : NULL};
        check_result(&results.items[0], spec, &expected);
        br_results_clear(&results);
        ++cases;
    }
    current_case = "verification follows each detector's component deduplication";
    fake.key = key;
    fake.id = spec->type == 136 ? adobe_id : NULL;
    fake.calls = fake.releases = 0;
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake.suffix};
    char duplicate_input[512];
    snprintf(duplicate_input, sizeof(duplicate_input), "%s\n%s", input, input);
    br_results results = scan(detector, &ctx, true, duplicate_input, strlen(duplicate_input));
    size_t expected_count = spec->type == 390 ? 2 : 1;
    CHECK(results.len == expected_count && fake.calls == expected_count && fake.releases == expected_count);
    for (size_t i = 0; i < results.len; ++i)
        CHECK(results.items[i].verified && results.items[i].verification_error == NULL);
    br_results_clear(&results);
    ++cases;

    current_case = "no candidate means no verification calls";
    fake.calls = fake.releases = 0;
    results = scan(detector, &ctx, true, "unrelated", strlen("unrelated"));
    CHECK(results.len == 0 && fake.calls == 0 && fake.releases == 0);
    br_results_clear(&results);
    ++cases;
    printf("PASS %s v%d verification/request/status/body/error paths\n", spec->name, spec->version);
}

static void descriptor_tests(const br_detector *const *detectors, size_t count)
{
    current_case = "private descriptors and inherited capabilities/default membership";
    CHECK(BR_ABI_REVISION == 1 && count == 4);
    size_t enabled = 0;
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        const specification *spec = &specs[i];
        CHECK(detector->type == spec->type && detector->version == spec->version);
        CHECK(strcmp(detector->name, spec->name) == 0);
        CHECK(strcmp(detector->description, spec->description) == 0);
        CHECK(detector->custom_name != NULL && detector->custom_name[0] == '\0');
        CHECK(detector->nkeywords == 1 && strcmp(detector->keywords[0], spec->keyword) == 0);
        CHECK(detector->state != NULL && detector->scan != NULL);
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
        CHECK(detector->max_credential_span == (spec->type == 136 ? 1024 : -1));
        CHECK(detector->clean == NULL && !detector->clean_always && detector->false_positive == NULL);
        CHECK(detector->validate_endpoints == NULL && detector->cloud_endpoint == NULL);
        CHECK(br_second_batch_is_default(detector) == (spec->type != 136));
        enabled += br_second_batch_is_default(detector);
        br_detector copy = *detector;
        CHECK(br_second_batch_is_default(&copy) == (spec->type != 136));
        copy.custom_name = "custom";
        CHECK(!br_second_batch_is_default(&copy));
    }
    CHECK(enabled == 3 && !br_second_batch_is_default(NULL));
    CHECK(detectors[0]->scan == detectors[1]->scan);
    CHECK(detectors[0]->keywords == detectors[1]->keywords);
    CHECK(strcmp(detectors[0]->description, detectors[1]->description) == 0);
    CHECK(detectors[0]->state != detectors[1]->state);
    br_detector invalid = {.type = 303, .version = 3};
    CHECK(!br_second_batch_is_default(&invalid));
    invalid = (br_detector){.type = 390, .version = 1};
    CHECK(!br_second_batch_is_default(&invalid));
    invalid = (br_detector){.type = 9999};
    CHECK(!br_second_batch_is_default(&invalid));
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    char *error = NULL;
    CHECK(br_second_batch(&again, &nagain, &error) == 0);
    CHECK(error == NULL && again == detectors && nagain == count);
    CHECK(br_second_batch(NULL, &nagain, &error) != 0);
    CHECK(error != NULL && nagain == 0);
    free(error);
    error = NULL;
    CHECK(br_second_batch(&again, NULL, &error) != 0);
    CHECK(error != NULL && again == NULL);
    free(error);
    ++cases;
    printf("PASS private batch descriptors: inherited versions, AdobeIO disabled default\n");
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_second_batch(&detectors, &count, &error) == 0);
    CHECK(error == NULL);
    descriptor_tests(detectors, count);
    for (size_t i = 0; i < count; ++i) {
        if (specs[i].type == 303) accuweather_extraction(detectors[i], &specs[i]);
        else if (specs[i].type == 390) adafruit_extraction(detectors[i], &specs[i]);
        else adobe_extraction(detectors[i], &specs[i]);
        verification_tests(detectors[i], &specs[i]);
    }
    printf("PASS: %zu second-batch cases, %zu assertions, 0 failures; fake transport only\n", cases, assertions);
    return 0;
}
