/* SPDX-License-Identifier: AGPL-3.0-only */
/* Source-derived acceptance with synthetic values and an injected HTTP transport. */
#include "../../src/detectors/fourth_batch.h"

#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static size_t cases, assertions;
static const char *current_case = "setup";
#define CHECK(expr) do { \
    ++assertions; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s at %s:%d: %s\n", current_case, __FILE__, __LINE__, #expr); \
        fprintf(stderr, "%zu cases completed, 1 failure\n", cases); \
        exit(1); \
    } \
} while (0)

typedef struct {
    int32_t type;
    const char *name, *keyword, *description;
    size_t key_len;
} specification;
static const specification specs[] = {
    {125, "AirbrakeProjectKey", "airbrake",
     "Airbrake is an error and performance monitoring service for web applications. Airbrake project keys can be used to report and track errors in applications.", 32},
    {126, "AirbrakeUserKey", "airbrake",
     "Airbrake is an error and performance monitoring service. Airbrake User Keys can be used to access and manage error reports and performance data.", 40},
    {277, "Airship", "airship",
     "Airship is a customer engagement platform that provides tools for mobile app messaging, in-app messaging, and web notifications. Airship API keys can be used to access and manage these messaging services.", 91},
    {1014, "AirtableOAuth", "airtable",
     "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases.", 0},
};
static const char project_id[] = "004207";
static const char rotation_guide[] = "https://howtorotate.com/docs/tutorials/airbrake/";
typedef struct { const char *secret, *id; } expected_result;

static void make_secret(const specification *spec, char out[128], size_t shift)
{
    if (spec->type == 1014) {
        strcpy(out, shift ? "Other8.v1.Different_-Payload.9e8d7c" : "Native7.v1.Synthetic_-Payload.1a2b3c");
        return;
    }
    static const char alphabet[] = "b7C9d2E5f6G8h3J4k1M0n2P4q6R8s1T3u5V7w9X2y4Z6";
    for (size_t i = 0; i < spec->key_len; ++i)
        out[i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    out[spec->key_len] = '\0';
}

static void make_input(const specification *spec, const char *secret, const char *id,
                        char *input, size_t len)
{
    if (spec->type == 125) snprintf(input, len, "airbrake %s\nairbrake %s", secret, id);
    else if (spec->type == 1014) snprintf(input, len, "%s", secret);
    else snprintf(input, len, "%s %s", spec->keyword, secret);
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

static bool matches_result(const br_result *result, const specification *spec,
                            const expected_result *expected)
{
    br_json *secret = NULL, *id = NULL;
    const char *name = spec->type == 1014 ? "token" : "key";
    if (!json_object_object_get_ex(result->secret_parts, name, &secret) ||
        strcmp(json_object_get_string(secret), expected->secret)) return false;
    if (!expected->id) return !json_object_object_get_ex(result->secret_parts, "id", &id);
    return json_object_object_get_ex(result->secret_parts, "id", &id) &&
           !strcmp(json_object_get_string(id), expected->id);
}

static void check_result(const br_result *result, const specification *spec,
                          const expected_result *expected)
{
    size_t len = strlen(expected->secret);
    CHECK(result->detector_type == spec->type);
    CHECK(result->detector_name == NULL && result->redacted == NULL);
    CHECK(result->raw.data != NULL && result->raw.len == len);
    CHECK(memcmp(result->raw.data, expected->secret, len) == 0);
    CHECK(result->secret_parts != NULL && json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == (expected->id ? 2 : 1));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, spec->type == 1014 ? "token" : "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(strcmp(json_object_get_string(part), expected->secret) == 0);
    if (expected->id) {
        CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
        CHECK(json_object_is_type(part, json_type_string));
        CHECK(strcmp(json_object_get_string(part), expected->id) == 0);
        CHECK(result->raw_v2.data != NULL && result->raw_v2.len == len + strlen(expected->id));
        CHECK(memcmp(result->raw_v2.data, expected->secret, len) == 0);
        CHECK(memcmp(result->raw_v2.data + len, expected->id, strlen(expected->id)) == 0);
    } else CHECK(result->raw_v2.data == NULL && result->raw_v2.len == 0);
    if (spec->type == 125 || spec->type == 126) {
        CHECK(result->extra_data != NULL && json_object_is_type(result->extra_data, json_type_object));
        CHECK(json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
        CHECK(json_object_is_type(part, json_type_string));
        CHECK(strcmp(json_object_get_string(part), rotation_guide) == 0);
    } else CHECK(result->extra_data == NULL);
    CHECK(result->structured_data == NULL && !result->verification_from_cache);
    CHECK(result->primary_secret.data == NULL && result->primary_secret.len == 0);
    CHECK(result->primary_line == 0 && result->chunk_offset == 0 && !result->chunk_offset_set);
}

typedef struct {
    const specification *spec;
    const char *secret, *id, *error, *body_error, *suffix;
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
    CHECK(request->detector_type == fake->spec->type);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->dedup_key.data == NULL && request->dedup_key.len == 0);
    CHECK(strcmp(request->method, fake->spec->type == 125 ? "POST" : "GET") == 0);
    char url[256];
    switch (fake->spec->type) {
    case 125: {
        snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects/%s/deploys?key=%s", fake->id, fake->secret);
        static const char payload[] = "{\"environment\":\"production\",\"username\":\"john\",\"email\":\"john@smith.com\",\"repository\":\"https://github.com/airbrake/airbrake\",\"revision\":\"38748467ea579e7ae64f7815452307c9d05e05c5\",\"version\":\"v2.0\"}";
        CHECK(request->body.len == sizeof(payload) - 1 && request->body.data != NULL);
        CHECK(memcmp(request->body.data, payload, sizeof(payload) - 1) == 0);
        break;
    }
    case 126:
        snprintf(url, sizeof(url), "https://api.airbrake.io/api/v4/projects?key=%s", fake->secret);
        break;
    case 277:
        snprintf(url, sizeof(url), "https://go.urbanairship.com/api/schedules");
        break;
    default:
        snprintf(url, sizeof(url), "https://api.airtable.com/v0/meta/whoami");
        break;
    }
    CHECK(strcmp(request->url, url) == 0);
    if (fake->spec->type != 125) CHECK(request->body.data == NULL && request->body.len == 0);
    size_t expected_headers = fake->spec->type == 277 ? 3 : fake->spec->type == 1014 ? 2 : 1;
    CHECK(request->nheaders == expected_headers);
    size_t agent = 0, accept = 0, auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcasecmp(header->name, "User-Agent")) {
            char expected[80];
            snprintf(expected, sizeof(expected), "TruffleHog%s%s", fake->suffix ? " " : "", fake->suffix ? fake->suffix : "");
            CHECK(strcmp(header->value, expected) == 0);
            ++agent;
        } else if (!strcasecmp(header->name, "Accept")) {
            CHECK(fake->spec->type == 277);
            CHECK(strcmp(header->value, "application/vnd.urbanairship+json; version=3") == 0);
            ++accept;
        } else if (!strcasecmp(header->name, "Authorization")) {
            CHECK(fake->spec->type == 277 || fake->spec->type == 1014);
            CHECK(strncmp(header->value, "Bearer ", 7) == 0);
            CHECK(strlen(header->value) == strlen(fake->secret) + 7);
            CHECK(strcmp(header->value + 7, fake->secret) == 0);
            ++auth;
        } else CHECK(!"unexpected header (including invented Content-Type)");
    }
    CHECK(agent == 1 && accept == (fake->spec->type == 277 ? 1u : 0u));
    CHECK(auth == (fake->spec->type == 277 || fake->spec->type == 1014 ? 1u : 0u));
    /* Populate failed sends too: a usable-looking status cannot override send failure. */
    *response = (br_http_response){.status = fake->status, .body = fake->body, .body_error = fake->body_error};
    *error = fake->error ? copy_string(fake->error) : NULL;
    return fake->send_fails ? 1 : 0;
}

static void fake_release(void *user, br_http_response *response)
{
    CHECK(response != NULL);
    ++((fake_http *)user)->releases;
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
    for (size_t i = 0; i < count; ++i) {
        size_t j;
        for (j = 0; j < count; ++j)
            if (!seen[j] && matches_result(&results.items[i], spec, &expected[j])) break;
        CHECK(j < count); /* All four upstream implementations iterate maps. */
        seen[j] = true;
        check_result(&results.items[i], spec, &expected[j]);
        CHECK(!results.items[i].verified && results.items[i].verification_error == NULL);
    }
    free(seen);
    br_results_clear(&results);
    CHECK(results.items == NULL && results.len == 0 && results.cap == 0);
    ++cases;
}

static void fixed_pattern_tests(const br_detector *detector, const specification *spec)
{
    char key[128], second[128], changed[128], input[4096];
    make_secret(spec, key, 0);
    make_secret(spec, second, 9);
    const char *id = spec->type == 125 ? project_id : NULL;
    expected_result one[] = {{key, id}}, two[] = {{key, id}, {second, id}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    make_input(spec, key, id, input, sizeof(input));
    EXTRACT("fixed capture and complete result metadata", 1, one);
    extraction(detector, spec, "empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("provider prefix required", 0, NULL);
    snprintf(input, sizeof(input), "%s %s", key, spec->keyword);
    EXTRACT("provider must precede the key", 0, NULL);
    char prefix[32];
    for (size_t i = 0; i <= strlen(spec->keyword); ++i)
        prefix[i] = (char)toupper((unsigned char)spec->keyword[i]);
    snprintf(input, sizeof(input), "pre%ssuffix:%s", prefix, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("scoped prefix case and no keyword word boundary", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen(spec->keyword);
        memcpy(input, spec->keyword, at);
        memset(input + at, ' ', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key);
        if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
        EXTRACT("prefix distance 40/41", gap == 40 ? 1 : 0, one);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = strlen(spec->keyword);
        memcpy(input, spec->keyword, at);
        for (size_t i = 0; i < gap; ++i) { input[at++] = (char)0xc3; input[at++] = (char)0xa9; }
        snprintf(input + at, sizeof(input) - at, "%s", key);
        if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
        EXTRACT("prefix rune distance 40/41", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "%s\r\n%s", spec->keyword, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("prefix spans CR/LF", 1, one);
    snprintf(input, sizeof(input), "%s _%s", spec->keyword, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("left underscore violates capture boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s %s_", spec->keyword, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("right underscore violates capture boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s %.*s", spec->keyword, (int)spec->key_len - 1, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("short fixed-length key rejected", 0, NULL);
    snprintf(input, sizeof(input), "%s %sq", spec->keyword, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("long fixed-length word rejected", 0, NULL);
    strcpy(changed, key);
    changed[spec->key_len / 2] = '$';
    make_input(spec, changed, id, input, sizeof(input));
    EXTRACT("invalid capture alphabet", 0, NULL);
    memset(changed, 'a', spec->key_len);
    changed[spec->key_len] = '\0';
    make_input(spec, changed, id, input, sizeof(input));
    expected_result low[] = {{changed, id}};
    EXTRACT("no detector-local entropy or false-positive filter", 1, low);
    make_input(spec, key, id, input, sizeof(input));
    size_t at = strlen(input);
    snprintf(input + at, sizeof(input) - at, "\n%s %s", spec->keyword, key);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("unique-key and unique-ID maps remove repeated occurrences", 1, one);
    snprintf(input, sizeof(input), "%s %s\n%s %s", spec->keyword, key, spec->keyword, second);
    if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
    EXTRACT("distinct keys survive without detector-local cleaning", 2, two);
    at = strlen(spec->keyword);
    memcpy(input, spec->keyword, at);
    input[at++] = '\0';
    at += (size_t)snprintf(input + at, sizeof(input) - at, "%s", key);
    if (id) at += (size_t)snprintf(input + at, sizeof(input) - at, "\nairbrake %s", id);
    extraction(detector, spec, "binary NUL prefix separator", input, at, one, 1);
    strcpy(changed, key);
    changed[10] = '-';
    expected_result hyphen[] = {{changed, id}};
    make_input(spec, changed, id, input, sizeof(input));
    EXTRACT("hyphen belongs only to the Airbrake alphabets", spec->type == 277 ? 0 : 1, hyphen);
    if (spec->type != 277) {
        strcpy(changed, key);
        changed[0] = '-';
        snprintf(input, sizeof(input), "airbrake%s", changed);
        if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
        EXTRACT("Airbrake leading hyphen after word satisfies boundary", 1, hyphen);
        make_input(spec, changed, id, input, sizeof(input));
        EXTRACT("Airbrake leading hyphen after space has no boundary", 0, NULL);
        strcpy(changed, key);
        changed[spec->key_len - 1] = '-';
        make_input(spec, changed, id, input, sizeof(input));
        EXTRACT("Airbrake trailing hyphen before nonword fails boundary", 0, NULL);
        snprintf(input, sizeof(input), "airbrake %sQ", changed);
        if (id) snprintf(input + strlen(input), sizeof(input) - strlen(input), "\nairbrake %s", id);
        EXTRACT("Airbrake trailing hyphen before word satisfies boundary", 1, hyphen);
    }
    if (spec->type == 125) {
        snprintf(input, sizeof(input), "airbrake %s", key);
        EXTRACT("project key without ID gives no credential", 0, NULL);
        snprintf(input, sizeof(input), "airbrake %s", id);
        EXTRACT("project ID without key gives no credential", 0, NULL);
        for (size_t gap = 40; gap <= 41; ++gap) {
            at = (size_t)snprintf(input, sizeof(input), "airbrake %s\nairbrake", key);
            memset(input + at, ' ', gap);
            snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
            EXTRACT("project ID prefix distance 40/41", gap == 40 ? 1 : 0, one);
        }
        snprintf(input, sizeof(input), "airbrake %s\nairbrake 00420", key);
        EXTRACT("project ID must be six digits", 0, NULL);
        snprintf(input, sizeof(input), "airbrake %s\nairbrake 0042070", key);
        EXTRACT("project ID right word boundary", 0, NULL);
        snprintf(input, sizeof(input), "airbrake %s\nairbrake x004207", key);
        EXTRACT("project ID left word boundary", 0, NULL);
        snprintf(input, sizeof(input), "airbrake %s\nairbrake %s\nairbrake %s\nairbrake 008209", key, second, id);
        expected_result product[] = {{key, id}, {key, "008209"}, {second, id}, {second, "008209"}};
        EXTRACT("project keys/IDs form a unique-set Cartesian product", 4, product);
        at = (size_t)snprintf(input, sizeof(input), "airbrake %s\n", key);
        memset(input + at, '.', 2048);
        snprintf(input + at + 2048, sizeof(input) - at - 2048, "\nairbrake %s", id);
        EXTRACT("project scan does not impose engine credential-span limits", 1, one);
        strcpy(changed, key);
        memcpy(changed + 2, "-123456-", 8);
        make_input(spec, changed, id, input, sizeof(input));
        expected_result embedded_id[] = {{changed, "123456"}, {changed, id}};
        EXTRACT("ID pattern independently finds a six-digit word inside a hyphenated key", 2, embedded_id);
    }
#undef EXTRACT
    printf("PASS %s extraction/unique sets/pairing/metadata\n", spec->name);
}

static void oauth_pattern_tests(const br_detector *detector, const specification *spec)
{
    char key[128], second[128], input[4096];
    make_secret(spec, key, 0);
    make_secret(spec, second, 1);
    expected_result one[] = {{key, NULL}}, two[] = {{key, NULL}, {second, NULL}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    snprintf(input, sizeof(input), "%s", key);
    EXTRACT("OAuth literal token pattern does not need a provider prefix", 1, one);
    extraction(detector, spec, "OAuth empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s airtable", key);
    EXTRACT("OAuth detector keyword need not precede token", 1, one);
    snprintf(input, sizeof(input), "airtable%100s%s", "", key);
    EXTRACT("OAuth has no 40-character provider-prefix restriction", 1, one);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    EXTRACT("OAuth unique match map", 1, one);
    snprintf(input, sizeof(input), "%s\n%s", key, second);
    EXTRACT("OAuth retains distinct tokens", 2, two);
    const struct { const char *input, *match; } fixtures[] = {
        {"a.v1.-.f", "a.v1.-.f"}, {"1.v1._.0", "1.v1._.0"},
        {"Ab9.v1.aZ09_-.abcdef0123456789", "Ab9.v1.aZ09_-.abcdef0123456789"},
        {"a.v2.x.f", NULL}, {"a.V1.x.f", NULL}, {"a.v1..f", NULL},
        {".v1.x.f", NULL}, {"a.v1.x.", NULL}, {"a.v1.x.ABCDEF", NULL},
        {"a.v1.x.abcG", NULL}, {"a.v1.x.abc_", NULL}, {"a.v1.x$.abc", NULL},
        {"_ab.v1.x.f", NULL}, {"aa_bb.v1.x.f", NULL},
        {"a-b.v1.x.f", "b.v1.x.f"}, {"a.v1.x.abc-def", "a.v1.x.abc"},
        {"\xc3\xa9.v1.x.f", NULL}, {"\xc3\xa9" "a.v1.x.f", "a.v1.x.f"},
        {"a.v1.x.f\xc3\xa9", "a.v1.x.f"},
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) {
        expected_result expected[] = {{fixtures[i].match, NULL}};
        extraction(detector, spec, "OAuth exact ASCII/segment/version/word-boundary captures",
                   fixtures[i].input, strlen(fixtures[i].input), expected, fixtures[i].match ? 1 : 0);
    }
    size_t at = (size_t)snprintf(input, sizeof(input), "Native7.v1.");
    memset(input + at, 'A', 1024);
    at += 1024;
    input[at++] = '.';
    memset(input + at, 'a', 512);
    at += 512;
    input[at] = '\0';
    expected_result long_token[] = {{input, NULL}};
    EXTRACT("OAuth segments are unbounded and not decoded/validated as JSON", 1, long_token);
    const char binary[] = {'\0', 'a', '.', 'v', '1', '.', 'x', '.', 'f', '\0'};
    expected_result binary_token[] = {{"a.v1.x.f", NULL}};
    extraction(detector, spec, "OAuth binary NUL boundaries", binary, sizeof(binary), binary_token, 1);
#undef EXTRACT
    printf("PASS AirtableOAuth extraction/ASCII classes/variable segments/uniqueness\n");
}

static void verification_case(const br_detector *detector, const specification *spec,
                               const char *label, fake_http *fake, const char *override,
                               bool verified, const char *expected_error)
{
    current_case = label;
    char key[128], input[4096];
    make_secret(spec, key, 0);
    const char *secret = override ? override : key;
    const char *id = spec->type == 125 ? project_id : NULL;
    fake->spec = spec;
    fake->secret = secret;
    fake->id = id;
    fake->calls = fake->releases = 0;
    make_input(spec, secret, id, input, sizeof(input));
    br_transport transport = {fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    br_results results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && fake->calls == 1 && fake->releases == 1);
    expected_result expected = {secret, id};
    check_result(&results.items[0], spec, &expected);
    CHECK(results.items[0].verified == verified);
    if (expected_error) {
        CHECK(results.items[0].verification_error != NULL);
        CHECK(strcmp(results.items[0].verification_error, expected_error) == 0);
    } else CHECK(results.items[0].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
}

static bool always_cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void verification_tests(const br_detector *detector, const specification *spec)
{
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', 'J', 'S', 'O', 'N'};
    fake_http fake = {.status = 200, .body = {body, sizeof(body)}};
    verification_case(detector, spec, "complete request and success independent of body", &fake, NULL, true, NULL);
    fake.suffix = "fourth-batch-tests";
    fake.body_error = "ignored body drain/read failure";
    const int statuses[] = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake.status = statuses[i];
        bool success = fake.status == 200;
        bool rejected = fake.status == 401 || (spec->type != 1014 && fake.status == 403);
        char error[80];
        snprintf(error, sizeof(error), spec->type == 1014 ? "unexpected HTTP response status %d" : "unexpected status code: %d", fake.status);
        verification_case(detector, spec, "exact status/rejection/error branches ignore body errors", &fake, NULL,
                          success, success || rejected ? NULL : error);
    }
    fake.status = 200;
    fake.body_error = NULL;
    fake.send_fails = true;
    const char *errors[] = {"context deadline exceeded", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fake.error = errors[i];
        verification_case(detector, spec, "failed transport retains candidate and releases partial response", &fake, NULL,
                          false, fake.error ? fake.error : "HTTP transport failed");
    }
    char key[128], sensitive_error[320];
    make_secret(spec, key, 0);
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s failed: %s", key, key);
    fake.error = sensitive_error;
    verification_case(detector, spec, "exact upstream redaction arguments (token only for OAuth)", &fake, NULL,
                      false, spec->type == 1014 ? "request [REDACTED] failed: [REDACTED]" : sensitive_error);
    fake.error = NULL;
    fake.send_fails = false;
    if (spec->type == 1014) {
        char long_token[2048];
        size_t at = (size_t)snprintf(long_token, sizeof(long_token), "Native7.v1.");
        memset(long_token + at, 'A', 1024);
        at += 1024;
        long_token[at++] = '.';
        memset(long_token + at, 'a', 512);
        long_token[at + 512] = '\0';
        verification_case(detector, spec, "unbounded OAuth token is not truncated in Authorization", &fake,
                          long_token, true, NULL);
    }
    char input[512];
    const char *id = spec->type == 125 ? project_id : NULL;
    make_input(spec, key, id, input, sizeof(input));
    for (int mode = 0; mode < 3; ++mode) {
        current_case = "missing transport and actual cancellation/deadline fail closed";
        fake.calls = fake.releases = 0;
        size_t checks = 0;
        br_transport transport = {&fake, fake_send, fake_release};
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
                           .cancelled = mode == 1 ? always_cancelled : NULL, .cancel_user = &checks,
                           .deadline_monotonic_ms = mode == 2 ? 1 : 0};
        br_results results = scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error != NULL && results.items[0].verification_error[0]);
        CHECK(fake.calls == 0 && fake.releases == (mode == 0 ? 0u : 1u));
        CHECK(mode != 1 || checks > 0);
        expected_result expected = {key, id};
        check_result(&results.items[0], spec, &expected);
        br_results_clear(&results);
        ++cases;
    }
    current_case = "unique maps verify one candidate for duplicate occurrences";
    fake.secret = key;
    fake.id = id;
    fake.calls = fake.releases = 0;
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake.suffix};
    char duplicate[1024];
    snprintf(duplicate, sizeof(duplicate), "%s\n%s", input, input);
    br_results results = scan(detector, &ctx, true, duplicate, strlen(duplicate));
    CHECK(results.len == 1 && fake.calls == 1 && fake.releases == 1);
    CHECK(results.items[0].verified && results.items[0].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
    current_case = "no match produces no HTTP request";
    fake.calls = fake.releases = 0;
    results = scan(detector, &ctx, true, "unrelated", strlen("unrelated"));
    CHECK(results.len == 0 && fake.calls == 0 && fake.releases == 0);
    br_results_clear(&results);
    ++cases;
    printf("PASS %s verification/request/status/body/error branches\n", spec->name);
}

static void descriptor_tests(const br_detector *const *detectors, size_t count)
{
    current_case = "fourth-batch identities/defaults/capabilities";
    CHECK(BR_ABI_REVISION == 1 && count == 4);
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        CHECK(detector->type == specs[i].type && detector->version == 0);
        CHECK(strcmp(detector->name, specs[i].name) == 0);
        CHECK(strcmp(detector->description, specs[i].description) == 0);
        CHECK(detector->custom_name != NULL && detector->custom_name[0] == '\0');
        CHECK(detector->nkeywords == 1 && strcmp(detector->keywords[0], specs[i].keyword) == 0);
        CHECK(detector->state != NULL && detector->scan != NULL);
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
        CHECK(detector->max_credential_span == (specs[i].type == 125 ? 1024 : -1));
        CHECK(detector->clean == NULL && !detector->clean_always && detector->false_positive == NULL);
        CHECK(detector->validate_endpoints == NULL && detector->cloud_endpoint == NULL);
        CHECK(br_fourth_batch_is_default(detector));
        br_detector copied = *detector;
        CHECK(br_fourth_batch_is_default(&copied));
        copied.version = 1;
        CHECK(!br_fourth_batch_is_default(&copied));
        copied.version = 0;
        copied.custom_name = "custom";
        CHECK(!br_fourth_batch_is_default(&copied));
    }
    br_detector unknown = {.type = 99999};
    CHECK(!br_fourth_batch_is_default(&unknown) && !br_fourth_batch_is_default(NULL));
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    char *error = NULL;
    CHECK(br_fourth_batch(&again, &nagain, &error) == 0 && error == NULL);
    CHECK(again == detectors && nagain == count);
    CHECK(br_fourth_batch(NULL, &nagain, &error) != 0 && error != NULL && nagain == 0);
    free(error);
    error = NULL;
    CHECK(br_fourth_batch(&again, NULL, &error) != 0 && error != NULL && again == NULL);
    free(error);
    ++cases;
    printf("PASS fourth-batch descriptors: exact inventory order, unversioned/default-enabled\n");
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_fourth_batch(&detectors, &count, &error) == 0 && error == NULL);
    descriptor_tests(detectors, count);
    for (size_t i = 0; i < count; ++i) {
        if (specs[i].type == 1014) oauth_pattern_tests(detectors[i], &specs[i]);
        else fixed_pattern_tests(detectors[i], &specs[i]);
        verification_tests(detectors[i], &specs[i]);
    }
    printf("PASS: %zu fourth-batch cases, %zu assertions, 0 failures; synthetic injected transport only\n", cases, assertions);
    return 0;
}
