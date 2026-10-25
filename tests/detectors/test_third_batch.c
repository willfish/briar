/* SPDX-License-Identifier: AGPL-3.0-only */
/* Synthetic detector-local acceptance. All verification uses injected responses. */
#include "../../src/detectors/third_batch.h"

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
    const char *name, *keyword, *description, *part_name, *key, *part;
} specification;
static const specification specs[] = {
    {431, "Adzuna", "adzuna",
     "Adzuna is a job search engine used to find job listings. Adzuna API keys can be used to access job listing data.",
     "id", "0123456789abcdef0123456789abcdef", "c7d8e9f0"},
    {693, "Aeroworkflow", "aeroworkflow",
     "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys and Account IDs can be used to access and manage workflows.",
     "id", "BcDfGhJkLmNpQrStVwXy", "00042"},
    {197, "Agora", "agora",
     "Agora is a real-time engagement platform providing APIs for voice, video, and messaging. Agora API keys can be used to access and manage these services.",
     "secret", "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"},
    {802, "Aha", "aha.io",
     "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows.",
     "url", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "synthetic.aha.io"},
};
typedef struct { const char *key, *part; } expected_pair;

static const char *key_prefix(const specification *spec)
{
    if (spec->type == 197) return "token";
    if (spec->type == 802) return "aha";
    return spec->keyword;
}

static const char *part_prefix(const specification *spec)
{
    return spec->type == 197 ? "secret" : spec->keyword;
}

static void make_input(const specification *spec, const char *key, const char *part,
                        char *input, size_t len)
{
    if (spec->type == 802) snprintf(input, len, "aha %s\n%s", key, part);
    else snprintf(input, len, "%s %s\n%s %s", key_prefix(spec), key, part_prefix(spec), part);
}

static char *copy_string(const char *value)
{
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    CHECK(copy != NULL);
    memcpy(copy, value, len);
    return copy;
}

static br_results scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const void *input, size_t len)
{
    br_results results = {0};
    char *error = NULL;
    int rc = detector->scan(detector, ctx, verify, (br_slice){input, len}, &results, &error);
    if (rc) fprintf(stderr, "scan failure: %s\n", error ? error : "no cause");
    CHECK(rc == 0 && error == NULL);
    return results;
}

static bool pair_matches(const br_result *result, const specification *spec,
                          const expected_pair *expected)
{
    br_json *key = NULL, *part = NULL;
    return json_object_object_get_ex(result->secret_parts, "key", &key) &&
           json_object_object_get_ex(result->secret_parts, spec->part_name, &part) &&
           !strcmp(json_object_get_string(key), expected->key) &&
           !strcmp(json_object_get_string(part), expected->part);
}

static void check_result(const br_result *result, const specification *spec,
                          const expected_pair *expected)
{
    size_t key_len = strlen(expected->key), part_len = strlen(expected->part);
    CHECK(result->detector_type == spec->type);
    CHECK(result->detector_name == NULL && result->redacted == NULL);
    CHECK(result->raw.data != NULL && result->raw.len == key_len);
    CHECK(memcmp(result->raw.data, expected->key, key_len) == 0);
    CHECK(result->raw_v2.data != NULL && result->raw_v2.len == key_len + part_len);
    CHECK(memcmp(result->raw_v2.data, expected->key, key_len) == 0);
    CHECK(memcmp(result->raw_v2.data + key_len, expected->part, part_len) == 0);
    CHECK(result->secret_parts != NULL && json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, spec->part_name, &part));
    CHECK(json_object_is_type(key, json_type_string) && json_object_is_type(part, json_type_string));
    CHECK(strcmp(json_object_get_string(key), expected->key) == 0);
    CHECK(strcmp(json_object_get_string(part), expected->part) == 0);
    CHECK(result->extra_data == NULL && result->structured_data == NULL);
    CHECK(!result->verification_from_cache);
    CHECK(result->primary_secret.data == NULL && result->primary_secret.len == 0);
    CHECK(result->primary_line == 0 && result->chunk_offset == 0 && !result->chunk_offset_set);
}

typedef struct {
    const specification *spec;
    const char *key, *part, *error, *body_error, *suffix;
    br_slice body;
    int status;
    bool send_fails, fallback_host;
    size_t calls, releases;
} fake_http;

static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    fake_http *fake = user;
    ++fake->calls;
    CHECK(ctx != NULL && ctx->transport != NULL && ctx->transport->user == fake);
    CHECK(strcmp(request->method, "GET") == 0);
    CHECK(request->detector_type == fake->spec->type);
    CHECK(request->profile == (fake->spec->type == 802 ? BR_HTTP_DETECTOR_PUBLIC : BR_HTTP_SANE));
    CHECK(request->timeout_ms == (fake->spec->type == 802 ? 10000u : 5000u));
    CHECK(request->body.data == NULL && request->body.len == 0);
    CHECK(request->dedup_key.data == NULL && request->dedup_key.len == 0);
    char url[2048];
    switch (fake->spec->type) {
    case 431:
        snprintf(url, sizeof(url), "https://api.adzuna.com/v1/api/jobs/us/search/1?app_id=%s&app_key=%s", fake->part, fake->key);
        CHECK(request->nheaders == 1);
        break;
    case 693:
        snprintf(url, sizeof(url), "https://api.aeroworkflow.com/api/%s/me", fake->part);
        CHECK(request->nheaders == 3);
        break;
    case 197:
        snprintf(url, sizeof(url), "https://api.agora.io/dev/v1/projects");
        CHECK(request->nheaders == 2);
        break;
    default:
        snprintf(url, sizeof(url), "https://%s/api/v1/me", fake->part);
        CHECK(request->nheaders == 3);
        break;
    }
    CHECK(strcmp(request->url, url) == 0);
    size_t agent = 0, accept = 0, auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcasecmp(header->name, "User-Agent")) {
            char expected[80];
            snprintf(expected, sizeof(expected), "TruffleHog%s%s", fake->suffix ? " " : "", fake->suffix ? fake->suffix : "");
            CHECK(strcmp(header->value, expected) == 0);
            ++agent;
        } else if (!strcasecmp(header->name, "Accept")) {
            CHECK(fake->spec->type == 693 || fake->spec->type == 802);
            CHECK(strcmp(header->value, fake->spec->type == 693 ? "application/json" : "application/vnd.aha+json; version=3") == 0);
            ++accept;
        } else if (!strcasecmp(header->name, "apikey")) {
            CHECK(fake->spec->type == 693 && strcmp(header->value, fake->key) == 0);
            ++auth;
        } else if (!strcasecmp(header->name, "Authorization")) {
            if (fake->spec->type == 197) {
                /* Independently generated from synthetic secret:key, including padding. */
                CHECK(strcmp(header->value, "Basic ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA6MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") == 0);
            } else {
                CHECK(fake->spec->type == 802);
                char expected[80];
                snprintf(expected, sizeof(expected), "Bearer %s", fake->key);
                CHECK(strcmp(header->value, expected) == 0);
            }
            ++auth;
        } else CHECK(!"unexpected request header");
    }
    CHECK(agent == 1);
    CHECK(accept == (fake->spec->type == 693 || fake->spec->type == 802 ? 1u : 0u));
    CHECK(auth == (fake->spec->type == 431 ? 0u : 1u));
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
                        const expected_pair *expected, size_t count)
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
        for (j = 0; j < count; ++j)
            if (!seen[j] && pair_matches(&results.items[i], spec, &expected[j])) break;
        CHECK(j < count);
        seen[j] = true;
        if (spec->type != 802) CHECK(j == i); /* Nested source-ordered slices, not sets. */
        check_result(&results.items[i], spec, &expected[j]);
        CHECK(!results.items[i].verified && results.items[i].verification_error == NULL);
    }
    free(seen);
    br_results_clear(&results);
    CHECK(results.items == NULL && results.len == 0 && results.cap == 0);
    ++cases;
}

static void ordered_extraction(const br_detector *detector, const specification *spec)
{
    char input[4096], changed[96], second[96], second_part[96];
    expected_pair one[] = {{spec->key, spec->part}};
    const char *kp = key_prefix(spec), *pp = part_prefix(spec);
    size_t key_len = strlen(spec->key);
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    make_input(spec, spec->key, spec->part, input, sizeof(input));
    EXTRACT("multipart baseline and exact result fields", 1, one);
    extraction(detector, spec, "empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s %s", kp, spec->key);
    EXTRACT("key alone has no result", 0, NULL);
    snprintf(input, sizeof(input), "%s %s", pp, spec->part);
    EXTRACT("part alone has no result", 0, NULL);
    snprintf(input, sizeof(input), "%s\n%s", spec->key, spec->part);
    EXTRACT("bare values do not match", 0, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "%s", kp);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\n%s %s", spec->key, pp, spec->part);
        EXTRACT("key prefix distance 40/41", gap == 40 ? 1 : 0, one);
        at = (size_t)snprintf(input, sizeof(input), "%s %s\n%s", kp, spec->key, pp);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", spec->part);
        EXTRACT("secondary prefix distance 40/41", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "%s\r\n%s\n%s\r\n%s", kp, spec->key, pp, spec->part);
    EXTRACT("both prefixes span CR/LF", 1, one);
    snprintf(input, sizeof(input), "%s _%s\n%s %s", kp, spec->key, pp, spec->part);
    EXTRACT("key left underscore boundary", 0, NULL);
    snprintf(input, sizeof(input), "%s %s_\n%s %s", kp, spec->key, pp, spec->part);
    EXTRACT("exact trailing key boundary semantics", spec->type == 693 ? 1 : 0, one);
    snprintf(input, sizeof(input), "%s %sx\n%s %s", kp, spec->key, pp, spec->part);
    EXTRACT("Aero captures first 20 bytes without end boundary", spec->type == 693 ? 1 : 0, one);
    snprintf(input, sizeof(input), "%s %.*s\n%s %s", kp, (int)key_len - 1, spec->key, pp, spec->part);
    EXTRACT("short key rejected", 0, NULL);
    strcpy(changed, spec->key);
    changed[key_len / 2] = '$';
    make_input(spec, changed, spec->part, input, sizeof(input));
    EXTRACT("invalid key alphabet", 0, NULL);
    strcpy(changed, spec->key);
    changed[0] = 'Z';
    expected_pair uppercase[] = {{changed, spec->part}};
    make_input(spec, changed, spec->part, input, sizeof(input));
    EXTRACT("scoped case does not change capture alphabet", spec->type == 693 ? 1 : 0, uppercase);
    memset(changed, 'a', key_len);
    changed[key_len] = '\0';
    expected_pair low[] = {{changed, spec->part}};
    make_input(spec, changed, spec->part, input, sizeof(input));
    EXTRACT("no local entropy or false-positive filtering", 1, low);
    snprintf(input, sizeof(input), "%s %s\n%s %s\n%s %s\n%s %s",
             kp, spec->key, kp, spec->key, pp, spec->part, pp, spec->part);
    expected_pair duplicate[] = {{spec->key, spec->part}, {spec->key, spec->part},
                                 {spec->key, spec->part}, {spec->key, spec->part}};
    EXTRACT("duplicate component occurrences are retained", 4, duplicate);
    strcpy(second, spec->key);
    second[0] = spec->type == 693 ? 'Q' : 'f';
    strcpy(second_part, spec->part);
    second_part[0] = spec->type == 693 ? '9' : 'b';
    snprintf(input, sizeof(input), "%s %s\n%s %s\n%s %s\n%s %s",
             kp, spec->key, kp, second, pp, spec->part, pp, second_part);
    expected_pair product[] = {{spec->key, spec->part}, {spec->key, second_part},
                               {second, spec->part}, {second, second_part}};
    EXTRACT("Cartesian pairing preserves key-outer/part-inner source order", 4, product);
    size_t at = (size_t)snprintf(input, sizeof(input), "%s %s\n", kp, spec->key);
    memset(input + at, '-', 2048);
    at += 2048;
    snprintf(input + at, sizeof(input) - at, "\n%s %s", pp, spec->part);
    EXTRACT("no invented detector-local 1024-byte pairing restriction", 1, one);
    at = (size_t)snprintf(input, sizeof(input), "%s", kp);
    input[at++] = '\0';
    at += (size_t)snprintf(input + at, sizeof(input) - at, "%s\n%s %s", spec->key, pp, spec->part);
    extraction(detector, spec, "binary NUL prefix separator", input, at, one, 1);
    if (spec->type == 431) {
        snprintf(input, sizeof(input), "adzuna %s\nad zuna %s", spec->key, spec->part);
        EXTRACT("ID needs a real prefix", 0, NULL);
        snprintf(input, sizeof(input), "adzuna %s\nadzuna C7d8e9f0", spec->key);
        EXTRACT("Adzuna ID is lowercase eight characters", 0, NULL);
        snprintf(input, sizeof(input), "adzuna %s\nadzuna c7d8e9f0q", spec->key);
        EXTRACT("Adzuna ID has a trailing boundary", 0, NULL);
        snprintf(input, sizeof(input), "adzuna %s %s", spec->key, spec->part);
        EXTRACT("independent patterns reuse the same provider prefix", 1, one);
    } else if (spec->type == 693) {
        strcpy(changed, spec->key);
        memcpy(changed + 3, "^!?#:*;", 7);
        expected_pair symbols[] = {{changed, spec->part}};
        make_input(spec, changed, spec->part, input, sizeof(input));
        EXTRACT("Aero retains every permitted punctuation character", 1, symbols);
        changed[0] = '^';
        snprintf(input, sizeof(input), "aeroworkflow%s\naeroworkflow %s", changed, spec->part);
        EXTRACT("Aero leading punctuation uses word-to-nonword boundary", 1, symbols);
        make_input(spec, changed, spec->part, input, sizeof(input));
        EXTRACT("Aero leading punctuation after space has no boundary", 0, NULL);
        snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow 7", spec->key);
        expected_pair single_id[] = {{spec->key, "7"}};
        EXTRACT("Aero accepts one-digit account IDs", 1, single_id);
        snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow a42b", spec->key);
        EXTRACT("Aero numeric ID word boundaries", 0, NULL);
        char long_id[1025];
        memset(long_id, '7', sizeof(long_id) - 1);
        long_id[sizeof(long_id) - 1] = '\0';
        snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow -%s", spec->key, long_id);
        /* The long numeric ID is itself an additional 20-byte key match upstream. */
        char numeric_key[21];
        memset(numeric_key, '7', 20);
        numeric_key[20] = '\0';
        expected_pair long_numeric[] = {{spec->key, long_id}, {numeric_key, long_id}};
        EXTRACT("Aero IDs are unbounded strings and can also match the key pattern", 2, long_numeric);
    } else {
        snprintf(input, sizeof(input), "key %s\nsecret %s", spec->key, spec->part);
        EXTRACT("Agora key alternative works without detector keyword prefilter", 1, one);
        snprintf(input, sizeof(input), "monKEY:%s\nSECRET:%s", spec->key, spec->part);
        EXTRACT("Agora alternate keyword fragments are scoped and unbounded", 1, one);
        snprintf(input, sizeof(input), "token %s\nsecret %s", spec->key, spec->key);
        EXTRACT("Agora filters identical key/secret values", 0, NULL);
        snprintf(input, sizeof(input), "agora %s\nagora %s", spec->key, spec->part);
        expected_pair reverse[] = {{spec->key, spec->part}, {spec->part, spec->key}};
        EXTRACT("Agora shared prefix gives both directed non-self pairs", 2, reverse);
        snprintf(input, sizeof(input), "agora %s\nagora %s\nagora %s", spec->key, spec->key, spec->part);
        expected_pair repeated[] = {{spec->key, spec->part}, {spec->key, spec->part},
                                    {spec->part, spec->key}, {spec->part, spec->key}};
        EXTRACT("Agora equality filtering is not deduplication", 4, repeated);
    }
#undef EXTRACT
    printf("PASS %s extraction/pairing/filtering\n", spec->name);
}

static void aha_extraction(const br_detector *detector, const specification *spec)
{
    char input[4096], changed[96], host[96];
    expected_pair one[] = {{spec->key, spec->part}}, fallback[] = {{spec->key, "aha.io"}};
#define EXTRACT(label, n, values) extraction(detector, spec, label, input, strlen(input), values, n)
    make_input(spec, spec->key, spec->part, input, sizeof(input));
    EXTRACT("Aha exact key/url metadata", 1, one);
    extraction(detector, spec, "Aha empty input", NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "aha %s", spec->key);
    EXTRACT("Aha key prefix differs from aha.io prefilter keyword; fallback host", 1, fallback);
    snprintf(input, sizeof(input), "%s", spec->part);
    EXTRACT("Aha host alone has no result", 0, NULL);
    snprintf(input, sizeof(input), "%s", spec->key);
    EXTRACT("Aha still requires the key prefix", 0, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "aha", 3);
        memset(input + 3, '-', gap);
        snprintf(input + 3 + gap, sizeof(input) - 3 - gap, "%s\n%s", spec->key, spec->part);
        EXTRACT("Aha key prefix 40/41", gap == 40 ? 1 : 0, one);
    }
    snprintf(input, sizeof(input), "AHA\r\n%s\n%s", spec->key, spec->part);
    EXTRACT("Aha scoped prefix case and CR/LF", 1, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 3;
        memcpy(input, "aha", 3);
        for (size_t i = 0; i < gap; ++i) { input[at++] = (char)0xc3; input[at++] = (char)0xa9; }
        snprintf(input + at, sizeof(input) - at, "%s\n%s", spec->key, spec->part);
        EXTRACT("Aha prefix counts runes, not bytes", gap == 40 ? 1 : 0, one);
    }
    strcpy(changed, spec->key);
    changed[10] = 'A';
    make_input(spec, changed, spec->part, input, sizeof(input));
    EXTRACT("Aha uppercase hex is rejected", 0, NULL);
    changed[10] = 'g';
    make_input(spec, changed, spec->part, input, sizeof(input));
    EXTRACT("Aha nonhex lowercase is rejected", 0, NULL);
    snprintf(input, sizeof(input), "aha _%s\n%s", spec->key, spec->part);
    EXTRACT("Aha leading word boundary", 0, NULL);
    snprintf(input, sizeof(input), "aha %s_\n%s", spec->key, spec->part);
    EXTRACT("Aha trailing word boundary", 0, NULL);
    snprintf(input, sizeof(input), "aha %.*s\n%s", 63, spec->key, spec->part);
    EXTRACT("Aha exactly 64 hex characters", 0, NULL);
    snprintf(input, sizeof(input), "aha %sf\n%s", spec->key, spec->part);
    EXTRACT("Aha long hex run rejected", 0, NULL);
    snprintf(input, sizeof(input), "aha %s\n%s\n%s", spec->key, spec->part, spec->part);
    EXTRACT("Aha deduplicates hosts only", 1, one);
    snprintf(input, sizeof(input), "aha %s\naha %s\n%s", spec->key, spec->key, spec->part);
    expected_pair duplicate[] = {{spec->key, spec->part}, {spec->key, spec->part}};
    EXTRACT("Aha retains duplicate key occurrences", 2, duplicate);
    snprintf(input, sizeof(input), "aha %s\n%s\nsecond.aha.io", spec->key, spec->part);
    expected_pair hosts[] = {{spec->key, spec->part}, {spec->key, "second.aha.io"}};
    EXTRACT("Aha pairs each unique host", 2, hosts);
    strcpy(changed, spec->key);
    changed[0] = 'f';
    snprintf(input, sizeof(input), "aha %s\naha %s\n%s\nsecond.aha.io", spec->key, changed, spec->part);
    expected_pair product[] = {{spec->key, spec->part}, {spec->key, "second.aha.io"},
                               {changed, spec->part}, {changed, "second.aha.io"}};
    EXTRACT("Aha key/unique-host Cartesian product", 4, product);
    const char *host_inputs[] = {"a.aha.io", "ab.aha.io", "MiXeD.aha.io", "ab.AHA.IO", "two-part.aha.io", "ab-.aha.io", "-ab.aha.io", "ab.aha.io.suffix.invalid"};
    const char *found_hosts[] = {"aha.io", "ab.aha.io", "MiXeD.aha.io", "aha.io", "two-part.aha.io", "aha.io", "ab.aha.io", "ab.aha.io"};
    for (size_t i = 0; i < sizeof(host_inputs) / sizeof(host_inputs[0]); ++i) {
        make_input(spec, spec->key, host_inputs[i], input, sizeof(input));
        expected_pair found[] = {{spec->key, found_hosts[i]}};
        EXTRACT("Aha exact hostname capture/boundary/case semantics", 1, found);
    }
    for (size_t len = 63; len <= 64; ++len) {
        memset(host, 'a', len);
        memcpy(host + len, ".aha.io", 8);
        make_input(spec, spec->key, host, input, sizeof(input));
        expected_pair found[] = {{spec->key, len == 63 ? host : "aha.io"}};
        EXTRACT("Aha hostname label maximum 63", 1, found);
    }
    size_t at = (size_t)snprintf(input, sizeof(input), "aha %s\n", spec->key);
    memset(input + at, '-', 2048);
    snprintf(input + at + 2048, sizeof(input) - at - 2048, "\n%s", spec->part);
    EXTRACT("Aha host collection has no detector-local distance cap", 1, one);
    memset(changed, '0', 64);
    changed[64] = '\0';
    make_input(spec, changed, spec->part, input, sizeof(input));
    expected_pair low[] = {{changed, spec->part}};
    EXTRACT("Aha does not locally filter entropy or false positives", 1, low);
#undef EXTRACT
    printf("PASS Aha extraction/host uniqueness/fallback\n");
}

static void verification_case(const br_detector *detector, const specification *spec,
                               const char *label, fake_http *fake, bool verified,
                               const char *expected_error)
{
    current_case = label;
    char input[512];
    fake->spec = spec;
    fake->key = spec->key;
    fake->part = fake->fallback_host ? "aha.io" : spec->part;
    fake->calls = fake->releases = 0;
    if (fake->fallback_host) snprintf(input, sizeof(input), "aha %s", spec->key);
    else make_input(spec, spec->key, spec->part, input, sizeof(input));
    br_transport transport = {fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake->suffix};
    br_results results = scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    if (spec->type == 802 && fake->calls == 0 && results.items[0].verification_error &&
        !strcmp(results.items[0].verification_error, "unsupported HTTP client profile")) {
        fprintf(stderr, "BLOCKED: br_http_send must support BR_HTTP_DETECTOR_PUBLIC (10s, no redirects, no local IPs); no fallback profile used\n");
    }
    CHECK(fake->calls == 1 && fake->releases == 1);
    expected_pair expected = {spec->key, fake->part};
    check_result(&results.items[0], spec, &expected);
    CHECK(results.items[0].verified == verified);
    if (expected_error) {
        CHECK(results.items[0].verification_error != NULL);
        CHECK(strcmp(results.items[0].verification_error, expected_error) == 0);
        CHECK(strstr(results.items[0].verification_error, spec->key) == NULL);
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
    static const unsigned char binary_body[] = {0, 0xff, 'n', 'o', 't', 'j', 's', 'o', 'n'};
    fake_http fake = {.status = 200, .body = {binary_body, sizeof(binary_body)}};
    verification_case(detector, spec, "successful status with exact effective request", &fake, true, NULL);
    fake.suffix = "third-batch-tests";
    fake.body_error = "ignored body read failure";
    const int statuses[] = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        fake.status = statuses[i];
        bool success = fake.status == 200 || (spec->type == 197 && fake.status == 201);
        bool rejected = fake.status == 401 || (spec->type != 431 && fake.status == 403) ||
                        (spec->type == 802 && fake.status == 404);
        char error[80];
        snprintf(error, sizeof(error), "unexpected HTTP response status %d", fake.status);
        verification_case(detector, spec, "all success/rejection/unexpected branches ignore body errors", &fake,
                          success, success || rejected ? NULL : error);
    }
    fake.status = 200;
    fake.body_error = NULL;
    fake.send_fails = true;
    const char *errors[] = {"context deadline exceeded", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fake.error = errors[i];
        verification_case(detector, spec, "transport failure retains candidate and releases even failed response", &fake,
                          false, fake.error ? fake.error : "HTTP transport failed");
    }
    char error[320], redacted[256];
    snprintf(error, sizeof(error), "key=%s part=%s key-again=%s", spec->key, spec->part, spec->key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] part=%s key-again=[REDACTED]", spec->part);
    fake.error = error;
    verification_case(detector, spec, "upstream redacts every key occurrence but not the secondary part", &fake, false, redacted);
    fake.error = NULL;
    fake.send_fails = false;
    if (spec->type == 802) {
        fake.fallback_host = true;
        verification_case(detector, spec, "Aha fallback URL verification request", &fake, true, NULL);
        fake.fallback_host = false;
    }
    char input[512];
    make_input(spec, spec->key, spec->part, input, sizeof(input));
    for (int mode = 0; mode < 3; ++mode) {
        current_case = "missing transport, actual cancellation and deadline retain candidates";
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
        expected_pair expected = {spec->key, spec->part};
        check_result(&results.items[0], spec, &expected);
        br_results_clear(&results);
        ++cases;
    }
    current_case = "verification does not coalesce duplicate component occurrences";
    fake.key = spec->key;
    fake.part = spec->part;
    fake.calls = fake.releases = 0;
    br_transport transport = {&fake, fake_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = fake.suffix};
    char duplicated[1024];
    snprintf(duplicated, sizeof(duplicated), "%s\n%s", input, input);
    br_results results = scan(detector, &ctx, true, duplicated, strlen(duplicated));
    size_t n = spec->type == 802 ? 2 : 4;
    CHECK(results.len == n && fake.calls == n && fake.releases == n);
    for (size_t i = 0; i < n; ++i) CHECK(results.items[i].verified && results.items[i].verification_error == NULL);
    br_results_clear(&results);
    ++cases;
    current_case = "no candidate means no verification I/O";
    fake.calls = fake.releases = 0;
    results = scan(detector, &ctx, true, "unrelated", strlen("unrelated"));
    CHECK(results.len == 0 && fake.calls == 0 && fake.releases == 0);
    br_results_clear(&results);
    ++cases;
    printf("PASS %s verification/request/status/body/error branches\n", spec->name);
}

static void descriptor_tests(const br_detector *const *detectors, size_t count)
{
    current_case = "third-batch descriptor identities/defaults/capabilities";
    CHECK(BR_ABI_REVISION == 1 && count == 4);
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        CHECK(detector->type == specs[i].type && detector->version == 0);
        CHECK(strcmp(detector->name, specs[i].name) == 0);
        CHECK(strcmp(detector->description, specs[i].description) == 0);
        CHECK(detector->custom_name != NULL && detector->custom_name[0] == '\0');
        CHECK(detector->nkeywords == 1 && strcmp(detector->keywords[0], specs[i].keyword) == 0);
        CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1 && detector->start_offset == -1);
        CHECK(detector->state != NULL && detector->scan != NULL);
        CHECK(detector->clean == NULL && !detector->clean_always && detector->false_positive == NULL);
        CHECK(detector->validate_endpoints == NULL && detector->cloud_endpoint == NULL);
        CHECK(br_third_batch_is_default(detector));
        br_detector copied = *detector;
        CHECK(br_third_batch_is_default(&copied));
        copied.version = 1;
        CHECK(!br_third_batch_is_default(&copied));
        copied.version = 0;
        copied.custom_name = "custom";
        CHECK(!br_third_batch_is_default(&copied));
    }
    br_detector unsupported = {.type = 99999};
    CHECK(!br_third_batch_is_default(&unsupported) && !br_third_batch_is_default(NULL));
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    char *error = NULL;
    CHECK(br_third_batch(&again, &nagain, &error) == 0);
    CHECK(error == NULL && again == detectors && nagain == count);
    CHECK(br_third_batch(NULL, &nagain, &error) != 0 && error != NULL && nagain == 0);
    free(error);
    error = NULL;
    CHECK(br_third_batch(&again, NULL, &error) != 0 && error != NULL && again == NULL);
    free(error);
    ++cases;
    printf("PASS third-batch descriptors: exact inventory order, all default-enabled/unversioned\n");
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_third_batch(&detectors, &count, &error) == 0 && error == NULL);
    descriptor_tests(detectors, count);
    for (size_t i = 0; i < count; ++i) {
        if (specs[i].type == 802) aha_extraction(detectors[i], &specs[i]);
        else ordered_extraction(detectors[i], &specs[i]);
    }
    for (size_t i = 0; i < count; ++i) verification_tests(detectors[i], &specs[i]);
    printf("PASS: %zu third-batch cases, %zu assertions, 0 failures; fake transport only\n", cases, assertions);
    return 0;
}
