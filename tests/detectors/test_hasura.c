/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <stdarg.h>

static const br_detector *detector, *observed_detector;
static char key[65], other_key[65], input[4096];
static const char domain[] = "synthetic.hasura.app";
static const char query[] = "{\"query\":\"query { __schema { types { name } } }\"}";

/* Narrow module-local hooks follow the existing detector tests. Ordinary
 * fixtures use the library factory; hooks check required fatal outcomes and
 * release/publication order without changing shared code or the ABI. */
typedef enum {
    NO_FAULT, CAPTURE, FINDING, ALLOCATE, MAP, STRING, MAP_ADD, DOCUMENT,
    MEMBERS, NUMBERS, TYPE_CAUSE, READ_COPY, STATUS_FORMAT, SETTER, PUSH
} fault_site;
static fault_site fault;
static size_t fault_nth, fault_size;
static bool hit(fault_site site)
{
    if (fault != site || (fault_nth && --fault_nth)) return false;
    fault = NO_FAULT;
    return true;
}
static void *checked_malloc(size_t size) { return size == fault_size && hit(ALLOCATE) ? NULL : malloc(size); }
static char *checked_strdup(const char *text) { return hit(READ_COPY) ? NULL : strdup(text); }
static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    if (hit(STATUS_FORMAT)) return -1;
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}
static int checked_captures(const br_regex *regex, br_slice data, br_captures *out, bool unique, char **error)
{
    CHECK(unique);
    if (hit(CAPTURE)) { *error = strdup("synthetic capture failure"); CHECK(*error); return 1; }
    return br_captures_find(regex, data, out, unique, error);
}
static br_result *candidate;
static int checked_finding(br_result *result, int32_t type, br_slice secret, const char *part)
{
    candidate = result;
    return hit(FINDING) ? 1 : br_finding_key_bytes(result, type, secret, part);
}
static br_json *checked_map(void) { return hit(MAP) ? NULL : json_object_new_object(); }
static br_json *checked_string(const char *text, int len) { return hit(STRING) ? NULL : json_object_new_string_len(text, len); }
static int checked_add(br_json *object, const char *name, br_json *value)
{
    return hit(MAP_ADD) ? 1 : json_object_object_add(object, name, value);
}
static int checked_document(br_slice bytes, br_json **root, char **cause)
{
    return hit(DOCUMENT) ? -1 : br_json_document(bytes, root, cause);
}
static int checked_members(br_slice bytes, br_json_member_fn callback, void *user)
{
    return hit(MEMBERS) ? 1 : br_json_each_member(bytes, callback, user);
}
static int checked_numbers(br_slice bytes, char **cause) { return hit(NUMBERS) ? -1 : br_json_check_float64_numbers(bytes, cause); }
static int checked_type(br_json *value, const char *field, const char *expected, char **cause)
{
    return hit(TYPE_CAUSE) ? 1 : br_json_type_cause(value, field, expected, cause);
}
static const br_http_request *provider_request;
static size_t send_attempts, release_attempts, setter_calls;
static bool usable_response;
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!provider_request && candidate && !candidate->verified && !candidate->extra_data);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[1].name, "X-Hasura-Admin-Secret"));
    provider_request = request;
    ++send_attempts;
    int rc = br_http_send(ctx, request, response, error);
    usable_response = rc == 0;
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && candidate && !candidate->verified && !candidate->extra_data && !candidate->verification_error);
    CHECK(!strcmp(provider_request->method, "POST") && !strncmp(provider_request->url, "https://", 8));
    CHECK(strlen(provider_request->headers[1].value) == candidate->raw.len &&
          !memcmp(provider_request->headers[1].value, candidate->raw.data, candidate->raw.len));
    CHECK(provider_request->body.len == sizeof(query) - 1 && !memcmp(provider_request->body.data, query, sizeof(query) - 1));
    br_http_release(ctx, response);
    provider_request = NULL;
    ++release_attempts;
}
static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(!provider_request && send_attempts == release_attempts);
    CHECK(count == 1 && secrets && secrets[0].len == 64 && !memcmp(secrets[0].data, result->raw.data, 64));
    CHECK((result->extra_data != NULL) == usable_response);
    ++setter_calls;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}
static int checked_push(br_results *out, br_result *result) { return hit(PUSH) ? 1 : br_results_push(out, result); }

#define malloc checked_malloc
#define strdup checked_strdup
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define json_object_new_object checked_map
#define json_object_new_string_len checked_string
#define json_object_object_add checked_add
#define br_json_document checked_document
#define br_json_each_member checked_members
#define br_json_check_float64_numbers checked_numbers
#define br_json_type_cause checked_type
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_hasura_init observed_hasura_init
#include "../../src/detectors/hasura.c"
#undef malloc
#undef strdup
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef json_object_new_object
#undef json_object_new_string_len
#undef json_object_object_add
#undef br_json_document
#undef br_json_each_member
#undef br_json_check_float64_numbers
#undef br_json_type_cause
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_hasura_init

static void field(br_json *map, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(map && json_object_object_get_ex(map, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected) && !strcmp(json_object_get_string(value), expected));
}
static void finding(const br_result *result, const char *secret, const char *host,
                    bool verified, const char *cause, bool extra)
{
    size_t a = strlen(host), b = strlen(secret);
    CHECK(result->detector_type == 1030 && !result->detector_name && result->verified == verified);
    CHECK(result->raw.len == b && !memcmp(result->raw.data, secret, b));
    CHECK(result->raw_v2.len == a + 1 + b && !memcmp(result->raw_v2.data, host, a));
    CHECK(result->raw_v2.data[a] == ':' && !memcmp(result->raw_v2.data + a + 1, secret, b));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    field(result->secret_parts, "domain", host); field(result->secret_parts, "key", secret);
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    CHECK((result->extra_data != NULL) == extra);
    if (extra) { CHECK(json_object_object_length(result->extra_data) == 1); field(result->extra_data, "domain", host); }
}
static void extract(const void *bytes, size_t len, const char *secret, const char *host)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, bytes, len);
    CHECK(out.len == (secret ? 1u : 0u) && !http.calls && !http.releases);
    if (secret) finding(&out.items[0], secret, host, false, NULL, false);
    br_results_clear(&out);
}
static void pair_input(const char *secret, const char *host)
{
    int n = snprintf(input, sizeof(input), "hasura %s\n%s", secret, host);
    CHECK(n > 0 && (size_t)n < sizeof(input));
}

static void extraction_and_metadata(void)
{
    char *error = NULL; const br_detector *again = NULL;
    CHECK(br_hasura_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_hasura_init(&detector, &error) == 0 && !error);
    CHECK(br_hasura_init(&again, NULL) == 0 && again == detector);
    CHECK(observed_hasura_init(&observed_detector, &error) == 0 && !error);
    CHECK(detector->type == 1030 && detector->version == 0 && !strcmp(detector->name, "Hasura"));
    CHECK(detector->custom_name && !*detector->custom_name && detector->nkeywords == 1 && !strcmp(detector->keywords[0], "hasura"));
    CHECK(!strcmp(detector->description,
        "Hasura is an open-source engine that instantly generates GraphQL and REST APIs over PostgreSQL (and other databases).\n"
        "\tIt allows you to query, mutate, and subscribe to data in real time. Admin secrets (or admin keys) are used to securely access\n"
        "\tand manage Hasura projects, giving full control over data, metadata, and schema."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(key, 64, 1); key[2] = 'Z'; key[19] = 'Q';
    test_secret(other_key, 64, 7); other_key[15] = 'R';
    pair_input(key, domain); extract(input, strlen(input), key, domain);
    extract(NULL, 0, NULL, NULL);
    snprintf(input, sizeof(input), "hasura %s", key); extract(input, strlen(input), NULL, NULL);
    extract(domain, strlen(domain), NULL, NULL);
    snprintf(input, sizeof(input), "%s %s", key, domain); extract(input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "xHaSuRa:%s\n%s", key, domain); extract(input, strlen(input), key, domain);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "hasura", 6); memset(input + 6, ' ', gap);
        memcpy(input + 6 + gap, key, 64); snprintf(input + 70 + gap, sizeof(input) - 70 - gap, "\n%s", domain);
        extract(input, strlen(input), gap == 40 ? key : NULL, domain);
    }
    memcpy(input, "HASURA", 6); memset(input + 6, ' ', 40); input[8] = '\r'; input[9] = '\n';
    memcpy(input + 46, key, 64); snprintf(input + 110, sizeof(input) - 110, "\n%s", domain);
    extract(input, strlen(input), key, domain);
    const char *bad_key[] = {"hasura _%s\n%s", "hasura %s_\n%s", "hasura A%s\n%s", "hasura %sA\n%s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), bad_key[i], key, domain); extract(input, strlen(input), NULL, NULL); }
    char letters[65]; memset(letters, 'A', 64); letters[64] = 0;
    pair_input(letters, domain); extract(input, strlen(input), letters, domain);
    const char *host_input[] = {"-foo.hasura.app", "_-foo.hasura.app", "_-.hasura.app", "x--.hasura.app", "AbC.hasura.app", "foo.hasura.app-", "foo.HASURA.app", "foo.hasura.APP", "foo.hasura.app_", "foo.hasura.appx", "_foo.hasura.app", "--.hasura.app"};
    const char *hosts[] = {"foo.hasura.app", "-foo.hasura.app", "-.hasura.app", "x--.hasura.app", "AbC.hasura.app", "foo.hasura.app", NULL, NULL, NULL, NULL, NULL, NULL};
    for (size_t i = 0; i < sizeof(hosts) / sizeof(*hosts); ++i) {
        pair_input(key, host_input[i]); extract(input, strlen(input), hosts[i] ? key : NULL, hosts[i]);
    }
    /* Independent unique sets: original case is retained, products are key-major. */
    snprintf(input, sizeof(input), "hasura %s\nhasura %s\nhasura %s\n%s Other.hasura.app %s other.hasura.app", key, key, other_key, domain, domain);
    br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 6);
    const char *product_hosts[] = {domain, "Other.hasura.app", "other.hasura.app"};
    for (size_t i = 0; i < 6; ++i) finding(&out.items[i], i < 3 ? key : other_key, product_hosts[i % 3], false, NULL, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts);
    br_results_clear(&out);
}

typedef struct {
    const char *secrets[6], *hosts[6]; size_t expected_calls;
    const char *borrowed_url, *borrowed_key; const unsigned char *borrowed_body;
    char read_cause[512]; bool poison_read;
    bool scripted;
} request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user;
    size_t i = http->calls - 1;
    CHECK(i < script->expected_calls && !script->borrowed_url && http->releases == i);
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1030);
    const char *host = script->hosts[i]; size_t n = strlen(host);
    CHECK(strlen(request->url) == 8 + n + 11 && !strncmp(request->url, "https://", 8));
    CHECK(!memcmp(request->url + 8, host, n) && !strcmp(request->url + 8 + n, "/v1/graphql"));
    CHECK(request->body.len == sizeof(query) - 1 && !memcmp(request->body.data, query, sizeof(query) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Hasura-Admin-Secret") && !strcmp(request->headers[1].value, script->secrets[i]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog hasura-offline"));
    script->borrowed_url = request->url; script->borrowed_key = request->headers[1].value; script->borrowed_body = request->body.data;
    if (script->scripted) {
        static const unsigned char rejected[] = "{\"errors\":[null]}";
        static const unsigned char valid[] = "{\"data\":false}";
        http->response = (br_http_response){.status = 200, .body = i == 0 ? (br_slice){rejected, sizeof(rejected) - 1} : (br_slice){valid, sizeof(valid) - 1}};
    }
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; request_script *script = http->user;
    if (script->borrowed_url) {
        size_t i = http->calls - 1, n = strlen(script->hosts[i]);
        CHECK(strlen(script->borrowed_url) == 8 + n + 11 && !memcmp(script->borrowed_url + 8, script->hosts[i], n));
        CHECK(!strcmp(script->borrowed_key, script->secrets[i]));
        CHECK(!memcmp(script->borrowed_body, query, sizeof(query) - 1));
        script->borrowed_url = script->borrowed_key = NULL; script->borrowed_body = NULL;
    } else CHECK(!response->status && !response->body.data && !response->body_error);
    if (script->poison_read) memset(script->read_cause, '!', strlen(script->read_cause));
    test_http_release(user, response);
}
static void outcome_bytes(int status, const void *body, size_t len, const char *read_error,
                          int send_rc, const char *send_error, bool valid, const char *cause)
{
    pair_input(key, domain);
    request_script script = {.secrets = {key}, .hosts = {domain}, .expected_calls = 1, .poison_read = read_error != NULL};
    if (read_error) snprintf(script.read_cause, sizeof(script.read_cause), "%s", read_error);
    test_http http = {.user = &script, .inspect = inspect, .send_rc = send_rc, .send_error = send_error,
        .response = {.status = status, .body = {body, len}, .body_error = read_error ? script.read_cause : NULL}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hasura-offline"};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !script.borrowed_url);
    finding(&out.items[0], key, domain, valid, cause, send_rc == 0); br_results_clear(&out);
}
static void outcome(int status, const char *body, const char *read_error, int send_rc,
                    const char *send_error, bool valid, const char *cause)
{
    outcome_bytes(status, body, body ? strlen(body) : 0, read_error, send_rc, send_error, valid, cause);
}
static void json_outcome(const char *body, bool valid, const char *cause) { outcome(200, body, NULL, 0, NULL, valid, cause); }

static void verification_branches(void)
{
    outcome(500, "Project not reachable", NULL, 0, NULL, false, NULL);
    outcome(500, "Unable to load this project", NULL, 0, NULL, false, NULL);
    static const unsigned char binary[] = "\0\xffProject not reachable\0not JSON";
    outcome_bytes(500, binary, sizeof(binary) - 1, NULL, 0, NULL, false, NULL);
    outcome(500, "project not reachable", NULL, 0, NULL, false, "unexpected status code: 500");
    outcome(503, "Unable to load this project", NULL, 0, NULL, false, "unexpected status code: 503");
    outcome(201, "{\"data\":{}}", NULL, 0, NULL, false, "unexpected status code: 201");
    outcome(401, "bad JSON", NULL, 0, NULL, false, "unexpected status code: 401");
    outcome(500, "Project not reachable", "", 0, NULL, false, "");
    outcome(200, "{\"data\":{}}", "synthetic read error", 0, NULL, false, "synthetic read error");
    char cause[512]; snprintf(cause, sizeof(cause), "read %s domain %s key %s", key, domain, key);
    outcome(500, "Project not reachable", cause, 0, NULL, false, "read [REDACTED] domain synthetic.hasura.app key [REDACTED]");
    outcome(200, "{\"data\":{}}", NULL, 1, "context deadline exceeded", false, "context deadline exceeded");
    outcome(200, "{\"data\":{}}", "ignored", -7, cause, false, "read [REDACTED] domain synthetic.hasura.app key [REDACTED]");
    outcome(200, NULL, NULL, 1, "", false, "");
    outcome(200, NULL, NULL, 1, NULL, false, "HTTP transport failed");
    /* Arbitrary injected text resembling local wrappers is never stripped. */
    outcome(200, NULL, NULL, 1, "failed to unmarshal json response: backend cause", false, "failed to unmarshal json response: backend cause");
    outcome(200, NULL, "json: cannot unmarshal number 1e999 into Go value of type float64", 0, NULL, false,
        "json: cannot unmarshal number 1e999 into Go value of type float64");
    pair_input(key, domain);
    br_results out = test_scan(detector, NULL, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, domain, false, "net/http: nil Context", false); br_results_clear(&out);
}

static void typed_json(void)
{
    const char *positive[] = {
        "{\"data\":{}}", "{\"data\":false}", "{\"data\":0}", "{\"data\":\"\"}", "{\"data\":[]}",
        "{\"data\":{\"x\":[null,1e-9999]},\"errors\":[]}", "{\"DATA\":true,\"ERRORS\":null}",
        "{\"data\":{},\"errors\":[null],\"errors\":[]}", "{\"data\":{},\"errors\":[null],\"errors\":null}",
        "{\"data\":null,\"data\":false}", "{\"data\":0,\"unknown\":{\"n\":1e9999}}",
        "{\"data\":{},\"error\\u017f\":[]}", " {\"data\":{}} \r\n\t"
    };
    for (size_t i = 0; i < sizeof(positive) / sizeof(*positive); ++i) json_outcome(positive[i], true, NULL);
    const char *negative[] = {"null", "{}", "{\"data\":null}", "{\"data\":{},\"data\":null}", "{\"data\":{},\"errors\":[null]}", "{\"data\":{},\"errors\":[{}]}", "{\"data\":{},\"errors\":[null],\"errors\":[1]}"};
    for (size_t i = 0; i < sizeof(negative) / sizeof(*negative); ++i) json_outcome(negative[i], false, NULL);
    json_outcome("", false, "unexpected end of JSON input");
    json_outcome("{\"data\":", false, "unexpected end of JSON input");
    json_outcome("{\"data\":{}} {}", false, "invalid character '{' after top-level value");
    json_outcome("[]", false, "json: cannot unmarshal array into Go value of type struct { Data interface {} \"json:\\\"data\\\"\"; Errors []interface {} \"json:\\\"errors\\\"\" }");
    json_outcome("{\"errors\":{\"x\":1e999},\"data\":{}}", false, "json: cannot unmarshal object into Go struct field .errors of type []interface {}");
    json_outcome("{\"errors\":true,\"errors\":[],\"data\":{}}", false, "json: cannot unmarshal bool into Go struct field .errors of type []interface {}");
    json_outcome("{\"data\":1e999}", false, "json: cannot unmarshal number 1e999 into Go struct field .data of type float64");
    json_outcome("{\"data\":{\"nested\":[{\"n\":-2E999}]}}", false, "json: cannot unmarshal number -2E999 into Go struct field .data of type float64");
    json_outcome("{\"data\":{\"n\":1e999,\"n\":0},\"data\":null}", false, "json: cannot unmarshal number 1e999 into Go struct field .data of type float64");
    json_outcome("{\"errors\":[{\"n\":[1e999]}],\"errors\":[],\"data\":{}}", false, "json: cannot unmarshal number 1e999 into Go struct field .errors of type float64");
    json_outcome("{\"errors\":{},\"data\":1e999}", false, "json: cannot unmarshal object into Go struct field .errors of type []interface {}");
    json_outcome("{\"data\":1e999,\"errors\":{}}", false, "json: cannot unmarshal number 1e999 into Go struct field .data of type float64");
    /* Syntax is checked in full before even the first typed error is saved. */
    json_outcome("{\"errors\":false}x", false, "invalid character 'x' after top-level value");
}

static bool cancelled(void *unused) { (void)unused; return true; }
static void products_lifecycle_and_setup(void)
{
    char *error = NULL;
    send_attempts = release_attempts = setter_calls = 0; usable_response = false;
    snprintf(input, sizeof(input), "hasura %s\nhasura %s\n%s second.hasura.app third.hasura.app", key, other_key, domain);
    request_script script = {.secrets = {key, key, other_key}, .hosts = {domain, "second.hasura.app", domain}, .expected_calls = 3, .scripted = true};
    test_http http = {.user = &script, .inspect = inspect}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hasura-offline"};
    br_results out = test_scan(observed_detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && setter_calls == 3 && send_attempts == 3 && release_attempts == 3);
    finding(&out.items[0], key, domain, false, NULL, true);
    finding(&out.items[1], key, "second.hasura.app", true, NULL, true);
    finding(&out.items[2], other_key, domain, true, NULL, true); br_results_clear(&out);
    /* No 1024-byte hint or DNS-label validation is present in the source. */
    char long_domain[1548]; memset(long_domain, 'A', 1536); memcpy(long_domain + 1536, ".hasura.app", 12);
    pair_input(key, long_domain); extract(input, strlen(input), key, long_domain);
    script = (request_script){.secrets = {key}, .hosts = {long_domain}, .expected_calls = 1};
    http = (test_http){.user = &script, .inspect = inspect, .response = {.status = 200, .body = {(const unsigned char *)"{\"data\":{}}", 11}}};
    out = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    finding(&out.items[0], key, long_domain, true, NULL, true); br_results_clear(&out);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    pair_input(key, domain);
    for (size_t mode = 0; mode < 4; ++mode) {
        script = (request_script){0}; http = (test_http){.user = &script};
        br_scan_ctx setup = {.transport = mode ? &transport : NULL, .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "bad\r\nagent" : NULL};
        send_attempts = release_attempts = setter_calls = 0; usable_response = false;
        out = test_scan(observed_detector, &setup, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u));
        CHECK(send_attempts == 1 && release_attempts == 1 && setter_calls == 1);
        finding(&out.items[0], key, domain, false, causes[mode], false); br_results_clear(&out);
    }
    br_result probe = {0}; probe.verification_error = strdup("retain"); CHECK(probe.verification_error);
    char *saved = probe.verification_error;
    CHECK(br_result_set_verification_error(&probe, NULL, NULL, 0) == 0 && probe.verification_error == saved); br_result_clear(&probe);
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error);
    free(error);
}

static void fatal(fault_site site, size_t nth, size_t size, const char *body,
                  const char *read, bool nil_context, const char *expected)
{
    pair_input(key, domain);
    request_script script = {.secrets = {key}, .hosts = {domain}, .expected_calls = 1};
    test_http http = {.user = &script, .inspect = inspect,
        .response = {.status = 500, .body = {(const unsigned char *)body, strlen(body)}, .body_error = read}};
    if (!read && strcmp(body, "Project not reachable") && site != STATUS_FORMAT) http.response.status = 200;
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hasura-offline"};
    br_results out = {0}; br_result seed = {0};
    CHECK(br_finding_key(&seed, 777, "caller", "key") == 0 && br_results_push(&out, &seed) == 0);
    unsigned char *saved = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts;
    fault = site; fault_nth = nth; fault_size = size;
    send_attempts = release_attempts = setter_calls = 0; usable_response = false;
    char *error = NULL;
    CHECK(observed_detector->scan(observed_detector, nil_context ? NULL : &ctx, true,
        (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(fault == NO_FAULT && error && !strcmp(error, expected));
    CHECK(out.len == 1 && out.items[0].raw.data == saved && out.items[0].secret_parts == parts && !memcmp(saved, "caller", 6));
    CHECK(send_attempts == release_attempts && !provider_request && http.calls == http.releases);
    free(error); br_results_clear(&out);
}
static void owned_failures_and_rollback(void)
{
    fatal(CAPTURE, 1, 0, "Project not reachable", NULL, false, "synthetic capture failure");
    fatal(CAPTURE, 2, 0, "Project not reachable", NULL, false, "synthetic capture failure");
    fatal(FINDING, 1, 0, "Project not reachable", NULL, true, "cannot create Hasura result");
    fatal(ALLOCATE, 1, strlen(domain) + 1 + 64, "Project not reachable", NULL, true, "cannot create Hasura result");
    fatal(STRING, 1, 0, "Project not reachable", NULL, true, "cannot create Hasura result");
    fatal(MAP_ADD, 1, 0, "Project not reachable", NULL, true, "cannot create Hasura result");
    fatal(ALLOCATE, 1, strlen(domain) + 8 + sizeof("/v1/graphql"), "Project not reachable", NULL, true, "cannot create Hasura URL");
    fatal(MAP, 1, 0, "Project not reachable", "read must not hide allocation", false, "cannot create Hasura extra data");
    fatal(MAP_ADD, 2, 0, "Project not reachable", NULL, false, "cannot create Hasura extra data");
    fatal(READ_COPY, 1, 0, "Project not reachable", "borrowed cause", false, "cannot copy Hasura read error");
    fatal(STATUS_FORMAT, 1, 0, "not unavailable", NULL, false, "cannot format Hasura status error");
    fatal(DOCUMENT, 1, 0, "{\"data\":{}}", NULL, false, "cannot decode Hasura JSON");
    fatal(MEMBERS, 1, 0, "{\"data\":{}}", NULL, false, "cannot project Hasura JSON");
    fatal(NUMBERS, 1, 0, "{\"errors\":{},\"data\":0}", NULL, false, "cannot project Hasura JSON");
    fatal(TYPE_CAUSE, 1, 0, "{\"data\":1e999,\"errors\":{}}", NULL, false, "cannot project Hasura JSON");
    fatal(ALLOCATE, 1, sizeof("json: cannot unmarshal number 1e999 into Go struct field .data of type float64"),
        "{\"errors\":{},\"data\":1e999}", NULL, false, "cannot project Hasura JSON");
    fatal(SETTER, 1, 0, "Project not reachable", NULL, true, "cannot store Hasura verification error");
    fatal(SETTER, 1, 0, "{\"data\":{}}", NULL, false, "cannot store Hasura verification error");
    fatal(PUSH, 1, 0, "{\"data\":{}}", NULL, false, "cannot append Hasura result");
    /* A second key's positive setter failure must undo this invocation's first
     * appended verified finding, without touching the caller's earlier result. */
    snprintf(input, sizeof(input), "hasura %s\nhasura %s\n%s", key, other_key, domain);
    request_script script = {.secrets = {key, other_key}, .hosts = {domain, domain}, .expected_calls = 2};
    test_http http = {.user = &script, .inspect = inspect,
        .response = {.status = 200, .body = {(const unsigned char *)"{\"data\":{}}", 11}}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "hasura-offline"};
    br_results out = {0}; br_result seed = {0};
    CHECK(br_finding_key(&seed, 777, "caller", "key") == 0 && br_results_push(&out, &seed) == 0);
    unsigned char *saved = out.items[0].raw.data;
    send_attempts = release_attempts = setter_calls = 0; usable_response = false;
    fault = SETTER; fault_nth = 2; char *error = NULL;
    CHECK(observed_detector->scan(observed_detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(fault == NO_FAULT && error && !strcmp(error, "cannot store Hasura verification error"));
    CHECK(out.len == 1 && out.items[0].raw.data == saved && !memcmp(saved, "caller", 6));
    CHECK(http.calls == 2 && http.releases == 2 && send_attempts == 2 && release_attempts == 2 && setter_calls == 2);
    free(error); br_results_clear(&out);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    extraction_and_metadata(); verification_branches(); typed_json();
    products_lifecycle_and_setup(); owned_failures_and_rollback();
    return test_finish("Hasura");
}
