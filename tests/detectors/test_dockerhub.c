/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char uuid[] = "zzzzzzzz-yyyy-xxxx-wwww-vvvvvvvvvvvv";
static const char pat[] = "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxY_-";
static const char oat[] = "dckr_oat_AbCdEfGhIjKlMnOpQrStUvWxY01234_-";
static size_t fail_size, fail_after, failed_allocations, fail_add_after, fail_realloc_size;

/* Target actual owned allocation/JSON/push boundaries, without production seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    size_t size = strlen(text) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_realloc_size && size == fail_realloc_size) { fail_realloc_size = 0; ++failed_allocations; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(int version)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    int (*init)(const br_detector **, char **) = version == 1 ? br_dockerhub_v1_init : br_dockerhub_v2_init;
    CHECK(BR_ABI_REVISION == 1 && strlen(uuid) == 36 && strlen(pat) == 36 && strlen(oat) == 41);
    CHECK(init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 921 && d->version == version && !strcmp(d->name, "Dockerhub") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, version == 1 ?
        "Docker is a platform used to develop, ship, and run applications. Docker access tokens can be used to authenticate and interact with Docker services." :
        "Dockerhub is a cloud-based repository in which Docker users and partners create, test, store and distribute container images. Dockerhub personal access tokens (PATs) can be used to access and manage these container images."));
    CHECK(d->nkeywords == (version == 1 ? 1u : 3u) && !strcmp(d->keywords[0], "docker"));
    if (version == 2) CHECK(!strcmp(d->keywords[1], "dckr_pat_") && !strcmp(d->keywords[2], "dckr_oat_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void json_string(br_json *object, const char *key, br_slice expected)
{
    br_json *value = NULL;
    CHECK(object && json_object_object_get_ex(object, key, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void finding(const br_result *r, const char *token, const char *attempt, const char *final,
                      bool verified, const char *cause)
{
    CHECK(r->detector_type == 921 && !r->detector_name && r->raw.len == strlen(token) && !memcmp(r->raw.data, token, r->raw.len));
    CHECK(!r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
    json_string(r->secret_parts, "pat", text(token));
    CHECK(json_object_object_length(r->secret_parts) == (final ? 2 : 1));
    if (final) json_string(r->secret_parts, "username", text(final));
    if (attempt) {
        size_t n = strlen(attempt), k = strlen(token);
        CHECK(r->raw_v2.len == n + 1 + k && !memcmp(r->raw_v2.data, attempt, n) && r->raw_v2.data[n] == ':' && !memcmp(r->raw_v2.data + n + 1, token, k));
    } else CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->extra_data);
}

static char *input_for(const br_detector *d, const char *username)
{
    const char *token = d->version == 1 ? uuid : pat;
    size_t n = strlen(username) + 160; char *input = malloc(n); CHECK(input);
    snprintf(input, n, d->version == 1 ? "docker %s\ndocker user=%s" : "%s\nuser=%s", token, username);
    return input;
}

static char *encode(br_slice data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *out = malloc((data.len + 2) / 3 * 4 + 1); CHECK(out);
    size_t at = 0;
    for (size_t i = 0; i < data.len; i += 3) {
        size_t left = data.len - i;
        unsigned word = (unsigned)data.data[i] << 16;
        if (left > 1) word |= (unsigned)data.data[i + 1] << 8;
        if (left > 2) word |= data.data[i + 2];
        out[at++] = alphabet[word >> 18]; out[at++] = alphabet[(word >> 12) & 63];
        if (left > 1) out[at++] = alphabet[(word >> 6) & 63];
        if (left > 2) out[at++] = alphabet[word & 63];
    }
    out[at] = '\0'; return out;
}

static char *jwt(br_slice header, br_slice claims)
{
    char *a = encode(header), *b = encode(claims); size_t size = strlen(a) + strlen(b) + 32;
    char *out = malloc(size); CHECK(out); snprintf(out, size, "%s.%s.not-base64!=", a, b);
    free(a); free(b); return out;
}

static char *response_token(const br_detector *d, br_slice token)
{
    br_json *object = json_object_new_object(); CHECK(object && token.len <= INT32_MAX);
    br_json *value = json_object_new_string_len((const char *)token.data, (int)token.len); CHECK(value);
    CHECK(json_object_object_add(object, d->version == 1 ? "token" : "access_token", value) == 0);
    char *out = strdup(json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN)); CHECK(out);
    json_object_put(object); return out;
}

typedef struct {
    const char *username, *token, *send_error, *read_error;
    int status, send_rc;
    br_slice body;
} row;
typedef struct {
    row rows[8]; size_t count;
    const br_detector *detector; const br_scan_ctx *ctx;
    const unsigned char *borrowed_body; size_t borrowed_len;
    char *read_storage, *transport_storage; unsigned char *body_storage;
    size_t arm_call, arm_size, arm_after, arm_add, arm_push;
    bool suffix;
} script;

static void body_equals(const script *steps, const row *reply, const unsigned char *body, size_t len)
{
    size_t size = strlen(reply->username) + strlen(reply->token) + 100;
    char *expected = calloc(size, 1); CHECK(expected);
    int n = snprintf(expected, size, steps->detector->version == 1 ? "{\"username\": \"%s\", \"password\": \"%s\"}" :
                     "{\"identifier\": \"%s\", \"secret\": \"%s\"}", reply->username, reply->token);
    CHECK(n >= 0 && len == (size_t)n && !memcmp(body, expected, len)); free(expected);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 8 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 921 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, steps->detector->version == 1 ?
        "https://hub.docker.com/v2/users/login" : "https://hub.docker.com/v2/auth/token"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog dockerhub-offline" : "TruffleHog"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    body_equals(steps, reply, request->body.data, request->body.len);
    steps->borrowed_body = request->body.data; steps->borrowed_len = request->body.len;
    if (reply->read_error) { steps->read_storage = strdup(reply->read_error); CHECK(steps->read_storage); }
    if (reply->body.len) {
        steps->body_storage = malloc(reply->body.len); CHECK(steps->body_storage);
        memcpy(steps->body_storage, reply->body.data, reply->body.len);
    }
    http->response = (br_http_response){.status = reply->status, .body_error = steps->read_storage,
        .body = {steps->body_storage, reply->body.len}};
    http->send_error = reply->send_error; http->send_rc = reply->send_rc;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *steps = http->user; steps->transport_storage = *error;
    if (steps->arm_call == http->calls) {
        fail_size = steps->arm_size; fail_after = steps->arm_after;
        fail_add_after = steps->arm_add; fail_realloc_size = steps->arm_push;
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    body_equals(steps, &steps->rows[http->calls - 1], steps->borrowed_body, steps->borrowed_len);
    steps->borrowed_body = NULL;
    if (steps->read_storage) memset(steps->read_storage, '!', strlen(steps->read_storage));
    if (steps->transport_storage) memset(steps->transport_storage, '!', strlen(steps->transport_storage));
    if (steps->body_storage) memset(steps->body_storage, '!', response->body.len);
    free(steps->read_storage); free(steps->body_storage);
    steps->read_storage = steps->transport_storage = NULL; steps->body_storage = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, bool verify, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "dockerhub-offline" : NULL};
    steps->detector = d; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, verify, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_body && !steps->read_storage && !steps->body_storage);
    return rc;
}

static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL;
    int rc = invoke(d, text(input), true, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static br_results one(const br_detector *d, int status, br_slice body, const char *read_error, const char *send_error, int send_rc)
{
    char *input = input_for(d, "ABCD"); script steps = {.count = 1};
    steps.rows[0] = (row){.username = "ABCD", .token = d->version == 1 ? uuid : pat,
        .status = status, .body = body, .read_error = read_error, .send_error = send_error, .send_rc = send_rc};
    br_results out = run(d, input, &steps); free(input); CHECK(out.len == 1); return out;
}

static void extraction_case(const br_detector *d, br_slice input, const char *token)
{
    br_results out = test_scan(d, NULL, false, input.data, input.len);
    CHECK(out.len == (token ? 1u : 0u));
    if (token) finding(&out.items[0], token, NULL, NULL, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[600], changed[50];
    extraction_case(v1, text(uuid), NULL);
    snprintf(input, sizeof(input), "DOCKER %s", uuid); extraction_case(v1, text(input), uuid);
    memset(input, ' ', sizeof(input)); memcpy(input, "docker", 6); memcpy(input + 46, uuid, 37); extraction_case(v1, text(input), uuid);
    memcpy(input + 47, uuid, 37); input[46] = ' '; extraction_case(v1, text(input), NULL);
    snprintf(input, sizeof(input), "docker Z%s", uuid); extraction_case(v1, text(input), NULL);
    memcpy(changed, uuid, sizeof(uuid)); changed[4] = 'Z'; snprintf(input, sizeof(input), "docker %s", changed); extraction_case(v1, text(input), NULL);
    extraction_case(v2, text(pat), pat); extraction_case(v2, text(oat), oat);
    const char *good[] = {"(%s)", "-%s.", "%s/"};
    for (size_t i = 0; i < 3; ++i) { snprintf(input, sizeof(input), good[i], pat); extraction_case(v2, text(input), pat); }
    const char *bad[] = {"_%s", "A%s", "%s_", "%s-", "%s9"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], pat); extraction_case(v2, text(input), NULL); }
    memcpy(changed, pat, sizeof(pat)); changed[0] = 'D'; extraction_case(v2, text(changed), NULL);
    memcpy(changed, "dckr_pat_", 9); memset(changed + 9, '_', 27); changed[36] = '\0'; extraction_case(v2, text(changed), changed);
    input[0] = '\0'; memcpy(input + 1, pat, 36); input[37] = '\0'; extraction_case(v2, (br_slice){(unsigned char *)input, 38}, pat);
    extraction_case(v1, (br_slice){0}, NULL); extraction_case(v2, (br_slice){0}, NULL);

    const char whites[] = {' ', '\t', '\n', '\r', '\f'};
    for (size_t i = 0; i < sizeof(whites); ++i) {
        snprintf(input, sizeof(input), "UsEr%cABCD\n%s", whites[i], pat);
        br_results out = test_scan(v2, NULL, false, input, strlen(input)); CHECK(out.len == 1);
        finding(&out.items[0], pat, "ABCD", "ABCD", false, NULL); br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "user\vABCD\n%s", pat); extraction_case(v2, text(input), pat);
    snprintf(input, sizeof(input), "user\v:ABCD\n%s", pat);
    br_results out = test_scan(v2, NULL, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], pat, "ABCD", "ABCD", false, NULL); br_results_clear(&out);

    snprintf(input, sizeof(input), "docker %s\n%080d\nuser=ABCD\nmail@example.test", uuid, 0);
    extraction_case(v1, text(input), uuid); /* V1 username AND email still need docker prefixes. */
    snprintf(input, sizeof(input), "docker %s\ndocker user=AbCd\ndocker My.Name+tag@EXAMPLE.test", uuid);
    out = test_scan(v1, NULL, false, input, strlen(input)); CHECK(out.len == 2 && out.items[0].secret_parts == out.items[1].secret_parts);
    finding(&out.items[0], uuid, "AbCd", "My.Name+tag@EXAMPLE.test", false, NULL);
    finding(&out.items[1], uuid, "My.Name+tag@EXAMPLE.test", "My.Name+tag@EXAMPLE.test", false, NULL); br_results_clear(&out);

    snprintf(input, sizeof(input), "first@example.test\nuser=AbCd\nuser=AbCd\nUSER=abcd\n%s.%s\n%s", pat, oat, pat);
    out = test_scan(v2, NULL, false, input, strlen(input)); CHECK(out.len == 6);
    const char *names[] = {"AbCd", "abcd", "first@example.test"}; const char *tokens[] = {pat, oat};
    for (size_t i = 0; i < 2; ++i) for (size_t j = 0; j < 3; ++j) {
        finding(&out.items[i * 3 + j], tokens[i], names[j], names[2], false, NULL);
        CHECK(out.items[i * 3].secret_parts == out.items[i * 3 + j].secret_parts);
    }
    CHECK(out.items[0].secret_parts != out.items[3].secret_parts); br_results_clear(&out);
    /* PAT-only fallback never constructs HTTP even with verify=true/nil ctx. */
    out = test_scan(v2, NULL, true, pat, strlen(pat)); CHECK(out.len == 1);
    finding(&out.items[0], pat, NULL, NULL, false, NULL); br_results_clear(&out);
}

static void http_branches(const br_detector *d)
{
    const char *token = d->version == 1 ? uuid : pat;
    const int statuses[] = {0, 199, 201, 204, 299, 300, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected response status %d", statuses[i]);
        br_results out = one(d, statuses[i], TEXT("\xff"), NULL, NULL, 0);
        finding(&out.items[0], token, "ABCD", "ABCD", false, cause); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    }
    const int reads[] = {200, 401, 500};
    for (size_t i = 0; i < 3; ++i) for (size_t empty = 0; empty < 2; ++empty) {
        const char *cause = empty ? "" : "unwrapped read cause";
        br_results out = one(d, reads[i], TEXT("\xff"), cause, NULL, 0);
        finding(&out.items[0], token, "ABCD", "ABCD", false, cause); br_results_clear(&out);
    }
    br_results out = one(d, 200, TEXT("{}"), NULL, "do not strip failed to make request: synthetic leaf", 1);
    finding(&out.items[0], token, "ABCD", "ABCD", false, "do not strip failed to make request: synthetic leaf"); br_results_clear(&out);
    char *input = input_for(d, "ABCD");
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], token, "ABCD", "ABCD", false, "net/http: nil Context"); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input));
    finding(&out.items[0], token, "ABCD", "ABCD", false, "HTTP transport not installed"); br_results_clear(&out); free(input);

    const char *mfa[] = {"{}", "null", "[]", "{", "{\"login_2fa_token\":9}", "{\"login_2fa_token\":\"\"}",
        "{\"login_2fa_token\":true,\"LOGIN_2FA_TOKEN\":\"valid\"}"};
    for (size_t i = 0; i < sizeof(mfa) / sizeof(*mfa); ++i) {
        out = one(d, 401, text(mfa[i]), NULL, NULL, 0);
        finding(&out.items[0], token, "ABCD", "ABCD", false, NULL); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    }
    out = one(d, 401, TEXT("{\"unknown\":1e10000,\"LOGIN_2FA_TOKEN\":\"\\u0000\",\"login_2fa_token\":null}"), NULL, NULL, 0);
    finding(&out.items[0], token, "ABCD", "ABCD", true, NULL);
    CHECK(json_object_object_length(out.items[0].extra_data) == 2); json_string(out.items[0].extra_data, "hub_username", TEXT("ABCD"));
    json_string(out.items[0].extra_data, "2fa_required", TEXT("true")); br_results_clear(&out);
}

static void jwt_case(const br_detector *d, br_slice header, br_slice claims, bool verified, const char *cause, const br_slice *scope, const br_slice *email)
{
    char *encoded = jwt(header, claims), *body = response_token(d, text(encoded));
    br_results out = one(d, 200, text(body), NULL, NULL, 0);
    finding(&out.items[0], d->version == 1 ? uuid : pat, "ABCD", "ABCD", verified, cause);
    if (scope) {
        CHECK(json_object_object_length(out.items[0].extra_data) == 3);
        json_string(out.items[0].extra_data, "hub_username", TEXT("ABCD"));
        json_string(out.items[0].extra_data, "hub_scope", *scope); json_string(out.items[0].extra_data, "hub_email", *email);
    } else CHECK(!out.items[0].extra_data);
    br_results_clear(&out); free(encoded); free(body);
}

static void typed_json_and_jwt(const br_detector *d)
{
    const char *token = d->version == 1 ? uuid : pat, *field = d->version == 1 ? "token" : "access_token";
    char body[400], expected[400]; br_results out;
    const char *empty[] = {"{}", "null", "{\"unknown\":1e10000}"};
    for (size_t i = 0; i < 3; ++i) { out = one(d, 200, text(empty[i]), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", false, NULL); br_results_clear(&out); }
    snprintf(body, sizeof(body), "{\"%s\":7,\"%s\":\"later\"}", field, field);
    snprintf(expected, sizeof(expected), "json: cannot unmarshal number into Go struct field tokenResponse.%s of type string", field);
    out = one(d, 200, text(body), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", false, expected); br_results_clear(&out);
    out = one(d, 200, TEXT("[]"), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", false, "json: cannot unmarshal array into Go value of type dockerhub.tokenResponse"); br_results_clear(&out);
    snprintf(body, sizeof(body), "{\"%s\":\"bad\",\"%s\":null}", field, field);
    out = one(d, 200, text(body), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", true, "token is malformed"); br_results_clear(&out);
    snprintf(body, sizeof(body), "{\"%s\":\"bad\",\"%s\":\"\"}", field, field);
    out = one(d, 200, text(body), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", false, NULL); br_results_clear(&out);
    snprintf(body, sizeof(body), "{\"%s\\u0000x\":\"bad\"}", field);
    out = one(d, 200, text(body), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", false, NULL); br_results_clear(&out);
    snprintf(body, sizeof(body), "{\"%s\":\"bad\"}", d->version == 1 ? "to\\u212Aen" : "access_to\\u212Aen");
    out = one(d, 200, text(body), NULL, NULL, 0); finding(&out.items[0], token, "ABCD", "ABCD", true, "token is malformed"); br_results_clear(&out);

    br_slice none = TEXT("{\"alg\":\"none\"}"), zero = TEXT("");
    jwt_case(d, none, TEXT("null"), true, NULL, &zero, &zero);
    br_slice scope = TEXT("pull\0🌲"), email = TEXT("u\0@example.test");
    jwt_case(d, none, TEXT("{\"scope\":\"old\",\"SCOPE\":\"pull\\u0000🌲\",\"scope\":null,\"https://hub.docker.com\":{\"Email\":\"u\\u0000@example.test\"},\"HTTPS://HUB.DOCKER.COM\":{\"username\":\"not-the-attempt\"},\"https://hub.docker.com\":null,\"unknown\":1e10000}"), true, NULL, &scope, &email);
    const char *algorithms[] = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"};
    for (size_t i = 0; i < sizeof(algorithms) / sizeof(*algorithms); ++i) {
        snprintf(body, sizeof(body), "{\"alg\":\"%s\"}", algorithms[i]); jwt_case(d, text(body), TEXT("{}"), true, NULL, &zero, &zero);
    }
    jwt_case(d, TEXT("{\"Alg\":\"none\"}"), TEXT("{}"), true, "token is unverifiable", NULL, NULL);
    jwt_case(d, TEXT("{\"alg\":\"none\",\"alg\":null}"), TEXT("{}"), true, "token is unverifiable", NULL, NULL);
    jwt_case(d, TEXT("{\"alg\":\"unregistered\"}"), TEXT("{}"), true, "token is unverifiable", NULL, NULL);
    jwt_case(d, TEXT("{\"alg\":\"none\",\"alg\\u0000x\":\"bad\"}"), TEXT("{}"), true, NULL, &zero, &zero);
    jwt_case(d, TEXT("{\"unknown\":1e10000,\"unknown\":0,\"alg\":\"none\"}"), TEXT("{}"), true,
        "token is malformed: could not JSON decode header: json: cannot unmarshal number 1e10000 into Go value of type float64", NULL, NULL);
    jwt_case(d, TEXT("[1e10000]"), TEXT("{}"), true,
        "token is malformed: could not JSON decode header: json: cannot unmarshal array into Go value of type map[string]interface {}", NULL, NULL);
    jwt_case(d, none, TEXT("[]"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal array into Go value of type dockerhub.hubJwtClaims", NULL, NULL);
    jwt_case(d, TEXT("{}"), TEXT("{\"scope\":5,\"scope\":\"later\"}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal number into Go struct field hubJwtClaims.scope of type string", NULL, NULL);
    jwt_case(d, none, TEXT("{\"https://hub.docker.com\":{\"email\":false}}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal bool into Go struct field userClaims.https://hub.docker.com.email of type string", NULL, NULL);
    jwt_case(d, none, TEXT("{\"ISS\":true,\"iss\":\"later\"}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal bool into Go struct field hubJwtClaims.RegisteredClaims.iss of type string", NULL, NULL);
    jwt_case(d, none, TEXT("{\"iss\":\"x\",\"sub\":null,\"jti\":\"\",\"aud\":[\"one\",\"two\"],\"aud\":null,\"exp\":-123.5,\"exp\":1e308,\"nbf\":\"1.5\",\"iat\":1e-10000}"), true, NULL, &zero, &zero);
    jwt_case(d, none, TEXT("{\"aud\":{\"unused\":1e10000}}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal number 1e10000 into Go struct field hubJwtClaims.RegisteredClaims.aud of type float64", NULL, NULL);
    jwt_case(d, none, TEXT("{\"exp\":true}"), true,
        "token is malformed: could not JSON decode claim: could not parse NumericData: json: cannot unmarshal bool into Go value of type json.Number", NULL, NULL);
    jwt_case(d, none, TEXT("{\"exp\":1e10000}"), true,
        "token is malformed: could not JSON decode claim: could not convert json number value to float: strconv.ParseFloat: parsing \"1e10000\": value out of range", NULL, NULL);
    jwt_case(d, none, TEXT("{\"exp\":\"bad\"}"), true,
        "token is malformed: could not JSON decode claim: could not parse NumericData: json: invalid number literal, trying to unmarshal \"\\\"bad\\\"\" into Number", NULL, NULL);

    const char *broken[] = {"bad", "a.b.c.d", "*.e30.sig", "e30=.e30.sig", "e30.A\n.sig"};
    const char *causes[] = {"token is malformed", "token is malformed",
        "token is malformed: could not base64 decode header: illegal base64 data at input byte 0",
        "token is malformed: could not base64 decode header: illegal base64 data at input byte 3",
        "token is malformed: could not base64 decode claim: illegal base64 data at input byte 1"};
    for (size_t i = 0; i < 5; ++i) {
        char *reply = response_token(d, text(broken[i])); out = one(d, 200, text(reply), NULL, NULL, 0);
        finding(&out.items[0], token, "ABCD", "ABCD", true, causes[i]); CHECK(!out.items[0].extra_data); br_results_clear(&out); free(reply);
    }
    /* Signature is never decoded: preserve even an embedded NUL in it. */
    char *encoded = jwt(none, TEXT("{}")); size_t n = strlen(encoded); encoded[n - 2] = '\0';
    char *reply = response_token(d, (br_slice){(unsigned char *)encoded, n}); out = one(d, 200, text(reply), NULL, NULL, 0);
    finding(&out.items[0], token, "ABCD", "ABCD", true, NULL); CHECK(out.items[0].extra_data); br_results_clear(&out); free(reply); free(encoded);
    /* Non-strict tail bits and ignored CR/LF, in both decoded segments. */
    encoded = jwt(none, TEXT("{}")); char *dot = strchr(encoded, '.'); CHECK(dot && dot[-1] == '0'); dot[-1] = '1';
    char *second = strchr(dot + 1, '.'); CHECK(second);
    char wrapped[160];
    CHECK(snprintf(wrapped, sizeof(wrapped), "\r\n%.*s\r.\n%.*s\n.%s", (int)(dot - encoded), encoded,
        (int)(second - dot - 1), dot + 1, second + 1) > 0);
    reply = response_token(d, text(wrapped)); out = one(d, 200, text(reply), NULL, NULL, 0);
    finding(&out.items[0], token, "ABCD", "ABCD", true, NULL); br_results_clear(&out); free(reply); free(encoded);
}

static void custom_error_priority(const br_detector *d)
{
    /* Immediate custom failure overrides the first saved primitive error and
     * stops before the later NumericDate failure. Ordinary errors stay saved. */
    jwt_case(d, TEXT("{\"alg\":\"none\"}"), TEXT("{\"scope\":7,\"aud\":[null],\"exp\":true}"), true,
        "token is malformed: could not JSON decode claim: invalid type for claim", NULL, NULL);
    /* ClaimStrings decodes the ENTIRE original aud into any before its type
     * checks: even overwritten nested overflow beats an earlier null element. */
    jwt_case(d, TEXT("{\"alg\":\"none\"}"), TEXT("{\"scope\":7,\"aud\":[null,{\"hidden\":1e10000,\"hidden\":0}],\"exp\":true}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal number 1e10000 into Go struct field hubJwtClaims.RegisteredClaims.aud of type float64", NULL, NULL);
    /* The embedded field context applies to array and scalar audience errors. */
    jwt_case(d, TEXT("{\"alg\":\"HS256\"}"), TEXT("{\"scope\":1,\"aud\":[null,1e9999]}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal number 1e9999 into Go struct field hubJwtClaims.RegisteredClaims.aud of type float64", NULL, NULL);
    jwt_case(d, TEXT("{\"alg\":\"HS256\"}"), TEXT("{\"aud\":1e9999}"), true,
        "token is malformed: could not JSON decode claim: json: cannot unmarshal number 1e9999 into Go struct field hubJwtClaims.RegisteredClaims.aud of type float64", NULL, NULL);
}

static void state_and_requests(const br_detector *d)
{
    const char *token = d->version == 1 ? uuid : pat;
    char input[400]; snprintf(input, sizeof(input), "docker %s\ndocker user=AAAA\ndocker user=BBBB\ndocker user=CCCC", token);
    char *encoded = jwt(TEXT("{\"alg\":\"none\"}"), TEXT("{}")), *body = response_token(d, text(encoded));
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.username = "AAAA", .token = token, .status = 500};
    steps.rows[1] = (row){.username = "BBBB", .token = token, .status = 401, .body = TEXT("{}")};
    steps.rows[2] = (row){.username = "CCCC", .token = token, .status = 200, .body = text(body)};
    br_results out = run(d, input, &steps); CHECK(out.len == 3);
    const char *names[] = {"AAAA", "BBBB", "CCCC"};
    for (size_t i = 0; i < 3; ++i) {
        finding(&out.items[i], token, names[i], "CCCC", i == 2, "unexpected response status 500");
        CHECK(out.items[0].secret_parts == out.items[i].secret_parts);
    }
    CHECK(out.items[0].verification_error != out.items[1].verification_error && out.items[1].verification_error != out.items[2].verification_error);
    CHECK(!out.items[0].extra_data && !out.items[1].extra_data && out.items[2].extra_data); br_results_clear(&out);
    free(encoded); free(body);
    steps = (script){.count = 2}; steps.rows[0] = (row){.username = "AAAA", .token = token, .status = 500};
    body = response_token(d, TEXT("bad")); steps.rows[1] = (row){.username = "BBBB", .token = token, .status = 200, .body = text(body)};
    out = run(d, input, &steps); CHECK(out.len == 2);
    finding(&out.items[0], token, "AAAA", "BBBB", false, "unexpected response status 500");
    finding(&out.items[1], token, "BBBB", "BBBB", true, "token is malformed"); CHECK(!out.items[1].extra_data); br_results_clear(&out); free(body);

    /* Long email is not capped by the username regex or a request stack buffer. */
    size_t local = 5000; char *email = malloc(local + 20); CHECK(email); memset(email, 'q', local); strcpy(email + local, "@example.test");
    size_t size = strlen(email) + 100; char *long_input = malloc(size); CHECK(long_input);
    snprintf(long_input, size, "docker %s\ndocker %s", token, email);
    steps = (script){.count = 1}; steps.rows[0] = (row){.username = email, .token = token, .status = 401, .body = TEXT("{}")};
    out = run(d, long_input, &steps); CHECK(out.len == 1); finding(&out.items[0], token, email, email, false, NULL); br_results_clear(&out); free(email); free(long_input);
    /* Quoted email capture must remain literally unescaped inside the body. */
    const char *quoted = "\"a\\\"b\"@example.test";
    snprintf(input, sizeof(input), "docker %s\ndocker Z%s", token, quoted);
    steps = (script){.count = 1}; steps.rows[0] = (row){.username = quoted, .token = token, .status = 401, .body = TEXT("{}")};
    out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], token, quoted, quoted, false, NULL); br_results_clear(&out);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0);
    return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(out);
}

static void resources_and_boundaries(const br_detector *d)
{
    char *input = input_for(d, "ABCD"); const char *token = d->version == 1 ? uuid : pat;
    size_t body_size = strlen(token) + strlen("ABCD") + (d->version == 1 ? strlen("{\"username\": \"\", \"password\": \"\"}") : strlen("{\"identifier\": \"\", \"secret\": \"\"}")) + 1;
    br_results out = caller_owned(); char *error = NULL;
    fail_size = body_size; fail_after = 1; size_t before = failed_allocations;
    int rc = d->scan(d, NULL, true, text(input), &out, &error);
    CHECK(failed_allocations == before + 1 && !fail_after); rolled_back(&out, rc, error); /* Body allocation BEFORE nil context. */
    for (size_t add = 1; add <= 2; ++add) {
        out = caller_owned(); error = NULL; fail_add_after = add;
        rc = d->scan(d, NULL, false, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    }
    const char *leaf = "distinct-borrowed-read-failure";
    script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(leaf) + 1, .arm_after = 1};
    steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 200, .read_error = leaf};
    out = caller_owned(); error = NULL; before = failed_allocations;
    rc = invoke(d, text(input), true, &steps, &out, &error); CHECK(failed_allocations == before + 1 && !fail_after); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_add = 1};
    steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 401, .body = TEXT("{\"login_2fa_token\":\"yes\"}")};
    out = caller_owned(); error = NULL; rc = invoke(d, text(input), true, &steps, &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    /* A push failure after verification is fatal, even for verified+JWT-error. */
    char *reply = response_token(d, TEXT("bad")); steps = (script){.count = 1, .arm_call = 1, .arm_push = 8 * sizeof(br_result)};
    steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 200, .body = text(reply)};
    out = (br_results){0}; error = NULL; before = failed_allocations;
    rc = invoke(d, text(input), true, &steps, &out, &error);
    CHECK(rc == -1 && error && out.len == 0 && failed_allocations == before + 1 && !fail_realloc_size); free(error); br_results_clear(&out); free(reply);
    /* Ordinary MFA errors are suppressed; allocation of their cause is NOT. */
    const char *mfa_cause = "json: cannot unmarshal number into Go struct field mfaRequiredResponse.login_2fa_token of type string";
    steps = (script){.count = 1, .arm_call = 1, .arm_size = strlen(mfa_cause) + 1, .arm_after = 1};
    steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 401, .body = TEXT("{\"login_2fa_token\":7}")};
    out = caller_owned(); error = NULL; before = failed_allocations;
    rc = invoke(d, text(input), true, &steps, &out, &error); CHECK(failed_allocations == before + 1 && !fail_after); rolled_back(&out, rc, error);

    const br_slice unsupported[] = {TEXT("{\"token\":\"\xff\"}"), TEXT("{\"access_token\":\"\xff\"}")};
    steps = (script){.count = 1}; steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 200, .body = unsupported[d->version - 1]};
    out = caller_owned(); error = NULL; rc = invoke(d, text(input), true, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: Dockerhub invalid UTF-8 response")); rolled_back(&out, rc, error);
    char *encoded = jwt(TEXT("{\"alg\":\"none\"}"), TEXT("{\"scope\":\"\xff\"}")); reply = response_token(d, text(encoded));
    steps = (script){.count = 1}; steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 200, .body = text(reply)};
    out = caller_owned(); error = NULL; rc = invoke(d, text(input), true, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: Dockerhub invalid UTF-8 JWT claims")); rolled_back(&out, rc, error); free(reply); free(encoded);
    encoded = jwt(TEXT("{\"alg\":\"none\"}"), TEXT("{\"exp\":\"🌲\"}")); reply = response_token(d, text(encoded));
    steps = (script){.count = 1}; steps.rows[0] = (row){.username = "ABCD", .token = token, .status = 200, .body = text(reply)};
    out = caller_owned(); error = NULL; rc = invoke(d, text(input), true, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: Dockerhub non-ASCII NumericDate")); rolled_back(&out, rc, error); free(reply); free(encoded);
    /* Roll back a prior finding from THIS call, not just the current candidate. */
    char multiple[220]; snprintf(multiple, sizeof(multiple), "docker %s\ndocker user=AAAA\ndocker user=BBBB", token);
    steps = (script){.count = 2, .arm_call = 2, .arm_size = strlen(leaf) + 1, .arm_after = 1};
    steps.rows[0] = (row){.username = "AAAA", .token = token, .status = 401, .body = TEXT("{}")};
    steps.rows[1] = (row){.username = "BBBB", .token = token, .status = 200, .read_error = leaf};
    out = caller_owned(); error = NULL; before = failed_allocations;
    rc = invoke(d, text(multiple), true, &steps, &out, &error); CHECK(failed_allocations == before + 1 && !fail_after); rolled_back(&out, rc, error);
    free(input);
}

int main(void)
{
    const br_detector *v1 = descriptor(1), *v2 = descriptor(2);
    extraction(v1, v2);
    http_branches(v1); http_branches(v2);
    typed_json_and_jwt(v1); typed_json_and_jwt(v2);
    custom_error_priority(v1); custom_error_priority(v2);
    state_and_requests(v1); state_and_requests(v2);
    resources_and_boundaries(v1); resources_and_boundaries(v2);
    CHECK(!fail_after && !fail_add_after && !fail_realloc_size);
    return test_finish("Dockerhub v1/v2");
}
