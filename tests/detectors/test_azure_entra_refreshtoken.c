/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

static const char client1[] = "13579bdf-2468-4ace-9bdf-13579bdf2468";
static const char client2[] = "2468ace0-1357-4bdf-8ace-2468ace01357";
static const char office[] = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
static char *token1, *token2;
static unsigned tenant_counter;

static char *make_token(size_t first, size_t second, bool numbered, size_t tail, unsigned shift)
{
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    char *out = malloc(first + second + tail + 32); CHECK(out);
    size_t at = 0;
    out[at++] = shift & 1 ? '1' : '0'; out[at++] = '.'; out[at++] = 'A';
    for (size_t i = 0; i < first; ++i) out[at++] = alphabet[(i * 17 + shift) % 64];
    if (numbered) { out[at++] = '.'; out[at++] = '7'; }
    memcpy(out + at, ".Ag", 3); at += 3;
    for (size_t i = 0; i < second; ++i) out[at++] = alphabet[(i * 19 + shift + 9) % 64];
    if (tail) {
        out[at++] = '.'; out[at++] = 'A';
        for (size_t i = 0; i < tail; ++i) out[at++] = alphabet[(i * 23 + shift + 5) % 64];
    }
    out[at] = '\0';
    return out;
}

static void fresh_tenant(char out[80])
{
    snprintf(out, 80, "synthetic-proof-%u.onmicrosoft.com", ++tenant_counter);
}

static char *input_for(const char *token, const char *client, const char *tenant)
{
    size_t len = strlen(token) + (client ? strlen(client) : 0) + (tenant ? strlen(tenant) : 0) + 80;
    char *out = malloc(len); CHECK(out);
    snprintf(out, len, "%s\n%s%s\n%s%s", token, client ? "client_id=" : "", client ? client : "",
             tenant ? "tenant=" : "", tenant ? tenant : "");
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

static void check_result(const br_result *result, const char *token, const char *client, const char *tenant)
{
    CHECK(result->detector_type == 1013 && !result->detector_name && !result->redacted);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, strlen(token)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    check_text(result->secret_parts, "key", token);
    if (client && *client && tenant && *tenant) {
        size_t len = strlen(token) + strlen(client) + strlen(tenant) + 70;
        char *expected = malloc(len); CHECK(expected);
        snprintf(expected, len, "{\"refreshToken\":\"%s\",\"clientId\":\"%s\",\"tenantId\":\"%s\"}", token, client, tenant);
        CHECK(result->raw_v2.len == strlen(expected) && !memcmp(result->raw_v2.data, expected, strlen(expected)));
        free(expected);
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

typedef struct {
    bool post;
    const char *tenant, *client, *token, *send_error;
    br_http_response response;
} step;
typedef struct { step steps[32]; br_header tags[32]; size_t count, calls, releases; bool released[32]; } fake_http;

static step discovery(const char *tenant, int status)
{
    return (step){.tenant = tenant, .response = {.status = status,
        .body = {(const unsigned char *)"ignored discovery body", 22}, .body_error = "ignored discovery drain error"}};
}

static step exchange(const char *tenant, const char *client, const char *token, int status, const char *body)
{
    return (step){.post = true, .tenant = tenant, .client = client, .token = token,
        .response = {.status = status, .body = {(const unsigned char *)body, strlen(body)}}};
}

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static int send_fake(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    fake_http *fake = user;
    size_t at = fake->calls++;
    CHECK(ctx && at < fake->count && at < 32);
    step *expected = &fake->steps[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1013 && request->timeout_ms == 5000);
    CHECK(!request->dedup_key.len); /* Refresh POSTs are never coalesced. */
    CHECK(!strcmp(request->method, expected->post ? "POST" : "GET"));
    char url[256];
    snprintf(url, sizeof(url), "https://login.microsoftonline.com/%s/%s", expected->tenant,
             expected->post ? "oauth2/v2.0/token" : ".well-known/openid-configuration");
    CHECK(!strcmp(request->url, url));
    CHECK(request->nheaders == (expected->post ? 2u : 1u));
    CHECK(!strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Authorization") && !header(request, "Accept"));
    if (expected->post) {
        CHECK(!strcmp(header(request, "Content-Type"), "application/x-www-form-urlencoded"));
        size_t len = strlen(expected->token) + strlen(expected->client) + 160;
        char *body = malloc(len); CHECK(body);
        snprintf(body, len, "client_id=%s&grant_type=refresh_token&refresh_token=%s&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default", expected->client, expected->token);
        CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, strlen(body)));
        free(body);
    } else CHECK(!request->body.len && !request->body.data);
    CHECK(fake->releases == at); /* Every prior response is drained/released. */
    *response = expected->response;
    response->headers = &fake->tags[at]; response->nheaders = 1;
    *error = expected->send_error ? strdup(expected->send_error) : NULL;
    CHECK(!expected->send_error || *error);
    return expected->send_error ? -1 : 0;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user;
    size_t at = 0;
    while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]);
    fake->released[at] = true; ++fake->releases;
}

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake};
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(fake->calls == fake->count && fake->releases == fake->calls);
    return results;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_entra_refreshtoken_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Azure refresh token detector output")); free(error); error = NULL;
    CHECK(!br_azure_entra_refreshtoken_init(&detector, &error) && detector && !error);
    CHECK(!br_azure_entra_refreshtoken_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1013 && detector->version == 0 && !strcmp(detector->name, "AzureRefreshToken"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Azure Entra ID refresh tokens provide long-lasting access to an account."));
    CHECK(detector->max_secret_size == 2048 && detector->start_offset == 4096 && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "0.A") && !strcmp(detector->keywords[1], "1.A"));
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void extraction(const br_detector *detector)
{
    fake_http fake = {0};
    br_results results = scan(detector, token1, false, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && !results.items[0].extra_data);
    check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results);
    char *input = input_for(token1, client1, "CasePreserved.onmicrosoft.com");
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], token1, client1, "CasePreserved.onmicrosoft.com"); br_results_clear(&results); free(input);
    input = input_for(token1, "13579BDF-2468-4ACE-9BDF-13579BDF2468", "31415926-5358-4979-8238-462643383279");
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], token1, client1, "31415926-5358-4979-8238-462643383279"); br_results_clear(&results); free(input);
    input = input_for(token1, "12345678-1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abc");
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results); free(input);
    input = input_for(token1, office, "synthetic-default.onmicrosoft.com");
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results); free(input);
    input = input_for(token1, client1, NULL);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results); free(input);

    size_t len = strlen(token1) * 2 + strlen(token2) + 512;
    input = malloc(len); CHECK(input);
    snprintf(input, len, "%s\n%s\n%s\nclient_id=%s\nclient_id=%s\ntenant=first.onmicrosoft.com\ntenant=second.onmicrosoft.com", token1, token1, token2, client1, client2);
    results = scan(detector, input, false, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], token1, NULL, NULL); check_result(&results.items[1], token2, NULL, NULL);
    br_results_clear(&results); free(input);
    char *short_first = make_token(49, 250, false, 0, 3), *short_second = make_token(50, 249, false, 0, 3);
    const char *bad[] = {"", "synthetic-token", short_first, short_second};
    for (size_t i = 0; i < 4; ++i) { results = scan(detector, bad[i], false, &fake); CHECK(!results.len); br_results_clear(&results); }
    free(short_first); free(short_second);
    input = strdup(token1); CHECK(input); input[0] = '2';
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    input[0] = '0'; input[2] = 'a';
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results); free(input);
    len = strlen(token1) + 2; input = malloc(len); CHECK(input); snprintf(input, len, "x%s", token1);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results); free(input);
    input = make_token(50, 250, false, 0, 3);
    for (size_t i = 3; input[i]; ++i) if (input[i] != '.') input[i] = 'x';
    char *ag = strchr(input + 3, '.'); CHECK(ag); ag[1] = 'A'; ag[2] = 'g';
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results); free(input);
    /* The optional tail can fail while the core still matches a prefix. */
    char *core = make_token(50, 250, false, 0, 3), *short_tail = make_token(50, 250, false, 199, 3);
    results = scan(detector, short_tail, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], core, NULL, NULL); br_results_clear(&results); free(core); free(short_tail);
}

static void typed_http(const br_detector *detector)
{
    const struct { int status; const char *body, *read_error, *error, *scope; bool verified; } cases[] = {
        {200, "{}", NULL, NULL, "", true}, {200, "null", NULL, NULL, "", true},
        {200, "{\"scope\":\"old\",\"SCOPE\":\"new\",\"scope\":null,\"access_token\":null} trailing", NULL, NULL, "new", true},
        {200, "{\"ignored\":1e9999}", NULL, NULL, "", true},
        {200, "{\"scope\":\"s\"}", "late read error", NULL, "s", true},
        {200, "", NULL, "EOF", NULL, false},
        {200, "{", "synthetic read error", "synthetic read error", NULL, false},
        {200, "[]", NULL, "json: cannot unmarshal array into Go value of type refreshtoken.successResponse", NULL, false},
        {200, "{\"scope\":1}", NULL, "json: cannot unmarshal number into Go struct field successResponse.scope of type string", NULL, false},
        {200, "{\"access_token\":true}", NULL, "json: cannot unmarshal bool into Go struct field successResponse.access_token of type string", NULL, false},
        {401, "{", NULL, "unexpected EOF", NULL, false},
        {401, "{\"error\":1}", NULL, "json: cannot unmarshal number into Go struct field errorResponse.error of type string", NULL, false},
        {401, "{\"error_description\":[]}", NULL, "json: cannot unmarshal array into Go struct field errorResponse.error_description of type string", NULL, false},
        {401, "{}", NULL, NULL, NULL, false},
        {400, "{\"error\":\"synthetic\",\"error_description\":\"denial\"}", NULL, "unexpected error 'synthetic': denial", NULL, false},
        {400, "null", NULL, "unexpected error '': ", NULL, false},
        {400, "{\"error_description\":\"aadsts70008: lower-case is unexpected\"}", NULL, "unexpected error '': aadsts70008: lower-case is unexpected", NULL, false},
        {500, "", NULL, "EOF", NULL, false},
        {500, "{}", NULL, "unexpected HTTP response status 500", NULL, false},
        {201, "{}", NULL, "unexpected HTTP response status 201", NULL, false},
        {403, "{}", "ignored late read error", "unexpected HTTP response status 403", NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char tenant[80]; fresh_tenant(tenant);
        char *input = input_for(token1, client1, tenant);
        fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200);
        fake.steps[1] = exchange(tenant, client1, token1, cases[i].status, cases[i].body);
        fake.steps[1].response.body_error = cases[i].read_error;
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        check_result(&results.items[0], token1, client1, tenant);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].verified) {
            CHECK(json_object_object_length(results.items[0].extra_data) == 3);
            check_text(results.items[0].extra_data, "Tenant", tenant); check_text(results.items[0].extra_data, "Client", client1);
            check_text(results.items[0].extra_data, "Scope", cases[i].scope);
        } else CHECK(!results.items[0].extra_data);
        br_results_clear(&results); free(input);
    }
    /* Defaults are retained for a verified actual pair, unlike fallback. */
    fake_http fake = {.count = 2}; fake.steps[0] = discovery("common", 200);
    fake.steps[1] = exchange("common", office, token1, 200, "{}");
    br_results results = scan(detector, token1, true, &fake);
    CHECK(results.len == 1 && results.items[0].verified); check_result(&results.items[0], token1, office, "common");
    br_results_clear(&results);
}

static void sentinel_and_cross_token_state(const br_detector *detector)
{
    char a[80], b[80]; fresh_tenant(a); fresh_tenant(b);
    size_t len = strlen(token1) + strlen(token2) + 512;
    char *input = malloc(len); CHECK(input);
    /* Known-invalid client/tenant pairs survive across refresh tokens, but the
     * original client count still controls confidence. */
    snprintf(input, len, "%s\n%s\nclient_id=%s\nclient_id=%s\ntenant=%s", token1, token2, client1, client2, a);
    fake_http fake = {.count = 4}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, token1, 400, "{\"error_description\":\"AADSTS700016: missing app\"}");
    fake.steps[2] = exchange(a, client2, token1, 400, "{\"error_description\":\"AADSTS9002313: invalid token\"}");
    fake.steps[3] = exchange(a, client2, token2, 401, "{}");
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    for (size_t i = 0; i < 2; ++i) { CHECK(!results.items[i].verified && !results.items[i].verification_error); check_result(&results.items[i], i ? token2 : token1, NULL, NULL); }
    br_results_clear(&results);
    /* Invalid for tenant A does not remove client1 from tenant B. */
    fresh_tenant(a); fresh_tenant(b);
    snprintf(input, len, "%s\n%s\nclient_id=%s\nclient_id=%s\ntenant=%s\ntenant=%s", token1, token2, client1, client2, a, b);
    fake = (fake_http){.count = 5}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, token1, 400, "{\"error_description\":\"AADSTS700016: missing app\"}");
    fake.steps[2] = discovery(b, 200); fake.steps[3] = exchange(b, client1, token1, 200, "{}");
    fake.steps[4] = exchange(b, client1, token2, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    for (size_t i = 0; i < 2; ++i) { CHECK(results.items[i].verified); check_result(&results.items[i], i ? token2 : token1, client1, b); }
    br_results_clear(&results);
    const char *sentinels[] = {"AADSTS70008:", "AADSTS700082:", "AADSTS70043:", "AADSTS50173:"};
    for (size_t i = 0; i < 4; ++i) {
        fresh_tenant(a); char body[128]; snprintf(body, sizeof(body), "{\"error_description\":\"%s synthetic\"}", sentinels[i]);
        snprintf(input, len, "%s\nclient_id=%s\nclient_id=%s\ntenant=%s", token1, client1, client2, a);
        fake = (fake_http){.count = 2}; fake.steps[0] = discovery(a, 200); fake.steps[1] = exchange(a, client1, token1, 400, body);
        results = scan(detector, input, true, &fake); CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
        check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results);
    }
    /* Unexpected errors retain the attempted pair even with multiple clients. */
    fresh_tenant(a); snprintf(input, len, "%s\nclient_id=%s\nclient_id=%s\ntenant=%s", token1, client1, client2, a);
    fake = (fake_http){.count = 2}; fake.steps[0] = discovery(a, 200); fake.steps[1] = exchange(a, client1, token1, 500, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verification_error);
    check_result(&results.items[0], token1, client1, a); br_results_clear(&results); free(input);
}

static void tenant_deletion_and_cache(const br_detector *detector)
{
    char a[80], b[80]; fresh_tenant(a); fresh_tenant(b);
    size_t len = strlen(token1) + strlen(token2) + 512;
    char *input = malloc(len); CHECK(input);
    snprintf(input, len, "%s\n%s\nclient_id=%s\ntenant=%s\ntenant=%s", token1, token2, client1, a, b);
    fake_http fake = {.count = 4}; fake.steps[0] = discovery(a, 200); fake.steps[1] = exchange(a, client1, token1, 401, "{}");
    fake.steps[2] = discovery(b, 400); fake.steps[3] = exchange(a, client1, token2, 401, "{}");
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    /* Source uses LAST assigned tenant B, even though B was just deleted and
     * A is the sole survivor. A later token visits only A. */
    check_result(&results.items[0], token1, client1, b); check_result(&results.items[1], token2, client1, a);
    br_results_clear(&results);
    fresh_tenant(a); snprintf(input, len, "%s\n%s\nclient_id=%s\ntenant=%s", token1, token2, client1, a);
    fake = (fake_http){.count = 1}; fake.steps[0] = discovery(a, 400);
    results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], token1, NULL, NULL); check_result(&results.items[1], token2, NULL, NULL); br_results_clear(&results);
    /* Discovery false is cached across scans, and still yields a finding. */
    fake = (fake_http){0}; results = scan(detector, input, true, &fake); CHECK(results.len == 2); br_results_clear(&results);
    fresh_tenant(a); fresh_tenant(b);
    snprintf(input, len, "%s\n%s\nclient_id=%s\ntenant=%s\ntenant=%s", token1, token2, client1, a, b);
    fake = (fake_http){.count = 5}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, token1, 400, "{\"error_description\":\"AADSTS90002: missing tenant\"}");
    fake.steps[2] = discovery(b, 200); fake.steps[3] = exchange(b, client1, token1, 200, "{}");
    fake.steps[4] = exchange(b, client1, token2, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    check_result(&results.items[0], token1, client1, b); check_result(&results.items[1], token2, client1, b); br_results_clear(&results);
    /* POST tenant deletion must not poison the globally cached GET=true. */
    char *one = input_for(token1, client1, a);
    fake = (fake_http){.count = 1}; fake.steps[0] = exchange(a, client1, token1, 200, "{}");
    results = scan(detector, one, true, &fake); CHECK(results.len == 1 && results.items[0].verified); br_results_clear(&results); free(one);
    fresh_tenant(a); one = input_for(token1, client1, a);
    fake = (fake_http){.count = 1}; fake.steps[0] = discovery(a, 0); fake.steps[0].send_error = "synthetic discovery transport error";
    results = scan(detector, one, true, &fake); CHECK(results.len == 1 && !results.items[0].verification_error);
    check_result(&results.items[0], token1, NULL, NULL); br_results_clear(&results); free(one); free(input);
}

static char *encode(const char *json)
{
    size_t len = strlen(json), cap = 4 * ((len + 2) / 3) + 1;
    unsigned char *out = malloc(cap); CHECK(out && len <= INT_MAX);
    int count = EVP_EncodeBlock(out, (const unsigned char *)json, (int)len); CHECK(count >= 0);
    while (count && out[count - 1] == '=') --count;
    out[count] = '\0';
    for (int i = 0; i < count; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    return (char *)out;
}

static char *jwt(const char *header_json, const char *claim_json, const char *signature)
{
    char *h = encode(header_json), *c = encode(claim_json);
    size_t len = strlen(h) + strlen(c) + strlen(signature) + 3;
    char *out = malloc(len); CHECK(out); snprintf(out, len, "%s.%s.%s", h, c, signature); free(h); free(c);
    return out;
}

static char *success_body(const char *access)
{
    br_json *object = json_object_new_object(); CHECK(object);
    CHECK(!json_object_object_add(object, "scope", json_object_new_string("synthetic-scope")));
    CHECK(!json_object_object_add(object, "access_token", json_object_new_string(access)));
    char *out = strdup(json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN)); CHECK(out);
    json_object_put(object); return out;
}

static void jwt_projection(const br_detector *detector)
{
    const struct { const char *header, *claims, *signature, *app, *user; } cases[] = {
        {"{\"alg\":\"HS256\"}", "{}", "", "<nil>", NULL},
        {"{\"alg\":\"HS256\"}", "{}", "@invalid-signature", "<nil>", NULL},
        {"{\"alg\":\"synthetic-unknown\"}", "{\"app_displayname\":\"synthetic-app\",\"email\":\"synthetic-email\",\"upn\":\"ignored\",\"exp\":0,\"nbf\":9999999999}", "@invalid-signature", "synthetic-app", "synthetic-email"},
        {"null", "null", "", "<nil>", NULL},
        {"{}", "{\"app_displayname\":false,\"email\":false,\"upn\":\"ignored\"}", "", "false", "false"},
        {"{}", "{\"app_displayname\":\"\",\"email\":null,\"upn\":\"synthetic-upn\",\"unique_name\":true}", "", NULL, "synthetic-upn"},
        {"{}", "{\"unique_name\":\"synthetic-user\"}", "", "<nil>", NULL},
        {"{}", "{\"unique_name\":true}", "", "<nil>", "true"},
        {"{}", "{\"app_displayname\":\"kept\",\"ignored\":1e9999,\"unique_name\":true}", "", "kept", "true"},
        {"{}", "{\"app_displayname\":\"old\",\"app_displayname\":1e9999,\"email\":1e9999,\"upn\":\"fallback\"}", "", "<nil>", "fallback"},
        {"{}", "{\"email\":\"old\",\"email\":null,\"upn\":\"fallback\"}", "", "<nil>", "fallback"},
        {"{}", "{", "", "<nil>", NULL},
        {"{}", "[\"synthetic\"]", "", "<nil>", NULL},
        {"{}", "{\"unique_name\":[true]}", "", "<nil>", NULL},
        {"{}", "{\"email\":\"kept\",\"upn\":[\"unused\"]}", "", "<nil>", "kept"},
        {"{}", "{\"APP_DISPLAYNAME\":\"ignored\",\"EMAIL\":\"ignored\"}", "", "<nil>", NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char tenant[80]; fresh_tenant(tenant);
        char *access = jwt(cases[i].header, cases[i].claims, cases[i].signature), *body = success_body(access);
        char *input = input_for(token1, client1, tenant);
        fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, token1, 200, body);
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
        CHECK(json_object_object_length(results.items[0].extra_data) == 3 + (cases[i].app != NULL) + (cases[i].user != NULL));
        if (cases[i].app) check_text(results.items[0].extra_data, "Application", cases[i].app);
        else CHECK(!json_object_object_get_ex(results.items[0].extra_data, "Application", NULL));
        if (cases[i].user) check_text(results.items[0].extra_data, "User", cases[i].user);
        else CHECK(!json_object_object_get_ex(results.items[0].extra_data, "User", NULL));
        br_results_clear(&results); free(input); free(body); free(access);
    }
    const char *tokens[] = {"synthetic.two", "e30.@@@.", "e30.e30.@signature-error", "e30.e30..extra"};
    for (size_t i = 0; i < 4; ++i) {
        char tenant[80]; fresh_tenant(tenant);
        char *body = success_body(tokens[i]), *input = input_for(token1, client1, tenant);
        fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, token1, 200, body);
        br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
        if (i == 1 || i == 2) check_text(results.items[0].extra_data, "Application", "<nil>");
        else CHECK(!json_object_object_get_ex(results.items[0].extra_data, "Application", NULL));
        br_results_clear(&results); free(body); free(input);
    }
}

static void panic_guards_and_rollback(const br_detector *detector)
{
    char *bad_header = jwt("[]", "{}", ""), *bad_header_json = jwt("{", "{}", "");
    char *overflow_header = jwt("{\"ignored\":1e9999}", "{}", "");
    char *complex = jwt("{}", "{\"app_displayname\":[\"not JSON formatting\"]}", "");
    char *numeric = jwt("{}", "{\"email\":123}", "");
    const char *accesses[] = {"@@.e30.", "e30=.e30.", bad_header, bad_header_json, overflow_header, complex, numeric};
    for (size_t i = 0; i < sizeof(accesses) / sizeof(accesses[0]); ++i) {
        char tenant[80]; fresh_tenant(tenant);
        char *body = success_body(accesses[i]);
        size_t len = strlen(token1) + strlen(token2) + 200;
        char *input = malloc(len); CHECK(input);
        snprintf(input, len, "%s\n%s\nclient_id=%s\ntenant=%s", token1, token2, client1, tenant);
        fake_http fake = {.count = 3}; fake.steps[0] = discovery(tenant, 200);
        fake.steps[1] = exchange(tenant, client1, token1, 200, "{}"); fake.steps[2] = exchange(tenant, client1, token2, 200, body);
        br_transport transport = {&fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport};
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data;
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && strstr(error, i < 5 ? "unsupported upstream panic: Azure refresh JWT Claims is nil" : "unsupported: Azure refresh JWT claim formatting"));
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
        CHECK(fake.calls == 3 && fake.releases == 3);
        free(error); br_results_clear(&results); free(input); free(body);
    }
    free(bad_header); free(bad_header_json); free(overflow_header); free(complex); free(numeric);
}

static void redaction_and_unbounded(const br_detector *detector)
{
    char tenant[80]; fresh_tenant(tenant);
    char *input = input_for(token1, client1, tenant);
    size_t len = strlen(token1) + 256;
    char *failure = malloc(len), *expected = malloc(len); CHECK(failure && expected);
    snprintf(failure, len, "synthetic transport %s %s %s", token1, client1, tenant);
    snprintf(expected, len, "synthetic transport [REDACTED] %s %s", client1, tenant);
    fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, token1, 0, ""); fake.steps[1].send_error = failure;
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, expected)); check_result(&results.items[0], token1, client1, tenant);
    br_results_clear(&results); free(input); free(failure); free(expected);
    char *long_token = make_token(80, 5000, true, 230, 21); CHECK(strlen(long_token) > 2048);
    fresh_tenant(tenant); input = input_for(long_token, client1, tenant);
    fake = (fake_http){.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, long_token, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_result(&results.items[0], long_token, client1, tenant);
    br_results_clear(&results); free(input); free(long_token);
}

int main(void)
{
    token1 = make_token(50, 250, false, 0, 3); token2 = make_token(70, 300, true, 200, 8);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)token1, strlen(token1)}) >= 4.0);
    const br_detector *detector = init();
    extraction(detector); typed_http(detector); sentinel_and_cross_token_state(detector);
    tenant_deletion_and_cache(detector); jwt_projection(detector);
    panic_guards_and_rollback(detector); redaction_and_unbounded(detector);
    free(token1); free(token2);
    return test_finish("Azure Entra refresh token state + typed HTTP + pinned JWT projection");
}
