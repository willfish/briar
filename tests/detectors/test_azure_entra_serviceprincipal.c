/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <openssl/evp.h>
#include <strings.h>
#include <time.h>

static const char client1[] = "13579bdf-2468-4ace-9bdf-13579bdf2468";
static const char client2[] = "2468ace0-1357-4bdf-8ace-2468ace01357";
static const char legacy1[] = "SyntheticLegacySecret_1234567890AB";
static const char punctuated[] = "!#$%&()*+,-./:;<=>?@[\\]^_{|}~AB12";
/* Independent Python urllib.parse.quote_plus golden for the synthetic v1 key. */
static const char escaped_punctuation[] = "%21%23%24%25%26%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%7B%7C%7D~AB12";
static char modern1[41], modern2[41];
static unsigned tenant_counter, uuid_counter;
static time_t wall_time = 1700000000;
/* Process-local cache clock only: one targeted expiry proves discovery is
 * consulted for EVERY eligible pair. No production hooks or live HTTP. */
int timespec_get(struct timespec *out, int base)
{
    if (base != TIME_UTC) return 0;
    *out = (struct timespec){wall_time, 0};
    return TIME_UTC;
}

static void make_modern(char *out, size_t tail, unsigned shift)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.-";
    CHECK(tail >= 30 && tail <= 35);
    memcpy(out, shift & 1 ? "abc1Q~" : "xyz2Q~", 6);
    for (size_t i = 0; i < tail; ++i) out[6 + i] = alphabet[(i * 17 + shift) % (sizeof(alphabet) - 1)];
    out[6 + tail] = '\0';
}

static void tenant_name(char out[80])
{
    snprintf(out, 80, "synthetic-sp-%u.onmicrosoft.com", ++tenant_counter);
}

static void unique_uuid(char out[37])
{
    snprintf(out, 37, "%08x-2468-4ace-9bdf-13579bdf2468", 0xa1395700u + ++uuid_counter);
}

static char *input_for(const br_detector *detector, const char *first, const char *second,
                         const char *c1, const char *c2, const char *t1, const char *t2)
{
    char *out = malloc(2048); CHECK(out);
    size_t at = 0;
    const char *secrets[] = {first, second};
    for (size_t i = 0; i < 2; ++i) {
        if (!secrets[i]) continue;
        /* Modern matches consume their trailing delimiter; leave another
         * delimiter available to begin the next synthetic secret match. */
        at += (size_t)snprintf(out + at, 2048 - at, detector->version == 1 ? "secret='%s'\n" : "%s\n\n", secrets[i]);
    }
    const char *clients[] = {c1, c2}, *tenants[] = {t1, t2};
    for (size_t i = 0; i < 2; ++i) if (clients[i]) at += (size_t)snprintf(out + at, 2048 - at, "client_id=%s\n", clients[i]);
    for (size_t i = 0; i < 2; ++i) if (tenants[i]) at += (size_t)snprintf(out + at, 2048 - at, "tenant_id=%s\n", tenants[i]);
    CHECK(at < 2048);
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

static void check_result(const br_result *result, const char *secret, const char *client, const char *tenant)
{
    CHECK(result->detector_type == 3 && !result->detector_name);
    CHECK(result->raw.len == strlen(secret) && !memcmp(result->raw.data, secret, strlen(secret)));
    char redacted[9]; memcpy(redacted, secret, 5); memcpy(redacted + 5, "...", 4);
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    check_text(result->secret_parts, "key", secret);
    if (client && tenant) {
        char expected[512];
        snprintf(expected, sizeof(expected), "{\"clientSecret\":\"%s\",\"clientId\":\"%s\",\"tenantId\":\"%s\"}", secret, client, tenant);
        CHECK(result->raw_v2.len == strlen(expected) && !memcmp(result->raw_v2.data, expected, strlen(expected)));
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

typedef struct {
    bool post, expire_after;
    const char *tenant, *client, *secret, *encoded, *send_error;
    br_http_response response;
} step;
typedef struct { step steps[24]; br_header tags[24]; size_t count, calls, releases; bool released[24]; } fake_http;

static step discovery(const char *tenant, int status)
{
    return (step){.tenant = tenant, .response = {.status = status,
        .body = {(const unsigned char *)"ignored discovery body", 22}, .body_error = "ignored discovery drain failure"}};
}

static step exchange(const char *tenant, const char *client, const char *secret, int status, const char *body)
{
    return (step){.post = true, .tenant = tenant, .client = client, .secret = secret,
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
    CHECK(ctx && at < fake->count && at < 24);
    step *expected = &fake->steps[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 3 && request->timeout_ms == 5000);
    CHECK(!request->dedup_key.len && !strcmp(request->method, expected->post ? "POST" : "GET"));
    char url[256]; snprintf(url, sizeof(url), "https://login.microsoftonline.com/%s/%s", expected->tenant,
                           expected->post ? "oauth2/v2.0/token" : ".well-known/openid-configuration");
    CHECK(!strcmp(request->url, url));
    CHECK(request->nheaders == (expected->post ? 4u : 1u) && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Authorization"));
    if (expected->post) {
        CHECK(!strcmp(header(request, "Accept"), "application/json"));
        CHECK(!strcmp(header(request, "Content-Type"), "application/x-www-form-urlencoded"));
        char body[512], length[32];
        snprintf(body, sizeof(body), "client_id=%s&client_secret=%s&grant_type=client_credentials&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default",
                 expected->client, expected->encoded ? expected->encoded : expected->secret);
        snprintf(length, sizeof(length), "%zu", strlen(body));
        CHECK(!strcmp(header(request, "Content-Length"), length));
        CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, strlen(body)));
    } else CHECK(!request->body.data && !request->body.len && !header(request, "Accept"));
    CHECK(fake->releases == at);
    *response = expected->response; response->headers = &fake->tags[at]; response->nheaders = 1;
    *error = expected->send_error ? strdup(expected->send_error) : NULL;
    CHECK(!expected->send_error || *error);
    if (expected->expire_after) wall_time += 13 * 60 * 60;
    return expected->send_error ? -1 : 0;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user;
    size_t at = 0;
    while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]); fake->released[at] = true; ++fake->releases;
}

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    if (fake->calls != fake->count || fake->releases != fake->calls)
        fprintf(stderr, "v%d fixture %s: expected=%zu calls=%zu releases=%zu results=%zu\n", detector->version,
                fake->count ? fake->steps[0].tenant : "no-I/O", fake->count, fake->calls, fake->releases, results.len);
    CHECK(fake->calls == fake->count && fake->releases == fake->calls);
    return results;
}

static void init(const br_detector **v1, const br_detector **v2)
{
    char *error = NULL; const br_detector *again = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_entra_serviceprincipal_v1_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_azure_entra_serviceprincipal_v2_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(!br_azure_entra_serviceprincipal_v1_init(v1, &error) && *v1 && !error);
    CHECK(!br_azure_entra_serviceprincipal_v2_init(v2, &error) && *v2 && !error);
    CHECK(!br_azure_entra_serviceprincipal_v1_init(&again, &error) && again == *v1 && !error);
    CHECK(!br_azure_entra_serviceprincipal_v2_init(&again, &error) && again == *v2 && !error);
    CHECK(*v1 != *v2 && (*v1)->scan == (*v2)->scan);
    const br_detector *detectors[] = {*v1, *v2};
    for (size_t i = 0; i < 2; ++i) {
        const br_detector *d = detectors[i];
        CHECK(d->type == 3 && d->version == (int32_t)i + 1 && !strcmp(d->name, "Azure") && !strcmp(d->custom_name, ""));
        CHECK(!strcmp(d->description, "Azure is a cloud service offering a wide range of services including compute, analytics, storage, and networking. Azure credentials can be used to access and manage these services."));
        CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
        CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
        CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    }
    const char *keywords[] = {"azure", "az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"};
    CHECK((*v1)->nkeywords == 6 && (*v2)->nkeywords == 1 && !strcmp((*v2)->keywords[0], "q~"));
    for (size_t i = 0; i < 6; ++i) CHECK(!strcmp((*v1)->keywords[i], keywords[i]));
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    fake_http fake = {0}; br_results results = scan(v2, modern1, false, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && !results.items[0].extra_data);
    check_result(&results.items[0], modern1, NULL, NULL); br_results_clear(&results);
    char *input = input_for(v1, legacy1, NULL, NULL, NULL, NULL, NULL);
    results = scan(v1, input, false, &fake); CHECK(!results.len); br_results_clear(&results); free(input);
    input = input_for(v1, punctuated, NULL, client1, NULL, "CasePreserved.onmicrosoft.com", NULL);
    results = scan(v1, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], punctuated, client1, "CasePreserved.onmicrosoft.com");
    CHECK(memchr(results.items[0].raw_v2.data, '\\', results.items[0].raw_v2.len)); br_results_clear(&results); free(input);
    input = input_for(v1, modern1, NULL, client1, NULL, NULL, NULL);
    results = scan(v1, input, false, &fake); CHECK(!results.len); br_results_clear(&results); free(input);
    input = input_for(v1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NULL, client1, NULL, NULL, NULL);
    results = scan(v1, input, false, &fake); CHECK(results.len == 1); br_results_clear(&results); free(input);
    char low[38]; memcpy(low, "aaa0Q~", 6); memset(low + 6, 'a', 31); low[37] = '\0';
    results = scan(v2, low, false, &fake); CHECK(results.len == 1); br_results_clear(&results);
    for (size_t tail = 30; tail <= 35; ++tail) {
        char value[42]; make_modern(value, tail, 3);
        results = scan(v2, value, false, &fake); CHECK(results.len == (tail >= 31 && tail <= 34 ? 1u : 0u)); br_results_clear(&results);
    }
    char value[42]; make_modern(value, 31, 3); value[4] = 'q';
    results = scan(v2, value, false, &fake); CHECK(!results.len); br_results_clear(&results);
    char text[512]; snprintf(text, sizeof(text), "X%s", modern1);
    results = scan(v2, text, false, &fake); CHECK(!results.len); br_results_clear(&results);
    snprintf(text, sizeof(text), "%s!%s", modern1, modern2);
    results = scan(v2, text, false, &fake); CHECK(results.len == 1); br_results_clear(&results);
    snprintf(text, sizeof(text), "%s!!%s", modern1, modern2);
    results = scan(v2, text, false, &fake); CHECK(results.len == 2); br_results_clear(&results);
    input = input_for(v2, modern1, modern1, client1, client2, "first.onmicrosoft.com", "second.onmicrosoft.com");
    results = scan(v2, input, false, &fake); CHECK(results.len == 1); check_result(&results.items[0], modern1, NULL, NULL); br_results_clear(&results); free(input);
    for (size_t padding = 80; padding <= 81; ++padding) {
        size_t at = 0; memcpy(text, "password", 8); at += 8; memset(text + at, 'X', padding); at += padding;
        snprintf(text + at, sizeof(text) - at, " %s\"\nclient_id=%s", legacy1, client1);
        results = scan(v1, text, false, &fake); CHECK(results.len == (padding == 80 ? 1u : 0u)); br_results_clear(&results);
    }
    snprintf(text, sizeof(text), "client_id=%s\nsecret %s", client1, legacy1);
    results = scan(v1, text, false, &fake); CHECK(!results.len); br_results_clear(&results); /* No EOF delimiter in v1. */
    input = input_for(v2, modern1, NULL, "12345678-1234-1234-1234-123456789abc", NULL, "12345678-1234-1234-1234-123456789abc", NULL);
    results = scan(v2, input, false, &fake); CHECK(results.len == 1); check_result(&results.items[0], modern1, NULL, NULL); br_results_clear(&results); free(input);
}

static void typed_http_and_wire(const br_detector *detector, const char *secret)
{
    const struct { int status; const char *body, *read_error, *error; bool verified; } cases[] = {
        {200, "{}", NULL, NULL, true}, {200, "null", NULL, NULL, true},
        {200, "{\"scope\":1,\"access_token\":null,\"ignored\":1e9999} trailing", NULL, NULL, true},
        {200, "{}", "late read failure", NULL, true},
        {200, "", NULL, "EOF", false},
        {200, "{", "synthetic read failure", "synthetic read failure", false},
        {200, "[]", NULL, "json: cannot unmarshal array into Go value of type serviceprincipal.TokenOkResponse", false},
        {200, "{\"access_token\":1}", NULL, "json: cannot unmarshal number into Go struct field TokenOkResponse.access_token of type string", false},
        {401, "{", NULL, "unexpected EOF", false},
        {401, "{\"error\":true}", NULL, "json: cannot unmarshal bool into Go struct field TokenErrResponse.error of type string", false},
        {400, "{\"error_description\":[]}", NULL, "json: cannot unmarshal array into Go struct field TokenErrResponse.error_description of type string", false},
        {401, "{}", NULL, "unexpected error '': ", false},
        {401, "{\"error_description\":\"AADSTS53003: denied\"}", NULL, "access blocked by Conditional Access policies (AADSTS53003)", false},
        {400, "{\"error\":\"synthetic\",\"error_description\":\"unknown\"}", NULL, "unexpected error 'synthetic': unknown", false},
        {400, "{\"error_description\":\"aadsts7000222: lower case\"}", NULL, "unexpected error '': aadsts7000222: lower case", false},
        {500, "", NULL, "EOF", false},
        {500, "{}", NULL, "unexpected HTTP response status 500", false},
        {201, "{}", NULL, "unexpected HTTP response status 201", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char tenant[80]; tenant_name(tenant);
        char *input = input_for(detector, secret, NULL, client1, NULL, tenant, NULL);
        fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200);
        fake.steps[1] = exchange(tenant, client1, secret, cases[i].status, cases[i].body);
        if (detector->version == 1) fake.steps[1].encoded = escaped_punctuation;
        fake.steps[1].response.body_error = cases[i].read_error;
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        check_result(&results.items[0], secret, client1, tenant);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].verified) {
            CHECK(json_object_object_length(results.items[0].extra_data) == 3);
            check_text(results.items[0].extra_data, "tenant", tenant); check_text(results.items[0].extra_data, "client", client1);
            check_text(results.items[0].extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/azure/");
        } else CHECK(!results.items[0].extra_data);
        br_results_clear(&results); free(input);
    }
}

static void mutable_clients(const br_detector *detector)
{
    char tenant[37]; unique_uuid(tenant);
    char *input = input_for(detector, modern1, modern2, tenant, client2, tenant, NULL);
    fake_http fake = {.count = 3}; fake.steps[0] = discovery(tenant, 200);
    fake.steps[1] = exchange(tenant, tenant, modern1, 500, "{}");
    fake.steps[2] = exchange(tenant, client2, modern2, 200, "{}");
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    /* Live count drops from two to one before the error, but the CURRENT,
     * just-deleted client is still attempted and is the emitted actual pair. */
    check_result(&results.items[0], modern1, tenant, tenant);
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    check_result(&results.items[1], modern2, client2, tenant); CHECK(results.items[1].verified);
    br_results_clear(&results); free(input);
    for (size_t expired = 0; expired < 2; ++expired) {
        unique_uuid(tenant); input = input_for(detector, modern1, modern2, tenant, NULL, tenant, NULL);
        fake = (fake_http){.count = 2}; fake.steps[0] = discovery(tenant, 200);
        fake.steps[1] = exchange(tenant, tenant, modern1, expired ? 401 : 200,
                               expired ? "{\"error_description\":\"AADSTS7000222: expired\"}" : "{}");
        results = scan(detector, input, true, &fake); CHECK(results.len == 2);
        CHECK(results.items[0].verified == !expired && !results.items[0].verification_error);
        check_result(&results.items[0], modern1, tenant, tenant);
        /* All clients were deleted, but the second unique secret still emits. */
        check_result(&results.items[1], modern2, NULL, NULL);
        CHECK(!results.items[1].verified && !results.items[1].verification_error);
        br_results_clear(&results); free(input);
    }
}

static void invalid_expired_and_unknown(const br_detector *detector)
{
    char a[80], b[80]; tenant_name(a); tenant_name(b);
    char *input = input_for(detector, modern1, modern2, client1, client2, a, b);
    fake_http fake = {.count = 4}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, modern1, 401, "{\"error_description\":\"AADSTS7000215: invalid secret\"}");
    fake.steps[2] = exchange(a, client2, modern1, 200, "{}");
    fake.steps[3] = exchange(a, client1, modern2, 200, "{}");
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    /* Skip remaining tenants, NOT remaining clients or secrets. The invalid
     * secret response also does not mark client1 as globally invalid. */
    check_result(&results.items[0], modern1, client2, a); check_result(&results.items[1], modern2, client1, a);
    br_results_clear(&results); free(input);
    tenant_name(a); tenant_name(b); input = input_for(detector, modern1, NULL, client1, client2, a, b);
    fake = (fake_http){.count = 2}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, modern1, 400, "{\"error_description\":\"AADSTS7000222: expired\"}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_result(&results.items[0], modern1, client1, a); br_results_clear(&results); free(input);
    tenant_name(a); input = input_for(detector, modern1, modern2, client1, client2, a, NULL);
    fake = (fake_http){.count = 4}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, modern1, 400, "{\"error_description\":\"AADSTS700016: missing app\"}");
    fake.steps[2] = exchange(a, client2, modern1, 200, "{}"); fake.steps[3] = exchange(a, client2, modern2, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    check_result(&results.items[0], modern1, client2, a); check_result(&results.items[1], modern2, client2, a);
    br_results_clear(&results); free(input);
    tenant_name(a); input = input_for(detector, modern1, NULL, client1, client2, a, NULL);
    fake = (fake_http){.count = 3}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, modern1, 400, "{\"error_description\":\"AADSTS53003: denied\"}");
    fake.steps[2] = exchange(a, client2, modern1, 500, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && !results.items[0].verification_error && !results.items[0].verified);
    check_result(&results.items[0], modern1, NULL, NULL); br_results_clear(&results); free(input);
}

static void tenants_and_discovery(const br_detector *detector)
{
    char a[80], b[80]; tenant_name(a); tenant_name(b);
    char *input = input_for(detector, modern1, modern2, client1, NULL, a, b);
    fake_http fake = {.count = 4}; fake.steps[0] = discovery(a, 200); fake.steps[1] = exchange(a, client1, modern1, 500, "{}");
    fake.steps[2] = discovery(b, 400); fake.steps[3] = exchange(a, client1, modern2, 500, "{}");
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    /* The first ambiguous error is dropped; fallback retains the LAST assigned
     * tenant, even though that tenant was deleted and only A survives. */
    check_result(&results.items[0], modern1, client1, b); CHECK(!results.items[0].verification_error);
    check_result(&results.items[1], modern2, client1, a); CHECK(results.items[1].verification_error);
    br_results_clear(&results); free(input);
    tenant_name(a); input = input_for(detector, modern1, modern2, client1, NULL, a, NULL);
    fake = (fake_http){.count = 1}; fake.steps[0] = discovery(a, 400);
    results = scan(detector, input, true, &fake); CHECK(results.len == 2);
    check_result(&results.items[0], modern1, NULL, NULL); check_result(&results.items[1], modern2, NULL, NULL);
    br_results_clear(&results);
    fake = (fake_http){0}; results = scan(detector, input, true, &fake); CHECK(results.len == 2); br_results_clear(&results); free(input);
    tenant_name(a); tenant_name(b); input = input_for(detector, modern1, modern2, client1, NULL, a, b);
    fake = (fake_http){.count = 5}; fake.steps[0] = discovery(a, 200);
    fake.steps[1] = exchange(a, client1, modern1, 401, "{\"error_description\":\"AADSTS90002: missing tenant\"}");
    fake.steps[2] = discovery(b, 200); fake.steps[3] = exchange(b, client1, modern1, 200, "{}"); fake.steps[4] = exchange(b, client1, modern2, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    br_results_clear(&results); free(input);
    input = input_for(detector, modern1, NULL, client1, NULL, a, NULL);
    fake = (fake_http){.count = 1}; fake.steps[0] = exchange(a, client1, modern1, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified); br_results_clear(&results); free(input);
    /* A discovery lookup is required again after cache expiry within this same
     * invocation. A copied refresh valid-tenants bitmap would miss this GET. */
    tenant_name(a); input = input_for(detector, modern1, NULL, client1, client2, a, NULL);
    fake = (fake_http){.count = 4}; fake.steps[0] = discovery(a, 200); fake.steps[1] = exchange(a, client1, modern1, 500, "{}"); fake.steps[1].expire_after = true;
    fake.steps[2] = discovery(a, 200); fake.steps[3] = exchange(a, client2, modern1, 200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_result(&results.items[0], modern1, client2, a); br_results_clear(&results); free(input);
}

static char *encoded(const char *json)
{
    size_t len = strlen(json), cap = 4 * ((len + 2) / 3) + 1;
    unsigned char *out = malloc(cap); CHECK(out && len <= INT_MAX);
    int count = EVP_EncodeBlock(out, (const unsigned char *)json, (int)len); CHECK(count >= 0);
    while (count && out[count - 1] == '=') --count;
    out[count] = '\0';
    for (int i = 0; i < count; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    return (char *)out;
}

static char *access_token(const char *header_json, const char *claims, const char *signature)
{
    char *h = encoded(header_json), *c = encoded(claims);
    size_t len = strlen(h) + strlen(c) + strlen(signature) + 3;
    char *out = malloc(len); CHECK(out); snprintf(out, len, "%s.%s.%s", h, c, signature); free(h); free(c);
    return out;
}

static char *success_body(const char *access)
{
    br_json *object = json_object_new_object(); CHECK(object);
    CHECK(!json_object_object_add(object, "scope", json_object_new_int(123))); /* Unused typed field. */
    CHECK(!json_object_object_add(object, "access_token", json_object_new_string(access)));
    char *out = strdup(json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN)); CHECK(out); json_object_put(object);
    return out;
}

static void jwt_projection(const br_detector *detector)
{
    const struct { const char *header, *claims, *signature, *app; } cases[] = {
        {"{\"alg\":\"HS256\"}", "{}", "", NULL},
        {"{\"alg\":\"HS256\"}", "{\"app_displayname\":\"synthetic-app\",\"exp\":0,\"nbf\":9999999999}", "@bad-signature", "synthetic-app"},
        {"{\"alg\":\"synthetic-unknown\"}", "{\"app_displayname\":\"\"}", "", ""},
        {"{}", "{\"app_displayname\":false}", "", "false"},
        {"null", "null", "", NULL},
        {"{}", "{\"app_displayname\":null,\"email\":123,\"upn\":[\"unused\"],\"unique_name\":true}", "", NULL},
        {"{}", "{\"app_displayname\":\"kept\",\"ignored\":1e9999}", "", "kept"},
        {"{}", "{\"app_displayname\":\"old\",\"app_displayname\":1e9999}", "", NULL},
        {"{}", "{\"app_displayname\":\"old\",\"app_displayname\":null}", "", NULL},
        {"{}", "{", "", NULL},
        {"{}", "{\"APP_DISPLAYNAME\":\"ignored\"}", "", NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char tenant[80]; tenant_name(tenant);
        char *access = access_token(cases[i].header, cases[i].claims, cases[i].signature), *body = success_body(access);
        char *input = input_for(detector, modern1, NULL, client1, NULL, tenant, NULL);
        fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, modern1, 200, body);
        br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
        CHECK(json_object_object_length(results.items[0].extra_data) == 3 + (cases[i].app != NULL));
        CHECK(!json_object_object_get_ex(results.items[0].extra_data, "User", NULL) && !json_object_object_get_ex(results.items[0].extra_data, "Scope", NULL));
        if (cases[i].app) check_text(results.items[0].extra_data, "application", cases[i].app);
        else CHECK(!json_object_object_get_ex(results.items[0].extra_data, "application", NULL));
        br_results_clear(&results); free(access); free(body); free(input);
    }
}

static void guards_and_redaction(const br_detector *detector)
{
    char *complex = access_token("{}", "{\"app_displayname\":[\"not JSON formatting\"]}", "");
    char *numeric = access_token("{}", "{\"app_displayname\":123}", "");
    const char *bad[] = {"@@.e30.", complex, numeric};
    for (size_t i = 0; i < 3; ++i) {
        char tenant[80]; tenant_name(tenant);
        char *input = input_for(detector, modern1, modern2, client1, NULL, tenant, NULL), *body = success_body(bad[i]);
        fake_http fake = {.count = 3}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, modern1, 200, "{}"); fake.steps[2] = exchange(tenant, client1, modern2, 200, body);
        br_transport transport = {&fake, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport};
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && strstr(error, i ? "unsupported: Azure service principal JWT claim formatting" : "unsupported upstream panic: Azure service principal JWT Claims is nil"));
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
        CHECK(fake.calls == 3 && fake.releases == 3);
        free(error); br_results_clear(&results); free(input); free(body);
    }
    free(complex); free(numeric);
    char tenant[80]; tenant_name(tenant);
    char *input = input_for(detector, modern1, NULL, client1, NULL, tenant, NULL);
    char failure[256], expected[256]; snprintf(failure, sizeof(failure), "synthetic failure %s %s %s", modern1, client1, tenant);
    snprintf(expected, sizeof(expected), "synthetic failure [REDACTED] %s %s", client1, tenant);
    fake_http fake = {.count = 2}; fake.steps[0] = discovery(tenant, 200); fake.steps[1] = exchange(tenant, client1, modern1, 0, ""); fake.steps[1].send_error = failure;
    br_results results = scan(detector, input, true, &fake); CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, expected));
    br_results_clear(&results); free(input);
}

int main(void)
{
    make_modern(modern1, 31, 3); make_modern(modern2, 34, 8);
    CHECK(strlen(legacy1) >= 31 && strlen(legacy1) <= 34 && strlen(punctuated) == 33);
    const br_detector *v1 = NULL, *v2 = NULL; init(&v1, &v2);
    extraction(v1, v2); typed_http_and_wire(v1, punctuated); typed_http_and_wire(v2, modern1);
    mutable_clients(v2); invalid_expired_and_unknown(v2); tenants_and_discovery(v2);
    jwt_projection(v2); guards_and_redaction(v2);
    return test_finish("Azure service principal v1/v2 source processing + form/JWT policy");
}
