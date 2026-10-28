/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <errno.h>
#include <malloc.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const char *const hosts[] = {"api-offline.duosecurity.com", "abcd-9.duosecurity.com"};
static const char *const ikeys[] = {"DI0123456789ABCDEFGH", "DIZYXWVUTSRQ98765432"};
static const char *const skeys[] = {"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt", "0123456789abcdef0123456789abcdefABCDEFGH"};
static const char admin_path[] = "/admin/v1/info/summary", auth_path[] = "/auth/v2/check";
static const char date0[] = "Tue, 02 Jan 2024 03:04:05 GMT", date1[] = "Tue, 02 Jan 2024 03:04:06 GMT";
/* Independent Python stdlib HMAC/SHA1/Base64 literals. Canonical bytes include
 * the final newline, rather than a C-string terminator. */
static const char canonical_admin[] = "Tue, 02 Jan 2024 03:04:05 GMT\nGET\napi-offline.duosecurity.com\n/admin/v1/info/summary\n";
static const char canonical_auth[] = "Tue, 02 Jan 2024 03:04:06 GMT\nGET\napi-offline.duosecurity.com\n/auth/v2/check\n";
static const char *const digest_gold[] = {
    "9cdb35ae347078e01944bf4609a1e282847f6649", "380e0f691a4577974b60b4152a32b6315675e222",
    "66f09067d7870a76b8f598d5841cc79f14bba5ff", "57fb4d0f450acb6a030ffc8d4f5458dac0dfc36f",
};
static const char *const basic_gold[] = {
    "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6OWNkYjM1YWUzNDcwNzhlMDE5NDRiZjQ2MDlhMWUyODI4NDdmNjY0OQ==",
    "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6MzgwZTBmNjkxYTQ1Nzc5NzRiNjBiNDE1MmEzMmI2MzE1Njc1ZTIyMg==",
    "Basic RElaWVhXVlVUU1JROTg3NjU0MzI6OWNkYjM1YWUzNDcwNzhlMDE5NDRiZjQ2MDlhMWUyODI4NDdmNjY0OQ==",
    "Basic RElaWVhXVlVUU1JROTg3NjU0MzI6MzgwZTBmNjkxYTQ1Nzc5NzRiNjBiNDE1MmEzMmI2MzE1Njc1ZTIyMg==",
    "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6NjZmMDkwNjdkNzg3MGE3NmI4ZjU5OGQ1ODQxY2M3OWYxNGJiYTVmZg==",
    "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6NTdmYjRkMGY0NTBhY2I2YTAzMGZmYzhkNGY1NDU4ZGFjMGRmYzM2Zg==",
    "Basic RElaWVhXVlVUU1JROTg3NjU0MzI6NjZmMDkwNjdkNzg3MGE3NmI4ZjU5OGQ1ODQxY2M3OWYxNGJiYTVmZg==",
    "Basic RElaWVhXVlVUU1JROTg3NjU0MzI6NTdmYjRkMGY0NTBhY2I2YTAzMGZmYzhkNGY1NDU4ZGFjMGRmYzM2Zg==",
};
static const char auth_basic[] = "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6ZTI3YzcyMDQwNDA1MTVhMmRiNGQ0M2FkNmViODA0ZGRjNTNhNDExYQ==";

static size_t fail_size, fail_after, allocation_failures, fail_push_size;
static size_t fail_application_after;
static const char *fail_application_value;
static struct timespec frames[16];
static size_t frame_count, real_calls, sign_calls, fail_clock_at, fail_sign_at, short_digest_at;
static size_t arm_clock_size, arm_sign_size;
static const char *required_canonical, *required_digest;
static test_http *clock_http;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_application_after && !strcmp(name, "application") &&
        !strcmp(json_object_get_string(value), fail_application_value) && --fail_application_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
int clock_gettime(clockid_t which, struct timespec *out)
{
    if (which != CLOCK_REALTIME) return (int)syscall(SYS_clock_gettime, which, out);
    /* Fresh Auth signing must happen AFTER Admin response release. */
    if (clock_http) CHECK(clock_http->calls == real_calls && clock_http->releases == real_calls);
    size_t at = real_calls++;
    if (fail_clock_at == real_calls) { errno = EIO; return -1; }
    CHECK(frame_count); *out = frames[at < frame_count ? at : frame_count - 1];
    if (arm_clock_size) { fail_size = arm_clock_size; fail_after = 1; arm_clock_size = 0; }
    return 0;
}

/* Native signing spy delegates to OpenSSL's incremental MAC APIs, not back to
 * EVP_Q_mac/HMAC (which may call each other). It observes pre-constructor
 * ordering and real canonical bytes, with two targeted native crypto failures. */
unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
    const char *subalg, const OSSL_PARAM *params, const void *key, size_t keylen,
    const unsigned char *data, size_t datalen, unsigned char *out, size_t outsize, size_t *outlen)
{
    ++sign_calls;
    CHECK(!libctx && !strcmp(name, "HMAC") && !propq && !strcmp(subalg, "SHA1") && !params);
    CHECK(key && keylen == 40 && out && outsize == 20 && outlen && data && datalen && data[datalen - 1] == '\n');
    if (required_canonical) CHECK(datalen == strlen(required_canonical) && !memcmp(data, required_canonical, datalen));
    if (fail_sign_at == sign_calls) return NULL;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL); CHECK(mac);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac); CHECK(ctx); char digest[] = "SHA1";
    OSSL_PARAM options[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_construct_end()};
    CHECK(EVP_MAC_init(ctx, key, keylen, options) == 1 && EVP_MAC_update(ctx, data, datalen) == 1);
    CHECK(EVP_MAC_final(ctx, out, outlen, outsize) == 1 && *outlen == 20);
    EVP_MAC_CTX_free(ctx); EVP_MAC_free(mac);
    if (required_digest) {
        static const char hex[] = "0123456789abcdef"; char actual[41];
        for (size_t i = 0; i < 20; ++i) { actual[i * 2] = hex[out[i] >> 4]; actual[i * 2 + 1] = hex[out[i] & 15]; }
        actual[40] = '\0'; CHECK(!strcmp(actual, required_digest));
    }
    if (short_digest_at == sign_calls) *outlen = 19;
    if (arm_sign_size) { fail_size = arm_sign_size; fail_after = 1; arm_sign_size = 0; }
    return out;
}

static void reset_clock(void)
{
    frames[0] = (struct timespec){1704164645, 123456789}; frame_count = 1;
    real_calls = sign_calls = fail_clock_at = fail_sign_at = short_digest_at = 0;
    arm_clock_size = arm_sign_size = 0; required_canonical = required_digest = NULL; clock_http = NULL;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(ikeys[0]) == 20 && strlen(ikeys[1]) == 20 && strlen(skeys[0]) == 40 && strlen(skeys[1]) == 40);
    CHECK(br_duo_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_duo_init(&d, &error) == 0 && d && !error);
    CHECK(br_duo_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 1063 && d->version == 0 && !strcmp(d->name, "Duo") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Duo is a security platform that provides multi-factor authentication and identity management services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "duosecurity"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void part(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL; CHECK(object && json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected) && !memcmp(json_object_get_string(value), expected, strlen(expected)));
}
static void finding(const br_result *r, const char *host, const char *ikey, const char *skey, const char *application, bool verified, const char *cause)
{
    CHECK(r->detector_type == 1063 && !r->detector_name && r->raw.len == 20 && !memcmp(r->raw.data, ikey, 20));
    size_t len = strlen(host); CHECK(r->raw_v2.len == len + 62 && !memcmp(r->raw_v2.data, host, len) && r->raw_v2.data[len] == ':');
    CHECK(!memcmp(r->raw_v2.data + len + 1, ikey, 20) && r->raw_v2.data[len + 21] == ':' && !memcmp(r->raw_v2.data + len + 22, skey, 40));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 4 && r->extra_data && json_object_object_length(r->extra_data) == 1);
    part(r->secret_parts, "host", host); part(r->secret_parts, "ikey", ikey); part(r->secret_parts, "skey", skey);
    part(r->secret_parts, "application", application); part(r->extra_data, "application", application);
    CHECK(r->verified == verified && (r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
    CHECK(!r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set);
}
static char *input_for(const char *host, const char *ikey, const char *skey)
{
    size_t size = strlen(host) + strlen(ikey) + strlen(skey) + 20; char *input = malloc(size); CHECK(input);
    snprintf(input, size, "%s\nduo %s\nduo %s", host, ikey, skey); return input;
}

typedef struct {
    const char *host, *ikey, *skey, *path, *date, *basic, *canonical, *digest, *send_error, *read_error;
    int status, rc;
} row;
typedef struct {
    row rows[16]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *url, *auth, *date;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;
static row admin_row(int status)
{
    return (row){.host = hosts[0], .ikey = ikeys[0], .skey = skeys[0], .path = admin_path,
        .date = date0, .basic = basic_gold[0], .canonical = canonical_admin, .digest = digest_gold[0], .status = status};
}
static row auth_row(int status)
{
    return (row){.host = hosts[0], .ikey = ikeys[0], .skey = skeys[0], .path = auth_path,
        .date = date1, .basic = auth_basic, .canonical = canonical_auth, .digest = "e27c7204040515a2db4d43ad6eb804ddc53a411a", .status = status};
}
static void request_values(const script *steps, const row *reply)
{
    size_t host_len = strlen(reply->host), path_len = strlen(reply->path);
    CHECK(steps->url && strlen(steps->url) == 8 + host_len + path_len && !memcmp(steps->url, "https://", 8));
    CHECK(!memcmp(steps->url + 8, reply->host, host_len) && !strcmp(steps->url + 8 + host_len, reply->path));
    CHECK(steps->auth && strlen(steps->auth) == 90 && !memcmp(steps->auth, reply->basic, 91));
    CHECK(steps->date && strlen(steps->date) == 29 && !memcmp(steps->date, reply->date, 30));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 16 && ctx == steps->ctx && http->releases == at);
    CHECK(real_calls == http->calls && sign_calls == http->calls);
    CHECK(request->detector_type == 1063 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[1].name, "Date"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog duo-offline" : "TruffleHog"));
    steps->url = request->url; steps->auth = request->headers[0].value; steps->date = request->headers[1].value;
    row *reply = &steps->rows[at]; request_values(steps, reply);
    http->response = (br_http_response){.status = reply->status, .body = TEXT("not JSON\0\xff"), .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (http->calls < steps->count) {
        required_canonical = steps->rows[http->calls].canonical; required_digest = steps->rows[http->calls].digest;
    }
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    request_values(steps, &steps->rows[http->calls - 1]); steps->url = steps->auth = steps->date = NULL;
    test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "duo-offline" : NULL};
    steps->ctx = &ctx; clock_http = &http;
    required_canonical = steps->count ? steps->rows[0].canonical : NULL; required_digest = steps->count ? steps->rows[0].digest : NULL;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->url && !steps->auth && !steps->date);
    clock_http = NULL; required_canonical = required_digest = NULL;
    return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static void fallback_clock(void)
{
    reset_clock(); frames[1] = (struct timespec){1704164646, 987654321}; frame_count = 2;
}

static void extraction_and_products(const br_detector *d)
{
    char *input = input_for(hosts[0], ikeys[0], skeys[0]); reset_clock();
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 1 && !real_calls && !sign_calls);
    finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", false, NULL); br_results_clear(&out); free(input);
    const char *bad_hosts[] = {"abcde.duosecurity.com", "UPPER-HOST.duosecurity.com", "abcdef.DUOSECURITY.com", "abcdef.duosecurity.net"};
    for (size_t i = 0; i < 4; ++i) {
        input = input_for(bad_hosts[i], ikeys[0], skeys[0]); out = test_scan(d, NULL, false, input, strlen(input)); CHECK(!out.len);
        br_results_clear(&out); free(input);
    }
    const char *bad_ikeys[] = {"Di0123456789ABCDEFGH", "DI0123456789ABCDEFG_", "DI0123456789ABCDEFG", "DI0123456789ABCDEFGHI"};
    for (size_t i = 0; i < 4; ++i) {
        input = input_for(hosts[0], bad_ikeys[i], skeys[0]); out = test_scan(d, NULL, false, input, strlen(input)); CHECK(!out.len);
        br_results_clear(&out); free(input);
    }
    char input_buffer[640];
    snprintf(input_buffer, sizeof(input_buffer), "%s\n%080d\n%s\n%s", hosts[0], 0, ikeys[0], skeys[0]);
    out = test_scan(d, NULL, false, input_buffer, strlen(input_buffer)); CHECK(!out.len); br_results_clear(&out); /* Credential prefixes are duo, not dispatch. */
    snprintf(input_buffer, sizeof(input_buffer), "%s\nDUO '%s'\nDuO:%s", hosts[0], ikeys[0], skeys[0]);
    out = test_scan(d, NULL, false, input_buffer, strlen(input_buffer)); CHECK(out.len == 1);
    finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", false, NULL); br_results_clear(&out);
    memset(input_buffer, ' ', sizeof(input_buffer)); memcpy(input_buffer, "duo", 3); memcpy(input_buffer + 43, ikeys[0], 20);
    snprintf(input_buffer + 63, sizeof(input_buffer) - 63, "\n%s\nduo %s", hosts[0], skeys[0]);
    out = test_scan(d, NULL, false, input_buffer, strlen(input_buffer)); CHECK(out.len == 1); br_results_clear(&out);
    memmove(input_buffer + 44, input_buffer + 43, strlen(input_buffer + 43) + 1); input_buffer[43] = ' ';
    out = test_scan(d, NULL, false, input_buffer, strlen(input_buffer)); CHECK(!out.len); br_results_clear(&out);

    snprintf(input_buffer, sizeof(input_buffer), "%s\n%s\nduo %s\nduo %s\nduo %s\nduo %s\n%s\nduo %s\nduo %s",
        hosts[0], hosts[1], ikeys[0], ikeys[1], skeys[0], skeys[1], hosts[0], ikeys[0], skeys[0]);
    reset_clock(); script steps = {.count = 8, .suffix = true};
    for (size_t h = 0; h < 2; ++h) for (size_t i = 0; i < 2; ++i) for (size_t s = 0; s < 2; ++s) {
        size_t at = h * 4 + i * 2 + s;
        steps.rows[at] = (row){.host = hosts[h], .ikey = ikeys[i], .skey = skeys[s], .path = admin_path, .date = date0,
            .basic = basic_gold[at], .digest = digest_gold[h * 2 + s], .status = 200, .read_error = "ignored drain failure"};
    }
    steps.rows[0].canonical = canonical_admin;
    out = run(d, input_buffer, &steps); CHECK(out.len == 8 && real_calls == 8 && sign_calls == 8);
    for (size_t h = 0; h < 2; ++h) for (size_t i = 0; i < 2; ++i) for (size_t s = 0; s < 2; ++s) {
        size_t at = h * 4 + i * 2 + s; finding(&out.items[at], hosts[h], ikeys[i], skeys[s], "Admin API", true, NULL);
        for (size_t before = 0; before < at; ++before)
            CHECK(out.items[at].secret_parts != out.items[before].secret_parts && out.items[at].extra_data != out.items[before].extra_data && out.items[at].raw.data != out.items[before].raw.data);
    }
    br_results_clear(&out);
}

static void fallback_status_and_causes(const br_detector *d)
{
    char *input = input_for(hosts[0], ikeys[0], skeys[0]);
    const int statuses[] = {200, 403, 0, 199, 201, 204, 299, 300, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_clock(); script steps = {.count = 1}; steps.rows[0] = admin_row(statuses[i]); steps.rows[0].read_error = "ignored read error";
        br_results out = run(d, input, &steps); CHECK(out.len == 1 && real_calls == 1);
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected HTTP status %d", statuses[i]); bool valid = statuses[i] == 200 || statuses[i] == 403;
        finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", valid, valid ? NULL : cause); br_results_clear(&out);
    }
    const int auth_statuses[] = {200, 401, 403, 0, 201, 500};
    for (size_t i = 0; i < sizeof(auth_statuses) / sizeof(*auth_statuses); ++i) {
        fallback_clock(); script steps = {.count = 2}; steps.rows[0] = admin_row(401); steps.rows[1] = auth_row(auth_statuses[i]);
        steps.rows[0].read_error = ""; steps.rows[1].read_error = "ignored Auth read";
        br_results out = run(d, input, &steps); CHECK(out.len == 1 && real_calls == 2 && sign_calls == 2);
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected HTTP status %d", auth_statuses[i]);
        bool valid = auth_statuses[i] == 200 || auth_statuses[i] == 403;
        finding(&out.items[0], hosts[0], ikeys[0], skeys[0], auth_statuses[i] == 403 ? "Admin API" : "Auth API", valid,
            valid || auth_statuses[i] == 401 ? NULL : cause); br_results_clear(&out);
    }
    char echo[256]; snprintf(echo, sizeof(echo), "opaque prefix %s %s %s %s", hosts[0], ikeys[0], skeys[0], hosts[0]);
    for (size_t auth = 0; auth < 2; ++auth) {
        fallback_clock(); script steps = {.count = auth + 1}; steps.rows[0] = admin_row(auth ? 401 : 403);
        if (auth) steps.rows[1] = auth_row(403); /* Supplied 403 PLUS Do error must report status ZERO and relabel Auth. */
        steps.rows[auth].rc = 1; steps.rows[auth].send_error = echo;
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], hosts[0], ikeys[0], skeys[0], auth ? "Auth API" : "Admin API", false,
            "opaque prefix [REDACTED] [REDACTED] [REDACTED] [REDACTED]"); br_results_clear(&out);
    }
    reset_clock(); script steps = {.count = 1}; steps.rows[0] = admin_row(401); steps.rows[0].rc = -1; steps.rows[0].send_error = "";
    br_results out = run(d, input, &steps); CHECK(out.len == 1 && real_calls == 1);
    finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", false, ""); br_results_clear(&out);
    reset_clock(); steps = (script){.count = 1}; steps.rows[0] = admin_row(401); steps.rows[0].rc = 1;
    out = run(d, input, &steps); finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", false, "HTTP transport failed"); br_results_clear(&out);
    /* Redaction order is observable when SKEY contains IKEY: replacing IKEY
     * first prevents a later whole-SKEY match, exactly as the source setter. */
    char overlapping[41]; memcpy(overlapping, ikeys[0], 20); memcpy(overlapping + 20, "abcdefghijklmnopqrst", 21);
    char *overlap_input = input_for(hosts[0], ikeys[0], overlapping); reset_clock();
    steps = (script){.count = 1}; steps.rows[0] = admin_row(200); steps.rows[0].skey = overlapping;
    steps.rows[0].digest = "1425c62ac08504bc07ca27106337f1efd4446fe3";
    steps.rows[0].basic = "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6MTQyNWM2MmFjMDg1MDRiYzA3Y2EyNzEwNjMzN2YxZWZkNDQ0NmZlMw==";
    snprintf(echo, sizeof(echo), "%s:%s:%s", hosts[0], ikeys[0], overlapping);
    steps.rows[0].rc = 1; steps.rows[0].send_error = echo;
    out = run(d, overlap_input, &steps); CHECK(out.len == 1 && real_calls == 1 && sign_calls == 1);
    finding(&out.items[0], hosts[0], ikeys[0], overlapping, "Admin API", false,
        "[REDACTED]:[REDACTED]:[REDACTED]abcdefghijklmnopqrst");
    br_results_clear(&out); free(overlap_input); free(input);
}

static void clocks_long_host_and_nil_context(const br_detector *d)
{
    const struct { int64_t epoch; const char *date, *basic, *digest; } cases[] = {
        {-1, "Wed, 31 Dec 1969 23:59:59 GMT", "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6Y2U4NmQ0YWJiNDUxNTc1MTMyNDEzYjhhYmVmZDY4Y2FmYTE5MzZjZA==", "ce86d4abb451575132413b8abefd68cafa1936cd"},
        {-62167219200LL, "Sat, 01 Jan 0000 00:00:00 GMT", "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6ZmExY2YzNmNmMGI1ZjViODJiMDdkOGZhYjU4MjdiMmRhYjc4OGIxOQ==", "fa1cf36cf0b5f5b82b07d8fab5827b2dab788b19"},
        {253402300799LL, "Fri, 31 Dec 9999 23:59:59 GMT", "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6NmVkY2U5NDQ2MzkwNmMwNzU0NDVkODQ5NjE2MTc4YThhYzRkZGIyOA==", "6edce94463906c075445d849616178a8ac4ddb28"},
    };
    char *input = input_for(hosts[0], ikeys[0], skeys[0]);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_clock(); frames[0].tv_sec = (time_t)cases[i].epoch;
        script steps = {.count = 1}; steps.rows[0] = admin_row(200);
        steps.rows[0].date = cases[i].date; steps.rows[0].basic = cases[i].basic; steps.rows[0].digest = cases[i].digest; steps.rows[0].canonical = NULL;
        br_results out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", true, NULL); br_results_clear(&out);
    }
    reset_clock(); required_canonical = canonical_admin; required_digest = digest_gold[0];
    br_results out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1 && real_calls == 1 && sign_calls == 1);
    finding(&out.items[0], hosts[0], ikeys[0], skeys[0], "Admin API", false, "net/http: nil Context"); br_results_clear(&out); free(input);
    size_t subdomain = 5000; char *host = malloc(subdomain + sizeof(".duosecurity.com")); CHECK(host);
    memset(host, 'a', subdomain); strcpy(host + subdomain, ".duosecurity.com"); input = input_for(host, ikeys[0], skeys[0]); reset_clock();
    script steps = {.count = 1}; steps.rows[0] = admin_row(200); steps.rows[0].host = host; steps.rows[0].canonical = NULL;
    steps.rows[0].digest = "043b2d30e18ca4e3b4e441cf29ba1929221a60cd";
    steps.rows[0].basic = "Basic REkwMTIzNDU2Nzg5QUJDREVGR0g6MDQzYjJkMzBlMThjYTRlM2I0ZTQ0MWNmMjliYTE5MjkyMjFhNjBjZA==";
    out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], host, ikeys[0], skeys[0], "Admin API", true, NULL);
    br_results_clear(&out); free(input); free(host);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key"); free(error); br_results_clear(out);
}
static void resources_before_constructor_fallback_and_append(const br_detector *d)
{
    char *input = input_for(hosts[0], ikeys[0], skeys[0]);
    for (size_t mode = 0; mode < 6; ++mode) {
        br_results out = caller_owned(); char *error = NULL; reset_clock();
        if (mode == 0) { fail_application_value = "Admin API"; fail_application_after = 1; }
        if (mode == 1) fail_clock_at = 1;
        if (mode == 2) arm_clock_size = strlen(hosts[0]) + strlen(admin_path) + 37;
        if (mode == 3) fail_sign_at = 1;
        if (mode == 4) short_digest_at = 1;
        if (mode == 5) arm_sign_size = 8 + strlen(hosts[0]) + strlen(admin_path) + 1;
        size_t before = allocation_failures;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(real_calls == (mode ? 1u : 0u) && sign_calls == (mode >= 3 ? 1u : 0u));
        if (mode == 2 || mode == 5) CHECK(allocation_failures == before + 1 && !fail_after);
        CHECK(!fail_application_after && !arm_clock_size && !arm_sign_size); rolled_back(&out, rc, error);
    }
    const int64_t outside[] = {-62198755200LL, 253402300800LL};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; reset_clock(); frames[0].tv_sec = (time_t)outside[i];
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(real_calls == 1 && !sign_calls && error && strstr(error, "unsupported: Duo signing clock range")); rolled_back(&out, rc, error);
    }
    for (size_t addition = 1; addition <= 2; ++addition) {
        br_results out = caller_owned(); char *error = NULL; fallback_clock();
        fail_application_value = "Auth API"; fail_application_after = addition;
        script steps = {.count = 2}; steps.rows[0] = admin_row(401); steps.rows[1] = auth_row(200);
        int rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_application_after && real_calls == 2); rolled_back(&out, rc, error);
    }
    /* Clock failure on Auth must abort BEFORE relabeling or another request. */
    br_results out = caller_owned(); char *error = NULL; fallback_clock(); fail_clock_at = 2;
    script steps = {.count = 1}; steps.rows[0] = admin_row(401);
    int rc = invoke(d, input, &steps, &out, &error); CHECK(real_calls == 2 && sign_calls == 1); rolled_back(&out, rc, error);
    /* Own cause creation and the source setter's +1 failure are not fallback. */
    const char *leaf = "unwrapped synthetic cause";
    for (size_t mode = 0; mode < 2; ++mode) {
        out = caller_owned(); error = NULL; reset_clock(); steps = (script){.count = 1, .arm_call = 1, .arm_after = 1};
        steps.rows[0] = admin_row(mode ? 401 : 500);
        if (mode) { steps.rows[0].rc = 1; steps.rows[0].send_error = leaf; }
        steps.arm_size = strlen(mode ? leaf : "unexpected HTTP status 500") + 1;
        size_t before = allocation_failures; rc = invoke(d, input, &steps, &out, &error);
        CHECK(allocation_failures == before + 1 && !fail_after && real_calls == 1); rolled_back(&out, rc, error);
    }
    out = caller_owned(); out.cap = out.len; error = NULL; reset_clock();
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)}; steps.rows[0] = admin_row(200);
    size_t before = allocation_failures; rc = invoke(d, input, &steps, &out, &error);
    CHECK(allocation_failures == before + 1 && !fail_push_size); rolled_back(&out, rc, error);
    /* Roll back a previous product from THIS invocation, preserving the caller. */
    char products[256]; snprintf(products, sizeof(products), "%s\nduo %s\nduo %s\nduo %s", hosts[0], ikeys[0], skeys[0], skeys[1]);
    out = caller_owned(); error = NULL; reset_clock(); fail_clock_at = 2;
    steps = (script){.count = 1}; steps.rows[0] = admin_row(200);
    rc = invoke(d, products, &steps, &out, &error); CHECK(real_calls == 2 && sign_calls == 1); rolled_back(&out, rc, error);
    free(input);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction_and_products(d);
    fallback_status_and_causes(d);
    clocks_long_host_and_nil_context(d);
    resources_before_constructor_fallback_and_append(d);
    CHECK(!fail_after && !fail_application_after && !fail_push_size && !arm_clock_size && !arm_sign_size);
    return test_finish("Duo");
}
