/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static const char account[] = "account-AbCd0123EfGh4567IjKl";
static const char master[] = "master-AbCd0123EfGh4567IjKl";
static const char secret[] = "AbCd0123EfGh4567IjKl8901MnOp";
static const char short_secret[] = "ZyXw9876VuTs5432RqPo1098Nml";
static struct timespec tick = {1704164645, 123456789};
static size_t clocks, fail_clock_at, fail_part_at, encodes, fail_encode_at;
static int (*real_encode)(unsigned char *, const unsigned char *, int);

int clock_gettime(clockid_t which, struct timespec *out)
{
    if (which != CLOCK_REALTIME) return (int)syscall(SYS_clock_gettime, which, out);
    ++clocks;
    if (fail_clock_at && clocks == fail_clock_at) { errno = EIO; return -1; }
    *out = tick; return 0;
}

int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int length)
{
    ++encodes;
    if (fail_encode_at && encodes == fail_encode_at) return -1;
    return real_encode(out, in, length);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "secret") && fail_part_at && --fail_part_at == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void reset(void)
{
    clocks = encodes = fail_clock_at = fail_part_at = fail_encode_at = 0;
    tick = (struct timespec){1704164645, 123456789};
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(account) == 28 && strlen(master) == 27 && strlen(secret) == 28 && strlen(short_secret) == 27);
    CHECK(br_gemini_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(!br_gemini_init(&d, &error) && d && !error);
    CHECK(!br_gemini_init(&again, &error) && again == d && !error);
    CHECK(d->type == 876 && d->version == 0 && !strcmp(d->name, "Gemini") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Gemini is a cryptocurrency exchange platform. API keys can be used to access and manage account details and perform transactions."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "master-") && !strcmp(d->keywords[1], "account-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, const char *value, bool verified)
{
    CHECK(r->detector_type == 876 && !r->detector_name && r->verified == verified && !r->verification_error);
    CHECK(r->raw.len == strlen(key) && !memcmp(r->raw.data, key, r->raw.len));
    CHECK(r->raw_v2.len == strlen(key) + strlen(value) && r->raw_v2.data != r->raw.data);
    CHECK(!memcmp(r->raw_v2.data, key, strlen(key)) && !memcmp(r->raw_v2.data + strlen(key), value, strlen(value)));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(r->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), value));
    CHECK(!r->redacted && !r->extra_data && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
}

static void extraction(const br_detector *d)
{
    char input[2400];
    const char *keys[] = {account, master, account};
    const char *values[] = {secret, short_secret, secret};
    snprintf(input, sizeof(input), "%s %s %s %s %s %s", account, master, account, secret, short_secret, secret);
    reset(); br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 9 && !clocks && !encodes);
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) check_result(&r.items[k * 3 + s], keys[k], values[s], false);
    br_results_clear(&r);
    const char *bad[] = {"Account-AbCd0123EfGh4567IjKl", "MASTER-AbCd0123EfGh4567IjKl", "xaccount-AbCd0123EfGh4567IjKl", "_master-AbCd0123EfGh4567IjKl", "account-AbCd0123EfGh4567IjKl_", "master-AbCd0123EfGh4567IjKlX", "master-AbCd0123EfGh4567IjK"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s", bad[i], secret); r = test_scan(d, NULL, false, input, strlen(input)); CHECK(!r.len); br_results_clear(&r);
    }
    /* Secret regex has no boundaries: greedy 28-byte nonoverlapping chunks,
     * even within a 55-byte run and adjacent to underscore/word characters. */
    snprintf(input, sizeof(input), "%s _%s%s_", master, secret, short_secret);
    r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 2); check_result(&r.items[0], master, secret, false); check_result(&r.items[1], master, short_secret, false); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s %sZ", master, secret); r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 1); check_result(&r.items[0], master, secret, false); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s %s", master, "AAAAAAAAAAAAAAAAAAAAAAAAAAA"); r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 1); br_results_clear(&r);
    /* Span is an inherited engine hint, not a cap on direct occurrence products. */
    snprintf(input, sizeof(input), "%s%2100s%s", master, "", secret); r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 1); check_result(&r.items[0], master, secret, false); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s%c%s", account, 0, secret); r = test_scan(d, NULL, false, input, strlen(account) + 1 + strlen(secret)); CHECK(r.len == 1); br_results_clear(&r);
    reset(); fail_clock_at = 1; r = test_scan(d, NULL, true, input, strlen(account) + 1 + strlen(secret)); CHECK(!r.len && !clocks && !encodes); br_results_clear(&r);
}

static const char *const payloads[] = {
    "eyJub25jZSI6MTcwNDE2NDY0NTEyMzQ1Njc4OSwicmVxdWVzdCI6Ii92MS9hY2NvdW50In0=",
    "eyJhY2NvdW50IjoicHJpbWFyeSIsIm5vbmNlIjoxNzA0MTY0NjQ1MTIzNDU2Nzg5LCJyZXF1ZXN0IjoiL3YxL2FjY291bnQifQ=="
};
/* Independent Python standard-library HMAC-SHA384 goldens, ASCII secret. */
static const char *const signatures[] = {
    "d8dcaf5af1c6ae3d98265460c4c5da041559172b5a82cf150994a5401dfe108d6596baeca3cb0c76287cf57c40e431ea",
    "e1767aaf4da8c3dbae6458d8522cd9f1fbe15247bbe208560d70e41ca7771b081ae52da68082f547cc7de199051a151b"
};
typedef struct {
    const char *key, *nonce; bool golden;
    const char *const *product_keys;
    const char *borrowed_key, *borrowed_payload, *borrowed_signature;
} expectation;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *q)
{
    (void)ctx; expectation *e = http->user;
    const char *key = e->product_keys ? e->product_keys[(http->calls - 1) / 3] : e->key;
    bool master_key = !strcmp(key, master);
    CHECK(clocks == http->calls && encodes == http->calls && http->releases + 1 == http->calls);
    CHECK(q->detector_type == 876 && q->profile == BR_HTTP_SANE && q->timeout_ms == 5000);
    CHECK(!strcmp(q->method, "POST") && !strcmp(q->url, "https://api.gemini.com/v1/account"));
    CHECK(!q->body.data && !q->body.len && !q->dedup_key.data && !q->dedup_key.len && q->nheaders == 7);
    const char *names[] = {"Content-Type", "Content-Length", "X-GEMINI-APIKEY", "X-GEMINI-PAYLOAD", "X-GEMINI-SIGNATURE", "Cache-Control", "User-Agent"};
    const char *values[7] = {0};
    for (size_t i = 0; i < q->nheaders; ++i) {
        size_t j; for (j = 0; j < 7; ++j) if (!strcmp(q->headers[i].name, names[j])) break;
        CHECK(j < 7 && !values[j]); values[j] = q->headers[i].value;
    }
    for (size_t j = 0; j < 7; ++j) CHECK(values[j]);
    CHECK(!strcmp(values[0], "text/plain") && !strcmp(values[1], "0") && !strcmp(values[2], key));
    CHECK(!strcmp(values[5], "no-cache") && !strcmp(values[6], "TruffleHog"));
    CHECK(strlen(values[4]) == 96);
    for (size_t i = 0; i < 96; ++i) CHECK((values[4][i] >= '0' && values[4][i] <= '9') || (values[4][i] >= 'a' && values[4][i] <= 'f'));
    if (e->golden) CHECK(!strcmp(values[3], payloads[master_key]) && !strcmp(values[4], signatures[master_key]));
    unsigned char decoded[128]; int n = EVP_DecodeBlock(decoded, (const unsigned char *)values[3], (int)strlen(values[3])); CHECK(n > 0);
    size_t encoded_len = strlen(values[3]); if (values[3][encoded_len - 1] == '=') --n; if (values[3][encoded_len - 2] == '=') --n;
    char expected[128]; int want = snprintf(expected, sizeof(expected), master_key ? "{\"account\":\"primary\",\"nonce\":%s,\"request\":\"/v1/account\"}" : "{\"nonce\":%s,\"request\":\"/v1/account\"}", e->nonce);
    CHECK(n == want && !memcmp(decoded, expected, (size_t)n));
    e->borrowed_key = values[2]; e->borrowed_payload = values[3]; e->borrowed_signature = values[4];
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user; expectation *e = http->user; CHECK(response);
    CHECK(e->borrowed_key && e->borrowed_payload && e->borrowed_signature);
    if (e->golden) {
        bool m = !strcmp(e->borrowed_key, master);
        CHECK(!strcmp(e->borrowed_payload, payloads[m]) && !strcmp(e->borrowed_signature, signatures[m]));
    }
    ++http->releases;
}

static void verified_products(const br_detector *d)
{
    reset(); char input[256];
    snprintf(input, sizeof(input), "%s %s %s %s %s %s", account, master, account, secret, secret, secret);
    const char *keys[] = {account, master, account};
    expectation e = {.nonce = "1704164645123456789", .golden = true, .product_keys = keys};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}};
    br_transport transport = test_transport(&http); transport.release = release;
    br_scan_ctx ctx = {.transport = &transport};
    br_results r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 9 && http.calls == 9 && http.releases == 9 && clocks == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) check_result(&r.items[k * 3 + s], keys[k], secret, true);
    br_results_clear(&r);
}

static void responses(const br_detector *d)
{
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 500};
    char input[128];
    for (int m = 0; m < 2; ++m) for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) for (int mode = 0; mode < 3; ++mode) {
        reset(); const char *key = m ? master : account; snprintf(input, sizeof(input), "%s %s", key, secret);
        expectation e = {.key = key, .nonce = "1704164645123456789", .golden = true};
        test_http http = {.inspect = inspect, .user = &e, .response = {.status = statuses[i], .body = {(const unsigned char *)"\xff\0not JSON", 11}, .body_error = "ignored read error"}, .send_rc = mode};
        if (mode == 1) http.send_error = "out of memory setting up adapter";
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&r.items[0], key, secret, mode == 0 && statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&r);
    }
    const struct { time_t sec; long ns; const char *nonce; } edges[] = {
        {0, 0, "0"}, {-1, 500000000, "-500000000"},
        {9223372036, 854775807, "9223372036854775807"}, {-9223372037, 145224192, "-9223372036854775808"}
    };
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        reset(); tick = (struct timespec){edges[i].sec, edges[i].ns};
        expectation e = {.key = master, .nonce = edges[i].nonce}; test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        snprintf(input, sizeof(input), "%s %s", master, secret); br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.releases == 1); br_results_clear(&r);
    }
}

static void resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "%s %s %s", master, secret, secret);
    for (int mode = 0; mode < 7; ++mode) {
        reset(); expectation e = {.key = master, .nonce = "1704164645123456789", .golden = true};
        test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results r = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&r, &prior));
        unsigned char *saved = r.items[0].raw.data; char *saved_error = r.items[0].verification_error, *error = NULL;
        if (mode == 0) fail_part_at = 2;
        if (mode == 1) fail_clock_at = 2;
        if (mode == 2) fail_encode_at = 2;
        if (mode == 3) CHECK(EVP_set_default_properties(NULL, "provider=nonexistent") == 1);
        if (mode == 4) tick = (struct timespec){9223372036, 854775808};
        if (mode == 5) tick = (struct timespec){-9223372037, 145224191};
        if (mode == 6) { fail_part_at = 1; fail_clock_at = 1; }
        int rc = d->scan(d, mode == 6 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        if (mode == 3) CHECK(EVP_set_default_properties(NULL, "") == 1);
        CHECK(rc == -1 && error);
        const char *wanted = mode == 0 || mode == 6 ? "cannot create Gemini finding" : mode == 1 ? "cannot read Gemini signing clock" : mode == 2 ? "cannot encode Gemini payload" : mode == 3 ? "cannot sign Gemini request" : "unsupported: Gemini signing clock range";
        CHECK(!strcmp(error, wanted));
        CHECK(http.calls == (mode < 3 ? 1u : 0u) && http.releases == http.calls);
        CHECK(r.len == 1 && r.items[0].raw.data == saved && r.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(r.items[0].detector_type == 777 && r.items[0].verified && r.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        if (mode == 6) CHECK(!clocks && !encodes);
        free(error); br_results_clear(&r);
    }
    reset();
}

int main(void)
{
    void *symbol = dlsym(RTLD_NEXT, "EVP_EncodeBlock"); CHECK(symbol);
    _Static_assert(sizeof(real_encode) == sizeof(symbol), "function pointer size"); memcpy(&real_encode, &symbol, sizeof(real_encode));
    const br_detector *d = descriptor(); extraction(d); verified_products(d); responses(d); resources(d);
    return test_finish("Gemini occurrence products + literal map headers + UnixNano/Base64/HMAC + status/resource policies");
}
