/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/azure_shared_key.h"

#include <dlfcn.h>
#include <openssl/evp.h>
#include <time.h>

extern int br_kraken_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings, decode and HTTP stay linked. */
#define br_results_push kraken_real_push
#define br_result_set_verification_error kraken_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error
#define br_azure_base64_std_decode kraken_real_decode
#include "../../src/detectors/azure_shared_key.c"
#undef br_azure_base64_std_decode

static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls, decode_calls;
static size_t last_mac_len;
static int fail_decode, fail_mac, fixed_nonce;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return kraken_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return kraken_real_setter(result, cause, secrets, count);
}

int br_azure_base64_std_decode(br_slice input, br_bytes *prefix, size_t *bad_offset)
{
    ++decode_calls;
    if (fail_decode) {
        int rc = fail_decode;
        fail_decode = 0;
        if (prefix) *prefix = (br_bytes){0};
        if (bad_offset) *bad_offset = SIZE_MAX;
        return rc;
    }
    return kraken_real_decode(input, prefix, bad_offset);
}

unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
                         const char *subalg, const OSSL_PARAM *params,
                         const void *key, size_t keylen,
                         const unsigned char *data, size_t datalen,
                         unsigned char *out, size_t outsize, size_t *outlen)
{
    typedef unsigned char *(*mac_fn)(OSSL_LIB_CTX *, const char *, const char *, const char *,
                                     const OSSL_PARAM *, const void *, size_t,
                                     const unsigned char *, size_t, unsigned char *, size_t, size_t *);
    static mac_fn real;
    if (!real) {
        void *symbol = dlsym(RTLD_NEXT, "EVP_Q_mac");
        memcpy(&real, &symbol, sizeof(real));
    }
    last_mac_len = datalen;
    if (fail_mac) {
        fail_mac = 0;
        return NULL;
    }
    return real(libctx, name, propq, subalg, params, key, keylen, data, datalen, out, outsize, outlen);
}

int clock_gettime(clockid_t clock_id, struct timespec *now)
{
    typedef int (*clock_fn)(clockid_t, struct timespec *);
    static clock_fn real;
    if (!real) {
        void *symbol = dlsym(RTLD_NEXT, "clock_gettime");
        memcpy(&real, &symbol, sizeof(real));
    }
    if (fixed_nonce && clock_id == CLOCK_REALTIME) {
        now->tv_sec = 1700000000;
        now->tv_nsec = 0;
        return 0;
    }
    return real(clock_id, now);
}

static const char description[] =
    "Kraken is a cryptocurrency exchange that allows trading of various digital assets. "
    "Kraken API keys can be used to access and manage account information and perform trading operations.";

static void token(char *out, size_t len, size_t shift)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < len; ++i) out[i] = alphabet[(i + shift) % 64];
    out[len] = '\0';
}

static void expect_pair(const br_result *result, const char *key, const char *private_key, bool verified)
{
    size_t key_len = strlen(key), private_len = strlen(private_key);
    CHECK(result->detector_type == 186 && !result->detector_name);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, key, key_len));
    CHECK(result->raw_v2.len == key_len + private_len);
    CHECK(!memcmp(result->raw_v2.data, key, key_len));
    CHECK(!memcmp(result->raw_v2.data + key_len, private_key, private_len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_error && result->verified == verified);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(part && json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(result->secret_parts, "private_key", &part));
    CHECK(part && json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), private_key));
}

static void expect_signature(const char *nonce, const char *private_key, const char *actual)
{
    br_bytes decoded = {0};
    size_t bad = SIZE_MAX;
    int decoded_rc = br_azure_base64_std_decode(
        (br_slice){(const unsigned char *)private_key, strlen(private_key)}, &decoded, &bad);
    CHECK(decoded_rc >= 0);
    char material[64];
    int n = snprintf(material, sizeof(material), "%snonce=%s", nonce, nonce);
    unsigned char digest[32], message[50], mac[64];
    size_t count = 0;
    static const unsigned char empty[] = "";
    CHECK(n > 0 && EVP_Q_digest(NULL, "SHA256", NULL, material, (size_t)n, digest, &count) && count == 32);
    memcpy(message, "/0/private/Balance", 18);
    memcpy(message + 18, digest, 32);
    count = 0;
    CHECK(EVP_Q_mac(NULL, "HMAC", NULL, "SHA512", NULL, decoded.data ? decoded.data : empty, decoded.len,
                    message, 50, mac, sizeof(mac), &count) && count == 64);
    char expected[89];
    CHECK(EVP_EncodeBlock((unsigned char *)expected, mac, 64) == 88);
    expected[88] = '\0';
    CHECK(!strcmp(actual, expected));
    free(decoded.data);
}

typedef struct { const char *const *keys, *const *privates; size_t npriv; } expected_pairs;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_pairs *expected = http->user;
    size_t index = http->calls - 1;
    const char *key = expected->keys[index / expected->npriv];
    const char *private_key = expected->privates[index % expected->npriv];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.kraken.com/0/private/Balance"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 186);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len >= 7 && !memcmp(request->body.data, "nonce=", 6));
    char nonce[32];
    CHECK(request->body.len - 6 < sizeof(nonce));
    memcpy(nonce, request->body.data + 6, request->body.len - 6);
    nonce[request->body.len - 6] = '\0';
    for (const char *digit = nonce; *digit; ++digit) CHECK(*digit >= '0' && *digit <= '9');
    long long seconds = strtoll(nonce, NULL, 10);
    time_t now = time(NULL);
    CHECK(seconds > (long long)now - 5 && seconds < (long long)now + 5);
    CHECK(strlen(nonce) < 13);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Api-Key") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "Api-Sign"));
    CHECK(strlen(request->headers[2].value) == 88);
    expect_signature(nonce, private_key, request->headers[2].value);
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    CHECK(!strcmp(request->headers[3].value, "TruffleHog"));
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_kraken_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid Kraken detector output"));
    free(error);
    CHECK(br_kraken_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(br_kraken_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "Kraken") && detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->type == 186 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "kraken"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static void add_text(char *out, size_t cap, const char *text)
{
    size_t used = strlen(out), extra = strlen(text);
    CHECK(used + extra < cap);
    memcpy(out + used, text, extra + 1);
}

static void test_extraction(const br_detector *detector)
{
    char key[57], other[57], mixed[57], private_key[89], other_private[89], short_private[87];
    char input[2048];
    token(key, 56, 1);
    token(other, 56, 3);
    token(mixed, 56, 7);
    mixed[10] = '=';
    mixed[11] = '/';
    mixed[12] = '+';
    token(private_key, 88, 5);
    token(other_private, 88, 9);
    token(short_private, 86, 11);

    snprintf(input, sizeof(input), "kraken %s kraken %s ", key, private_key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, private_key, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "kraken %s\" kraken %s'", key, private_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    char quoted_key[58], quoted_private[90];
    snprintf(quoted_key, sizeof(quoted_key), "%s\"", key);
    snprintf(quoted_private, sizeof(quoted_private), "%s'", private_key);
    expect_pair(&out.items[0], quoted_key, quoted_private, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "kraken %s\rkraken %s\n", key, private_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, private_key, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "KRAKEN %s kraken %s ", mixed, private_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], mixed, private_key, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "kraken %s kraken %s kraken %s kraken %s ",
             key, other, private_key, other_private);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    expect_pair(&out.items[0], key, private_key, false);
    expect_pair(&out.items[1], key, other_private, false);
    expect_pair(&out.items[2], other, private_key, false);
    expect_pair(&out.items[3], other, other_private, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "kraken %s kraken %s kraken %s ", key, key, private_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_pair(&out.items[0], key, private_key, false);
    expect_pair(&out.items[1], key, private_key, false);
    br_results_clear(&out);

    input[0] = '\0';
    add_text(input, sizeof(input), "kraken ");
    add_text(input, sizeof(input), key);
    add_text(input, sizeof(input), " ");
    for (size_t i = 0; i < 1100; ++i) add_text(input, sizeof(input), "x");
    add_text(input, sizeof(input), " kraken ");
    add_text(input, sizeof(input), private_key);
    add_text(input, sizeof(input), " ");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, private_key, false);
    br_results_clear(&out);

    input[0] = '\0';
    add_text(input, sizeof(input), "kraken");
    for (size_t i = 0; i < 40; ++i) add_text(input, sizeof(input), " ");
    add_text(input, sizeof(input), key);
    add_text(input, sizeof(input), " kraken ");
    add_text(input, sizeof(input), private_key);
    add_text(input, sizeof(input), " ");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);

    char miss[256];
    snprintf(miss, sizeof(miss), "kraken %s", key);
    out = test_scan(detector, NULL, false, miss, strlen(miss));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(miss, sizeof(miss), "kraken %s ", private_key);
    out = test_scan(detector, NULL, false, miss, strlen(miss));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(miss, sizeof(miss), "kraken%s kraken %s ", key, private_key);
    out = test_scan(detector, NULL, false, miss, strlen(miss));
    CHECK(!out.len);
    br_results_clear(&out);
    input[0] = '\0';
    add_text(input, sizeof(input), "kraken");
    for (size_t i = 0; i < 41; ++i) add_text(input, sizeof(input), " ");
    add_text(input, sizeof(input), key);
    add_text(input, sizeof(input), " kraken ");
    add_text(input, sizeof(input), private_key);
    add_text(input, sizeof(input), " ");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(miss, sizeof(miss), "kraken %.*s kraken %s ", 55, key, private_key);
    out = test_scan(detector, NULL, false, miss, strlen(miss));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(miss, sizeof(miss), "kraken %sA kraken %s ", key, short_private);
    out = test_scan(detector, NULL, false, miss, strlen(miss));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void test_verification(const br_detector *detector)
{
    char key[57], other[57], private_key[89], other_private[89], short_private[87], input[512];
    token(key, 56, 2);
    token(other, 56, 4);
    token(private_key, 88, 6);
    token(other_private, 88, 8);
    token(short_private, 86, 12);
    snprintf(input, sizeof(input), "kraken %s kraken %s kraken %s kraken %s ",
             key, other, private_key, other_private);
    const char *keys[] = {key, other};
    const char *privates[] = {private_key, other_private};
    expected_pairs expected = {keys, privates, 2};
    test_http http = {.response = {.status = 500}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 4 && http.calls == 4 && http.releases == 4);
    expect_pair(&out.items[0], key, private_key, true);
    expect_pair(&out.items[1], key, other_private, true);
    expect_pair(&out.items[2], other, private_key, true);
    expect_pair(&out.items[3], other, other_private, true);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "kraken %s kraken %s ", key, short_private);
    const char *one_key[] = {key};
    const char *one_private[] = {short_private};
    expected = (expected_pairs){one_key, one_private, 1};
    const unsigned char hidden[] = {0, 'I', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'k', 'e', 'y'};
    const unsigned char wrong_case[] = {'I', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'K', 'e', 'y'};
    const struct {
        int status, send_rc;
        br_slice body;
        const char *body_error, *send_error;
        bool verified;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body = {(const unsigned char *)"balance ok", 10}, .body_error = "read failed", .verified = true},
        {.status = 401, .verified = true},
        {.status = 403, .body = {(const unsigned char *)"Invalid key", 11}},
        {.status = 200, .body = {hidden, sizeof(hidden)}, .body_error = "truncated"},
        {.status = 200, .body = {wrong_case, sizeof(wrong_case)}, .verified = true},
        {.status = 200, .send_rc = 1, .send_error = "failed key", .body = {(const unsigned char *)"Invalid key", 11}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http one = {
            .response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport one_transport = test_transport(&one);
        br_scan_ctx one_ctx = {.transport = &one_transport};
        out = test_scan(detector, &one_ctx, true, input, strlen(input));
        CHECK(out.len == 1 && one.calls == 1 && one.releases == 1);
        expect_pair(&out.items[0], key, short_private, cases[i].verified);
        br_results_clear(&out);
    }

    char quoted_key[58], quoted_private[90], quoted_input[256];
    snprintf(quoted_key, sizeof(quoted_key), "%s\"", key);
    snprintf(quoted_private, sizeof(quoted_private), "%s\"", private_key);
    snprintf(quoted_input, sizeof(quoted_input), "kraken %s\" kraken %s\"", key, private_key);
    const char *quoted_keys[] = {quoted_key};
    const char *quoted_privates[] = {quoted_private};
    expected = (expected_pairs){quoted_keys, quoted_privates, 1};
    test_http quoted = {.response = {.status = 204}, .inspect = inspect_request, .user = &expected};
    br_transport quoted_transport = test_transport(&quoted);
    br_scan_ctx quoted_ctx = {.transport = &quoted_transport};
    out = test_scan(detector, &quoted_ctx, true, quoted_input, strlen(quoted_input));
    CHECK(out.len == 1 && quoted.calls == 1 && quoted.releases == 1);
    expect_pair(&out.items[0], quoted_key, quoted_private, true);
    br_results_clear(&out);

    br_results prior = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 777, "prior", "key") == 0 && br_results_push(&prior, &kept) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == 0);
    CHECK(!error && prior.len == 1 && prior.items[0].raw.len == 5 && !memcmp(prior.items[0].raw.data, "prior", 5));
    br_results_clear(&prior);
}

static void keep_prior(br_results *results, br_result *sentinel, unsigned char **raw, char **cause)
{
    memset(sentinel, 0, sizeof(*sentinel));
    sentinel->detector_type = 12345;
    sentinel->verified = true;
    sentinel->raw.data = malloc(4);
    CHECK(sentinel->raw.data);
    memcpy(sentinel->raw.data, "keep", 4);
    sentinel->raw.len = 4;
    sentinel->verification_error = strdup("caller-owned");
    CHECK(sentinel->verification_error);
    *raw = sentinel->raw.data;
    *cause = sentinel->verification_error;
    CHECK(br_results_push(results, sentinel) == 0);
}

static void prior_unchanged(const br_results *results, unsigned char *raw, char *cause)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned"));
}

/* These fail an archived verify && !ctx return: that path never captures, creates
 * a finding, or signs, so an injected failure cannot be observed. */
static void test_nil_context(const br_detector *detector)
{
    const char *none = "kraken";
    br_slice empty = {(const unsigned char *)none, strlen(none)};
    for (int capture = 0; capture < 2; ++capture) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {0};
        size_t decodes = decode_calls, setters = setter_calls;
        fail_size = 2 * sizeof(br_span);
        fail_after = (size_t)capture + 1; /* 1 is the key FindAll; 2 is the private FindAll. */
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, empty, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory iterating regex"));
        CHECK(!fail_after && !http.calls && !http.releases);
        CHECK(decode_calls == decodes && setter_calls == setters);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    char key[57], private_key[89], input[180];
    token(key, 56, 15);
    token(private_key, 88, 16);
    snprintf(input, sizeof(input), "kraken %s kraken %s ", key, private_key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory creating Kraken result",
        "Kraken signature failed",
        "Kraken signature failed",
    };
    for (int mode = 0; mode < 3; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        size_t setters = setter_calls;
        if (mode == 0) fail_part_after = 1;
        else if (mode == 1) fail_decode = -1;
        else fail_mac = 1;
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, messages[mode]));
        CHECK(!fail_part_after && !fail_decode && !fail_mac);
        CHECK(!http.calls && !http.releases && setter_calls == setters);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 200}};
    size_t decodes = decode_calls, setters = setter_calls;
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    CHECK(decode_calls == decodes + 1);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    const char *keys[] = {key};
    const char *privates[] = {private_key};
    expected_pairs expected = {keys, privates, 1};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

static const char source_signature[] =
    "X4C7MT6bCQkeucnne215zygrdQJeAMbptbsKAPAA2V6Dw6wnhsZsFgtJ4IUQr3XilXt9qkEkqp+XrPbcFYjT2g==";
static const char rejected_nul_signature[] =
    "BcssL4OXZDPixY1NqTCx1icdR0Y/8vZfia2UNIGquwPVAHNLkXYUlSTlZWVtPltNaUsI0IcZGoyQz+PBje8/Nw==";

static void inspect_fixed_vector(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && ctx->transport);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(request->body.len == 16 && !memcmp(request->body.data, "nonce=1700000000", 16));
    CHECK(!strcmp(request->headers[2].name, "Api-Sign"));
    CHECK(!strcmp(request->headers[2].value, source_signature));
    CHECK(strcmp(request->headers[2].value, rejected_nul_signature));
    CHECK(last_mac_len == 50);
}

static void test_signature_vector(const br_detector *detector)
{
    char key[57], input[192];
    const char *private_key =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    token(key, 56, 3);
    snprintf(input, sizeof(input), "kraken %s kraken %s ", key, private_key);
    const char *keys[] = {key};
    const char *privates[] = {private_key};
    expected_pairs expected = {keys, privates, 1};
    test_http http = {.response = {.status = 200}, .inspect = inspect_fixed_vector, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    fixed_nonce = 1;
    last_mac_len = 0;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    fixed_nonce = 0;
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_pair(&out.items[0], key, private_key, true);
    br_results_clear(&out);
}

static void test_body_projection(const br_detector *detector)
{
    char key[57], input[192];
    const char *private_key =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    token(key, 56, 7);
    snprintf(input, sizeof(input), "kraken %s kraken %s ", key, private_key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http invalid = {.response = {.status = 200, .body = {NULL, 1}}};
    br_transport invalid_transport = test_transport(&invalid);
    br_scan_ctx invalid_ctx = {.transport = &invalid_transport};
    char *error = NULL;
    int rc = detector->scan(detector, &invalid_ctx, true, slice, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "invalid Kraken response body"));
    CHECK(invalid.calls == 1 && invalid.releases == 1);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);

    memset(&sentinel, 0, sizeof(sentinel));
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http failed = {
        .response = {.status = 200, .body = {NULL, 1}},
        .send_rc = 1, .send_error = "failed key",
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    error = NULL;
    CHECK(detector->scan(detector, &failed_ctx, true, slice, &results, &error) == 0 && !error);
    CHECK(failed.calls == 1 && failed.releases == 1);
    CHECK(results.len == 2 && !results.items[1].verified && !results.items[1].verification_error);
    CHECK(results.items[0].raw.data == raw && results.items[0].verification_error == cause);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_signature_vector(detector);
    test_body_projection(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("Kraken");
}
