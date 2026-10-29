/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/azure_shared_key.h"
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <time.h>

extern int br_kucoin_init(const br_detector **out, char **error);

static const char key[] = "c19c2539c53367c726a5c04c";
static const char other_key[] = "0123456789abcdef01234567";
static const char secret[] = "2313b299-7ba8-66b6-5b30-3e94050324ff";
static const char passphrase[] = "_4K~W4|RHH--o}:BiwRhY9J2pl/5x,";
static const char sample[] = "kucoin _4K~W4|RHH--o}:BiwRhY9J2pl/5x, kucoin 2313b299-7ba8-66b6-5b30-3e94050324ff kucoin c19c2539c53367c726a5c04c";
static size_t fail_size, fail_after, fail_part_after, fail_hmac_after, hmac_calls;
static bool inject_time;
static time_t injected_seconds;
static int injected_errno;

time_t time(time_t *tloc)
{
    if (!inject_time) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            if (tloc) *tloc = (time_t)-1;
            return (time_t)-1;
        }
        if (tloc) *tloc = (time_t)ts.tv_sec;
        return (time_t)ts.tv_sec;
    }
    errno = injected_errno;
    if (tloc) *tloc = injected_seconds;
    return injected_seconds;
}

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static int real_hmac(br_slice key, br_slice message, char out[45])
{
    if (!out || (!key.data && key.len) || (!message.data && message.len)) return -1;
    static const unsigned char empty[] = "";
    unsigned char digest[32];
    size_t len = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key.data ? key.data : empty, key.len,
                   message.data ? message.data : empty, message.len, digest, sizeof(digest), &len) || len != 32)
        return -1;
    return EVP_EncodeBlock((unsigned char *)out, digest, 32) == 44 ? 0 : -1;
}

int br_azure_hmac_sha256_base64(br_slice key, br_slice message, char out[45])
{
    ++hmac_calls;
    if (fail_hmac_after && --fail_hmac_after == 0) return 1;
    return real_hmac(key, message, out);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 24 && strlen(secret) == 36 && strlen(passphrase) == 30);
    CHECK(br_kucoin_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_kucoin_init(NULL, NULL) == -1);
    CHECK(br_kucoin_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_kucoin_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 736 && detector->version == 0 && !strcmp(detector->name, "KuCoin"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "KuCoin is a cryptocurrency exchange that provides various digital asset trading services. KuCoin API keys can be used to access and manage trading accounts, execute trades, and retrieve market data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "kucoin"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, const char *expected_key, const char *expected_pass, bool verified)
{
    size_t key_len = strlen(expected_key), pass_len = strlen(expected_pass);
    br_json *part = NULL;
    CHECK(result->detector_type == 736 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, expected_key, key_len));
    CHECK(result->raw_v2.len == key_len + pass_len);
    CHECK(!memcmp(result->raw_v2.data, expected_key, key_len));
    CHECK(!memcmp(result->raw_v2.data + key_len, expected_pass, pass_len));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), expected_key));
    CHECK(json_object_object_get_ex(result->secret_parts, "passphrase", &part) && !strcmp(json_object_get_string(part), expected_pass));
    CHECK(!json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_pairs(const br_detector *detector, const void *input, size_t len,
                         const char *const *keys, const char *const *passes, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_pair(&out.items[i], keys[i], passes[i], false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, len);
    CHECK(out.len == count);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[1600];
    const char *one_key[] = {key}, *one_pass[] = {passphrase};
    const char *both_pass[] = {passphrase, key};
    const char *same_keys[] = {key, key}, *same_pass[] = {passphrase, passphrase};
    const char *ordered_keys[] = {key, other_key}, *ordered_pass[] = {passphrase, passphrase};
    expect_pairs(detector, sample, strlen(sample), one_key, one_pass, 1);
    int n = snprintf(input, sizeof(input), "KUCOIN %s kucoin %s kucoin %s", passphrase, secret, key);
    expect_pairs(detector, input, (size_t)n, one_key, one_pass, 1);
    n = snprintf(input, sizeof(input), "kucoin\n%s\rkucoin %s kucoin %s", passphrase, secret, key);
    expect_pairs(detector, input, (size_t)n, one_key, one_pass, 1);
    n = snprintf(input, sizeof(input), "kucoin !@#$%%^& kucoin %s kucoin %s", secret, key);
    expect_pairs(detector, input, (size_t)n, one_key, (const char *[]){"!@#$%^&"}, 1);
    /* Trailing delimiter makes the spaced key a passphrase too. Do not drop it. */
    n = snprintf(input, sizeof(input), "%s ", sample);
    expect_pairs(detector, input, (size_t)n, same_keys, both_pass, 2);
    n = snprintf(input, sizeof(input), "kucoin %s\tkucoin %s\tkucoin %s kucoin %s ", key, key, secret, passphrase);
    expect_pairs(detector, input, (size_t)n, same_keys, same_pass, 2);
    n = snprintf(input, sizeof(input), "kucoin %s\tkucoin %s\tkucoin %s kucoin %s ", key, other_key, secret, passphrase);
    expect_pairs(detector, input, (size_t)n, ordered_keys, ordered_pass, 2);
    n = snprintf(input, sizeof(input), "kucoin %s kucoin %s", passphrase, secret);
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "kucoin %s kucoin %s", passphrase, key);
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "kucoin %s kucoin %s", secret, key);
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "kucoin%*s%s\tkucoin %s kucoin %s ", 41, "", key, secret, passphrase);
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "kucoin%*s%s\tkucoin %s kucoin %s ", 40, "", key, secret, passphrase);
    expect_pairs(detector, input, (size_t)n, one_key, one_pass, 1);
    n = snprintf(input, sizeof(input), "kucoin abcdef kucoin %s kucoin %s", secret, key);
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "kucoin %s", "X19c2539c53367c726a5c04c");
    expect_pairs(detector, input, (size_t)n, NULL, NULL, 0);
    expect_pairs(detector, "kucoin keyword is not close to the real key in the data\n = 'c19c2539c53367c726a5c04c' domain = '2313b299-7ba8-66b6-5b30-3e94050324ff' email = '_4K~W4|RHH--o}:BiwRhY9J2pl/5x,'",
                 strlen("kucoin keyword is not close to the real key in the data\n = 'c19c2539c53367c726a5c04c' domain = '2313b299-7ba8-66b6-5b30-3e94050324ff' email = '_4K~W4|RHH--o}:BiwRhY9J2pl/5x,'"),
                 NULL, NULL, 0);
    expect_pairs(detector, "kucoin key = 'X19c2539c53367c726a5c04c' domain = 'X313b299-7ba8-66b6-5b30-3e94050324ff' email = '_4Kix,'",
                 strlen("kucoin key = 'X19c2539c53367c726a5c04c' domain = 'X313b299-7ba8-66b6-5b30-3e94050324ff' email = '_4Kix,'"),
                 NULL, NULL, 0);
    memset(input, '.', 1100);
    n = snprintf(input + 1100, sizeof(input) - 1100, "kucoin %s", secret);
    CHECK(n > 0 && 1100 + (size_t)n < sizeof(input));
    memcpy(input, "kucoin ", 7);
    memcpy(input + 7, passphrase, strlen(passphrase));
    memcpy(input + 7 + strlen(passphrase), " kucoin ", 8);
    memcpy(input + 15 + strlen(passphrase), key, 24);
    expect_pairs(detector, input, 1100 + (size_t)n, one_key, one_pass, 1);
    expect_pairs(detector, "", 0, NULL, NULL, 0);
}

typedef struct { const char *key, *secret, *passphrase; int status, send_rc; const char *send_error, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 736 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.kucoin.com/api/v1/accounts"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 6);
    const char *names[] = {"Kc-Api-Key", "Kc-Api-Sign", "Kc-Api-Timestamp", "Kc-Api-Passphrase", "Kc-Api-Key-Version", "User-Agent"};
    for (size_t i = 0; i < 6; ++i) CHECK(!strcmp(request->headers[i].name, names[i]));
    CHECK(!strcmp(request->headers[0].value, row->key));
    CHECK(!strcmp(request->headers[4].value, "2"));
    CHECK(!strcmp(request->headers[5].value, steps->suffix ? "TruffleHog kucoin-offline" : "TruffleHog"));
    char *end = NULL;
    int64_t captured = strtoll(request->headers[2].value, &end, 10);
    time_t now = time(NULL);
    int64_t delta = captured - (int64_t)now * 1000;
    CHECK(end && !*end && now != (time_t)-1 && delta < 10000 && delta > -10000);
    char message[64], sign[45], pass_sign[45];
    int n = snprintf(message, sizeof(message), "%sGET/api/v1/accounts", request->headers[2].value);
    CHECK(n > 0 && (size_t)n < sizeof(message));
    br_slice secret_key = {(const unsigned char *)row->secret, strlen(row->secret)};
    CHECK(br_azure_hmac_sha256_base64(secret_key, (br_slice){(const unsigned char *)message, (size_t)n}, sign) == 0);
    CHECK(br_azure_hmac_sha256_base64(secret_key, (br_slice){(const unsigned char *)row->passphrase, strlen(row->passphrase)}, pass_sign) == 0);
    CHECK(strlen(sign) == 44 && sign[43] == '=' && !strcmp(request->headers[1].value, sign));
    CHECK(strlen(pass_sign) == 44 && !strcmp(request->headers[3].value, pass_sign));
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)}, .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static br_results run(const br_detector *detector, const void *input, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "kucoin-offline" : NULL};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, input, len);
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {199, 200, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .secret = secret, .passphrase = passphrase, .status = statuses[i],
            .body_error = i % 2 ? "synthetic read failure" : ""};
        script steps = {.rows = &row, .count = 1, .suffix = true};
        br_results out = run(detector, sample, strlen(sample), &steps);
        CHECK(out.len == 1);
        check_pair(&out.items[0], key, passphrase, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    char doubled[180];
    int n = snprintf(doubled, sizeof(doubled), "%s ", sample);
    const reply rows[] = {
        {key, secret, passphrase, 200, 0, NULL, "ignored"},
        {key, secret, key, 401, 0, NULL, "synthetic read failure"},
    };
    script steps = {.rows = rows, .count = 2};
    br_results out = run(detector, doubled, (size_t)n, &steps);
    CHECK(out.len == 2);
    check_pair(&out.items[0], key, passphrase, true);
    check_pair(&out.items[1], key, key, false);
    br_results_clear(&out);
    reply failed = {.key = key, .secret = secret, .passphrase = passphrase, .status = 200, .send_rc = 1,
        .send_error = "context deadline exceeded", .body_error = "synthetic read failure"};
    script fail_steps = {.rows = &failed, .count = 1};
    out = run(detector, sample, strlen(sample), &fail_steps);
    CHECK(out.len == 1);
    check_pair(&out.items[0], key, passphrase, false);
    br_results_clear(&out);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx live = {.transport = &transport};
    char *error = NULL;
    br_results dropped = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)sample, strlen(sample)},
                         &dropped, &error) == 0 && !error);
    CHECK(dropped.len == 0 && !http.calls && !http.releases);
    br_results_clear(&dropped);
    reply kept = {.key = key, .secret = secret, .passphrase = passphrase, .status = 200};
    script kept_steps = {.rows = &kept, .count = 1, .ctx = &live};
    http.inspect = inspect_request;
    http.user = &kept_steps;
    br_results sent = test_scan(detector, &live, true, sample, strlen(sample));
    CHECK(sent.len == 1 && http.calls == 1 && http.releases == 1);
    check_pair(&sent.items[0], key, passphrase, true);
    br_results_clear(&sent);
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_send(const br_detector *detector)
{
    char doubled[180];
    int n = snprintf(doubled, sizeof(doubled), "%s ", sample);
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, doubled, (size_t)n);
        CHECK(out.len == 2 && !http.calls && http.releases == (mode == 0 ? 0u : 2u));
        check_pair(&out.items[0], key, passphrase, false);
        check_pair(&out.items[1], key, key, false);
        br_results_clear(&out);
    }
}

static void preserve_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(out->items[0].secret_parts == parts);
}

static void owned_failures(const br_detector *detector)
{
    br_slice data = {(const unsigned char *)sample, strlen(sample)};
    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;

    test_http http = {0};
    br_slice none = {(const unsigned char *)"kucoin", 6};
    for (size_t capture = 1; capture <= 3; ++capture) {
        fail_size = 2 * sizeof(br_span);
        fail_after = capture;
        CHECK(detector->scan(detector, NULL, true, none, &out, &error) != 0 && error && !fail_after);
        CHECK(!strcmp(error, "out of memory iterating regex") && !http.calls && !http.releases);
        free(error); error = NULL;
        preserve_prior(&out, raw, saved, parts);
    }
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    preserve_prior(&out, raw, saved, parts);

    fail_size = 2 * sizeof(br_span);
    fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create KuCoin result") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_hmac_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_hmac_after);
    CHECK(!strcmp(error, "cannot sign KuCoin candidate") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    br_slice bad = {NULL, 4};
    CHECK(detector->scan(detector, NULL, true, bad, &out, &error) == -1 && error);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot create KuCoin result") && !fail_part_after && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    reply row = {.key = key, .secret = secret, .passphrase = passphrase, .status = 200};
    script steps = {.rows = &row, .count = 1};
    http.inspect = inspect_request; http.user = &steps; steps.ctx = &ctx;
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot append KuCoin result") && http.calls == 1 && http.releases == 1);
    out.cap = cap;
    free(error);
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);
}

static const char *clock_stamp;

static void inspect_clock(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    const reply *row = steps->rows;
    CHECK(http->calls == 1 && http->releases == 0 && ctx == steps->ctx);
    CHECK(request->detector_type == 736 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.kucoin.com/api/v1/accounts"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 6);
    const char *names[] = {"Kc-Api-Key", "Kc-Api-Sign", "Kc-Api-Timestamp", "Kc-Api-Passphrase", "Kc-Api-Key-Version", "User-Agent"};
    for (size_t i = 0; i < 6; ++i) CHECK(!strcmp(request->headers[i].name, names[i]));
    CHECK(!strcmp(request->headers[0].value, row->key));
    CHECK(!strcmp(request->headers[2].value, clock_stamp));
    CHECK(!strcmp(request->headers[4].value, "2"));
    char message[80], sign[45], pass_sign[45];
    int n = snprintf(message, sizeof(message), "%sGET/api/v1/accounts", clock_stamp);
    CHECK(n > 0 && (size_t)n < sizeof(message));
    br_slice secret_key = {(const unsigned char *)row->secret, strlen(row->secret)};
    CHECK(br_azure_hmac_sha256_base64(secret_key, (br_slice){(const unsigned char *)message, (size_t)n}, sign) == 0);
    CHECK(br_azure_hmac_sha256_base64(secret_key, (br_slice){(const unsigned char *)row->passphrase, strlen(row->passphrase)}, pass_sign) == 0);
    CHECK(strlen(sign) == 44 && sign[43] == '=' && !strcmp(request->headers[1].value, sign));
    CHECK(strlen(pass_sign) == 44 && pass_sign[43] == '=' && !strcmp(request->headers[3].value, pass_sign));
    http->response.status = 200;
}

static void expect_injected(const br_detector *detector, time_t seconds, int err, const char *stamp)
{
    injected_seconds = seconds;
    injected_errno = err;
    inject_time = true;
    clock_stamp = stamp;
    reply row = {.key = key, .secret = secret, .passphrase = passphrase, .status = 200};
    test_http http = {.inspect = inspect_clock};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    script steps = {.rows = &row, .count = 1, .ctx = &ctx};
    http.user = &steps;
    char *error = NULL;
    br_results out = {0};
    br_slice data = {(const unsigned char *)sample, strlen(sample)};
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == 0 && !error);
    inject_time = false;
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    check_pair(&out.items[0], key, passphrase, true);
    br_results_clear(&out);
}

static void expect_nil_signed(const br_detector *detector, time_t seconds, int err)
{
    injected_seconds = seconds;
    injected_errno = err;
    inject_time = true;
    size_t before = hmac_calls;
    test_http http = {0};
    char *error = NULL;
    br_results out = {0};
    br_slice data = {(const unsigned char *)sample, strlen(sample)};
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    inject_time = false;
    CHECK(out.len == 0 && !http.calls && !http.releases && hmac_calls == before + 2);
    br_results_clear(&out);
}

static void clock_range(const br_detector *detector)
{
    CHECK(sizeof(time_t) >= 8);
    expect_injected(detector, 1700000000, 0, "1700000000000");
    expect_injected(detector, (time_t)-1, 0, "-1000");
    expect_nil_signed(detector, (time_t)-1, 0);
    expect_injected(detector, (time_t)9223372036854776LL, 0, "-9223372036854775616");
    expect_nil_signed(detector, (time_t)9223372036854776LL, 0);

    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    br_slice data = {(const unsigned char *)sample, strlen(sample)};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    injected_seconds = (time_t)-1;
    injected_errno = EIO;
    inject_time = true;
    size_t before = hmac_calls;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) != 0 && error && !http.calls && !http.releases);
    CHECK(!strcmp(error, "cannot sign KuCoin candidate") && hmac_calls == before);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && hmac_calls == before);
    CHECK(!strcmp(error, "cannot sign KuCoin candidate"));
    free(error);
    inject_time = false;
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);

    reply row = {.key = key, .secret = secret, .passphrase = passphrase, .status = 200};
    script steps = {.rows = &row, .count = 1};
    br_results ordinary = run(detector, sample, strlen(sample), &steps);
    CHECK(ordinary.len == 1 && ordinary.items[0].verified);
    br_results_clear(&ordinary);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    shared_send(detector);
    owned_failures(detector);
    clock_range(detector);
    return test_finish("KuCoin");
}
