/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

#define KEY_A "Ab3d_Ef5-Gh7Jk9Lm2Np"
#define KEY_B "9zY8xW7vU6tS5rQ4pO3n"
static const char *const keys[] = {
    KEY_A, KEY_B, "-b3d_Ef5-Gh7Jk9Lm2Np", "Ab3d_Ef5-Gh7Jk9Lm2N-", "-b3d_Ef5-Gh7Jk9Lm2N-",
};
/* Independent Python standard Base64 goldens, not the production encoder. */
static const char *const auths[] = {
    "Basic QWIzZF9FZjUtR2g3Sms5TG0yTnA6", "Basic OXpZOHhXN3ZVNnRTNXJRNHBPM246",
    "Basic LWIzZF9FZjUtR2g3Sms5TG0yTnA6", "Basic QWIzZF9FZjUtR2g3Sms5TG0yTi06",
    "Basic LWIzZF9FZjUtR2g3Sms5TG0yTi06",
};
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static size_t encoder_calls, fail_encoder_after;
static int encoder_failure = 27;
static bool fail_agent;
static const char *borrowed_auth, *borrowed_url, *expected_auth;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n); if (p) memcpy(p, s, n); return p;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
/* Same interposition as Guru: normal calls use libcrypto's streaming encoder. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls; CHECK(len == 21 && in[20] == ':');
    if (fail_encoder_after && --fail_encoder_after == 0) return encoder_failure;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[64]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 28); out[at] = '\0'; return (int)at;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_hiveage_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_hiveage_init(NULL, NULL) != 0);
    CHECK(br_hiveage_init(&d, &error) == 0 && d && !error);
    CHECK(br_hiveage_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 572 && !d->version && !strcmp(d->name, "Hiveage") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Hiveage is an online invoicing and billing software. Hiveage API keys can be used to access and manage invoicing and billing data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "hiveage"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 572, key, "key");
    CHECK(r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 20);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction_and_boundaries(const br_detector *d)
{
    const struct { const char *input, *key; } cases[] = {
        {"hIvEaGe " KEY_A, KEY_A}, {"prefixHIVEAGEsuffix::" KEY_B, KEY_B},
        {"hiveage\r\n" KEY_A, KEY_A}, {"hiveage \t" KEY_A "\r\n", KEY_A},
        {"hiveage -" KEY_A "-", KEY_A}, {"hiveage _" KEY_A, NULL},
        {"hiveage " KEY_A "_", NULL}, {"hiveage " KEY_A "x", NULL},
        {"hiveage Ab3d_Ef5-Gh7Jk9Lm2N", NULL}, {"hiveage Ab3d_Ef5+Gh7Jk9Lm2Np", NULL},
        {KEY_A, NULL}, {KEY_A " hiveage", NULL}, {"hive " KEY_A, NULL},
        {"hiveage-b3d_Ef5-Gh7Jk9Lm2Np", keys[2]}, {"hiveage -b3d_Ef5-Gh7Jk9Lm2Np", NULL},
        {"hiveage Ab3d_Ef5-Gh7Jk9Lm2N-x", keys[3]}, {"hiveage Ab3d_Ef5-Gh7Jk9Lm2N-", NULL},
        {"hiveage-b3d_Ef5-Gh7Jk9Lm2N-x", keys[4]},
        {"hiveage _b3d_Ef5-Gh7Jk9Lm2N_", "_b3d_Ef5-Gh7Jk9Lm2N_"},
        {"hiveage ____________________", "____________________"},
        {"hiveage--------------------x", "--------------------"},
        {"hiveage ABCDEFGHIJKLMNOPQRST", "ABCDEFGHIJKLMNOPQRST"},
        {"hiveage 01234567890123456789", "01234567890123456789"},
        {"hiveage " KEY_A " " KEY_B, KEY_A}, /* Whole matches consume their prefix. */
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
        extract_case(d, cases[i].input, strlen(cases[i].input), cases[i].key);
    unsigned char input[240];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "hiveage", 7); memset(input + 7, ':', gap); memcpy(input + 7 + gap, KEY_A, 20);
        extract_case(d, input, 7 + gap + 20, gap == 40 ? KEY_A : NULL);
        input[8] = '\r'; input[9] = '\n'; input[10] = '\0';
        extract_case(d, input, 7 + gap + 20, gap == 40 ? KEY_A : NULL);
        memcpy(input, "hiveage", 7);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 7 + 4*i, "💡", 4);
        memcpy(input + 7 + 4*gap, KEY_A, 20);
        extract_case(d, input, 7 + 4*gap + 20, gap == 40 ? KEY_A : NULL);
    }
    extract_case(d, NULL, 0, NULL);
}

typedef struct { const char *const *auths; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 572 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://mltb8350.hiveage.com/api/network"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    expected_auth = e->auths[at]; CHECK(!strcmp(request->headers[1].value, expected_auth));
    CHECK(strlen(request->headers[1].value) == 34 && !strchr(request->headers[1].value, '='));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, e->agent));
    /* Retain provider-original values only, never prepared headers/request/UA. */
    borrowed_auth = request->headers[1].value; borrowed_url = request->url;
}
static void release_response(void *user, br_http_response *response)
{
    if (borrowed_auth) {
        CHECK(!strcmp(borrowed_auth, expected_auth));
        CHECK(!strcmp(borrowed_url, "https://mltb8350.hiveage.com/api/network"));
    } else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_auth = borrowed_url = expected_auth = NULL;
    test_http_release(user, response);
}
static void occurrences_and_base64_order(const br_detector *d)
{
    const char input[] = "hiveage " KEY_A "\nhiveage " KEY_B "\nhiveage " KEY_A;
    const char *sequence[] = {auths[0], auths[1], auths[0]};
    expected e = {.auths = sequence, .count = 3, .agent = "TruffleHog hiveage-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hiveage-offline"}; e.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        size_t before = encoder_calls; br_results out = test_scan(d, &ctx, pass != 0, input, sizeof(input)-1);
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        CHECK(encoder_calls == before + (pass ? 3u : 0u));
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], i == 1 ? KEY_B : KEY_A, pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    for (size_t i = 2; i < 5; ++i) {
        char contextual[60]; int n = snprintf(contextual, sizeof(contextual), "hiveage%s%s%s", i == 3 ? " " : "", keys[i], i == 2 ? "" : "x");
        const char *auth[] = {auths[i]}; e.auths = auth; e.count = 1; http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, contextual, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result(&out.items[0], keys[i], true); br_results_clear(&out);
    }
    size_t before = encoder_calls; br_results out = test_scan(d, NULL, true, input, sizeof(input)-1);
    CHECK(!out.len && encoder_calls == before + 3); br_results_clear(&out);
    fail_encoder_after = 1; before = encoder_calls;
    out = test_scan(d, NULL, false, input, sizeof(input)-1);
    CHECK(out.len == 3 && encoder_calls == before && fail_encoder_after == 1); br_results_clear(&out);
    const int failed_returns[] = {27, 29, -1};
    for (size_t i = 0; i < sizeof(failed_returns)/sizeof(failed_returns[0]); ++i) {
        encoder_failure = failed_returns[i]; fail_encoder_after = 1; char *error = NULL;
        CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, &error) != 0 && error);
        CHECK(!strcmp(error, "Hiveage native Base64 encoding failed") && !out.len && !fail_encoder_after);
        free(error); br_results_clear(&out);
    }
    encoder_failure = 27;
}
static bool fail_headers(void *user) { (void)user; fail_size = 3*sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void status_body_and_shared_failures(const br_detector *d)
{
    const char input[] = "hiveage " KEY_A; const char *auth[] = {auths[0]};
    expected e = {.auths = auth, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0,199,200,201,204,206,299,300,401,403,429,500};
    static const unsigned char body[] = {0,0xff,'{'};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i%2 ? "ignored" : ""};
        br_results out = test_scan(d, &ctx, true, input, sizeof(input)-1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], KEY_A, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1,"timeout"}, {-7,"cannot create Hiveage result"}, {1,"out of memory constructing HTTP headers"},
        {-1,NULL}, {1,KEY_A}, {7,"Hiveage native Base64 encoding failed"},
    };
    for (size_t i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, sizeof(input)-1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    size_t cancellations = 0; br_transport no_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_send}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts)/sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, sizeof(input)-1);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 2 || i == 3 ? 1u : 0u));
        result(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5) && !strcmp(prior->verification_error, "caller-owned"));
}
static void owned_failures_and_rollback(const br_detector *d)
{
    const char input[] = "hiveage " KEY_A "\nhiveage " KEY_B;
    const char *sequence[] = {auths[0], auths[1]}; expected e = {.auths = sequence, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 21; fail_after = 2; } /* Second capture, before any verification. */
        if (failure == 1) { fail_size = 20; fail_after = 2; } /* Second finding Raw. */
        if (failure == 2) fail_part_after = 2; /* Positive JSON insertion failure. */
        if (failure == 3) fail_encoder_after = 2;
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && !fail_encoder_after);
        CHECK(http.calls == (failure ? 1u : 0u) && http.releases == http.calls && !borrowed_auth);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Finding failure is fatal before encoding/nil constructor skip. */
    size_t before = encoder_calls; fail_size = 20; fail_after = 1; fail_encoder_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, &error) != 0 && error && !fail_after);
    CHECK(encoder_calls == before && fail_encoder_after == 1); check_prior(&out, &prior); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, &error) != 0 && error && !fail_encoder_after);
    CHECK(encoder_calls == before + 1); check_prior(&out, &prior); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; /* Shared push reports a positive failure. */
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, &error) != 0 && error && !strcmp(error, "cannot append Hiveage result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error);
    fail_encoder_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input)-1}, &out, NULL) != 0 && !fail_encoder_after);
    check_prior(&out, &prior); br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction_and_boundaries(d); occurrences_and_base64_order(d);
    status_body_and_shared_failures(d); owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_encoder_after && !fail_agent && !borrowed_auth && !borrowed_url && !expected_auth);
    return test_finish("Hiveage");
}
