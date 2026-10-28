/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>
#include <openssl/evp.h>

static const char key[] = "g7h8j9k0m1n2p3q4", other[] = "r5s6t7u8v9w0x1y2";
/* Independently generated/decoded with Python stdlib base64.b64encode(KEY +
 * b':'), NOT the production encoder/projection. Exactly one '=' padding byte. */
static const char *const goldens[] = {
    "Basic ZzdoOGo5azBtMW4ycDNxNDo=", "Basic cjVzNnQ3dTh2OXcweDF5Mjo=",
};
static size_t encoder_calls, fail_encoder_after;
static int encoder_failure;
static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_size;

/* Observe/fail the existing native codec, not an invented provider/API seam.
 * Normal interposed calls use OpenSSL's separate streaming codec and independent
 * fixed goldens; the production object directly calls linked EVP_EncodeBlock. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls;
    CHECK(len == 17 && in[16] == ':');
    size_t which = !memcmp(in, key, 16) ? 0u : 1u;
    CHECK(!memcmp(in, which ? other : key, 16));
    if (fail_encoder_after && --fail_encoder_after == 0) return encoder_failure;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[64]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 24 && out[23] == '=' && out[22] != '='); out[at] = '\0';
    CHECK(!memcmp(out, goldens[which] + 6, 25)); return (int)at;
}
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, previous < size ? previous : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 16 && strlen(other) == 16);
    CHECK(br_formcraft_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:formcraft)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_formcraft_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_formcraft_init(&d, &error) == 0 && d && !error);
    CHECK(br_formcraft_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 812 && d->version == 0 && !strcmp(d->name, "Formcraft") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Formcraft is a form building and data collection service. Formcraft keys can be used to access and manage forms and collected data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "formcraft"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 812, expected, "key");
    CHECK(r->raw.len == 16 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[120], changed[18];
    const char *good[] = {"formcraft='%s'", "FORMCRAFT %s", "FoRmCrAfT\r\n%s", "preformcraftsuffix:(%s)", "formcraft-%s-"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, strlen(input), key); }
    const char *bad[] = {"%s", "%s formcraft", "form craft %s", "formcraft%s", "formcraft _%s", "formcraft %s_", "formcraft X%s", "formcraft %sa"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, strlen(input), NULL); }
    extraction_case(d, "formcraft zzzzzzzzzzzzzzzz", sizeof("formcraft zzzzzzzzzzzzzzzz") - 1, "zzzzzzzzzzzzzzzz");
    extraction_case(d, "formcraft 0000000000000000", sizeof("formcraft 0000000000000000") - 1, "0000000000000000");
    memcpy(changed, key, sizeof(key)); changed[0] = 'A'; snprintf(input, sizeof(input), "FORMCRAFT %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[15] = '\0'; snprintf(input, sizeof(input), "formcraft %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[16] = 'a'; changed[17] = '\0'; snprintf(input, sizeof(input), "formcraft %s", changed); extraction_case(d, input, strlen(input), NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "formcraft%*s%s", (int)gap, "", key); CHECK(n > 0);
        extraction_case(d, input, (size_t)n, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "formcraft%c%s", 0, key); CHECK(n > 0); extraction_case(d, input, (size_t)n, key);
    extraction_case(d, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, rc; bool empty_body; } row;
typedef struct {
    const row *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_auth;
    size_t arm_call, arm_push;
} script;
static void authorization(const char *value, const char *expected)
{
    size_t which = !strcmp(expected, key) ? 0u : 1u; CHECK(!strcmp(expected, which ? other : key));
    CHECK(strlen(value) == 30 && !memcmp(value, goldens[which], 31));
    /* Independent native BLOCK decoder checks actual borrowed header bytes:
     * KEY first, literal colon, EMPTY password, standard '=' padding. */
    unsigned char decoded[18];
    CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)value + 6, 24) == 18);
    CHECK(!memcmp(decoded, expected, 16) && decoded[16] == ':' && value[29] == '=' && value[28] != '=');
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const row *reply = &steps->rows[at];
    CHECK(request->detector_type == 812 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://formcrafts.com/api/v1/"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, reply->key); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog formcraft-offline"));
    static const unsigned char garbage[] = "\0\xff {not JSON} \"status\":401";
    http->response = (br_http_response){.status = reply->status,
        .body = reply->empty_body ? (br_slice){0} : (br_slice){garbage, sizeof(garbage) - 1},
        .body_error = reply->empty_body ? "" : "ignored response body read error"};
    http->send_error = reply->send_error; http->send_rc = reply->rc;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) fail_push_size = steps->arm_push;
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth); authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key);
    steps->borrowed_auth = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "formcraft-offline"}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static void occurrences_constructor_order_and_statuses(const br_detector *d)
{
    char input[110]; snprintf(input, sizeof(input), "formcraft %s\nFORMCRAFT %s\nformcraft %s", key, other, key);
    row replies[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .empty_body = true},
        {.key = key, .status = 200, .rc = -7, .send_error = "Formcraft native Base64 encoding failed"}};
    script steps = {.rows = replies, .count = 3}; size_t before = encoder_calls;
    br_results out = run(d, input, &steps); CHECK(out.len == 3 && encoder_calls == before + 3);
    finding(&out.items[0], key, true); finding(&out.items[1], other, true); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    before = encoder_calls; out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3 && encoder_calls == before);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], i == 1 ? other : key, false);
    br_results_clear(&out);
    before = encoder_calls; out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !out.items && !out.cap && encoder_calls == before + 3); br_results_clear(&out); /* Encode BEFORE nil-context skip. */
    snprintf(input, sizeof(input), "formcraft %s", key);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        row reply = {.key = key, .status = statuses[i], .empty_body = i % 2 != 0}; steps = (script){.rows = &reply, .count = 1};
        out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    char echo[120]; snprintf(echo, sizeof(echo), "out of memory %s echoed %s", key, key);
    const char *errors[] = {echo, "", "cannot append Formcraft finding"};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        row reply = {.key = key, .status = 200, .rc = i % 2 ? 1 : -1, .send_error = errors[i]}; steps = (script){.rows = &reply, .count = 1};
        out = run(d, input, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    } /* Whole mixed shared send domain suppressed, no setter/classifier. */
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void actual_shared_failures(const br_detector *d)
{
    char input[50]; snprintf(input, sizeof(input), "formcraft %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u)); finding(&out.items[0], key, false); br_results_clear(&out);
    }
}
static br_results caller_owned(void)
{
    br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("prior diagnostic"); CHECK(prior.verification_error && br_results_push(&out, &prior) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error, unsigned char *raw, br_json *parts, char *cause)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    CHECK(out->items[0].verified && out->items[0].raw.data == raw && out->items[0].secret_parts == parts && out->items[0].verification_error == cause && !strcmp(cause, "prior diagnostic"));
    free(error); br_results_clear(out);
}
static void owned_failures_and_stage_order(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "formcraft %s\nFORMCRAFT %s", key, other);
    const size_t sizes[] = {2 * sizeof(br_span), 17, 16};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures, enc_before = encoder_calls; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1 && encoder_calls == enc_before);
        rolled_back(&out, rc, error, raw, parts, cause); /* Capture/finding fail BEFORE encoding/constructor skip. */
    }
    const row replies[] = {{.key = key, .status = 200}, {.key = other, .status = 200, .rc = 1, .send_error = "suppressed before owned push failure"}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        script steps = {.rows = replies, .count = 1}; size_t before = encoder_calls; fail_part_after = 2;
        int rc = mode == 0 ? invoke(d, input, &steps, &out, &error) : d->scan(d, NULL, mode == 2, text(input), &out, &error);
        CHECK(!fail_part_after && encoder_calls == before + (mode == 1 ? 0u : 1u)); rolled_back(&out, rc, error, raw, parts, cause);
    }
    /* Actual negative crypto failure BEFORE nil-context skip. */
    br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
    size_t before = encoder_calls; fail_encoder_after = 1; encoder_failure = -1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error);
    CHECK(!fail_encoder_after && encoder_calls == before + 1 && error && !strcmp(error, "Formcraft native Base64 encoding failed")); rolled_back(&out, rc, error, raw, parts, cause);
    /* Short-POSITIVE crypto failure after the first verified finding appended,
     * BEFORE second send: fatal with caller-preserving invocation rollback. */
    out = caller_owned(); raw = out.items[0].raw.data; parts = out.items[0].secret_parts; cause = out.items[0].verification_error; error = NULL;
    script steps = {.rows = replies, .count = 1}; before = encoder_calls; fail_encoder_after = 2; encoder_failure = 1;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_encoder_after && encoder_calls == before + 2); rolled_back(&out, rc, error, raw, parts, cause);
    out = caller_owned(); out.cap = out.len; raw = out.items[0].raw.data; parts = out.items[0].secret_parts; cause = out.items[0].verification_error; error = NULL;
    steps = (script){.rows = replies, .count = 2, .arm_call = 2, .arm_push = 4 * sizeof(br_result)};
    before = allocation_failures; rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error, raw, parts, cause);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_constructor_order_and_statuses(d);
    actual_shared_failures(d);
    owned_failures_and_stage_order(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_size && !fail_encoder_after);
    return test_finish("Formcraft");
}
