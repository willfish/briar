/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

#include <openssl/evp.h>
#include <time.h>

static const char key1[] = "g7h9j2k5m6n8p3q4r1s0t";
static const char key2[] = "z9y8x7w6v5u4t3s2r1q0p";
/* Independent standard-Base64(KEY + ':') goldens, including the empty password. */
static const char *const goldens[] = {
    "Basic ZzdoOWoyazVtNm44cDNxNHIxczB0Og==",
    "Basic ejl5OHg3dzZ2NXU0dDNzMnIxcTBwOg==",
};
static size_t encoder_calls, fail_encoder_after, fail_part_after;
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, guard_rejections;
static int encoder_failure;
static bool fail_guard_error_copy, observe_auth_lifetime;
static const char *borrowed_auth, *borrowed_golden;

/* Observe/fail the actual native encoder, not a new production auth seam.
 * Normal calls use OpenSSL's streaming codec and the independent goldens. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls;
    CHECK(len == 22 && in[21] == ':');
    size_t which = !memcmp(in, key1, 21) ? 0 : 1;
    CHECK(!memcmp(in, which ? key2 : key1, 21));
    if (fail_encoder_after && --fail_encoder_after == 0) return encoder_failure;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[80]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx);
    CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail);
    EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i)
        if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 32 && out[31] == '=' && out[30] == '=' && out[29] != '=');
    out[at] = '\0';
    CHECK(!memcmp(out, goldens[which] + 6, 33));
    if (observe_auth_lifetime) {
        CHECK(!borrowed_auth);
        borrowed_auth = (const char *)out - 6;
        borrowed_golden = goldens[which];
        CHECK(!memcmp(borrowed_auth, borrowed_golden, 39));
    }
    return (int)at;
}

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (!strcmp(text, "unsupported HTTP request coalescing")) {
        ++guard_rejections;
        if (fail_guard_error_copy) { fail_guard_error_copy = false; return NULL; }
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 21 && strlen(key2) == 21);
    CHECK(br_databox_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Databox detector output"));
    free(error); error = NULL;
    CHECK(br_databox_init(NULL, NULL) == -1);
    fail_alloc_size = sizeof("(?i:databox)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_databox_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_databox_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_databox_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 834 && detector->version == 0 && !strcmp(detector->name, "Databox"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Databox is a business analytics platform that pulls all your data into one place, so you can track performance and discover insights in real-time. Databox API keys can be used to access and modify data within your Databox account."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "databox"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    /* Default registration/selection is parent-owned, not asserted by this direct factory test. */
    return detector;
}

static void check_result(const br_result *result, const char *key)
{
    test_key_result(result, 834, key, "key");
    CHECK(result->raw.len == 21 && !result->verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 21 && !memcmp(json_object_get_string(part), key, 21));
}

static void unexpected_send(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx; (void)request;
    CHECK(!"Databox's nonempty coalescing key must be rejected BEFORE any send callback");
}

static void release_guarded(void *user, br_http_response *response)
{
    CHECK(response && !response->status && !response->headers && !response->nheaders);
    CHECK(!response->body.data && !response->body.len && !response->body_error);
    if (observe_auth_lifetime) {
        CHECK(borrowed_auth && borrowed_golden && strlen(borrowed_auth) == 38);
        CHECK(!memcmp(borrowed_auth, borrowed_golden, 39)); /* Includes NUL; live THROUGH release. */
        borrowed_auth = borrowed_golden = NULL;
    }
    test_http_release(user, response);
}

static br_transport guarded_transport(test_http *http)
{
    return (br_transport){http, test_http_send, release_guarded};
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {.inspect = unexpected_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (expected) check_result(&results.items[0], expected);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[23];
    const struct { const char *format; bool matches; } cases[] = {
        {"databox '%s'", true}, {"DATAbox=%s", true}, {"predataboxsuffix:%s", true},
        {"databox\r\n%s", true}, {"databox\r%s", true}, {"databox\n%s", true},
        {"databox +%s/", true}, {"%s", false}, {"%s databox", false},
        {"data box %s", false}, {"databox%s", false}, {"databox x%s", false},
        {"databox _%s", false}, {"databox %s_", false}, {"databox %s9", false},
        {"databox %.20s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char disallowed[] = "AFZ_-+./";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key1, sizeof(key1)); changed[10] = disallowed[i];
        snprintf(input, sizeof(input), "DATABOX %s", changed);
        extraction_case(detector, input, strlen(input), NULL); /* Only the keyword is CI. */
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "databox", 7); size_t at = 7;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, 21); at += 21;
            extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    const char low_entropy[] = {'a', 'z', '0'};
    for (size_t i = 0; i < sizeof(low_entropy); ++i) {
        memset(changed, low_entropy[i], 21); changed[21] = '\0';
        snprintf(input, sizeof(input), "databox %s", changed);
        extraction_case(detector, input, strlen(input), changed); /* Not hex-only; no local entropy/FP filter. */
    }
    snprintf(input, sizeof(input), "databox %s %s", key1, key2);
    extraction_case(detector, input, strlen(input), key1); /* Non-overlapping whole matches. */
    snprintf(input, sizeof(input), "databox databox %s", key1);
    extraction_case(detector, input, strlen(input), key1);
    int n = snprintf(input, sizeof(input), "databox%c%s", 0, key1);
    CHECK(n == 29); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\ndatabox %s\n\xff", key1);
    extraction_case(detector, input, (size_t)n, key1); /* No invented global UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

static void unchanged_shared_guard(void)
{
    static const unsigned char key[] = "834:g7h9j2k5m6n8p3q4r1s0t";
    CHECK(sizeof(key) - 1 == 25 && !memcmp(key + 4, key1, 21));
    test_http http = {.response = {.status = 204}, .inspect = unexpected_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const br_http_request request = {
        .method = "POST", .url = "https://synthetic.invalid/coalescing-control",
        .profile = BR_HTTP_SANE, .detector_type = 834, .dedup_key = {key, sizeof(key) - 1},
    };
    br_http_response response = {0}; char *error = NULL;
    CHECK(br_http_send(&ctx, &request, &response, &error) != 0 && error);
    CHECK(!strcmp(error, "unsupported HTTP request coalescing") && !http.calls);
    free(error); br_http_release(&ctx, &response);
    CHECK(!http.calls && http.releases == 1 && http.response.status == 204);
    /* This is only the mandatory guard, never provider success/coalescing evidence. */
}

static void occurrences_and_skips(const br_detector *detector)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "databox %s\nDATABOX %s\ndatabox %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 204, .body_error = "UNUSED"}, .inspect = unexpected_send};
    br_transport transport = guarded_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "databox-offline"};
    for (int pass = 0; pass < 3; ++pass) {
        size_t before = encoder_calls, guards = guard_rejections;
        observe_auth_lifetime = pass != 0;
        br_results results = test_scan(detector, &ctx, pass != 0, input, (size_t)n);
        CHECK(results.len == 3 && !http.calls && http.releases == (pass ? 3u : 0u));
        CHECK(encoder_calls == before + (pass ? 3u : 0u) && guard_rejections == guards + (pass ? 3u : 0u));
        CHECK(!borrowed_auth && http.response.status == 204 && !strcmp(http.response.body_error, "UNUSED"));
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
        br_results_clear(&results); http.releases = 0;
    } /* Repeated occurrences and repeated scans are not a persistent verification cache. */
    observe_auth_lifetime = false;
    size_t before = encoder_calls;
    br_results results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && encoder_calls == before + 3 && !http.calls && !http.releases);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3 && encoder_calls == before + 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i]);
    br_results_clear(&results);
    /* Encoding precedes nil-context skips. This borrowed transport never
     * consumes the prepared response; owned-client coverage is separate. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "databox %s", key1);
    test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "invalid\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = encoder_calls, guards = guard_rejections;
        observe_auth_lifetime = i != 0;
        if (i == 1) fail_guard_error_copy = true; /* Actual shared diagnostic allocation can fail too. */
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(encoder_calls == before + 1 && guard_rejections == guards + (i ? 1u : 0u));
        CHECK(!fail_guard_error_copy && !borrowed_auth);
        check_result(&results.items[0], key1); br_results_clear(&results); http.releases = 0;
    }
    observe_auth_lifetime = false;
    CHECK(!cancellations); /* Coalescing guard precedes interruption/header setup, not cancellation parity. */
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
    CHECK(results->items[0].secret_parts == prior->secret_parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(prior->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "databox %s\ndatabox %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe); /* Real positive helper failure. */
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = unexpected_send}; br_transport transport = guarded_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_result sentinel = {0}; br_results results = {0};
        CHECK(br_finding_key(&sentinel, 777, "prior", "key") == 0);
        sentinel.verified = true; sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        CHECK(br_results_push(&results, &sentinel) == 0); br_result prior = results.items[0];
        const char *expected[] = {
            "out of memory iterating regex", "out of memory collecting detector captures",
            "out of memory copying detector capture", "cannot create Databox result", "cannot create Databox result",
            "Databox native Base64 encoding failed",
        };
        for (int failure = 0; failure < (mode == 0 ? 5 : 6); ++failure) {
            if (failure == 0) { fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; }
            if (failure == 1) { fail_alloc_size = 8 * sizeof(size_t); fail_alloc_after = 2; }
            if (failure == 2) { fail_alloc_size = 22; fail_alloc_after = 2; }
            if (failure == 3) { fail_alloc_size = 21; fail_alloc_after = 2; }
            if (failure == 4) fail_part_after = 2;
            if (failure == 5) { fail_encoder_after = 2; encoder_failure = 1; }
            observe_auth_lifetime = mode == 1;
            size_t before = encoder_calls, allocs = allocation_failures, guards = guard_rejections;
            CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error);
            CHECK(!strcmp(error, expected[failure]) && !fail_alloc_after && !fail_part_after && !fail_encoder_after);
            CHECK(allocation_failures == allocs + (failure < 4 ? 1u : 0u));
            size_t encoded = mode == 0 || failure < 3 ? 0 : failure == 5 ? 2 : 1;
            CHECK(encoder_calls == before + encoded);
            size_t sent = mode == 1 && failure >= 3 ? 1 : 0;
            CHECK(!http.calls && http.releases == sent && guard_rejections == guards + sent && !borrowed_auth);
            check_prior(&results, &prior); free(error); error = NULL; http.releases = 0;
        }
        observe_auth_lifetime = false;
        if (mode != 0) {
            const int failures[] = {-1, 0, 31, 33};
            for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
                fail_encoder_after = 1; encoder_failure = failures[i]; size_t before = encoder_calls;
                CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, true, data, &results, &error) == -1 && error);
                CHECK(!strcmp(error, "Databox native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 1);
                CHECK(!http.calls && !http.releases); check_prior(&results, &prior); free(error); error = NULL;
            }
        }
        /* Finding failure must precede even nil-context skip and encoding. */
        fail_part_after = 1; size_t before = encoder_calls;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot create Databox result") && !fail_part_after && encoder_calls == before);
        check_prior(&results, &prior); free(error); error = NULL;
        /* The real append guard returns +1; normalize it without losing caller data. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, mode == 1, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append Databox result")); results.cap = capacity;
        CHECK(!http.calls && http.releases == (mode == 1 ? 1u : 0u));
        check_prior(&results, &prior); free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == 0);
        check_prior(&results, &prior); br_results_clear(&results);
    }
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    br_results results = {0};
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !results.len && !fail_alloc_after);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(results.len == 2); check_result(&results.items[0], key1); check_result(&results.items[1], key2);
    br_results_clear(&results);
}

/* Fake bytes only: the real Databox POST mutates remote metrics. This block
 * exercises the private owned client, not a borrowed-transport key bypass. */
typedef struct {
    test_http http;
    const br_http_request *pending;
    br_http_response *raw;
    size_t which;
    int64_t deadline;
    bool destroyed;
} databox_backend;

static int64_t databox_now_ms(void)
{
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void databox_owned_request(const databox_backend *fake, const br_http_request *request)
{
    static const unsigned char payload[] =
        "{\n"
        "\t\t\t\t\"data\":[\n"
        "\t\t\t\t  {\n"
        "\t\t\t\t\t\"$sales\": 420,\n"
        "\t\t\t\t\t\"$visitors\": 123000\n"
        "\t\t\t\t  }\n"
        "\t\t\t\t]\n"
        "\t\t\t  }";
    const char *key = fake->which ? key2 : key1;
    CHECK(!fake->destroyed && request == fake->pending);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://push.databox.com"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 834);
    /* The detached winner retains a five-second entry deadline; preparation
     * can reduce the remaining timeout by scheduling elapsed time. */
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 5000);
    CHECK(request->dedup_key.len == 25 && !memcmp(request->dedup_key.data, "834:", 4));
    CHECK(!memcmp(request->dedup_key.data + 4, key, 21));
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/vnd.databox.v2+json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization") && !strcmp(request->headers[2].value, goldens[fake->which]));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog databox-offline"));
}

static int databox_owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                              br_http_response *response, char **error)
{
    databox_backend *fake = user;
    CHECK(!fake->pending && !fake->raw);
    fake->pending = request; fake->raw = response;
    fake->deadline = ctx->deadline_monotonic_ms;
    CHECK(!ctx->cancelled && !ctx->cancel_user && !strcmp(ctx->user_agent, "databox-offline"));
    databox_owned_request(fake, request);
    return test_http_send(&fake->http, ctx, request, response, error);
}

static void databox_owned_release(void *user, br_http_response *response)
{
    databox_backend *fake = user;
    CHECK(response == fake->raw && fake->http.calls == 1 && !fake->http.releases);
    databox_owned_request(fake, fake->pending); /* Exact request stays live through raw release. */
    test_http_release(&fake->http, response);
    fake->pending = NULL; fake->raw = NULL;
}

static void databox_owned_destroy(void *user)
{
    databox_backend *fake = user;
    CHECK(!fake->destroyed && !fake->pending && !fake->raw);
    CHECK(fake->http.calls == 1 && fake->http.releases == 1);
    fake->destroyed = true;
}

static void owned_client_verification(const br_detector *detector)
{
    static const struct { int status, send_rc; const char *body_error; bool verified; } cases[] = {
        {200, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {401, 0, NULL, false}, {500, 0, NULL, false},
        {204, 1, NULL, false}, {201, 0, "synthetic body read failure", false},
    };
    static const unsigned char body[] = {'o', 'k', 0, 0xff};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        databox_backend fake = {
            .http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)},
                                 .body_error = cases[i].body_error},
                     .send_rc = cases[i].send_rc,
                     .send_error = cases[i].send_rc ? "synthetic send failure" : NULL},
            .which = i % 2,
        };
        br_http_owned_backend backend = {
            .transport = {&fake, databox_owned_send, databox_owned_release},
            .destroy = databox_owned_destroy,
        };
        br_http_client *client = NULL; char *error = NULL;
        CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &error) == 0 && client && !error);
        const br_transport *transport = br_http_client_transport(client);
        CHECK(br_http_client_is_owned(transport));
        br_scan_ctx ctx = {.transport = transport, .user_agent = "databox-offline"};
        const char *key = fake.which ? key2 : key1;
        char input[64]; snprintf(input, sizeof(input), "databox %s", key);
        size_t guards = guard_rejections, encoders = encoder_calls;
        int64_t before = databox_now_ms();
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        int64_t after = databox_now_ms();
        CHECK(br_http_client_drain(client, &error) == 0 && !error);
        CHECK(!fake.destroyed && !fake.pending && !fake.raw && fake.http.calls == 1 && fake.http.releases == 1);
        CHECK(fake.deadline >= before + 5000 && fake.deadline <= after + 5000);
        CHECK(guard_rejections == guards && encoder_calls == encoders + 1);
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        test_key_result(&results.items[0], 834, key, "key");
        br_results_clear(&results);
        br_http_client_destroy(client);
        CHECK(fake.destroyed); /* Stack backend state outlives drain and destruction. */
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); unchanged_shared_guard(); occurrences_and_skips(detector);
    suppressed_send_domain(detector); resources_and_rollback(detector);
    owned_client_verification(detector);
    return test_finish("Databox extraction/encoding/rollback + borrowed guard + owned-client verification");
}
