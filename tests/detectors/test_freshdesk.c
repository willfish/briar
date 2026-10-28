/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char key1[21], key2[21];
static const char fixture_host[] = "fixture.freshdesk.com";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, encoder_calls, fail_encoder_after;
static size_t url_attempts;
static bool track_url, fail_agent_copy;
static const unsigned char *last_credentials, *last_encoded;
static const char *borrowed_url, *borrowed_host, *borrowed_auth;
static char saved_auth[39];

/* Observe/fail the actual encoder entry, not a production seam. Normal calls use
 * OpenSSL streaming Base64; request checks independently decode and use a golden. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls; last_credentials = last_encoded = NULL; CHECK(len == 22 && in[20] == ':' && in[21] == 'X');
    if (fail_encoder_after && --fail_encoder_after == 0) return 1; /* Positive wrong length is an OWN fatal failure. */
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx); unsigned char wrapped[80]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1); EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0; for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 32 && out[31] == '=' && out[30] == '=' && out[29] != '='); out[at] = '\0'; last_credentials = in; last_encoded = out; return (int)at;
}

void *malloc(size_t size)
{
    if (track_url && size == strlen(fixture_host) + 24) ++url_attempts;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 20 && strlen(key2) == 20);
    CHECK(br_freshdesk_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Freshdesk detector output")); free(error); error = NULL;
    CHECK(br_freshdesk_init(NULL, NULL) == -1);
    CHECK(br_freshdesk_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_freshdesk_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 678 && detector->version == 0 && !strcmp(detector->name, "Freshdesk"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Freshdesk is a customer support software. Freshdesk API keys can be used to access and manage support tickets, contacts, and other customer support data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "freshdesk"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 678, key, "key"); /* Host required but hidden, no RawV2/Extra/Redacted/primary/cache, including verified. */
    CHECK(result->raw.len == 20 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 20);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, len); CHECK(results.len == count && !http.calls && !http.releases && encoder_calls == before);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key, false);
    br_results_clear(&results);
}

static size_t append_host(char *input, size_t at, const char *host, size_t gap)
{
    memset(input + at, '.', gap); at += gap; size_t n = strlen(host); memcpy(input + at, host, n + 1); return at + n;
}

static void key_extraction(const br_detector *detector)
{
    char input[512], changed[22];
    const struct { const char *format; bool matches; } cases[] = {
        {"freshdesk '%s'", true}, {"FrEsHdEsK=%s", true}, {"prefreshdesk suffix:%s", true}, {"freshdesk\r\n%s", true},
        {"%s", false}, {"fresh desk %s", false}, {"freshdesk%s", false}, {"freshdesk x%s", false}, {"freshdesk _%s", false},
        {"freshdesk %s_", false}, {"freshdesk %s9", false}, {"freshdesk %.19s", false}, {"freshdesk \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), cases[i].format, key1); at = append_host(input, at, fixture_host, 80);
        extraction_case(detector, input, at, key1, cases[i].matches ? 1 : 0);
    }
    const char invalid[] = "_-/.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, key1, sizeof(changed) - 1); changed[10] = invalid[i]; size_t at = (size_t)snprintf(input, sizeof(input), "freshdesk %s", changed); at = append_host(input, at, fixture_host, 80); extraction_case(detector, input, at, key1, 0); }
    memset(changed, 'A', 20); changed[20] = '\0'; size_t at = (size_t)snprintf(input, sizeof(input), "freshdesk %s", changed); at = append_host(input, at, fixture_host, 80); extraction_case(detector, input, at, changed, 1);
    for (size_t gap = 40; gap <= 41; ++gap) for (int unicode = 0; unicode < 2; ++unicode) {
        memcpy(input, "freshdesk", 9); at = 9;
        for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = ':'; }
        memcpy(input + at, key1, 20); at += 20; at = append_host(input, at, fixture_host, 80); extraction_case(detector, input, at, key1, gap == 40 ? 1 : 0);
    }
    at = (size_t)snprintf(input, sizeof(input), "\xff\nfreshdesk%c%s", 0, key1); at = append_host(input, at, fixture_host, 80); extraction_case(detector, input, at, key1, 1);
    at = (size_t)snprintf(input, sizeof(input), "freshdesk %s", key1); extraction_case(detector, input, at, key1, 0); /* Host REQUIRED. */
    extraction_case(detector, fixture_host, strlen(fixture_host), key1, 0); extraction_case(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *const *keys, *const *hosts; size_t nkeys, nhosts; const char *agent; const br_scan_ctx *original; } expected_http;

static void check_url(const char *url, const char *host)
{
    size_t n = strlen(host); CHECK(strlen(url) == n + 23 && !memcmp(url, "https://", 8));
    CHECK(!memcmp(url + 8, host, n) && !memcmp(url + 8 + n, "/api/v2/tickets", 16));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->nkeys * expected->nhosts);
    size_t product = http->calls - 1; const char *key = expected->keys[product / expected->nhosts], *host = expected->hosts[product % expected->nhosts];
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, host);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 678); /* NOT invented PUBLIC semantics. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 38 && !memcmp(request->headers[1].value, "Basic ", 6));
    const unsigned char *encoded = (const unsigned char *)request->headers[1].value + 6; unsigned char decoded[24]; CHECK(encoded[30] == '=' && encoded[31] == '=' && encoded[29] != '=');
    CHECK(EVP_DecodeBlock(decoded, encoded, 32) == 24 && !memcmp(decoded, key, 20) && decoded[20] == ':' && decoded[21] == 'X' && !decoded[22] && !decoded[23]);
    CHECK(last_credentials && last_encoded && !memcmp(last_credentials, decoded, 22) && !memcmp(last_encoded, encoded, 33));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent)); /* No Accept. */
    static const char all_a[] = "AAAAAAAAAAAAAAAAAAAA";
    if (!memcmp(key, all_a, 20)) CHECK(!strcmp(request->headers[1].value, "Basic QUFBQUFBQUFBQUFBQUFBQUFBQUE6WA==")); /* Independent standard-Base64 golden. */
    CHECK(!borrowed_url && !borrowed_auth && !borrowed_host); borrowed_url = request->url; borrowed_host = host; borrowed_auth = request->headers[1].value; memcpy(saved_auth, borrowed_auth, 39);
}

static void release_response(void *user, br_http_response *response)
{
    CHECK(last_credentials && last_encoded && strlen((const char *)last_encoded) == 32);
    unsigned char decoded[24]; CHECK(EVP_DecodeBlock(decoded, last_encoded, 32) == 24 && !memcmp(last_credentials, decoded, 22));
    if (borrowed_url) {
        check_url(borrowed_url, borrowed_host); CHECK(!memcmp(borrowed_auth, saved_auth, 39) && borrowed_auth[38] == '\0' && !memcmp(borrowed_auth + 6, last_encoded, 33));
    } else CHECK(!borrowed_auth && !borrowed_host && !((test_http *)user)->calls);
    borrowed_url = borrowed_host = borrowed_auth = NULL; last_credentials = last_encoded = NULL; /* Full URL/auth/crypto bytes valid THROUGH release, URL freed only afterward. */
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void host_extraction(const br_detector *detector)
{
    const struct { const char *input, *capture; } cases[] = {
        {"a.freshdesk.com", "a.freshdesk.com"}, {"0.freshdesk.com", "0.freshdesk.com"}, {"a--b.freshdesk.com", "a--b.freshdesk.com"}, {"a-.freshdesk.com", "a-.freshdesk.com"},
        {"-good.freshdesk.com", "good.freshdesk.com"}, {"UPPER-good.freshdesk.com", "-good.freshdesk.com"}, {"X-.freshdesk.com", "-.freshdesk.com"},
        {"http://a.freshdesk.com/path", "a.freshdesk.com"}, {"a.freshdesk.com.evil", "a.freshdesk.com"}, {"a.freshdesk.com-tail", "a.freshdesk.com"},
        {"GOOD.freshdesk.com", NULL}, {"a.Freshdesk.com", NULL}, {"a.freshdesk.COM", NULL}, {".freshdesk.com", NULL}, {"aXfreshdeskYcom", NULL},
        {"a.freshdesk.comevil", NULL}, {"a.freshdesk.com_", NULL}, {"_a.freshdesk.com", NULL},
    };
    const char *keys[] = {key1}, *hosts[] = {NULL}; expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[512];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), "freshdesk %s", key1); at = append_host(input, at, cases[i].input, 80); hosts[0] = cases[i].capture; http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == (cases[i].capture ? 1u : 0u) && http.calls == results.len && http.releases == http.calls);
        if (results.len) check_result(&results.items[0], key1, true);
        br_results_clear(&results);
    } /* Direct, case-sensitive literal dots/ASCII word boundaries, not full-host assertions or DNS validation. */
}

static void products_and_long_host(const br_detector *detector)
{
    char input[1024]; const char *keys[] = {key1, key2, key1}, *hosts[] = {"tenant-one.freshdesk.com", "tenant-two.freshdesk.com", "tenant-one.freshdesk.com"};
    expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 3, .nhosts = 3, .agent = "TruffleHog freshdesk-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "freshdesk-offline"}; expected.original = &ctx;
    size_t at = 0; for (size_t i = 0; i < 3; ++i) { if (i) { memset(input + at, '.', 80); at += 80; } at += (size_t)snprintf(input + at, sizeof(input) - at, "freshdesk %s", keys[i]); }
    for (size_t i = 0; i < 3; ++i) at = append_host(input, at, hosts[i], 80);
    size_t before = encoder_calls; br_results results = test_scan(detector, &ctx, false, input, at); CHECK(results.len == 9 && !http.calls && !http.releases && encoder_calls == before);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], false);
    CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].secret_parts != results.items[1].secret_parts); br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; before = encoder_calls; results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 9 && http.calls == 9 && http.releases == 9 && encoder_calls == before + 9);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], true);
        br_results_clear(&results);
    } /* Original key-major occurrence duplicates in BOTH roles, NO set/break/cache policy. */
    http.calls = http.releases = 0; before = encoder_calls; results = test_scan(detector, NULL, true, input, at); CHECK(!results.len && !http.calls && !http.releases && encoder_calls == before + 9); br_results_clear(&results); last_credentials = last_encoded = NULL; /* Encoding/URL preparation BEFORE constructor skip. */
    const char *one_key[] = {key1}, *one_host[] = {fixture_host}; expected.keys = one_key; expected.hosts = one_host; expected.nkeys = expected.nhosts = 1;
    at = (size_t)snprintf(input, sizeof(input), "%s %s", fixture_host, key1); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results); /* Host supplies the keyword cue; host pattern itself needs no prefix. */
    const char *golden[] = {"AAAAAAAAAAAAAAAAAAAA"}; expected.keys = golden; at = (size_t)snprintf(input, sizeof(input), "freshdesk %s %s", golden[0], fixture_host); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], golden[0], true); br_results_clear(&results);
    size_t label_len = 6000; char *host = malloc(label_len + sizeof(".freshdesk.com")); CHECK(host); memset(host, 'a', label_len); memcpy(host + label_len, ".freshdesk.com", sizeof(".freshdesk.com"));
    size_t size = 10 + 20 + 2048 + strlen(host) + 1; char *large = malloc(size); CHECK(large); at = (size_t)snprintf(large, size, "freshdesk %s", key1); at = append_host(large, at, host, 2048);
    one_host[0] = host; expected.keys = one_key; http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, large, at);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results); free(large); free(host); /* Unbounded direct label/complete heap URL; span1024 is engine hint, NOT local cap. */
}

static void statuses_and_suppressed_send(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {{199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true}, {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false}};
    const char *keys[] = {key1}, *hosts[] = {fixture_host}; expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[128]; snprintf(input, sizeof(input), "freshdesk %s %s", key1, fixture_host);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "cannot allocate Freshdesk URL"}, {-1, NULL}, {1, key1}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = ""};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "freshdesk %s %s", key1, fixture_host); test_http http = {0}; br_transport transport = transport_for(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy && !borrowed_url && !borrowed_auth);
        check_result(&results.items[0], key1, false); br_results_clear(&results); last_credentials = last_encoded = NULL;
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[512]; size_t at = (size_t)snprintf(input, sizeof(input), "freshdesk %s", key1); memset(input + at, '.', 80); at += 80; at += (size_t)snprintf(input + at, sizeof(input) - at, "freshdesk %s", key2); at = append_host(input, at, fixture_host, 80); br_slice data = {(const unsigned char *)input, at};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL; size_t before = encoder_calls; track_url = true; url_attempts = 0;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Freshdesk result") && !fail_part_after && encoder_calls == before && !url_attempts); check_prior(&results, prior); free(error); error = NULL; /* Finding precedes encoding AND URL AND skip. */
    fail_encoder_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "Freshdesk native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 1 && !url_attempts); check_prior(&results, prior); free(error); error = NULL; /* OWN crypto +1 fatal even nilctx, BEFORE any URL allocation. */
    fail_alloc_size = strlen(fixture_host) + 24; fail_alloc_after = 1; before = encoder_calls;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot allocate Freshdesk URL") && !fail_alloc_after && encoder_calls == before + 1 && url_attempts == 1); check_prior(&results, prior); free(error); error = NULL; last_credentials = last_encoded = NULL; /* OWN actual URL allocation fatal AFTER encode, even nilctx. */
    br_scan_ctx missing = {0}; fail_alloc_after = 1; url_attempts = 0;
    CHECK(detector->scan(detector, &missing, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot allocate Freshdesk URL") && !fail_alloc_after && url_attempts == 1); check_prior(&results, prior); free(error); error = NULL; last_credentials = last_encoded = NULL; /* Cannot swallow OWN URL failure into suppressed missing transport. */
    before = encoder_calls; url_attempts = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && encoder_calls == before + 2 && url_attempts == 2); check_prior(&results, prior); last_credentials = last_encoded = NULL;
    const char *keys[] = {key1, key2}, *hosts[] = {fixture_host}; expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 2, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 2; before = encoder_calls; url_attempts = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Freshdesk result") && !fail_part_after && encoder_calls == before + 1 && url_attempts == 1 && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    fail_encoder_after = 2; before = encoder_calls; url_attempts = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "Freshdesk native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 2 && url_attempts == 1 && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = strlen(fixture_host) + 24; fail_alloc_after = 2; before = encoder_calls; url_attempts = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot allocate Freshdesk URL") && !fail_alloc_after && encoder_calls == before + 2 && url_attempts == 2 && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL; last_credentials = last_encoded = NULL; /* Late OWN failures roll back earlier verified findings, preserving caller pointers. */
    for (size_t collection = 1; collection <= 2; ++collection) {
        fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = collection; before = encoder_calls; url_attempts = 0;
        CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after && encoder_calls == before && !url_attempts); check_prior(&results, prior);
    } /* Actual positive iterator failures in BOTH independent collections normalize fatal before constructor skip. */
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); last_credentials = last_encoded = NULL;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Freshdesk result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results); track_url = false;
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 20, 0); test_secret(key2, 20, 11); key1[3] = 'Z'; key1[19] = 'K'; key2[3] = 'A'; key2[19] = 'Q';
    const br_detector *detector = descriptor(); key_extraction(detector); host_extraction(detector); products_and_long_host(detector); statuses_and_suppressed_send(detector); suppressed_setup(detector); resources_and_rollback(detector);
    CHECK(!borrowed_url && !borrowed_auth && !borrowed_host); return test_finish("Freshdesk direct unbounded hosts + pre-constructor Basic/URL + hidden hosts");
}
