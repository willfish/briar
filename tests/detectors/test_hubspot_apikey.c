/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <limits.h>
#include <stdarg.h>

static const char v1_key[] = "G1h2Z3k4-L5m6-N7p8-Q9r0-S1t2U3v4W5x6";
static const char v1_other[] = "z9Y8x7W6-v5U4-t3S2-r1Q0-p9N8m7L6k5J4";
static const char v2_key[] = "pat-na1-G1h2Z3k4-L5m6-N7p8-Q9r0-S1t2U3v4W5x6";
static const char v2_other[] = "pat-eu1-z9Y8x7W6-v5U4-t3S2-r1Q0-p9N8m7L6k5J4";
static const char v1_url[] = "https://api.hubapi.com/contacts/v1/lists?hapikey=";
static const char v2_url[] = "https://api.hubapi.com/account-info/v3/api-usage/daily/private-apps";
typedef int (*factory)(const br_detector **, char **);

/* Existing named-test technique: observe the provider's original request and
 * positive owned failures without altering shared helpers or the ABI. */
typedef enum {
    NO_FAULT, CAPTURE, FINDING, ALLOCATE, URL_FORMAT, AUTH_FORMAT,
    STATUS_MEASURE, STATUS_FORMAT, CONSTRUCTOR_CAUSE, TRANSPORT_CAUSE, SETTER, PUSH
} fault_site;
static fault_site fault;
static size_t fault_nth, fault_size;
static bool oversized_format, omit_send_cause, source_verified;
static br_result *candidate;
static const br_http_request *provider_request;
static size_t send_attempts, release_attempts, setter_calls;

static bool hit(fault_site site)
{
    if (fault != site || (fault_nth && --fault_nth)) return false;
    fault = NO_FAULT;
    return true;
}

static void *checked_malloc(size_t size)
{
    return size == fault_size && hit(ALLOCATE) ? NULL : malloc(size);
}

static char *checked_strdup(const char *text)
{
    if (!strcmp(text, "net/http: nil Context")) {
        CHECK(candidate && !candidate->verified && !candidate->verification_error);
        CHECK(candidate->raw.len == 36 || (candidate->raw.len == 44 && candidate->redacted));
        if (hit(CONSTRUCTOR_CAUSE)) return NULL;
    }
    if (!strcmp(text, "HTTP transport failed") && hit(TRANSPORT_CAUSE)) return NULL;
    return strdup(text);
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    fault_site site = !strcmp(format, "%s%.*s") ? URL_FORMAT :
                      !strcmp(format, "Bearer %.*s") ? AUTH_FORMAT :
                      out ? STATUS_FORMAT : STATUS_MEASURE;
    if (hit(site)) return oversized_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out,
                             bool unique, char **error)
{
    CHECK(unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    candidate = result;
    source_verified = false;
    return hit(FINDING) ? 1 : br_finding_key_bytes(result, type, key, part);
}

static void original_request(const br_http_request *request)
{
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && !request->timeout_ms);
    CHECK(request->detector_type == 107 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    if (candidate->raw.len == 36) {
        CHECK(!candidate->redacted && !request->headers && !request->nheaders);
        CHECK(strlen(request->url) == strlen(v1_url) + 36 && !memcmp(request->url, v1_url, strlen(v1_url)));
        CHECK(!memcmp(request->url + strlen(v1_url), candidate->raw.data, 36));
    } else {
        CHECK(candidate->raw.len == 44 && candidate->redacted && strlen(candidate->redacted) == 39);
        CHECK(!memcmp(candidate->redacted, candidate->raw.data + 8, 36) && !strcmp(candidate->redacted + 36, "..."));
        CHECK(!strcmp(request->url, v2_url) && request->nheaders == 1);
        CHECK(!strcmp(request->headers[0].name, "Authorization"));
        CHECK(strlen(request->headers[0].value) == 51 && !memcmp(request->headers[0].value, "Bearer ", 7));
        CHECK(!memcmp(request->headers[0].value + 7, candidate->raw.data, 44));
    }
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    CHECK(!provider_request && send_attempts == release_attempts);
    original_request(request);
    provider_request = request;
    ++send_attempts;
    int rc = br_http_send(ctx, request, response, error);
    source_verified = rc == 0 && (response->status == 200 || response->status == 403);
    if (rc != 0 && omit_send_cause) { free(*error); *error = NULL; }
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && send_attempts == release_attempts + 1);
    original_request(provider_request);
    br_http_release(ctx, response);
    provider_request = NULL;
    ++release_attempts;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(result == candidate && !provider_request && send_attempts == release_attempts);
    CHECK(!secrets && !count && result->verified == source_verified);
    ++setter_calls;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!provider_request && send_attempts == release_attempts);
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

#define malloc checked_malloc
#define strdup checked_strdup
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_hubspot_apikey_v1_init observed_hubspot_v1_init
#define br_hubspot_apikey_v2_init observed_hubspot_v2_init
#include "../../src/detectors/hubspot_apikey.c"
#undef malloc
#undef strdup
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_hubspot_apikey_v1_init
#undef br_hubspot_apikey_v2_init

static const char *key(const br_detector *d) { return d->version == 1 ? v1_key : v2_key; }
static const char *other(const br_detector *d) { return d->version == 1 ? v1_other : v2_other; }

static const br_detector *descriptor(factory init, int version)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, version == 1 ? "invalid HubSpot v1 detector output" : "invalid HubSpot v2 detector output"));
    free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 107 && d->version == version && !strcmp(d->name, "HubSpotApiKey") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "HubSpot is a CRM platform that provides tools for marketing, sales, and customer service. HubSpot API keys can be used to access and modify data within the HubSpot platform."));
    const char *v1_words[] = {"hubapi", "hapikey", "hapi_key", "hubspot"};
    const char *v2_words[] = {"pat-na1-", "pat-eu1-"};
    CHECK(d->nkeywords == (version == 1 ? 4u : 2u));
    for (size_t i = 0; i < d->nkeywords; ++i) CHECK(!strcmp(d->keywords[i], version == 1 ? v1_words[i] : v2_words[i]));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified, const char *cause)
{
    br_result plain = *result;
    plain.redacted = NULL;
    test_key_result(&plain, 107, expected, "key");
    if (strlen(expected) == 44) {
        CHECK(result->redacted && strlen(result->redacted) == 39);
        CHECK(!memcmp(result->redacted, expected + 8, 36) && !strcmp(result->redacted + 36, "..."));
    } else CHECK(!result->redacted);
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}

static void v1_grammar(const br_detector *d)
{
    char input[512], changed[37];
    const char *good[] = {"hubapi '%s'", "hapikey %s", "hapi_key %s", "hubspot %s", "HaPi_KeY\r\n%s", "xHUBAPIsuffix:%s", "hubapi-%s", "hubapi\r%s", "hubapi\n%s", "hubapi \t%s\t "};
    const char *bad[] = {"%s", "%s hubapi", "hapi key %s", "hapi__key %s", "hapi_?key %s", "hubapi%s", "hubapi x%s", "hubapi _%s", "hubapi %s_", "hubapi %sX", "hubapi %.35s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], v1_key); extract(d, input, strlen(input), v1_key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], v1_key); extract(d, input, strlen(input), NULL);
    }
    const size_t blocks[] = {0, 9, 14, 19, 24};
    for (size_t i = 0; i < sizeof(blocks) / sizeof(*blocks); ++i) {
        memcpy(changed, v1_key, sizeof(changed)); changed[blocks[i]] = 'Z';
        snprintf(input, sizeof(input), "hubspot %s", changed); extract(d, input, strlen(input), changed);
        changed[blocks[i]] = '_';
        snprintf(input, sizeof(input), "hubspot %s", changed); extract(d, input, strlen(input), NULL);
    }
    memcpy(changed, v1_key, sizeof(changed)); changed[8] = '_';
    snprintf(input, sizeof(input), "hubspot %s", changed); extract(d, input, strlen(input), NULL);
    const char zeros[] = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "hubspot %s", zeros); extract(d, input, strlen(input), zeros);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "hubapi", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, v1_key, 36);
        extract(d, input, 42 + gap, gap == 40 ? v1_key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 6 + 4 * gap, v1_key, 36);
        extract(d, input, 42 + 4 * gap, gap == 40 ? v1_key : NULL);
    }
    memcpy(input, "hubapi\0", 7); memcpy(input + 7, v1_key, 36); extract(d, input, 43, v1_key);
    snprintf(input, sizeof(input), "hubspot %s %s", v1_key, v1_other);
    extract(d, input, strlen(input), v1_key); /* Prefix consumption is not reusable. */
    extract(d, NULL, 0, NULL);
}

static void v2_grammar(const br_detector *d)
{
    char input[512], changed[45];
    const char *good[] = {"%s", "'%s'", " \t%s\r\n", "-%s-", "hubspot %s", "%s/more"};
    const char *bad[] = {"x%s", "_%s", "%s_", "%sX", "%.43s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], v2_key); extract(d, input, strlen(input), v2_key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], v2_key); extract(d, input, strlen(input), NULL);
    }
    extract(d, v2_other, strlen(v2_other), v2_other);
    const char *bad_prefixes[] = {"Pat-na1-", "pat-NA1-", "pat-as1-", "pat-na2-", "pat-eu2-"};
    for (size_t i = 0; i < sizeof(bad_prefixes) / sizeof(*bad_prefixes); ++i) {
        snprintf(input, sizeof(input), "%s%s", bad_prefixes[i], v1_key); extract(d, input, strlen(input), NULL);
    }
    const size_t blocks[] = {8, 17, 22, 27, 32};
    for (size_t i = 0; i < sizeof(blocks) / sizeof(*blocks); ++i) {
        memcpy(changed, v2_key, sizeof(changed)); changed[blocks[i]] = 'Z'; extract(d, changed, 44, changed);
        changed[blocks[i]] = '_'; extract(d, changed, 44, NULL);
    }
    memcpy(changed, v2_key, sizeof(changed)); changed[16] = '_'; extract(d, changed, 44, NULL);
    extract(d, "pat-eu1-00000000-0000-0000-0000-000000000000", 44, "pat-eu1-00000000-0000-0000-0000-000000000000");
    memset(input, ':', 100); memcpy(input + 100, v2_key, 44); extract(d, input, 144, v2_key);
    memcpy(input, "\0", 1); memcpy(input + 1, v2_key, 44); extract(d, input, 45, v2_key);
    extract(d, NULL, 0, NULL);
}

static size_t make_input(char *input, size_t size, const br_detector *d, bool repeated)
{
    int n = repeated ? snprintf(input, size, d->version == 1 ? "hubapi %s\nhapi_key %s\nhubspot %s" : "%s\n%s\n%s", key(d), other(d), key(d)) :
                       snprintf(input, size, d->version == 1 ? "hubapi %s" : "%s", key(d));
    CHECK(n >= 0 && (size_t)n < size);
    return (size_t)n;
}

static void unique_original_tokens(const br_detector *d)
{
    char input[300], changed[45]; size_t len = make_input(input, sizeof(input), d, true);
    br_results out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == 2);
    unsigned seen = 0;
    for (size_t i = 0; i < out.len; ++i) {
        bool first = out.items[i].raw.len == strlen(key(d)) && !memcmp(out.items[i].raw.data, key(d), strlen(key(d)));
        unsigned bit = first ? 1 : 2;
        CHECK(!(seen & bit)); seen |= bit;
        finding(&out.items[i], first ? key(d) : other(d), false, NULL);
    }
    CHECK(seen == 3); br_results_clear(&out);
    strcpy(changed, key(d)); changed[d->version == 1 ? 0 : 8] = 'g';
    int n = snprintf(input, sizeof(input), d->version == 1 ? "hubapi %s\nhubapi %s" : "%s\n%s", key(d), changed);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 2); /* Case is preserved, not normalized for uniqueness. */
    seen = 0;
    for (size_t i = 0; i < out.len; ++i) {
        bool first = !memcmp(out.items[i].raw.data, key(d), strlen(key(d)));
        unsigned bit = first ? 1 : 2; CHECK(!(seen & bit)); seen |= bit;
        finding(&out.items[i], first ? key(d) : changed, false, NULL);
    }
    CHECK(seen == 3); br_results_clear(&out);
}

typedef struct {
    const br_detector *d;
    const br_scan_ctx *ctx;
    const char *agent;
    bool multiple;
    unsigned seen;
    const char *borrowed_url, *borrowed_auth;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx == s->ctx && http->calls == http->releases + 1 && !s->borrowed_url && !s->borrowed_auth);
    CHECK(request->detector_type == 107 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    size_t ua = s->d->version == 1 ? 0 : 1;
    CHECK(request->nheaders == ua + 1);
    const char *token;
    if (s->d->version == 1) {
        CHECK(strlen(request->url) == strlen(v1_url) + 36 && !memcmp(request->url, v1_url, strlen(v1_url)));
        token = request->url + strlen(v1_url);
    } else {
        CHECK(!strcmp(request->url, v2_url) && !strcmp(request->headers[0].name, "Authorization"));
        CHECK(!memcmp(request->headers[0].value, "Bearer ", 7) && strlen(request->headers[0].value) == 51);
        token = request->headers[0].value + 7;
        s->borrowed_auth = request->headers[0].value;
    }
    unsigned bit = !strcmp(token, key(s->d)) ? 1 : 2;
    CHECK(bit == 1 || (s->multiple && !strcmp(token, other(s->d))));
    CHECK(!(s->seen & bit)); s->seen |= bit;
    CHECK(!strcmp(request->headers[ua].name, "User-Agent") && !strcmp(request->headers[ua].value, s->agent));
    /* Never borrow synthesized request/header-array/UA storage across send. */
    s->borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_url) {
        CHECK(http->calls == http->releases + 1);
        if (s->d->version == 1) CHECK(!memcmp(s->borrowed_url, v1_url, strlen(v1_url)) && strlen(s->borrowed_url) == strlen(v1_url) + 36);
        else CHECK(!strcmp(s->borrowed_url, v2_url) && s->borrowed_auth && strlen(s->borrowed_auth) == 51 && !memcmp(s->borrowed_auth, "Bearer ", 7));
        s->borrowed_url = s->borrowed_auth = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void verification(const br_detector *d)
{
    char input[300]; size_t len = make_input(input, sizeof(input), d, true);
    script s = {.d = d, .agent = "TruffleHog hubspot-offline", .multiple = true};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 403, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hubspot-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, len);
        CHECK(out.len == 2 && http.calls == (pass ? 2u : 0u) && http.releases == http.calls);
        CHECK(s.seen == (pass ? 3u : 0u));
        for (size_t i = 0; i < 2; ++i) {
            bool first = !memcmp(out.items[i].raw.data, key(d), strlen(key(d)));
            finding(&out.items[i], first ? key(d) : other(d), pass != 0, NULL);
        }
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, len);
    CHECK(out.len == 2);
    for (size_t i = 0; i < 2; ++i) {
        bool first = !memcmp(out.items[i].raw.data, key(d), strlen(key(d)));
        finding(&out.items[i], first ? key(d) : other(d), false, "net/http: nil Context");
    }
    br_results_clear(&out);
    len = make_input(input, sizeof(input), d, false); s.multiple = false; s.agent = "TruffleHog"; ctx.user_agent = NULL;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500, INT_MIN, INT_MAX};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0; s.seen = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored body read failure"};
        out = test_scan(d, &ctx, true, input, len);
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        bool valid = statuses[i] == 200 || statuses[i] == 403;
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && s.seen == 1);
        finding(&out.items[0], key(d), valid, valid || statuses[i] == 401 ? NULL : cause);
        br_results_clear(&out);
    }
    char whole_cause[220]; snprintf(whole_cause, sizeof(whole_cause), "outer cause: %s / %s", key(d), key(d));
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {-1, "cannot allocate HubSpot v1 URL"}, {1, "cannot allocate HubSpot v2 authorization"},
        {1, "out of memory constructing HTTP headers"}, {1, "unexpected HTTP response status 401"},
        {-7, whole_cause}, {1, ""}, {1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; s.seen = 0;
        http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key(d), false, failures[i].cause ? failures[i].cause : "HTTP transport failed");
        br_results_clear(&out);
    }
    CHECK(!s.borrowed_url && !s.borrowed_auth);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void shared_setup(const br_detector *d)
{
    char input[100]; size_t len = make_input(input, sizeof(input), d, false);
    script s = {.d = d}; test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response}, missing_send = {&http, NULL, release_response};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; send_attempts = release_attempts = setter_calls = 0;
        br_results out = test_scan(d, &contexts[i], true, input, len);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(send_attempts == 1 && release_attempts == 1 && setter_calls == 1);
        finding(&out.items[0], key(d), false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures(const br_detector *d)
{
    char input[300]; size_t len = make_input(input, sizeof(input), d, true);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    CHECK(br_result_set_verification_error(&out.items[0], NULL, NULL, 0) == 0); prior_unchanged(&out, &prior);
    script s = {.d = d, .agent = "TruffleHog", .multiple = true};
    test_http http = {.user = &s, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    size_t request_size = d->version == 1 ? sizeof(v1_url) + 36 : sizeof("Bearer ") + 44;
    const char *allocation = d->version == 1 ? "cannot allocate HubSpot v1 URL" : "cannot allocate HubSpot v2 authorization";
    const char *formatting = d->version == 1 ? "cannot format HubSpot v1 URL" : "cannot format HubSpot v2 authorization";
    const struct {
        fault_site site; size_t nth, size, attempts; int status; bool nil, do_error, no_cause, oversized;
        const char *error;
    } cases[] = {
        {CAPTURE, 1, 0, 0, 200, false, false, false, false, "synthetic capture failure"},
        {FINDING, 1, 0, 0, 200, true, false, false, false, "cannot create HubSpot finding"},
        {FINDING, 2, 0, 1, 200, false, true, false, false, "cannot create HubSpot finding"},
        {ALLOCATE, 2, request_size, 1, 200, false, true, false, false, allocation},
        {d->version == 1 ? URL_FORMAT : AUTH_FORMAT, 1, 0, 0, 200, false, false, false, false, formatting},
        {d->version == 1 ? URL_FORMAT : AUTH_FORMAT, 1, 0, 0, 200, false, false, false, true, formatting},
        {ALLOCATE, 2, sizeof("unexpected HTTP response status 503"), 2, 503, false, false, false, false, "cannot allocate HubSpot status cause"},
        {STATUS_MEASURE, 2, 0, 2, 503, false, false, false, false, "cannot format HubSpot status cause"},
        {STATUS_FORMAT, 2, 0, 2, 503, false, false, false, true, "cannot format HubSpot status cause"},
        {CONSTRUCTOR_CAUSE, 2, 0, 0, 200, true, false, false, false, "cannot create HubSpot constructor cause"},
        {TRANSPORT_CAUSE, 2, 0, 2, 200, false, true, true, false, "cannot create HubSpot transport cause"},
        {SETTER, 2, 0, 2, 200, false, false, false, false, "cannot set HubSpot verification error"},
        {SETTER, 2, 0, 2, 403, false, false, false, false, "cannot set HubSpot verification error"},
        {SETTER, 2, 0, 2, 401, false, false, false, false, "cannot set HubSpot verification error"},
        {SETTER, 2, 0, 2, 200, false, true, false, false, "cannot set HubSpot verification error"},
        {PUSH, 2, 0, 2, 200, false, false, false, false, "cannot append HubSpot finding"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        fault = cases[i].site; fault_nth = cases[i].nth; fault_size = cases[i].size;
        oversized_format = cases[i].oversized; omit_send_cause = cases[i].no_cause;
        http.calls = http.releases = 0; s.seen = 0; http.send_rc = cases[i].do_error ? 7 : 0;
        http.send_error = cases[i].do_error ? "cannot create HubSpot finding" : NULL;
        http.response = (br_http_response){.status = cases[i].status, .body_error = "ignored"};
        send_attempts = release_attempts = setter_calls = 0;
        char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].error)); free(error);
        CHECK(fault == NO_FAULT && !fault_nth && !provider_request && !s.borrowed_auth && !s.borrowed_url);
        CHECK(http.calls == cases[i].attempts && http.releases == http.calls);
        CHECK(send_attempts == cases[i].attempts && release_attempts == send_attempts);
        prior_unchanged(&out, &prior);
    }
    oversized_format = omit_send_cause = false;
    fault = ALLOCATE; fault_nth = 1; fault_size = request_size;
    send_attempts = release_attempts = setter_calls = 0;
    char *error = NULL;
    if (d->version == 1) {
        CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, allocation) && fault == NO_FAULT && !setter_calls); free(error);
        prior_unchanged(&out, &prior); /* URL allocation precedes the nil constructor. */
        fault = URL_FORMAT; fault_nth = 1;
        CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, formatting) && fault == NO_FAULT && !setter_calls); free(error);
        prior_unchanged(&out, &prior);
    } else {
        br_results nil = test_scan(d, NULL, true, input, len);
        CHECK(nil.len == 2 && fault == ALLOCATE && fault_nth == 1 && setter_calls == 2);
        for (size_t i = 0; i < 2; ++i) finding(&nil.items[i], i ? other(d) : key(d), false, "net/http: nil Context");
        br_results_clear(&nil); /* Authorization allocation follows construction. */
        fault_size = 40; fault_nth = 2;
        CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot allocate HubSpot v2 redaction") && fault == NO_FAULT); free(error);
        prior_unchanged(&out, &prior); /* Redaction precedes verification, including nil. */
        fault = ALLOCATE; fault_nth = 1; fault_size = 40;
        CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot allocate HubSpot v2 redaction") && fault == NO_FAULT); free(error);
        prior_unchanged(&out, &prior);
    }
    CHECK(!send_attempts && !release_attempts);
    fault = ALLOCATE; fault_nth = 1; fault_size = request_size;
    size_t before = setter_calls;
    br_results nov = test_scan(d, NULL, false, input, len);
    CHECK(nov.len == 2 && fault == ALLOCATE && fault_nth == 1 && setter_calls == before);
    br_results_clear(&nov);
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, NULL) == -1);
    CHECK(fault == NO_FAULT && !fault_nth); prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    prior_unchanged(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(v1_key) == 36 && strlen(v1_other) == 36 && strlen(v2_key) == 44 && strlen(v2_other) == 44);
    const br_detector *v1 = descriptor(br_hubspot_apikey_v1_init, 1), *v2 = descriptor(br_hubspot_apikey_v2_init, 2);
    CHECK(v1 != v2 && v1->state != v2->state && v1->keywords != v2->keywords);
    v1_grammar(v1); v2_grammar(v2); unique_original_tokens(v1); unique_original_tokens(v2);
    char mixed[150]; snprintf(mixed, sizeof(mixed), "hubspot %s\n%s", v1_key, v2_key);
    extract(v1, mixed, strlen(mixed), v1_key); extract(v2, mixed, strlen(mixed), v2_key);
    snprintf(mixed, sizeof(mixed), "hubspot %s", v2_key);
    extract(v1, mixed, strlen(mixed), v1_key); extract(v2, mixed, strlen(mixed), v2_key);
    verification(v1); verification(v2);
    const br_detector *observed_v1 = descriptor(observed_hubspot_v1_init, 1), *observed_v2 = descriptor(observed_hubspot_v2_init, 2);
    verification(observed_v1); verification(observed_v2);
    shared_setup(observed_v1); shared_setup(observed_v2);
    owned_failures(observed_v1); owned_failures(observed_v2);
    CHECK(fault == NO_FAULT && !fault_nth && !provider_request && !oversized_format && !omit_send_cause);
    return test_finish("HubSpot API-key v1/v2 grammar/unique-originals/metadata/redaction/request/status/ignored-reads/whole-cause/zero-secret-setter/release/resources/rollback");
}
