/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* The factory is intentionally not added to the shared header by this worker. */
int br_loginradius_init(const br_detector **out, char **error);

/* Reuse the named-test seams for real positive append failures and observing
 * forbidden setter calls. Production regex, findings and HTTP remain linked. */
#define br_results_push loginradius_real_push
#define br_result_set_verification_error loginradius_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "fedcba98-7654-3210-fedc-ba9876543210";
static const char zero[] = "00000000-0000-0000-0000-000000000000";
static const char url_prefix[] = "https://api.loginradius.com/identity/v2/serverinfo?apikey=";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, failed_allocations, setter_calls;
static bool fail_next_malloc, arm_request, arm_headers;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false;
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "key")) {
        if (arm_request) { arm_request = false; fail_next_malloc = true; }
        if (arm_headers) { arm_headers = false; fail_size = sizeof(br_header); fail_after = 1; }
    }
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return loginradius_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return loginradius_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_loginradius_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Loginradius detector output")); free(error); error = NULL;
    CHECK(br_loginradius_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:loginradius)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_loginradius_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_loginradius_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_loginradius_init(&again, &error) == 0 && again == detector && !error);
    CHECK(br_loginradius_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 510 && detector->version == 0 && !strcmp(detector->name, "Loginradius"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Loginradius is a customer identity and access management (CIAM) platform. The API keys can be used "
        "to manage user identities, authentication, and access control."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "loginradius"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 510, expected, "key");
    CHECK(result->raw.len == 36 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], changed[38];
    snprintf(input, sizeof(input), "loginradius = '%s'", key);
    extraction_case(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "preLoGiNrAdIuSsuffix:\r\n'%s'", key);
    extraction_case(detector, input, strlen(input), key);
    extraction_case(detector, key, strlen(key), NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = 'A';
    snprintf(input, sizeof(input), "LOGINRADIUS %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'g';
    snprintf(input, sizeof(input), "loginradius %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[35] = '\0';
    snprintf(input, sizeof(input), "loginradius %s", changed);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loginradius x%s", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loginradius %s_", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loginradius %s0", key);
    extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loginradius \xc3\xa9%s\xc3\xa9", key);
    extraction_case(detector, input, strlen(input), key); /* ASCII word boundaries. */
    snprintf(input, sizeof(input), "loginradius %s", zero);
    extraction_case(detector, input, strlen(input), zero); /* No entropy or semantic UUID filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = sizeof("loginradius") - 1;
        memcpy(input, "loginradius", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, sizeof(key));
        extraction_case(detector, input, at + 36, gap == 40 ? key : NULL);
        at = sizeof("loginradius") - 1;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, sizeof(key));
        extraction_case(detector, input, at + 36, gap == 40 ? key : NULL);
    }
    memcpy(input, "loginradius", 11); input[11] = '\0'; input[12] = '\n'; input[13] = '\r';
    memcpy(input + 14, key, sizeof(key)); extraction_case(detector, input, 14 + 36, key);
    snprintf(input, sizeof(input), "loginradius %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Full-match nonoverlap consumes the prefix. */
    extraction_case(detector, NULL, 0, NULL);

    snprintf(input, sizeof(input), "loginradius %s\nloginradius %s\nloginradius %s", key, other, key);
    const char *keys[] = {key, other, key};
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

typedef struct {
    test_http http;
    br_results *published;
    const char *const *keys;
    size_t nkeys, initial_len, release_len;
    const char *urls[3];
    unsigned char markers[3];
} wire_case;

static void check_url(const char *url, const char *expected)
{
    CHECK(url && !strncmp(url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!strcmp(url + sizeof(url_prefix) - 1, expected));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_case *wire = http->user;
    size_t i = http->calls - 1;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(i < wire->nkeys && wire->nkeys <= 3);
    CHECK(wire->published->len == wire->initial_len + i);
    CHECK(http->releases == (http->send_rc ? i : 0));
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, wire->keys[i]);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 510);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog loginradius-test" : "TruffleHog"));
    /* Only the provider URL is retained, never the temporary prepared request,
     * synthesized headers or User-Agent, whose lifetimes end at send return. */
    wire->urls[i] = request->url;
    wire->markers[i] = (unsigned char)i;
    http->response.body = (br_slice){wire->markers + i, 1};
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; wire_case *wire = http->user;
    if (!http->calls) {
        CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
        CHECK(wire->published->len == wire->initial_len);
    } else {
        size_t i = http->send_rc ? http->calls - 1 : http->calls - 1 - http->releases;
        CHECK(response->body.len == 1 && response->body.data[0] == i);
        check_url(wire->urls[i], wire->keys[i]);
        CHECK(wire->published->len == (http->send_rc ? wire->initial_len + i : wire->release_len));
        if (!http->send_rc) for (size_t j = 0; j <= i; ++j) check_url(wire->urls[j], wire->keys[j]);
    }
    test_http_release(http, response);
}

static br_transport wire_transport(wire_case *wire)
{
    wire->http.inspect = inspect_request; wire->http.user = wire;
    return (br_transport){&wire->http, test_http_send, release_response};
}

static void scan_into(const br_detector *detector, const br_scan_ctx *ctx, const char *input, br_results *results)
{
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, results, &error) == 0);
    CHECK(!error);
}

static void http_policy(const br_detector *detector)
{
    const char *keys[] = {key}; char input[80], sensitive[128];
    snprintf(input, sizeof(input), "loginradius %s", key);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read failure for %s", key);
    const struct { int status, rc; const char *cause; } cases[] = {
        {199, 0, NULL}, {200, 0, NULL}, {201, 0, NULL}, {204, 0, NULL}, {299, 0, NULL},
        {300, 0, NULL}, {401, 0, NULL}, {403, 0, NULL}, {429, 0, NULL}, {500, 0, NULL},
        {200, 1, sensitive}, {200, -1, "context canceled"}, {200, 7, "net/http: nil Context"},
        {200, -1, "out of memory constructing HTTP headers"}, {200, 1, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = {0};
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 1, .release_len = 1,
            .http = {.response = {.status = cases[i].status, .body_error = sensitive},
                     .send_rc = cases[i].rc, .send_error = cases[i].cause}};
        br_transport transport = wire_transport(&wire);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = i % 2 ? "loginradius-test" : NULL};
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && wire.http.calls == 1 && wire.http.releases == 1);
        result_is(&results.items[0], key, !cases[i].rc && cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&results);
    }
    const char *multiple[] = {key, other, key};
    char repeated[160];
    snprintf(repeated, sizeof(repeated), "loginradius %s\nloginradius %s\nloginradius %s", key, other, key);
    for (int failure = 0; failure < 2; ++failure) {
        br_results results = {0};
        wire_case wire = {.published = &results, .keys = multiple, .nkeys = 3, .release_len = 3,
            .http = {.response = {.status = 299, .body_error = "ignored read error"},
                     .send_rc = failure, .send_error = failure ? sensitive : NULL}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport};
        scan_into(detector, &ctx, repeated, &results);
        CHECK(results.len == 3 && wire.http.calls == 3 && wire.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result_is(&results.items[i], multiple[i], !failure);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void preparation_errors(const br_detector *detector)
{
    const char *keys[] = {key}; char input[80]; snprintf(input, sizeof(input), "loginradius %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        br_results results = {0}; wire_case wire = {.published = &results, .keys = keys, .nkeys = 1};
        br_transport transport = wire_transport(&wire);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        if (mode == 4) arm_headers = true;
        size_t before = failed_allocations;
        scan_into(detector, &ctx, input, &results);
        CHECK(results.len == 1 && !wire.http.calls && wire.http.releases == (mode == 2 ? 0u : 1u));
        CHECK(!arm_headers && !fail_after && failed_allocations == before + (mode == 4));
        result_is(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void owned_failures(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "loginradius %s\nloginradius %s", key, other);
    const char *keys[] = {key, other};
    for (int mode = 0; mode < 5; ++mode) {
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
        wire_case wire = {.published = &results, .keys = keys, .nkeys = 2, .initial_len = 1, .release_len = 2,
                          .http = {.response = {.status = 200}}};
        br_transport transport = wire_transport(&wire); br_scan_ctx ctx = {.transport = &transport};
        const char *expected;
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span); fail_after = 1;
            expected = "out of memory iterating regex"; /* Actual regex/capture +1. */
        } else if (mode == 1 || mode == 2) {
            fail_part_after = mode == 1 ? 2 : 1;
            expected = "out of memory creating Loginradius result";
        } else if (mode == 3) {
            fail_push_after = 2; expected = "out of memory appending Loginradius result";
        } else {
            arm_request = true; expected = "out of memory creating Loginradius request";
        }
        char *error = NULL;
        int rc = detector->scan(detector, mode == 2 || mode == 4 ? NULL : &ctx, true,
            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_next_malloc && !arm_request);
        CHECK(results.len == 1 && results.items[0].detector_type == 12345 && results.items[0].verified);
        CHECK(results.items[0].raw.data == original_raw && results.items[0].raw.len == 4 && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
        CHECK(wire.http.calls == (mode == 1 ? 1u : mode == 3 ? 2u : 0u) && wire.http.releases == wire.http.calls);
        free(error); br_results_clear(&results);
    }
    br_results results = {0}; char *error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &results, &error) == -1 && error);
    free(error); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); http_policy(detector); preparation_errors(detector); owned_failures(detector);
    CHECK(!setter_calls);
    return test_finish("Loginradius extraction, suppressed HTTP, deferred LIFO release and owned rollback");
}
