/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char key[] = "0123456789abcdefghijklmnopqrstuvwxyz0123";
static const char other[] = "zyxwvutsrqponmlkjihgfedcba9876543210zyxw";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static size_t basic_allocations;
static bool track_basic, fail_agent;
static const char *borrowed_auth, *borrowed_url, *expected_key;

/* Reuse the focused allocation seam used by the other named detector tests.
 * Basic(KEY40, "X") owns 63 bytes: 42 plaintext, 56 Base64, "Basic " and NUL. */
void *malloc(size_t size)
{
    if (track_basic && size == 63) ++basic_allocations;
    if (size == fail_size && fail_after && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, s, n);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other) == 40);
    CHECK(br_helpscout_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Helpscout detector output"));
    free(error);
    CHECK(br_helpscout_init(NULL, NULL) == -1);
    CHECK(br_helpscout_init(&d, &error) == 0 && d && !error);
    CHECK(br_helpscout_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 153 && d->version == 0 && !strcmp(d->name, "Helpscout") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Helpscout is a customer service software that provides a help desk for managing customer communications. Helpscout API keys can be used to access and manage customer interactions and data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "helpscout"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 153, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    basic_allocations = 0;
    track_basic = true;
    br_results out = test_scan(d, &ctx, false, input, len);
    track_basic = false;
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && !basic_allocations);
    if (expected) check_result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[300], changed[42];
    const char *formats[] = {"helpscout '%s'", "HELPSCOUT=-%s-", "prefixHeLpScOuTsuffix\r\n%s", "helpscout\r%s", "helpscout\n%s", "helpscout \t%s\t "};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extract_case(d, input, strlen(input), key);
    }
    const char *missing[] = {"%s", "help scout %s", "%s helpscout", "helpscout%s", "helpscout _%s", "helpscout %s_", "helpscout %sa"};
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key);
        extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = {'A', '_', '-', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key));
        changed[15] = invalid[i];
        snprintf(input, sizeof(input), "helpscout %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[39] = '\0';
    snprintf(input, sizeof(input), "helpscout %s", changed);
    extract_case(d, input, strlen(input), NULL);
    memset(changed, 'z', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "helpscout %s", changed);
    extract_case(d, input, strlen(input), changed); /* Not hex-only; no entropy or key validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "helpscout", 9); memset(input + 9, ':', gap); memcpy(input + 9 + gap, key, 40);
        extract_case(d, input, 49 + gap, gap == 40 ? key : NULL);
        memcpy(input, "helpscout", 9);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 9 + 4 * i, "💡", 4);
        memcpy(input + 9 + 4 * gap, key, 40);
        extract_case(d, input, 49 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "helpscout\0 ", 11); memcpy(input + 11, key, 40);
    extract_case(d, input, 51, key);
    snprintf(input, sizeof(input), "helpscout %s %s", key, other);
    extract_case(d, input, strlen(input), key); /* FindAll does not reuse a consumed prefix. */
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent;
} expected;

static void check_auth(const char *auth, const char *value)
{
    CHECK(auth && strlen(auth) == 62 && !memcmp(auth, "Basic ", 6) && !strchr(auth + 6, '='));
    unsigned char plain[43];
    CHECK(EVP_DecodeBlock(plain, (const unsigned char *)auth + 6, 56) == 42);
    CHECK(!memcmp(plain, value, 40) && plain[40] == ':' && plain[41] == 'X');
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 153 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://docsapi.helpscout.net/v1/collections"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    expected_key = e->keys[at];
    check_auth(request->headers[0].value, expected_key);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Borrow only provider-original values, never synthesized headers or UA. */
    borrowed_auth = request->headers[0].value;
    borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_auth) {
        check_auth(borrowed_auth, expected_key);
        CHECK(!strcmp(borrowed_url, "https://docsapi.helpscout.net/v1/collections"));
    } else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_auth = borrowed_url = expected_key = NULL;
    test_http_release(user, response);
}

static void duplicates_and_constructor_order(const br_detector *d)
{
    char input[200];
    snprintf(input, sizeof(input), "helpscout %s\nhelpscout %s\nhelpscout %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog helpscout-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "helpscout-offline"}; e.ctx = &ctx;
    for (int verify = 0; verify < 2; ++verify) {
        basic_allocations = 0; track_basic = true;
        br_results out = test_scan(d, &ctx, verify, input, strlen(input));
        track_basic = false;
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        CHECK(basic_allocations == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    fail_size = 63; fail_after = 1; basic_allocations = 0; track_basic = true;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !basic_allocations && fail_after == 1);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    track_basic = false;
    CHECK(out.len == 3 && !basic_allocations && fail_after == 1); fail_after = 0;
    for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void status_read_send_and_setup(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "helpscout %s", key);
    const char *keys[] = {key};
    expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char body[] = {0xff, 0, '{'};
    const char *read_errors[] = {NULL, "", "ignored body read error"};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = read_errors[i % 3]};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Helpscout result"},
        {1, "out of memory constructing Basic authentication"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "helpscout %s\nhelpscout %s", key, other);
    const char *keys[] = {key, other};
    expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Positive regex/capture error. */
        if (failure == 1) { fail_size = 41; fail_after = 2; } /* Capture collection finishes before findings. */
        if (failure == 2) { fail_size = 40; fail_after = 2; } /* Second finding Raw. */
        if (failure == 3) fail_part_after = 2; /* Positive secret-part insertion error. */
        if (failure == 4) { fail_size = 63; fail_after = 2; } /* Positive Basic encoder/assembly error. */
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        if (failure == 4) CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
        check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Finding construction fails before the nil-context skip; encoding does not run. */
    fail_part_after = 1; fail_size = 63; fail_after = 1; basic_allocations = 0; track_basic = true;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    track_basic = false;
    CHECK(!strcmp(error, "cannot create Helpscout result") && !fail_part_after && fail_after == 1 && !basic_allocations);
    check_prior(&out, &prior); free(error); error = NULL; fail_after = 0;
    /* A positive push failure must override even a successfully verified attempt. */
    size_t cap = out.cap; out.cap = 0; http.send_rc = 0; http.send_error = NULL; http.response = (br_http_response){.status = 200};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Helpscout result") && http.calls == 1 && http.releases == 1);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_size = 40; fail_after = 1;
    CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && !fail_after);
    check_prior(&out, &prior);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    duplicates_and_constructor_order(d);
    status_read_send_and_setup(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !track_basic && !borrowed_auth && !borrowed_url && !expected_key);
    return test_finish("Helpscout");
}
