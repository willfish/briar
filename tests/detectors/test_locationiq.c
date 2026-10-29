/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Main owns the shared factory declarations and registry integration. */
int br_locationiq_init(const br_detector **out, char **error);

/* Existing named-test seams observe forbidden setter calls and actual owned
 * allocation/JSON failures without replacing the shared HTTP adapter. */
#define br_result_set_verification_error locationiq_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static size_t fail_size, fail_after, fail_part_after, fail_request_after;
static size_t failed_allocations, setter_calls;
static bool fail_next_allocation, fail_agent;

void *malloc(size_t size)
{
    if (fail_next_allocation || (size == fail_size && fail_after && --fail_after == 0)) {
        fail_next_allocation = false;
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    /* The next provider allocation after the completed finding is its request. */
    if (!rc && !strcmp(name, "key") && fail_request_after && --fail_request_after == 0)
        fail_next_allocation = true;
    return rc;
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return locationiq_real_setter(result, cause, secrets, count);
}

static char key[36], other[36];

static void make_keys(void)
{
    memcpy(key, "pk.", 3);
    test_secret(key + 3, 32, 0);
    key[3] = 'A'; key[10] = 'Z'; key[15] = '-'; key[34] = '9';
    memcpy(other, "pk.", 3);
    test_secret(other + 3, 32, 9);
    other[5] = 'B'; other[16] = '-'; other[34] = '7';
    CHECK(strlen(key) == 35 && strlen(other) == 35 && strcmp(key, other));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_locationiq_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid LocationIQ detector output"));
    free(error);
    CHECK(br_locationiq_init(NULL, NULL) != 0);
    CHECK(br_locationiq_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_locationiq_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 450 && detector->version == 0);
    CHECK(!strcmp(detector->name, "LocationIQ") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "LocationIQ provides location-based services such as geocoding and reverse geocoding. LocationIQ API keys can be used to access these services and retrieve location data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "locationiq"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 450, value, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len,
                            const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[400], changed[36];
    const char *one[] = {key};
    const char *formats[] = {
        "%s", "'%s'", "locationiq = %s", "LOCATIONIQ\r\n%s", "%s locationiq",
        "-%s-", "\xc3\xa9%s\xc3\xa9", "\xff %s \xfe", "\t%s\r\n",
    };
    for (size_t i = 0; i < sizeof(formats) / sizeof(*formats); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, strlen(input), one, 1);
    }
    const char *absent[] = {"x%s", "_%s", "%sx", "%s_", "%.34s", "%s0"};
    for (size_t i = 0; i < sizeof(absent) / sizeof(*absent); ++i) {
        snprintf(input, sizeof(input), absent[i], key);
        extraction_case(detector, input, strlen(input), NULL, 0);
    }
    const char invalid[] = {'_', '/', '.', ':', ' ', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = invalid[i];
        extraction_case(detector, changed, 35, NULL, 0);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'P';
    extraction_case(detector, changed, 35, NULL, 0);
    memcpy(changed, key, sizeof(key)); changed[1] = 'K';
    extraction_case(detector, changed, 35, NULL, 0);
    memcpy(changed, key, sizeof(key)); changed[3] = '-';
    const char *hyphen[] = {changed};
    extraction_case(detector, changed, 35, hyphen, 1);
    changed[34] = '-';
    extraction_case(detector, changed, 35, NULL, 0);
    snprintf(input, sizeof(input), "%s ", changed);
    extraction_case(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "%sx", changed);
    extraction_case(detector, input, strlen(input), hyphen, 1); /* Literal final word boundary, not a token filter. */
    snprintf(input, sizeof(input), "%s_", changed);
    extraction_case(detector, input, strlen(input), hyphen, 1);
    snprintf(input, sizeof(input), "%s-", changed);
    extraction_case(detector, input, strlen(input), NULL, 0);

    memcpy(changed, "pk.", 3); memset(changed + 3, 'a', 32); changed[35] = '\0';
    const char *low_entropy[] = {changed};
    extraction_case(detector, changed, 35, low_entropy, 1);
    const char *three[] = {key, other, key};
    snprintf(input, sizeof(input), "%s %s\n%s", key, other, key);
    extraction_case(detector, input, strlen(input), three, 3);
    memcpy(input, key, 35); input[35] = '\0'; memcpy(input + 36, other, 35);
    extraction_case(detector, input, 71, three, 2);
    memset(input, '-', 200); memcpy(input + 200, key, 35);
    extraction_case(detector, input, 235, one, 1);
    extraction_case(detector, NULL, 0, NULL, 0);

    br_results results = test_scan(detector, NULL, false, input, 235);
    CHECK(results.len == 1); check_result(&results.items[0], key, false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, 235);
    CHECK(!results.len);
    br_results_clear(&results);
}

typedef struct {
    const br_scan_ctx *ctx;
    const char *keys[3], *agent, *causes[3], *urls[3];
    size_t count;
    int statuses[3], send_rc[3];
    const char *read_errors[3];
    br_header markers[3];
    br_results *out;
    size_t released_ids[3], release_lengths[3], sends_at_release[3];
} expected;

static void check_url(const char *url, const char *value)
{
    char full[160];
    snprintf(full, sizeof(full), "https://us1.locationiq.com/v1/reverse.php?key=%s&lat=-37.870662&lon=144.9803321&format=json", value);
    CHECK(url && !strcmp(url, full));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(ctx == e->ctx && at < e->count && e->out);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, e->keys[at]);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 450);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, e->agent));
    /* Only provider-original URL bytes are borrowed beyond send return. */
    CHECK(!e->urls[at]); e->urls[at] = request->url;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = e->read_errors[at],
    };
    http->send_rc = e->send_rc[at]; http->send_error = e->causes[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    size_t id = 0;
    while (id < e->count && response->headers != &e->markers[id]) ++id;
    CHECK(id < e->count && http->releases < e->count && e->out && e->urls[id]);
    check_url(e->urls[id], e->keys[id]);
    e->urls[id] = NULL;
    e->released_ids[http->releases] = id;
    e->release_lengths[http->releases] = e->out->len;
    e->sends_at_release[http->releases] = http->calls;
    test_http_release(user, response);
}

static void scan_success(const br_detector *detector, const br_scan_ctx *ctx,
                          const char *input, expected *e, br_results *out)
{
    e->ctx = ctx; e->out = out;
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, out, &error) == 0 && !error);
}

static void deferred_publication(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "%s %s %s", key, other, key);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        expected e = {.keys = {key, other, key}, .count = 3, .agent = "TruffleHog locationiq-offline",
                      .statuses = {200, 401, 299}, .read_errors = {"ignored", "", "ignored"}};
        if (mixed) { e.send_rc[1] = 7; e.causes[1] = "cannot create LocationIQ result"; }
        test_http http = {.inspect = inspect_request, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        const char *configured[] = {"https://ignored.invalid"};
        br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .use_cloud = true, .use_found = true};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "locationiq-offline", .endpoints = &endpoints};
        br_results out = {0}; scan_success(detector, &ctx, input, &e, &out);
        CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) {
            check_result(&out.items[i], e.keys[i], i != 1);
            CHECK(!e.urls[i]);
            CHECK(e.released_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 2u : 0u) : 2 - i));
            CHECK(e.release_lengths[i] == (mixed && i == 0 ? 1u : 3u));
            CHECK(e.sends_at_release[i] == (mixed && i == 0 ? 2u : 3u));
        }
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
}

static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void statuses_and_shared_failures(const br_detector *detector)
{
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        expected e = {.keys = {key}, .count = 1, .agent = "TruffleHog", .statuses = {statuses[i]}, .read_errors = {"ignored body failure"}};
        test_http http = {.inspect = inspect_request, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; br_results out = {0};
        scan_success(detector, &ctx, key, &e, &out);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create LocationIQ result"}, {7, "cannot construct LocationIQ request"},
        {-1, NULL}, {1, key}, {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        expected e = {.keys = {key}, .count = 1, .agent = "TruffleHog", .statuses = {200},
                      .send_rc = {failures[i].rc}, .causes = {failures[i].cause}};
        test_http http = {.inspect = inspect_request, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; br_results out = {0};
        scan_success(detector, &ctx, key, &e, &out);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 0);
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport no_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_send},
        {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        size_t before = failed_allocations;
        br_results out = test_scan(detector, &contexts[i], true, key, 35);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 2 || i == 3 ? 1u : 0u));
        check_result(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "%s %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    for (size_t failure = 0; failure < 5; ++failure) {
        expected e = {.keys = {key, other}, .count = 2, .agent = "TruffleHog", .statuses = {200, 200}, .out = &out};
        test_http http = {.inspect = inspect_request, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 regex failure. */
        if (failure == 1) { fail_size = 36; fail_after = 2; } /* Second owned capture. */
        if (failure == 2) { fail_size = 35; fail_after = 2; } /* Second finding after success. */
        if (failure == 3) fail_part_after = 2; /* Nonzero JSON insertion. */
        if (failure == 4) fail_request_after = 2;
        size_t before = failed_allocations;
        CHECK(detector->scan(detector, &ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && !fail_request_after && !fail_next_allocation);
        CHECK(failed_allocations == before + (failure == 3 ? 0u : 1u));
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        if (failure >= 2) CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2);
        if (failure == 4) CHECK(!strcmp(error, "cannot construct LocationIQ request"));
        check_prior(&out, &prior); free(error); error = NULL;
    }
    /* Owned allocation/map failures precede the nil-context constructor drop. */
    for (size_t failure = 0; failure < 3; ++failure) {
        if (failure == 0) { fail_size = 35; fail_after = 1; }
        if (failure == 1) fail_part_after = 1;
        if (failure == 2) fail_request_after = 1;
        CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && !fail_request_after && !fail_next_allocation);
        check_prior(&out, &prior); free(error); error = NULL;
    }
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    check_prior(&out, &prior);
    expected e = {.keys = {key, other}, .count = 2, .agent = "TruffleHog", .statuses = {204, 200}, .out = &out};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    size_t cap = out.cap; out.cap = 0; /* Actual shared push +1 after verified success. */
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append LocationIQ result") && http.calls == 1 && http.releases == 1);
    CHECK(e.release_lengths[0] == 1); check_prior(&out, &prior); free(error);
    fail_size = 35; fail_after = 2;
    CHECK(detector->scan(detector, NULL, false, data, &out, NULL) != 0 && !fail_after);
    check_prior(&out, &prior);
    br_results_clear(&out);
}

int main(void)
{
    make_keys();
    const br_detector *detector = descriptor();
    extraction(detector);
    deferred_publication(detector);
    statuses_and_shared_failures(detector);
    owned_failures(detector);
    CHECK(!fail_after && !fail_part_after && !fail_request_after && !fail_next_allocation && !fail_agent && !setter_calls);
    return test_finish("LocationIQ");
}
