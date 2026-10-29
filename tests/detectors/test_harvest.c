/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[98], key2[98];
static size_t fail_size, fail_after, fail_part;

/* Target actual owned operations without adding production failure seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 260, capture, "key");
    CHECK(result->raw.len == 97 && result->verified == verified && !result->verification_error);
    br_json *hidden = NULL;
    CHECK(!json_object_object_get_ex(result->secret_parts, "id", &hidden));
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_harvest_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_harvest_init(NULL, NULL) != 0);
    CHECK(br_harvest_init(&d, &error) == 0 && d && !error);
    CHECK(br_harvest_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 260 && !d->version && !strcmp(d->name, "Harvest") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Harvest is a time tracking and invoicing software. Harvest API keys can be used to access and manage time tracking data and invoices."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "harvest"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/defaults/type-name integration is parent-owned. */
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *capture)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(d, &ctx, false, input, len);
    CHECK(results.len == (capture ? 1u : 0u) && !http.calls && !http.releases);
    if (capture) result_is(&results.items[0], capture, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *d)
{
    char input[512], changed[98];
    const struct { const char *format; bool match; } cases[] = {
        {"harvest '%s'", true}, {"hArVeSt:%s", true}, {"preHARVESTsuffix\r\n%s", true},
        {"harvest\r%s", true}, {"harvest\n%s", true}, {"harvest .%s.", true},
        {"%s", false}, {"%s harvest", false}, {"har vest %s", false}, {"harvest%s", false},
        {"harvest _%s", false}, {"harvest %s_", false}, {"harvest %s9", false},
        {"harvest %.96s", false}, {"harvest %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, key, key2);
        n += snprintf(input + n, sizeof(input) - (size_t)n, "\nharvest 0012");
        extract_case(d, input, (size_t)n, cases[i].match ? key : NULL);
    }
    const char invalid[] = "-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(changed)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "harvest %s\nharvest 0012", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char *bad_ids[] = {"123", "1234567890", "_1234", "1234_", "x1234", "1234x", "12.34", "12a34"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(*bad_ids); ++i) {
        snprintf(input, sizeof(input), "harvest %s\nharvest %s", key, bad_ids[i]);
        extract_case(d, input, strlen(input), NULL);
    }
    for (size_t len = 4; len <= 9; ++len) {
        snprintf(input, sizeof(input), "harvest %s\nharvest %.*s", key, (int)len, "000123456");
        extract_case(d, input, strlen(input), key);
    }
    snprintf(input, sizeof(input), "harvest %s\n0012", key);
    extract_case(d, input, strlen(input), NULL); /* Each role needs its own prefix. */
    snprintf(input, sizeof(input), "harvest %s", key);
    extract_case(d, input, strlen(input), NULL);
    extract_case(d, "harvest 0012", strlen("harvest 0012"), NULL);
    extract_case(d, NULL, 0, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int role = 0; role < 2; ++role) {
            int n = snprintf(input, sizeof(input), "harvest %s\nharvest", role ? key : "0012");
            memset(input + n, '.', gap); n += (int)gap;
            n += snprintf(input + n, sizeof(input) - (size_t)n, "%s", role ? "0012" : key);
            extract_case(d, input, (size_t)n, gap == 40 ? key : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "harvest%c%s\nharvest 0012", 0, key);
    extract_case(d, input, (size_t)n, key);
    memcpy(changed, key, sizeof(changed)); changed[0] = '.';
    snprintf(input, sizeof(input), "harvest %s\nharvest 0012", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "harvestX%s\nharvest 0012", changed);
    extract_case(d, input, strlen(input), changed);
    memcpy(changed, key, sizeof(changed)); changed[96] = '.';
    snprintf(input, sizeof(input), "harvest %s\nharvest 0012", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "harvest %sX\nharvest 0012", changed);
    extract_case(d, input, strlen(input), changed);
    memset(changed, '.', 97); changed[97] = '\0';
    snprintf(input, sizeof(input), "harvest X%sY\nharvest 0012", changed);
    extract_case(d, input, strlen(input), changed); /* Boundaries are not alphabet validation. */
}

typedef struct {
    const char *const *keys, *const *ids;
    size_t nkeys, nids;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_url;
} expected;

static void check_url(const char *url, const char *capture, const char *id)
{
    char literal[192];
    int n = snprintf(literal, sizeof(literal), "https://api.harvestapp.com/v2/users/me?access_token=%s&account_id=%s", capture, id);
    CHECK(n > 0 && (size_t)n < sizeof(literal));
    CHECK(strlen(url) == (size_t)n && !strcmp(url, literal));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t index = http->calls - 1;
    CHECK(index < e->nkeys * e->nids && http->releases == index && !e->borrowed_url);
    CHECK(ctx == e->ctx && !strcmp(request->method, "GET"));
    check_url(request->url, e->keys[index / e->nids], e->ids[index % e->nids]);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 260);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, e->agent));
    /* Borrow only original URL storage, never prepared request/headers/UA. */
    e->borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user;
    size_t index = http->calls - 1;
    CHECK(e->borrowed_url && http->releases == index);
    check_url(e->borrowed_url, e->keys[index / e->nids], e->ids[index % e->nids]);
    CHECK(response->status == http->response.status && response->body.data == http->response.body.data);
    e->borrowed_url = NULL;
    test_http_release(user, response);
}

static void products(const br_detector *d)
{
    char input[4096];
    int n = snprintf(input, sizeof(input), "harvest %s\nharvest %s\nharvest %s\n", key, key2, key);
    memset(input + n, '.', 1800); n += 1800;
    n += snprintf(input + n, sizeof(input) - (size_t)n, "\nharvest 0012\nharvest 000000001\nharvest 0012");
    const char *keys[] = {key, key2, key}, *ids[] = {"0012", "000000001", "0012"};
    expected e = {.keys = keys, .ids = ids, .nkeys = 3, .nids = 3, .agent = "TruffleHog harvest-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "harvest-offline"}; e.ctx = &ctx;
    br_results results = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(results.len == 9 && !http.calls && !http.releases);
    for (size_t i = 0; i < 9; ++i) result_is(&results.items[i], keys[i / 3], false);
    CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
    br_results_clear(&results);
    results = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9 && !e.borrowed_url);
    for (size_t i = 0; i < 9; ++i) result_is(&results.items[i], keys[i / 3], true);
    br_results_clear(&results);
    results = test_scan(d, NULL, true, input, (size_t)n); CHECK(!results.len); br_results_clear(&results);

    /* Independent regex passes may bind an ID inside the key itself. */
    char overlap[98]; memset(overlap, 'Q', 97); overlap[97] = '\0'; memcpy(overlap + 12, ".0012.", 6);
    snprintf(input, sizeof(input), "harvest %s", overlap);
    const char *overlapping_keys[] = {overlap}, *overlapping_ids[] = {"0012"};
    e.keys = overlapping_keys; e.ids = overlapping_ids; e.nkeys = e.nids = 1;
    http.calls = http.releases = 0;
    results = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
    result_is(&results.items[0], overlap, true); br_results_clear(&results);
}

static void verification(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "harvest %s\nharvest 0000", key);
    const char *keys[] = {key}, *ids[] = {"0000"};
    expected e = {.keys = keys, .ids = ids, .nkeys = 1, .nids = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '!', '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read failure"};
        br_results results = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result_is(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {7, "cannot create Harvest result"}, {-7, "out of memory constructing HTTP headers"},
        {1, "net/http: nil Context"}, {1, key}, {-1, NULL},
    };
    http.response.status = 200;
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_url);
        result_is(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "harvest %s\nharvest 0012", key);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"}, {.transport = &transport, .cancelled = fail_headers},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        br_results results = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_after);
        result_is(&results.items[0], key, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static void expect_fatal(const br_detector *d, const br_scan_ctx *ctx, br_slice input,
                         br_results *results, const br_result *prior)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, true, input, results, &error) != 0 && error && !fail_after && !fail_part);
    CHECK(results->len == 1 && results->items[0].raw.data == prior->raw.data && results->items[0].secret_parts == prior->secret_parts);
    CHECK(results->items[0].verified && results->items[0].verification_error == prior->verification_error);
    CHECK(!memcmp(prior->raw.data, "prior", 5) && !strcmp(prior->verification_error, "caller-owned"));
    free(error);
}

static void resources(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "harvest %s\nharvest %s\nharvest 0012", key, key2);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); prior = results.items[0];
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};

    fail_size = 98; fail_after = 2; /* Second key capture: no partial verification. */
    expect_fatal(d, &ctx, text(input), &results, &prior); CHECK(!http.calls && !http.releases);
    fail_size = 5; fail_after = 1; /* Independent ID capture failure is equally fatal. */
    expect_fatal(d, NULL, text(input), &results, &prior);
    fail_part = 1; /* Positive finding/projection error precedes nil-context skip. */
    expect_fatal(d, NULL, text(input), &results, &prior);
    fail_part = 2; /* Roll back the first successful addition, not caller results. */
    expect_fatal(d, &ctx, text(input), &results, &prior); CHECK(http.calls == 1 && http.releases == 1);
    http.calls = http.releases = 0; http.send_rc = 7;
    fail_part = 2; /* Shared Do suppression must not suppress a later owned failure. */
    expect_fatal(d, &ctx, text(input), &results, &prior); CHECK(http.calls == 1 && http.releases == 1);
    http.calls = http.releases = 0; http.send_rc = 0;
    size_t cap = results.cap; results.cap = 0; /* Actual positive push validation error. */
    expect_fatal(d, &ctx, text(input), &results, &prior); results.cap = cap;
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    results = test_scan(d, NULL, false, input, strlen(input)); CHECK(results.len == 2); br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 97, 0); key[0] = 'Z'; key[23] = '.'; key[47] = '_';
    memset(key2, 'A', 97); key2[97] = '\0'; /* No detector-local entropy/FP filter. */
    const br_detector *d = descriptor();
    extraction(d); products(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part);
    return test_finish("Harvest extraction/products/hidden-ID/metadata/requests/status/read/errors/lifetime/rollback");
}
