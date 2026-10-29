/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <malloc.h>

static const char key[] = "0123456789abcdefghijklmnopqrstuv";
static const char other[] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
static const char url_prefix[] = "https://mainnet.infura.io/v3/";
static const unsigned char payload[] =
    "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}";
static size_t fail_size, fail_after, fail_part_after, fail_realloc_size, failed;

/* Reuse the existing named-test seams for owned failures, distinct from the
 * shared setup/Do domain that this provider deliberately suppresses. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed; return NULL; }
    return calloc(1, size);
}

void *realloc(void *p, size_t size)
{
    if (fail_realloc_size && size == fail_realloc_size) {
        fail_realloc_size = 0; ++failed; return NULL;
    }
    if (!size) { free(p); return NULL; }
    size_t previous = p ? malloc_usable_size(p) : 0;
    void *copy = malloc(size);
    if (copy) {
        if (p) memcpy(copy, p, previous < size ? previous : size);
        free(p);
    }
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) { ++failed; return 7; }
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_infura_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_infura_init(NULL, NULL) != 0);
    CHECK(br_infura_init(&d, &error) == 0 && d && !error);
    CHECK(br_infura_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 906 && !d->version && !strcmp(d->name, "Infura") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Infura provides the infrastructure for decentralized applications to connect to the Ethereum blockchain. Infura keys can be used to interact with the Ethereum network."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "infura"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default integration belongs to the parent. */
}

static void result_is(const br_result *r, const char *value, bool verified)
{
    test_key_result(r, 906, value, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *value)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (value ? 1u : 0u) && !http.calls && !http.releases);
    if (value) result_is(&out.items[0], value, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[300], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"infura '%s'", true}, {"INFURA=%s", true}, {"preInFuRasuffix:%s", true},
        {"infura\r\n%s", true}, {"infura\r%s", true}, {"infura\n%s", true},
        {"infura \t%s\t ", true}, {"infura -%s-context", true},
        {"%s", false}, {"%s infura", false}, {"in fura %s", false}, {"infura%s", false},
        {"infura x%s", false}, {"infura _%s", false}, {"infura %s_", false},
        {"infura %sz", false}, {"infura %.31s", false},
        {"infura %s %s", true}, /* A consumed prefix cannot serve another key. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key, other);
        extract_case(d, input, strlen(input), cases[i].matches ? key : NULL);
    }
    const char invalid[] = "AZ_-+/ ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = invalid[i];
        snprintf(input, sizeof(input), "infura %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "infura", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, key, 32);
        extract_case(d, input, 6 + gap + 32, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "💡", 4);
        memcpy(input + 6 + 4 * gap, key, 32);
        extract_case(d, input, 6 + 4 * gap + 32, gap == 40 ? key : NULL);
    }
    int n = snprintf(input, sizeof(input), "infura%c%s", 0, key);
    extract_case(d, input, (size_t)n, key);
    snprintf(input, sizeof(input), "infura %s", other);
    extract_case(d, input, strlen(input), other); /* Neither hex nor entropy validation. */
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_url, *borrowed_name, *borrowed_value;
    br_slice borrowed_body;
    const br_http_response *responses;
    bool arm_raw_failure;
} expected;

static void check_url(const char *url, const char *value)
{
    char full[sizeof(url_prefix) + 32];
    snprintf(full, sizeof(full), "%s%s", url_prefix, value);
    CHECK(url && !strcmp(url, full));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at);
    CHECK(!e->borrowed_url && !e->borrowed_body.data && !e->borrowed_name && !e->borrowed_value);
    CHECK(!strcmp(request->method, "POST"));
    check_url(request->url, e->keys[at]);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 906);
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Borrow only provider-original values, not the effective request, header
     * array or common synthesized User-Agent, which expire at send return. */
    e->borrowed_url = request->url; e->borrowed_body = request->body;
    e->borrowed_name = request->headers[0].name; e->borrowed_value = request->headers[0].value;
    if (e->responses) http->response = e->responses[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && http->releases == at);
    check_url(e->borrowed_url, e->keys[at]);
    CHECK(e->borrowed_body.len == sizeof(payload) - 1 && !memcmp(e->borrowed_body.data, payload, sizeof(payload) - 1));
    CHECK(e->borrowed_name && !strcmp(e->borrowed_name, "Content-Type"));
    CHECK(e->borrowed_value && !strcmp(e->borrowed_value, "application/json"));
    CHECK(response->status == http->response.status && response->body.data == http->response.body.data);
    CHECK(response->body.len == http->response.body.len && response->body_error == http->response.body_error);
    e->borrowed_url = e->borrowed_name = e->borrowed_value = NULL; e->borrowed_body = (br_slice){0};
    test_http_release(user, response);
    if (e->arm_raw_failure) { e->arm_raw_failure = false; fail_size = 32; fail_after = 1; }
}

static void occurrences(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "infura %s\nINFURA %s\ninfura %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog infura-offline"};
    test_http http = {.inspect = inspect_request, .user = &e,
        .response = {.status = 500, .body = {(const unsigned char *)"\"result\"", 8}}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "infura-offline"}; e.ctx = &ctx;
    for (int verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], verify);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    const br_http_response responses[] = {
        {.status = 200, .body = {(const unsigned char *)"\"result\"", 8}, .body_error = ""},
        {.status = 401, .body = {(const unsigned char *)"result", 6}},
        {.status = 500, .body = {(const unsigned char *)"\"result\"", 8}},
    };
    e.responses = responses; http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 3 && http.releases == 3);
    result_is(&out.items[0], other, false); result_is(&out.items[1], key, true); br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], false);
    br_results_clear(&out);
    CHECK(http.calls == 3 && http.releases == 3 && !e.borrowed_url && !e.borrowed_body.data);
}

static void verification(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "infura %s", key);
    const char *keys[] = {key}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 204, 299, 302, 401, 403, 429, 500, 599};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = text("\"result\"")};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, true); br_results_clear(&out);
    }
    static const unsigned char binary[] = {0xff, 0, '"', 'r', 'e', 's', 'u', 'l', 't', '"', 0};
    const struct { br_slice body; bool verifies; } bodies[] = {
        {text("{\"result\":null}"), true}, {text("malformed x\"result\"y trailing"), true},
        {{binary, sizeof(binary)}, true}, {{0}, false}, {text("result"), false},
        {text("{\"Result\":1}"), false}, {text("{\"res\\u0075lt\":1}"), false},
        {text("\"result \""), false}, {text("\" result\""), false},
        {text("\"res ult\""), false}, {text("\"result"), false}, {text("result\""), false},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(*bodies); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 500, .body = bodies[i].body};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, bodies[i].verifies); br_results_clear(&out);
    }
    const struct { int status; br_slice body; const char *cause; } reads[] = {
        {200, text("\"result\""), ""}, {500, {binary, sizeof(binary)}, "read failed"},
        {401, {0}, "read failed"}, {302, {NULL, 9}, ""}, /* Error precedes partial-body projection. */
    };
    for (size_t i = 0; i < sizeof(reads) / sizeof(*reads); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = reads[i].status, .body = reads[i].body, .body_error = reads[i].cause};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(!out.len && http.calls == 1 && http.releases == 1); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } sends[] = {
        {7, "cannot construct Infura URL"}, {-7, "cannot create Infura result"},
        {1, "invalid Infura response body slice"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(sends) / sizeof(*sends); ++i) {
        http.calls = http.releases = 0; http.send_rc = sends[i].rc; http.send_error = sends[i].cause;
        http.response = (br_http_response){.status = 200, .body = {binary, sizeof(binary)}, .body_error = ""};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static bool fail_agent(void *user)
{
    (void)user; fail_size = sizeof("TruffleHog ") + strlen("infura-offline"); fail_after = 1; return false;
}

static void shared_setup(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "infura %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport incomplete = {&http, NULL, test_http_release}; size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &incomplete}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = fail_agent, .user_agent = "infura-offline"},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; size_t before = failed;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && failed == before + (i == 2 || i == 3 ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void expect_fatal(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input,
                         br_results *out, const br_result *prior, const char *message)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, verify, input, out, &error) != 0 && error);
    CHECK(!strcmp(error, message) && !fail_after && !fail_part_after && !fail_realloc_size);
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
    free(error);
}

static void resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "infura %s\ninfura %s\ninfura %s", key, other, key);
    const char *keys[] = {key, other, key}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e,
        .response = {.status = 500, .body = {(const unsigned char *)"\"result\"", 8}}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    size_t before = failed;
    fail_size = 33; fail_after = 2; /* FindAll completes before any verification. */
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "out of memory copying detector capture");
    CHECK(!http.calls && !http.releases && failed == ++before);
    fail_part_after = 1; /* Finding failure precedes the nil-constructor drop. */
    expect_fatal(d, NULL, true, text(input), &out, &prior, "cannot create Infura result");
    CHECK(failed == ++before);
    fail_size = sizeof(url_prefix) + 32; fail_after = 1; /* Full URL before nil. */
    expect_fatal(d, NULL, true, text(input), &out, &prior, "cannot construct Infura URL");
    CHECK(failed == ++before);
    fail_part_after = 2;
    expect_fatal(d, &ctx, false, text(input), &out, &prior, "cannot create Infura result");
    CHECK(!http.calls && !http.releases && failed == ++before);
    e.arm_raw_failure = true; /* Fail second Raw after one verified append. */
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "cannot create Infura result");
    CHECK(!e.arm_raw_failure && http.calls == 1 && http.releases == 1 && failed == ++before);
    http.calls = http.releases = 0;
    fail_size = sizeof(url_prefix) + 32; fail_after = 2;
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "cannot construct Infura URL");
    CHECK(http.calls == 1 && http.releases == 1 && failed == ++before);
    http.calls = http.releases = 0; http.send_rc = -7; http.send_error = "synthetic Do failure";
    fail_part_after = 2; /* Do suppression cannot swallow a later owned error. */
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "cannot create Infura result");
    CHECK(http.calls == 1 && http.releases == 1 && failed == ++before);
    const br_http_response responses[] = {
        {.status = 200, .body_error = ""},
        {.status = 500, .body = {(const unsigned char *)"\"result\"", 8}},
    };
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL; e.responses = responses;
    fail_part_after = 3; /* First drops, second appends, third fails: roll back only this invocation. */
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "cannot create Infura result");
    CHECK(http.calls == 2 && http.releases == 2 && failed == ++before);
    http.calls = http.releases = 0; e.responses = NULL;
    out.cap = 2; fail_realloc_size = 4 * sizeof(br_result); /* Actual positive second-push failure. */
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "cannot append Infura result");
    CHECK(http.calls == 2 && http.releases == 2 && failed == ++before);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 500, .body = {NULL, 9}};
    expect_fatal(d, &ctx, true, text(input), &out, &prior, "invalid Infura response body slice");
    CHECK(http.calls == 1 && http.releases == 1 && failed == before);
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, false, text(input), &out, NULL) != 0 && !fail_part_after && failed == ++before);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(!e.borrowed_url && !e.borrowed_body.data && !e.borrowed_name && !e.borrowed_value);
    br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) != 0);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_realloc_size);
    return test_finish("Infura extraction/occurrences/metadata/POST/status/binary-marker/read-errors/Do/setup/lifetime/rollback");
}
