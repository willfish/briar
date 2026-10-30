/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_moralis_init(const br_detector **out, char **error);

static char key[65], other[65];
static const char url[] =
    "https://deep-index.moralis.io/api/v2/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nft?chain=eth&format=decimal";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_key, fail_next_malloc;

static void fill_key(char *out, unsigned salt)
{
    static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < 64; ++i) out[i] = alphabet[(i + salt) % 62];
    out[64] = '\0';
}

void *malloc(size_t size)
{
    if (fail_next_malloc) { fail_next_malloc = false; ++allocation_failures; return NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key")) {
        if (arm_http_headers) { arm_http_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
        if (arm_key) { arm_key = false; fail_size = 65; fail_after = 1; }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 9);
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64 && strcmp(key, other));
    CHECK(strlen(url) == 108 && !strcmp(url, "https://deep-index.moralis.io/api/v2/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nft?chain=eth&format=decimal"));
    CHECK(br_moralis_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_moralis_init(&d, &error) == 0 && d && !error);
    CHECK(br_moralis_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 909 && d->version == 0 && !strcmp(d->name, "Moralis"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Moralis is a platform for building and deploying decentralized applications (dApps). Moralis API keys can be used to interact with blockchain data and services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "moralis"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 909, expected, "key");
    CHECK(result->verified == verified && !result->verification_error && !result->extra_data && !result->raw_v2.data);
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[65];
    extraction_case(d, key, NULL);
    snprintf(input, sizeof(input), "moralis %s", key); extraction_case(d, input, key);
    snprintf(input, sizeof(input), "MORALIS:%s", key); extraction_case(d, input, key);
    snprintf(input, sizeof(input), "moralis%s", key); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "moralis %.63s", key); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "moralis %sa", key); extraction_case(d, input, NULL);
    memcpy(changed, key, 65); changed[8] = '-';
    snprintf(input, sizeof(input), "moralis %s", changed); extraction_case(d, input, NULL);
    char gap[160];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "moralis", 7); memcpy(gap + 47, key, 64);
    br_results out = test_scan(d, NULL, false, gap, 111); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "moralis", 7); memcpy(gap + 48, key, 64);
    out = test_scan(d, NULL, false, gap, 112); CHECK(out.len == 0); br_results_clear(&out);
    snprintf(input, sizeof(input), "moralis %s\nMoralis %s\nmoralis %s", key, other, key);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; } row;
typedef struct { const char *api_key, *key; } held;
typedef struct {
    row rows[5]; size_t count; const br_scan_ctx *ctx; bool suffix, expect_published, retain_fails;
    const char *borrowed_key; br_results *results;
    size_t arm_call, arm_size, arm_after, arm_push;
    held deferred[5]; size_t deferred_len; size_t failed_sends;
    bool immediate; const char *immediate_key, *immediate_expected;
    const char *released_keys[5]; size_t release_n;
} script;

static void api_key(const char *value, const char *expected)
{
    CHECK(value && expected && strlen(value) == 64 && !memcmp(value, expected, 65));
    CHECK(strncmp(value, "Bearer ", 7) && strncmp(value, "Token ", 6));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 909 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    /* Canonical stored name. Source spelling X-API-Key must not be sent. */
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && strcmp(request->headers[1].name, "X-API-Key"));
    api_key(request->headers[1].value, reply->key);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog moralis-offline" : "TruffleHog"));
    steps->borrowed_key = request->headers[1].value;
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        CHECK(steps->deferred[i].api_key && steps->deferred[i].api_key != request->headers[1].value);
        api_key(steps->deferred[i].api_key, steps->deferred[i].key);
        for (size_t j = 0; j < i; ++j) CHECK(steps->deferred[i].api_key != steps->deferred[j].api_key);
    }
    http->response = (br_http_response){.status = reply->status, .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    row *reply = &steps->rows[http->calls - 1];
    bool failed = reply->rc != 0;
    bool retain_this = steps->retain_fails && !failed && http->calls == steps->count;
    if (failed || retain_this) {
        steps->immediate = true;
        steps->immediate_key = steps->borrowed_key; steps->immediate_expected = reply->key;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 5);
        steps->deferred[steps->deferred_len++] = (held){.api_key = steps->borrowed_key, .key = reply->key};
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *owned = NULL, *expected = NULL; bool deferred = false;
    if (steps->immediate) {
        owned = steps->immediate_key; expected = steps->immediate_expected; steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].api_key != owned);
            api_key(steps->deferred[i].api_key, steps->deferred[i].key);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        owned = item.api_key; expected = item.key; deferred = true;
    }
    api_key(owned, expected);
    if (deferred && steps->expect_published) {
        bool found = false; CHECK(steps->results);
        for (size_t i = 0; steps->results && i < steps->results->len; ++i) {
            const br_result *item = &steps->results->items[i];
            if (item->raw.len == 64 && item->raw.data && !memcmp(item->raw.data, expected, 64)) found = true;
        }
        CHECK(found);
    }
    if (steps->release_n < 5) steps->released_keys[steps->release_n++] = expected;
    steps->borrowed_key = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "moralis-offline" : NULL}; steps->ctx = &ctx;
    steps->results = out;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_key && !steps->deferred_len && !steps->immediate);
    return rc;
}

static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_and_send_policy(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "moralis %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = status, .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = statuses[i], .read_error = "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = "must not be read"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    char occurrences[240];
    snprintf(occurrences, sizeof(occurrences), "moralis %s\nMORALIS %s\nmoralis %s", key, other, key);
    script steps = {.count = 3, .suffix = true, .expect_published = true};
    steps.rows[0] = (row){.key = key, .status = 200, .read_error = "read failed"};
    steps.rows[1] = (row){.key = other, .status = 401};
    steps.rows[2] = (row){.key = key, .status = 204, .read_error = ""};
    br_results out = run(d, occurrences, &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, true); finding(&out.items[1], other, false); finding(&out.items[2], key, true);
    CHECK(!steps.failed_sends && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "moralis %s\nMORALIS %s", key, other);
    script early = {.count = 2, .expect_published = true};
    early.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = "early Do", .read_error = "must not be read"};
    early.rows[1] = (row){.key = other, .status = 204, .read_error = ""};
    out = run(d, occurrences, &early); CHECK(out.len == 2);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key && early.released_keys[1] == other);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "moralis %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    arm_key = true;
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    /* Finding exists first. The armed key allocation is not consumed. */
    CHECK(!arm_key && fail_after == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key"); fail_after = 0; br_results_clear(&caller);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(out);
}

static void own_failure_rollback(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "moralis %s", key);
    const size_t sizes[] = {65, 64};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_key = true;
    rc = d->scan(d, &ctx, true, text(input), &out, &error);
    CHECK(!arm_key && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "allocate")); rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[180]; snprintf(pair, sizeof(pair), "moralis %s\nmoralis %s", key, key);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 64, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, pair, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .status = 200, .read_error = "kept"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 1 && steps.released_keys[0] == key && !steps.failed_sends);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    char many[500]; size_t used = 0;
    const char *cycle[] = {key, other, key, other, key};
    steps = (script){.count = 5, .retain_fails = true, .expect_published = true};
    for (size_t i = 0; i < 5; ++i) {
        int wrote = snprintf(many + used, sizeof(many) - used, "%smoralis %s", i ? "\n" : "", cycle[i]);
        CHECK(wrote > 0 && (size_t)wrote < sizeof(many) - used); used += (size_t)wrote;
        steps.rows[i] = (row){.key = cycle[i], .status = 200 + (int)i};
    }
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, many, &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1 && steps.release_n == 5);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    CHECK(steps.released_keys[3] == other && steps.released_keys[4] == key);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(input), &out, NULL) == -1);
    error = NULL; CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !fail_next_malloc);
    CHECK(!arm_http_headers && !arm_key);
    return test_finish("Moralis");
}
