/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <limits.h>

int br_monday_init(const br_detector **out, char **error);

#define br_results_push monday_real_push
#define br_result_set_verification_error monday_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static size_t fail_size, fail_after, allocation_failures, fail_part_after, fail_push_after, fail_set_after;
static size_t setter_calls, null_setters;
static char key[149], other[149];
static void observe_setter(const br_result *, const char *);
static void observe_push(const br_results *);

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t n = strlen(value) + 1; char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
int br_results_push(br_results *out, br_result *owned)
{
    observe_push(out);
    if (fail_push_after && --fail_push_after == 0) return 1;
    return monday_real_push(out, owned);
}
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; if (!cause) ++null_setters;
    CHECK(!secrets && !count); /* Source passes ZERO explicit secrets, not Raw/token. */
    observe_setter(result, cause);
    if (fail_set_after && --fail_set_after == 0) return 1;
    return monday_real_setter(result, cause, secrets, count);
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static void token(char *out, size_t first, size_t second, size_t signature, size_t shift)
{
    memcpy(out, "eyJ", 3); test_secret(out + 3, first, shift); size_t at = first + 3;
    out[at++] = '.'; memcpy(out + at, "eyJ", 3); at += 3; test_secret(out + at, second, shift + 1); at += second;
    out[at++] = '.'; test_secret(out + at, signature, shift + 2);
    CHECK(strlen(out) == 8 + first + second + signature);
}
static const br_detector *descriptor(void)
{
    token(key, 15, 100, 25, 0); token(other, 15, 100, 25, 5);
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 148 && strlen(other) == 148 && strcmp(key, other));
    CHECK(br_monday_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Monday detector output")); free(error); error = NULL;
    CHECK(br_monday_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:monday)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_monday_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_monday_init(&d, &error) == 0 && d && !error);
    CHECK(br_monday_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 246 && d->version == 0 && !strcmp(d->name, "Monday") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Monday.com is a work operating system that powers teams to run projects and workflows with confidence. Monday API keys can be used to access and modify data and workflows on the platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "monday"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}
static void finding(const br_result *r, const char *expected, bool verified, const char *cause)
{
    test_key_result(r, 246, expected, "key");
    CHECK(r->verified == verified && (r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
}
static void extraction_case(const br_detector *d, const void *data, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, false, data, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected) finding(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void token_case(const br_detector *d, const char *value, const char *expected)
{
    char input[750]; int n = snprintf(input, sizeof(input), "monday '%s'", value); CHECK(n > 0 && (size_t)n < sizeof(input));
    extraction_case(d, input, (size_t)n, expected);
}
static void extraction(const br_detector *d)
{
    char input[900], changed[520];
    snprintf(input, sizeof(input), "preMoNdAySuffix\r\n%s", key); extraction_case(d, input, strlen(input), key);
    extraction_case(d, key, strlen(key), NULL); extraction_case(d, NULL, 0, NULL);
    const struct { size_t first, second, signature; bool accepted; } lengths[] = {
        {15,100,25,true}, {100,300,100,true}, {14,100,25,false}, {101,100,25,false},
        {15,99,25,false}, {15,301,25,false}, {15,100,24,false}, {15,100,101,false},
    };
    for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
        token(changed, lengths[i].first, lengths[i].second, lengths[i].signature, i);
        token_case(d, changed, lengths[i].accepted ? changed : NULL);
    }
    const size_t positions[] = {0, 1, 2, 18, 19, 20, 21, 122};
    for (size_t i = 0; i < sizeof(positions) / sizeof(*positions); ++i) {
        memcpy(changed, key, sizeof(key)); changed[positions[i]] = positions[i] == 18 || positions[i] == 122 ? 'x' : 'X'; token_case(d, changed, NULL);
    }
    const char excluded[] = {'+', '/', '=', ':'};
    for (size_t i = 0; i < sizeof(excluded); ++i) { memcpy(changed, key, sizeof(key)); changed[40] = excluded[i]; token_case(d, changed, NULL); }
    memcpy(changed, key, sizeof(key)); changed[4] = 'Z'; changed[25] = '-'; changed[40] = '_'; changed[130] = '-'; changed[147] = '_'; token_case(d, changed, changed);
    snprintf(input, sizeof(input), "monday _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "monday %sx", key); extraction_case(d, input, strlen(input), input + 7); /* Signature grows inside its range. */
    snprintf(input, sizeof(input), "monday \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    /* A trailing nonword hyphen permits a shorter capture at its preceding word
     * boundary; this is literal regex behavior, not whole-token validation. */
    snprintf(input, sizeof(input), "monday %s-", key); extraction_case(d, input, strlen(input), key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "monday", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, key, sizeof(key));
        extraction_case(d, input, 6 + gap + 148, gap == 40 ? key : NULL);
        size_t at = 6; for (size_t j = 0; j < gap; ++j) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, sizeof(key)); extraction_case(d, input, at + 148, gap == 40 ? key : NULL);
    }
    memcpy(input, "monday", 6); input[6] = '\0'; input[7] = '\r'; input[8] = '\n'; memcpy(input + 9, key, sizeof(key)); extraction_case(d, input, 157, key);
    snprintf(input, sizeof(input), "monday %s %s", key, key); extraction_case(d, input, strlen(input), key);
    char repeated[2400]; size_t at = 0;
    for (size_t i = 0; i < 12; ++i) at += (size_t)snprintf(repeated + at, sizeof(repeated) - at, "MONDAY %s\n", i % 2 ? other : key);
    size_t before = setter_calls; br_results out = test_scan(d, NULL, false, repeated, at); CHECK(out.len == 12 && setter_calls == before);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], i % 2 ? other : key, false, NULL);
    br_results_clear(&out);
}

typedef struct { const char *key, *cause; int status, code; bool no_diagnostic; } row;
typedef struct {
    test_http http; const row *rows; size_t count;
    br_results *out; size_t base, setters, pushes, releases_per_setter;
    const char *url, *authorization; br_slice body; char *transport_error;
    size_t arm_call, arm_size, arm_after;
} wire;
static wire *active;
static const unsigned char payload[] = "{\"query\":\"{boards(limit:1){id name}}\"}";
static void original_values(const wire *w)
{
    CHECK(w->url && !strcmp(w->url, "https://api.monday.com/v2"));
    CHECK(w->authorization && !strcmp(w->authorization, w->rows[w->http.calls - 1].key));
    CHECK(w->body.data && w->body.len == sizeof(payload) - 1 && !memcmp(w->body.data, payload, sizeof(payload) - 1));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire *w = http->user; size_t i = http->calls - 1;
    CHECK(active == w && i < w->count && http->releases == i && w->setters == i && w->pushes == i && w->out->len == w->base + i);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(request->detector_type == 246 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog monday-offline" : "TruffleHog"));
    /* Only provider original URL/body/header VALUE pointers survive send. */
    w->url = request->url; w->authorization = request->headers[1].value; w->body = request->body; original_values(w);
    static const unsigned char garbage[] = "\0\xff not JSON and no JWT claims";
    const row *r = w->rows + i;
    http->response = (br_http_response){.status = r->status, .body = {garbage, sizeof(garbage) - 1}, .body_error = i % 2 ? "" : "ignored read/drain error"};
    http->send_error = r->cause; http->send_rc = r->code;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; wire *w = http->user; int rc = test_http_send(user, ctx, request, response, error); w->transport_error = *error;
    if (w->rows[http->calls - 1].no_diagnostic) {
        CHECK(rc != 0 && !*error); fail_size = sizeof("HTTP transport failed"); fail_after = 1;
    } /* Actual shared fallback allocation fails: its mixed domain may return NULL cause. */
    if (w->arm_call == http->calls) { fail_size = w->arm_size; fail_after = w->arm_after; }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; wire *w = http->user;
    CHECK(active == w && w->out->len == w->base + w->setters && w->pushes == w->setters);
    if (http->calls) {
        CHECK(http->calls == w->setters + 1 && http->releases == w->setters); original_values(w);
        /* Caller retains allocation ownership; poisoning its borrowed bytes
         * proves the cause was copied BEFORE close, but setter runs AFTER. */
        if (w->transport_error) memset(w->transport_error, '!', strlen(w->transport_error));
    } else CHECK(!response->status && !response->body.data && !response->body.len);
    w->url = w->authorization = NULL; w->body = (br_slice){0}; w->transport_error = NULL;
    test_http_release(user, response);
}
static void observe_setter(const br_result *result, const char *cause)
{
    if (!active) return;
    wire *w = active; size_t i = w->setters++;
    CHECK(i < w->count && w->out->len == w->base + i && w->pushes == i && !w->url && !w->authorization && !w->body.data);
    CHECK(w->http.releases == (i + 1) * w->releases_per_setter);
    CHECK(result->detector_type == 246 && result->raw.len == strlen(w->rows[i].key));
    CHECK(!memcmp(result->raw.data, w->rows[i].key, result->raw.len)); (void)cause;
}
static void observe_push(const br_results *out)
{
    if (!active) return;
    wire *w = active;
    CHECK(out == w->out && w->setters == w->pushes + 1 && out->len == w->base + w->pushes);
    CHECK(w->http.releases == w->setters * w->releases_per_setter); ++w->pushes;
}
static int invoke(const br_detector *d, const char *input, wire *w, br_results *out, char **error)
{
    w->out = out; w->base = out->len; w->http.inspect = inspect; w->http.user = w; w->releases_per_setter = 1;
    br_transport transport = {&w->http, send_reply, release_reply}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "monday-offline"};
    active = w; int rc = d->scan(d, &ctx, true, text(input), out, error); active = NULL;
    CHECK(!w->url && !w->authorization && !w->body.data && !w->transport_error && w->http.releases == w->http.calls);
    return rc;
}
static br_results run(const br_detector *d, const char *input, wire *w)
{
    br_results out = {0}; char *error = NULL; CHECK(invoke(d, input, w, &out, &error) == 0 && !error);
    CHECK(out.len == w->count && w->http.calls == w->count && w->setters == w->count && w->pushes == w->count); return out;
}
static void statuses_and_causes(const br_detector *d)
{
    char input[600]; snprintf(input, sizeof(input), "monday %s", key);
    const int statuses[] = {INT_MIN,-1,0,199,200,201,204,299,300,401,403,500,INT_MAX};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        row r = {.key = key, .status = statuses[i]}; wire w = {.rows = &r, .count = 1}; br_results out = run(d, input, &w);
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        finding(&out.items[0], key, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause); br_results_clear(&out);
    }
    char sensitive[400]; snprintf(sensitive, sizeof(sensitive), "synthetic echo %s then %s", key, key);
    const char *causes[] = {sensitive, "out of memory constructing HTTP headers", "net/http: nil Context", "cannot create Monday result", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        row r = {.key = key, .status = 200, .code = i % 2 ? 1 : -7, .cause = causes[i]}; wire w = {.rows = &r, .count = 1};
        br_results out = run(d, input, &w); finding(&out.items[0], key, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    size_t before = null_setters, failed = allocation_failures;
    row no_cause = {.key = key, .status = 200, .code = 1, .no_diagnostic = true}; wire w = {.rows = &no_cause, .count = 1};
    br_results out = run(d, input, &w); CHECK(null_setters == before + 1 && allocation_failures == failed + 1 && !fail_after);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    const row rows[] = {{key,NULL,200,0,false},{other,NULL,401,0,false},{key,sensitive,200,1,false}};
    snprintf(input, sizeof(input), "monday %s\nMONDAY %s\nmonday %s", key, other, key); w = (wire){.rows = rows, .count = 3}; out = run(d, input, &w);
    finding(&out.items[0], key, true, NULL); finding(&out.items[1], other, false, NULL); finding(&out.items[2], key, false, sensitive); br_results_clear(&out);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void nil_and_shared_preparation(const br_detector *d)
{
    char input[600]; snprintf(input, sizeof(input), "monday %s\nmonday %s", key, other);
    row rows[] = {{.key = key}, {.key = other}}; br_results out = {0}; wire w = {.rows = rows, .count = 2, .out = &out}; active = &w;
    char *error = NULL; CHECK(d->scan(d, NULL, true, text(input), &out, &error) == 0 && !error); active = NULL;
    CHECK(out.len == 2 && w.setters == 2 && w.pushes == 2 && !w.http.calls && !w.http.releases);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], rows[i].key, false, "net/http: nil Context");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "monday %s", key);
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        out = (br_results){0}; w = (wire){.rows = rows, .count = 1, .out = &out, .releases_per_setter = i ? 1u : 0u}; w.http.user = &w;
        br_transport transport = {&w.http, send_reply, release_reply}; br_scan_ctx ctx = {.transport = i ? &transport : NULL,
            .cancelled = i == 1 ? cancelled : i == 4 ? fail_headers : NULL, .deadline_monotonic_ms = i == 2 ? 1 : 0, .user_agent = i == 3 ? "bad\r\nagent" : NULL};
        size_t failed = allocation_failures; active = &w; error = NULL; CHECK(d->scan(d, &ctx, true, text(input), &out, &error) == 0 && !error); active = NULL;
        CHECK(out.len == 1 && !w.http.calls && w.http.releases == (i ? 1u : 0u) && w.setters == 1 && w.pushes == 1 && !fail_after);
        CHECK(allocation_failures == failed + (i == 4)); finding(&out.items[0], key, false, causes[i]); br_results_clear(&out);
    }
}
static br_results caller_owned(void)
{
    br_results out = {0}; br_result prior = {.detector_type = 17, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data);
    memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4; prior.verification_error = strdup("caller diagnostic"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&out, &prior)); return out;
}
static void preserved(br_results *out, unsigned char *raw, char *cause, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1 && out->items[0].detector_type == 17 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(out->items[0].verification_error == cause && !strcmp(cause, "caller diagnostic")); free(error); br_results_clear(out);
}
static void owned_failures(const br_detector *d)
{
    char input[400]; snprintf(input, sizeof(input), "monday %s\nmonday %s", key, other);
    /* Reached capture/raw/cause and actual setter allocations remain fatal even
     * at nil context; NULL constructor is an error finding, never a drop. */
    const size_t sizes[] = {2 * sizeof(br_span),148,sizeof("net/http: nil Context"),sizeof("net/http: nil Context")};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); ++i) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; char *cause = out.items[0].verification_error, *error = NULL;
        size_t before = allocation_failures; fail_size = sizes[i]; fail_after = i == 3 ? 2 : 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1);
        preserved(&out, raw, cause, rc, error);
    }
    for (int mode = 0; mode < 6; ++mode) {
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; char *cause = out.items[0].verification_error, *error = NULL;
        const row rows[] = {{.key = key, .status = 200}, {.key = other, .status = mode == 4 ? 401 : 200}};
        wire w = {.rows = rows, .count = 2};
        if (mode <= 2) fail_part_after = 2; else if (mode == 3) fail_push_after = 2; else fail_set_after = 2;
        int rc = mode == 1 || mode == 2 ? d->scan(d, NULL, mode == 2, text(input), &out, &error) : invoke(d, input, &w, &out, &error);
        CHECK(!fail_part_after && !fail_push_after && !fail_set_after);
        if (mode == 0) CHECK(w.http.calls == 1 && w.http.releases == 1 && w.setters == 1);
        if (mode >= 3) CHECK(w.http.calls == 2 && w.http.releases == 2 && w.setters == 2);
        preserved(&out, raw, cause, rc, error);
    }
    const char diagnostic[] = "synthetic provider cause remains exact";
    for (int mode = 0; mode < 4; ++mode) {
        const row rows[] = {{.key = key, .status = 200}, {.key = other, .status = 503, .code = mode >= 2 ? 1 : 0, .cause = mode >= 2 ? diagnostic : NULL}};
        wire w = {.rows = rows, .count = 2, .arm_call = 2, .arm_size = mode >= 2 ? sizeof(diagnostic) : sizeof("unexpected status code: 503"), .arm_after = mode % 2 ? 2u : 1u};
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; char *cause = out.items[0].verification_error, *error = NULL; size_t before = allocation_failures;
        int rc = invoke(d, input, &w, &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1 && w.http.calls == 2 && w.http.releases == 2 && w.setters == (mode % 2 ? 2u : 1u));
        preserved(&out, raw, cause, rc, error);
    }
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); statuses_and_causes(d); nil_and_shared_preparation(d); owned_failures(d);
    CHECK(setter_calls && null_setters && !active && !fail_after && !fail_part_after && !fail_push_after && !fail_set_after);
    return test_finish("Monday helper-local release before mandatory zero-secret setter, exact statuses and rollback");
}
