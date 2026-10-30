/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_oanda_init(const br_detector **out, char **error);

static size_t fail_size, fail_after, fail_key_after, fail_push_after, setter_calls;
static bool fail_compile, fail_capture, fail_agent;
static br_slice captured[4];

void *malloc(size_t size)
{
    if (size == fail_size && fail_after && !--fail_after) return NULL;
    return calloc(1, size);
}
char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) { fail_agent = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && !--fail_key_after) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
#define br_result_set_verification_error oanda_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return oanda_real_setter(result, cause, secrets, count);
}
static int oanda_compile(const char *const *keywords, size_t count, const char *suffix, br_regex **out, char **error)
{
    if (fail_compile) { *out = NULL; if (error) *error = strdup("owned compile +1"); return 1; }
    return br_regex_compile_prefixed(keywords, count, suffix, out, error);
}
static int oanda_capture(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    memset(captured, 0, sizeof(captured));
    for (size_t i = 0; i < out->len && i < 4; ++i) captured[i] = br_captures_at(out, i);
    if (fail_capture) { if (error && !*error) *error = strdup("owned capture +1"); return 1; }
    return rc;
}
static int oanda_push(br_results *out, br_result *result)
{
    return fail_push_after && !--fail_push_after ? 1 : br_results_push(out, result);
}
#define br_regex_compile_prefixed oanda_compile
#define br_captures_find oanda_capture
#define br_results_push oanda_push
#include "../../src/detectors/oanda.c"
#undef br_results_push
#undef br_captures_find
#undef br_regex_compile_prefixed

static const br_detector *detector;
static char key[25], other[25];
typedef struct {
    test_http http; br_transport transport; br_scan_ctx ctx;
    size_t count, release_ids[4], release_lengths[4], release_calls[4];
    const char *keys[4], *causes[4], *auth[4], *urls[4];
    int statuses[4], send_rc[4]; br_header markers[4];
    br_results *out;
} script;
static void check_auth(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 31 && !memcmp(value, "Bearer ", 7) && !strcmp(value + 7, expected));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && at < 4);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://web-services.oanda.com/rates/api/v2/currencies.json"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 635);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization")); check_auth(request->headers[0].value, s->keys[at]);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog oanda-offline"));
    /* Only original provider values are borrowed, not prepared request/UA/array. */
    s->auth[at] = request->headers[0].value; s->urls[at] = request->url;
    s->markers[at] = (br_header){"synthetic-attempt", s->keys[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored body read failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; size_t at = 0;
    while (at < s->count && response->headers != &s->markers[at]) ++at;
    CHECK(http->releases < 4 && s->out && !setter_calls);
    if (at < s->count) {
        check_auth(s->auth[at], s->keys[at]);
        CHECK(!strcmp(s->urls[at], "https://web-services.oanda.com/rates/api/v2/currencies.json"));
        CHECK(captured[at].len == 24 && !memcmp(captured[at].data, s->keys[at], 24));
    } else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_ids[http->releases] = at; s->release_lengths[http->releases] = s->out->len;
    s->release_calls[http->releases] = http->calls; test_http_release(user, response);
}
static void setup(script *s, size_t count)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) { s->keys[i] = key; s->statuses[i] = 200; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "oanda-offline"};
}
static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    s->out = NULL; return rc;
}
static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}
static void result_check(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 635, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}
static void extract_case(const void *input, size_t len, const char *expected, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases && !setter_calls);
    for (size_t i = 0; i < count; ++i) result_check(&out.items[i], expected, false);
    br_results_clear(&out);
}
static void descriptor_and_grammar(void)
{
    char *error = NULL; const br_detector *again = NULL;
    fail_compile = true; CHECK(br_oanda_init(&again, &error) != 0 && !again && error); free(error); fail_compile = false;
    CHECK(br_oanda_init(NULL, &error) != 0 && error); free(error); error = NULL; CHECK(br_oanda_init(NULL, NULL) != 0);
    CHECK(br_oanda_init(&detector, &error) == 0 && detector && !error); CHECK(br_oanda_init(&again, NULL) == 0 && again == detector);
    CHECK(BR_ABI_REVISION == 1 && detector->type == 635 && detector->version == 0 && !strcmp(detector->name, "Oanda") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Oanda is a forex trading platform. Oanda API keys can be used to access and manage trading accounts, execute trades, and retrieve market data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "oanda"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(key, 24, 0); test_secret(other, 24, 9); key[0] = 'Z'; key[12] = 'Q'; other[4] = 'A';
    const char *formats[] = {"oanda %s", "OANDA '%s'", "preoandasuffix\r\n%s", "oanda\r%s", "oanda\n%s", "oanda \xc3\xa9%s\xc3\xa9", "\xffoanda %s", "oanda %s-tail"};
    char input[1100], changed[26];
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), formats[i], key); CHECK(n > 0); extract_case(input, (size_t)n, key, 1);
    }
    const char *bad_formats[] = {"missing-keyword %s", "oanda _%s", "oanda %s_", "oanda 0%s", "oanda %s0"};
    for (size_t i = 0; i < sizeof(bad_formats) / sizeof(bad_formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), bad_formats[i], key); CHECK(n > 0); extract_case(input, (size_t)n, NULL, 0);
    }
    memcpy(changed, key, sizeof(key)); changed[23] = 0;
    snprintf(input, sizeof(input), "oanda %s", changed); extract_case(input, strlen(input), NULL, 0);
    const char bad_characters[] = {'_', '-', '.', '/', '+', '='};
    for (size_t i = 0; i < sizeof(bad_characters); ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = bad_characters[i];
        snprintf(input, sizeof(input), "oanda %s", changed); extract_case(input, strlen(input), NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "oanda", 5); size_t n = 5;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + n, "\xf0\x9f\x92\xa1", 4); n += 4; }
        memcpy(input + n, key, 24); n += 24; extract_case(input, n, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
    }
    int n = snprintf(input, sizeof(input), "oanda %s", key); input[14] = 0; extract_case(input, (size_t)n, NULL, 0);
    const char *unfiltered[] = {"AAAAAAAAAAAAAAAAAAAAAAAA", "000000000000000000000000"};
    for (size_t i = 0; i < sizeof(unfiltered) / sizeof(unfiltered[0]); ++i) {
        snprintf(input, sizeof(input), "oanda %s", unfiltered[i]); extract_case(input, strlen(input), unfiltered[i], 1);
    }
    snprintf(input, sizeof(input), "oanda %s\noanda %s\noanda %s", key, other, key);
    script s; setup(&s, 0); br_results out = run(&s, NULL, false, input);
    CHECK(out.len == 3 && !s.http.calls && !s.http.releases);
    result_check(&out.items[0], key, false); result_check(&out.items[1], other, false); result_check(&out.items[2], key, false); br_results_clear(&out);
}
static void http_policy_and_lifetime(void)
{
    char input[500]; snprintf(input, sizeof(input), "oanda %s", key); script s;
    /* Every 2xx, with a malformed binary body and body_error, is verified. */
    for (int status = 200; status < 300; ++status) {
        setup(&s, 1); s.statuses[0] = status; br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 1);
        result_check(&out.items[0], key, true); br_results_clear(&out);
    }
    const int bad_statuses[] = {-1, 0, 199, 300, 401, 500};
    for (size_t i = 0; i < sizeof(bad_statuses) / sizeof(bad_statuses[0]); ++i) {
        setup(&s, 1); s.statuses[0] = bad_statuses[i]; br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 1);
        result_check(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *causes[] = {NULL, "unsupported: native profile", "out of memory in shared preparation", "owned helper words are not provenance"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        setup(&s, 1); s.send_rc[0] = i % 2 ? 7 : -1; s.causes[0] = causes[i];
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && !s.release_lengths[0]);
        result_check(&out.items[0], key, false); br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "oanda %s\noanda %s\noanda %s", key, other, key);
    setup(&s, 3); s.keys[1] = other; s.statuses[1] = 403; br_results out = run(&s, &s.ctx, true, input);
    CHECK(out.len == 3 && s.http.calls == 3 && s.http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        result_check(&out.items[i], i == 1 ? other : key, i != 1);
        CHECK(s.release_ids[i] == 2 - i && s.release_lengths[i] == 3 && s.release_calls[i] == 3);
    }
    br_results_clear(&out);
    setup(&s, 3); s.keys[1] = other; s.send_rc[1] = 7; s.causes[1] = "unsupported: shared error";
    out = run(&s, &s.ctx, true, input); CHECK(out.len == 3 && s.http.calls == 3 && s.http.releases == 3);
    CHECK(s.release_ids[0] == 1 && s.release_lengths[0] == 1 && s.release_calls[0] == 2);
    CHECK(s.release_ids[1] == 2 && s.release_ids[2] == 0 && s.release_lengths[1] == 3 && s.release_lengths[2] == 3);
    for (size_t i = 0; i < 3; ++i) result_check(&out.items[i], i == 1 ? other : key, i != 1);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "oanda %s", key);
    setup(&s, 1); s.ctx.user_agent = "bad\r\nagent"; out = run(&s, &s.ctx, true, input);
    CHECK(out.len == 1 && !s.http.calls && s.http.releases == 1 && !s.release_lengths[0]); result_check(&out.items[0], key, false); br_results_clear(&out);
    setup(&s, 1); s.ctx.user_agent = NULL; fail_agent = true; out = run(&s, &s.ctx, true, input);
    CHECK(out.len == 1 && !fail_agent && !s.http.calls && s.http.releases == 1); result_check(&out.items[0], key, false); br_results_clear(&out);
    setup(&s, 1); br_scan_ctx missing = {0}; out = run(&s, &missing, true, input);
    CHECK(out.len == 1 && !s.http.calls && !s.http.releases); result_check(&out.items[0], key, false); br_results_clear(&out);
    CHECK(!setter_calls);
}
static void fatal(script *s, const br_scan_ctx *ctx, bool verify, const char *input,
                   br_results *out, const br_result *saved, const char *expected_error)
{
    char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, &error) != 0 && error);
    CHECK(!strcmp(error, expected_error) && out->len == 1 && !memcmp(&out->items[0], saved, sizeof(*saved))); free(error);
}
static void owned_failures_and_nil_order(void)
{
    char input[500]; snprintf(input, sizeof(input), "oanda %s", key);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 19, "caller-owned", "key") == 0);
    prior.verification_error = strdup("caller diagnostic"); prior.extra_data = json_object_new_object(); CHECK(br_results_push(&out, &prior) == 0);
    br_result saved = out.items[0]; script s; setup(&s, 1);
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 1);
    fail_size = 24; fail_after = 1; fatal(&s, NULL, true, input, &out, &saved, "cannot create Oanda result"); CHECK(!fail_after);
    fail_size = sizeof(oanda_pending); fail_after = 1; fail_key_after = 1;
    fatal(&s, NULL, true, input, &out, &saved, "cannot create Oanda result"); CHECK(!fail_key_after && fail_after == 1); fail_after = 0;
    fail_size = sizeof(oanda_pending); fail_after = 1;
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 1 && fail_after == 1);
    CHECK(invoke(&s, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 2 && fail_after == 1);
    result_check(&out.items[1], key, false); br_result_clear(&out.items[--out.len]); fail_after = 0;
    CHECK(!s.http.calls && !s.http.releases);
    snprintf(input, sizeof(input), "oanda %s\noanda %s", key, other);
    struct allocation { size_t size, after, sends; const char *error; } cases[] = {
        {25, 2, 0, "out of memory copying detector capture"},
        {24, 2, 1, "cannot create Oanda result"},
        {sizeof(oanda_pending), 2, 1, "cannot construct Oanda request"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        setup(&s, 2); s.keys[1] = other; fail_size = cases[i].size; fail_after = cases[i].after;
        fatal(&s, &s.ctx, true, input, &out, &saved, cases[i].error);
        CHECK(!fail_after && s.http.calls == cases[i].sends && s.http.releases == s.http.calls);
        if (s.http.releases) CHECK(s.release_lengths[0] == 2);
    }
    setup(&s, 2); s.keys[1] = other; fail_key_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot create Oanda result"); CHECK(!fail_key_after && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 2);
    setup(&s, 2); s.keys[1] = other; fail_push_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot append Oanda result");
    CHECK(!fail_push_after && s.http.calls == 2 && s.http.releases == 2 && s.release_ids[0] == 1 && s.release_ids[1] == 0 && s.release_lengths[0] == 2 && s.release_lengths[1] == 2);
    setup(&s, 0); fail_capture = true; fatal(&s, NULL, false, input, &out, &saved, "owned capture +1"); fail_capture = false;
    CHECK(!s.http.calls && !s.http.releases && !setter_calls); br_results_clear(&out);
}
int main(void)
{
    descriptor_and_grammar(); http_policy_and_lifetime(); owned_failures_and_nil_order();
    return test_finish("oanda");
}
