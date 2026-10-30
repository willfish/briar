/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_moderation_init(const br_detector **out, char **error);

static size_t fail_size, fail_after, fail_key_after, fail_push_after, setter_calls;
static bool fail_compile, fail_capture, fail_agent;

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
#define br_result_set_verification_error moderation_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return moderation_real_setter(result, cause, secrets, count);
}
static int moderation_compile(const char *const *keywords, size_t count, const char *suffix, br_regex **out, char **error)
{
    if (fail_compile) { *out = NULL; if (error) *error = strdup("owned compile +1"); return 1; }
    return br_regex_compile_prefixed(keywords, count, suffix, out, error);
}
static int moderation_capture(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (fail_capture) { if (error && !*error) *error = strdup("owned capture +1"); return 1; }
    return rc;
}
static int moderation_push(br_results *out, br_result *result)
{
    return fail_push_after && !--fail_push_after ? 1 : br_results_push(out, result);
}
#define br_regex_compile_prefixed moderation_compile
#define br_captures_find moderation_capture
#define br_results_push moderation_push
#include "../../src/detectors/moderation.c"
#undef br_results_push
#undef br_captures_find
#undef br_regex_compile_prefixed

static const br_detector *detector;
static char key[197], other[197];
static const char payload[] = "{\"value\": \"This is an english text\"}";

typedef struct {
    test_http http; br_transport transport; br_scan_ctx ctx;
    size_t count, release_ids[4], release_lengths[4], release_calls[4];
    const char *keys[4], *causes[4], *authorization[4], *urls[4];
    br_slice bodies[4]; br_header markers[4];
    int statuses[4], send_rc[4];
    br_results *out;
} script;
static void check_authorization(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 203 && !memcmp(value, "Bearer ", 7) && !strcmp(value + 7, expected));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && at < 4);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://moderationapi.com/api/v1/analyze/language"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 669);
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization")); check_authorization(request->headers[0].value, s->keys[at]);
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog moderation-offline"));
    /* Borrow original values only, never the prepared request/header-array/UA. */
    s->authorization[at] = request->headers[0].value; s->bodies[at] = request->body; s->urls[at] = request->url;
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
        check_authorization(s->authorization[at], s->keys[at]);
        CHECK(s->bodies[at].len == sizeof(payload) - 1 && !memcmp(s->bodies[at].data, payload, sizeof(payload) - 1));
        CHECK(!strcmp(s->urls[at], "https://moderationapi.com/api/v1/analyze/language"));
    } else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_ids[http->releases] = at; s->release_lengths[http->releases] = s->out->len;
    s->release_calls[http->releases] = http->calls;
    test_http_release(user, response);
}
static void setup(script *s, size_t count)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) { s->keys[i] = key; s->statuses[i] = 200; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "moderation-offline"};
}
static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    s->out = NULL;
    return rc;
}
static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}
static void result_check(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 669, value, "key"); CHECK(result->verified == verified && !result->verification_error);
}
static void extract_case(const void *input, size_t len, const char *expected, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases && !setter_calls);
    for (size_t i = 0; i < count; ++i) result_check(&out.items[i], expected, false);
    br_results_clear(&out);
}
static void token_case(const char *value, size_t count)
{
    char input[600]; int n = snprintf(input, sizeof(input), "moderation %s", value); CHECK(n > 0 && (size_t)n < sizeof(input));
    extract_case(input, (size_t)n, count ? value : NULL, count);
}
static void lengths(char *out, size_t first, size_t second, size_t third)
{
    memset(out, 'A', first); out[first] = '.';
    memset(out + first + 1, 'b', second); out[first + 1 + second] = '.';
    memset(out + first + second + 2, '_', third); out[first + second + third + 2] = 0;
}
static void descriptor_and_grammar(void)
{
    char *error = NULL; const br_detector *again = NULL;
    fail_compile = true; CHECK(br_moderation_init(&again, &error) != 0 && !again && error); free(error); fail_compile = false;
    CHECK(br_moderation_init(NULL, &error) != 0 && error); free(error); error = NULL; CHECK(br_moderation_init(NULL, NULL) != 0);
    CHECK(br_moderation_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_moderation_init(&again, NULL) == 0 && again == detector);
    CHECK(BR_ABI_REVISION == 1 && detector->type == 669 && detector->version == 0 && !strcmp(detector->name, "Moderation") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Moderation API keys are used to access the Moderation API, which provides services for analyzing and moderating content."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "moderation"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(key, 196, 0); test_secret(other, 196, 9);
    key[0] = 'Z'; key[36] = key[152] = '.'; key[44] = 'Q'; key[160] = key[195] = '_';
    other[0] = 'A'; other[36] = other[152] = '.'; other[180] = '_';
    const char *formats[] = {"moderation %s", "MODeration '%s'", "premoderationsuffix\r\n%s", "moderation\r%s", "moderation\n%s", "moderation \xc3\xa9%s\xc3\xa9", "\xffmoderation %s"};
    char input[1400], changed[300];
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), formats[i], key); CHECK(n > 0); extract_case(input, (size_t)n, key, 1);
    }
    /* JWT-shaped text is regex-only, not valid JSON/JWT claims or time data. */
    lengths(changed, 36, 115, 43); token_case(changed, 1);
    const size_t bad_lengths[][3] = {{35, 115, 43}, {37, 115, 43}, {36, 114, 43}, {36, 116, 43}, {36, 115, 42}, {36, 115, 44}};
    for (size_t i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i) {
        lengths(changed, bad_lengths[i][0], bad_lengths[i][1], bad_lengths[i][2]); token_case(changed, 0);
    }
    const size_t positions[] = {2, 55, 170, 36, 152};
    const char replacements[] = {'_', '_', '-', '/', ':'};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, key, sizeof(key)); changed[positions[i]] = replacements[i]; token_case(changed, 0);
    }
    snprintf(input, sizeof(input), "moderation _%s", key); extract_case(input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "moderation %s_", key); extract_case(input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "missing-keyword %s", key); extract_case(input, strlen(input), NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "moderation", 10); size_t n = 10;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + n, "\xf0\x9f\x92\xa1", 4); n += 4; }
        memcpy(input + n, key, 196); n += 196; extract_case(input, n, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
    }
    int n = snprintf(input, sizeof(input), "moderation %s", key); input[70] = 0; extract_case(input, (size_t)n, NULL, 0);
    n = snprintf(input, sizeof(input), "moderation %s\nmoderation %s\nmoderation %s", key, other, key);
    script s; setup(&s, 0); br_results out = run(&s, &s.ctx, false, input);
    CHECK(out.len == 3 && !s.http.calls && !s.http.releases);
    result_check(&out.items[0], key, false); result_check(&out.items[1], other, false); result_check(&out.items[2], key, false); br_results_clear(&out);
    CHECK((size_t)n == strlen(input));
}
static void http_policy_and_lifetime(void)
{
    char input[1300]; snprintf(input, sizeof(input), "moderation %s", key);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 500}; script s;
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        setup(&s, 1); s.statuses[0] = statuses[i]; br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 1);
        result_check(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {NULL, "unsupported: native profile", "out of memory constructing shared request", "owned helper diagnostic is not ownership"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        setup(&s, 1); s.send_rc[0] = i % 2 ? 7 : -1; s.causes[0] = causes[i];
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1 && !s.release_lengths[0]);
        result_check(&out.items[0], key, false); br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "moderation %s\nmoderation %s\nmoderation %s", key, other, key);
    setup(&s, 3); s.keys[1] = other; s.statuses[1] = 403; s.statuses[2] = 299;
    br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 3 && s.http.calls == 3 && s.http.releases == 3);
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
    snprintf(input, sizeof(input), "moderation %s", key);
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
    char input[1300]; snprintf(input, sizeof(input), "moderation %s", key);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 19, "caller-owned", "key") == 0);
    prior.verification_error = strdup("caller diagnostic"); prior.extra_data = json_object_new_object(); CHECK(br_results_push(&out, &prior) == 0);
    br_result saved = out.items[0]; script s; setup(&s, 1);
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 1);
    fail_size = sizeof(payload); fail_after = 1; fatal(&s, NULL, true, input, &out, &saved, "cannot construct Moderation body"); CHECK(!fail_after);
    fail_size = 204; fail_after = 1; CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 1 && fail_after == 1); fail_after = 0;
    fail_size = sizeof(moderation_pending); fail_after = 1; CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 1 && fail_after == 1); fail_after = 0;
    fail_size = sizeof(payload); fail_after = 1; fail_key_after = 1;
    fatal(&s, NULL, true, input, &out, &saved, "cannot create Moderation result"); CHECK(!fail_key_after && fail_after == 1); fail_after = 0;
    fail_size = 196; fail_after = 1; fatal(&s, NULL, true, input, &out, &saved, "cannot create Moderation result"); CHECK(!fail_after);
    fail_size = sizeof(payload); fail_after = 1;
    CHECK(invoke(&s, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == 0 && out.len == 2 && fail_after == 1);
    result_check(&out.items[1], key, false); br_result_clear(&out.items[--out.len]); fail_after = 0;
    CHECK(!s.http.calls && !s.http.releases);
    snprintf(input, sizeof(input), "moderation %s\nmoderation %s", key, other);
    struct allocation { size_t size, after, sends; const char *error; } cases[] = {
        {197, 2, 0, "out of memory copying detector capture"},
        {196, 2, 1, "cannot create Moderation result"},
        {sizeof(payload), 2, 1, "cannot construct Moderation body"},
        {sizeof(moderation_pending), 2, 1, "cannot construct Moderation request"},
        {204, 2, 1, "cannot construct Moderation authorization"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        setup(&s, 2); s.keys[1] = other; fail_size = cases[i].size; fail_after = cases[i].after;
        fatal(&s, &s.ctx, true, input, &out, &saved, cases[i].error);
        CHECK(!fail_after && s.http.calls == cases[i].sends && s.http.releases == s.http.calls);
        if (s.http.releases) CHECK(s.release_lengths[0] == 2);
    }
    setup(&s, 2); s.keys[1] = other; fail_key_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot create Moderation result"); CHECK(!fail_key_after && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 2);
    setup(&s, 2); s.keys[1] = other; fail_push_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot append Moderation result");
    CHECK(!fail_push_after && s.http.calls == 2 && s.http.releases == 2 && s.release_ids[0] == 1 && s.release_ids[1] == 0 && s.release_lengths[0] == 2 && s.release_lengths[1] == 2);
    setup(&s, 0); fail_capture = true; fatal(&s, NULL, false, input, &out, &saved, "owned capture +1"); fail_capture = false;
    CHECK(!s.http.calls && !s.http.releases && !setter_calls); br_results_clear(&out);
}
int main(void)
{
    descriptor_and_grammar(); http_policy_and_lifetime(); owned_failures_and_nil_order();
    return test_finish("moderation");
}
