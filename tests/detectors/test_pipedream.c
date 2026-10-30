/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pipedream_init(const br_detector **out, char **error);

static bool fail_next_malloc, fail_compile, fail_capture;
static size_t fail_part_after, fail_push_after, arm_request_fault, findings, setter_calls;
static br_slice captured[4];

void *malloc(size_t size)
{
    if (fail_next_malloc) { fail_next_malloc = false; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && !--fail_part_after) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key")) {
        ++findings;
        if (arm_request_fault && !--arm_request_fault) fail_next_malloc = true;
    }
    return rc;
}
#define br_result_set_verification_error pipedream_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return pipedream_real_setter(result, cause, secrets, count);
}
static int compile_prefixed(const char *const *keywords, size_t count, const char *suffix, br_regex **out, char **error)
{
    if (fail_compile) { *out = NULL; if (error) *error = strdup("owned compile +1"); return 1; }
    return br_regex_compile_prefixed(keywords, count, suffix, out, error);
}
static int capture_find(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    memset(captured, 0, sizeof(captured));
    for (size_t i = 0; i < out->len && i < 4; ++i) captured[i] = br_captures_at(out, i);
    if (fail_capture) { if (error && !*error) *error = strdup("owned capture +1"); return 1; }
    return rc;
}
static int push_result(br_results *out, br_result *result)
{
    return fail_push_after && !--fail_push_after ? 1 : br_results_push(out, result);
}
#define br_regex_compile_prefixed compile_prefixed
#define br_captures_find capture_find
#define br_results_push push_result
#include "../../src/detectors/pipedream.c"
#undef br_results_push
#undef br_captures_find
#undef br_regex_compile_prefixed

static const br_detector *detector;
static char key[33], other[33];
static const char url[] = "https://api.pipedream.com/v1/users/me";
typedef struct {
    test_http http; br_transport transport; br_scan_ctx ctx;
    size_t count, release_ids[4], release_lengths[4], release_calls[4];
    const char *keys[4], *causes[4], *auth[4], *urls[4];
    int statuses[4], send_rc[4]; br_header markers[4];
    br_results *out;
} script;
static void check_auth(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 39 && !memcmp(value, "Bearer ", 7) && !strcmp(value + 7, expected));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && at < 4);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 15000 && request->detector_type == 724);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    check_auth(request->headers[0].value, s->keys[at]);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog pipedream-offline"));
    s->auth[at] = request->headers[0].value; s->urls[at] = request->url;
    s->markers[at] = (br_header){"synthetic-attempt", s->keys[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored unread body failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; size_t at = 0;
    while (at < s->count && response->headers != &s->markers[at]) ++at;
    CHECK(http->releases < 4 && s->out && !setter_calls);
    if (at < s->count) {
        check_auth(s->auth[at], s->keys[at]);
        CHECK(!strcmp(s->urls[at], url));
        CHECK(captured[at].len == 32 && !memcmp(captured[at].data, s->keys[at], 32));
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
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "pipedream-offline"};
}
static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    s->out = NULL; return rc;
}
static void result_check(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 724, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}
static void extract_case(const void *input, size_t len, const char *expected, size_t count)
{
    script s; setup(&s, 0); br_results out = {0}; char *error = NULL; size_t before = setter_calls;
    CHECK(invoke(&s, NULL, false, (br_slice){input, len}, &out, &error) == 0 && !error && out.len == count);
    CHECK(!s.http.calls && !s.http.releases && setter_calls == before);
    for (size_t i = 0; i < count; ++i) result_check(&out.items[i], expected, false);
    br_results_clear(&out);
}
static void grammar(void)
{
    char *error = NULL; const br_detector *again = NULL;
    fail_compile = true; CHECK(br_pipedream_init(&again, &error) != 0 && !again && error && !strcmp(error, "owned compile +1"));
    free(error); fail_compile = false;
    fail_next_malloc = true; CHECK(br_pipedream_init(&again, &error) != 0 && !again && error && !fail_next_malloc);
    free(error); error = NULL;
    CHECK(br_pipedream_init(NULL, &error) != 0 && error); free(error); CHECK(br_pipedream_init(NULL, NULL) != 0);
    CHECK(br_pipedream_init(&detector, &error) == 0 && detector && !error);
    fail_next_malloc = true; CHECK(br_pipedream_init(&again, NULL) == 0 && again == detector && fail_next_malloc);
    fail_next_malloc = false;
    CHECK(BR_ABI_REVISION == 1 && detector->type == 724 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Pipedream") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Pipedream is an integration platform for developers to build and run workflows that integrate apps, data, and APIs. Pipedream API keys can be used to access and modify these workflows and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pipedream"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(key, 32, 0); test_secret(other, 32, 9);
    char input[1200], changed[40];
    const char *formats[] = {"pipedream %s", "PIPEDREAM %s", "PipeDream %s", "pIpEdReAm\t%s", "xxpipedream:%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        int n = snprintf(input, sizeof(input), formats[i], key); CHECK(n > 0); extract_case(input, (size_t)n, key, 1);
    }
    const char *unfiltered[] = {"01234567890123456789012345678901", "abcdefghijklmnopqrstuvwxyzabcdef"};
    for (size_t i = 0; i < sizeof(unfiltered) / sizeof(unfiltered[0]); ++i) {
        int n = snprintf(input, sizeof(input), "pipedream %s", unfiltered[i]); extract_case(input, (size_t)n, unfiltered[i], 1);
    }
    const char *bad[] = {"missing %s", "pipedream%s", "%s pipedream", "pipedream _%s", "pipedream %s_", "pipedream %sA"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        int n = snprintf(input, sizeof(input), bad[i], key); extract_case(input, (size_t)n, NULL, 0);
    }
    memcpy(changed, key, 33); changed[10] = 'A'; int n = snprintf(input, sizeof(input), "pipedream %s", changed); extract_case(input, (size_t)n, NULL, 0);
    memcpy(changed, key, 33); changed[4] = '_'; n = snprintf(input, sizeof(input), "pipedream %s", changed); extract_case(input, (size_t)n, NULL, 0);
    memcpy(changed, key, 33); changed[8] = '-'; n = snprintf(input, sizeof(input), "pipedream %s", changed); extract_case(input, (size_t)n, NULL, 0);
    memcpy(changed, key, 32); changed[31] = 0; n = snprintf(input, sizeof(input), "pipedream %s", changed); extract_case(input, (size_t)n, NULL, 0);
    n = snprintf(input, sizeof(input), "pipedream %sa", key); extract_case(input, (size_t)n, NULL, 0);
    n = snprintf(input, sizeof(input), "pipedream %s-", key); extract_case(input, (size_t)n, key, 1);
    n = snprintf(input, sizeof(input), "pipedream %s.", key); extract_case(input, (size_t)n, key, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "pipedream", 9); size_t used = 9;
        memset(input + used, ' ', gap); used += gap; memcpy(input + used, key, 32); used += 32;
        extract_case(input, used, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
        used = 9;
        for (size_t i = 0; i < gap; ++i) { memcpy(input + used, "\xf0\x9f\x92\xa1", 4); used += 4; }
        memcpy(input + used, key, 32); used += 32;
        extract_case(input, used, gap == 40 ? key : NULL, gap == 40 ? 1 : 0);
    }
    n = snprintf(input, sizeof(input), "pipedream %s pipedream %s pipedream %s", key, other, key);
    script s; setup(&s, 0); br_results out = {0};
    CHECK(invoke(&s, NULL, false, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 3);
    result_check(&out.items[0], key, false); result_check(&out.items[1], other, false); result_check(&out.items[2], key, false);
    br_results_clear(&out);
}
static void policy(void)
{
    char input[300]; int n = snprintf(input, sizeof(input), "pipedream %s", key); CHECK(n > 0);
    script s; char *error = NULL; const int statuses[] = {200, 201, 204, 299, 199, 300, 401, 500, 0, -1};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        setup(&s, 1); s.statuses[0] = statuses[i]; br_results out = {0};
        CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1);
        CHECK(s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 1 && s.release_calls[0] == 1);
        result_check(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    char echo[180]; snprintf(echo, sizeof(echo), "unsupported: echo %s", key);
    const char *causes[] = {echo, "out of memory in shared preparation", NULL};
    for (size_t i = 0; i < 3; ++i) {
        setup(&s, 1); s.send_rc[0] = i % 2 ? -1 : 7; s.causes[0] = causes[i]; br_results out = {0};
        CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1);
        CHECK(s.http.calls == 1 && s.http.releases == 1 && !s.release_lengths[0] && s.release_calls[0] == 1);
        result_check(&out.items[0], key, false); br_results_clear(&out);
    }
    setup(&s, 1); s.ctx.user_agent = "bad\r\nagent"; br_results out = {0};
    CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1);
    CHECK(!s.http.calls && s.http.releases == 1 && !s.release_lengths[0]); result_check(&out.items[0], key, false); br_results_clear(&out);
    findings = 0; arm_request_fault = 1; setup(&s, 0);
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && !out.len);
    CHECK(findings == 1 && fail_next_malloc && !arm_request_fault && !s.http.calls && !s.http.releases);
    fail_next_malloc = false; findings = 0;
    n = snprintf(input, sizeof(input), "pipedream %s pipedream %s pipedream %s", key, other, key);
    setup(&s, 3); s.keys[1] = other; s.statuses[1] = 403;
    CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 3);
    CHECK(s.http.calls == 3 && s.http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        result_check(&out.items[i], i == 1 ? other : key, i != 1);
        CHECK(s.release_ids[i] == 2 - i && s.release_lengths[i] == 3 && s.release_calls[i] == 3);
    }
    br_results_clear(&out);
    setup(&s, 3); s.keys[1] = other; s.send_rc[1] = 7; s.causes[1] = "unsupported: shared error";
    CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 3);
    CHECK(s.http.calls == 3 && s.http.releases == 3);
    CHECK(s.release_ids[0] == 1 && s.release_lengths[0] == 1 && s.release_calls[0] == 2);
    CHECK(s.release_ids[1] == 2 && s.release_ids[2] == 0 && s.release_lengths[1] == 3 && s.release_lengths[2] == 3);
    for (size_t i = 0; i < 3; ++i) result_check(&out.items[i], i == 1 ? other : key, i != 1);
    br_results_clear(&out); CHECK(!setter_calls);
}
static void fatal(script *s, const br_scan_ctx *ctx, bool verify, const char *input, br_results *out, const br_result *saved, const char *expected)
{
    char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, &error) != 0 && error);
    CHECK(!strcmp(error, expected) && out->len == 1 && !memcmp(&out->items[0], saved, sizeof(*saved))); free(error);
}
static void failures(void)
{
    char input[400]; snprintf(input, sizeof(input), "pipedream %s", key);
    br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 19, "caller-owned", "key") == 0);
    prior.verification_error = strdup("caller diagnostic"); prior.extra_data = json_object_new_object();
    CHECK(br_results_push(&out, &prior) == 0);
    br_result saved = out.items[0]; script s; setup(&s, 1);
    CHECK(detector->scan(NULL, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) != 0 && out.len == 1);
    fail_capture = true; fatal(&s, NULL, false, input, &out, &saved, "owned capture +1"); fail_capture = false;
    fail_part_after = 1; fatal(&s, &s.ctx, true, input, &out, &saved, "cannot create Pipedream result");
    CHECK(!fail_part_after && !s.http.calls && !s.http.releases);
    arm_request_fault = 1; fatal(&s, &s.ctx, true, input, &out, &saved, "cannot construct Pipedream request");
    CHECK(!arm_request_fault && !fail_next_malloc && !s.http.calls && !s.http.releases);
    snprintf(input, sizeof(input), "pipedream %s pipedream %s", key, other);
    setup(&s, 2); s.keys[1] = other; arm_request_fault = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot construct Pipedream request");
    CHECK(!arm_request_fault && !fail_next_malloc && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 2);
    setup(&s, 2); s.keys[1] = other; fail_part_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot create Pipedream result");
    CHECK(!fail_part_after && s.http.calls == 1 && s.http.releases == 1 && s.release_lengths[0] == 2);
    setup(&s, 2); s.keys[1] = other; fail_push_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved, "cannot append Pipedream result");
    CHECK(!fail_push_after && s.http.calls == 2 && s.http.releases == 2);
    CHECK(s.release_ids[0] == 1 && s.release_ids[1] == 0 && s.release_lengths[0] == 2 && s.release_lengths[1] == 2);
    CHECK(!setter_calls); br_results_clear(&out);
}
int main(void)
{
    grammar(); policy(); failures(); return test_finish("pipedream");
}
