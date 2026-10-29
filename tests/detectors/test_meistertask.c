/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_meistertask_init(const br_detector **out, char **error);
static char key[44], other[44];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, freed_patterns, sends, releases, setters;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static br_result *active_result;

static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
/* Existing named-test positive-return seams around actual shared helpers. */
static int checked_compile(const char *const *keywords, size_t count, const char *capture,
                            br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "meistertask") && !strcmp(capture, "\\b([a-zA-Z0-9]{43})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, capture, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *pattern)
{
    if (pattern) ++freed_patterns;
    br_regex_free(pattern);
}
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out,
                            bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(pattern, input, out, unique, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    int rc = br_finding_key_bytes(r, type, token, part); active_result = r;
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && r->detector_type == 656 && r->profile == BR_HTTP_SANE);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://www.meistertask.com/api/projects"));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Authorization") && strlen(r->headers[0].value) == 50);
    CHECK(!memcmp(r->headers[0].value, "Bearer ", 7) && active_result->raw.len == 43 && !memcmp(r->headers[0].value + 7, active_result->raw.data, 43));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request && active_result && !active_result->verification_error);
    request_values(r, false); provider_request = r; provider_ctx = ctx; ++sends;
    return br_http_send(ctx, r, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && provider_ctx == ctx && !active_result->verification_error);
    /* Inspect only provider-original request/header/auth/URL storage, not
     * synthesized prepared headers/UA whose lifetime ends at send return. */
    request_values(provider_request, false);
    br_http_release(ctx, response); ++releases; provider_request = NULL; provider_ctx = NULL;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(r == active_result && !provider_request && sends == releases);
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    ++setters; return br_result_set_verification_error(r, cause, secrets, count);
}

#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error checked_setter
#include "../../src/detectors/meistertask.c"
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other) == 43);
    CHECK(br_meistertask_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_meistertask_init(NULL, NULL) == -1);
    fault = COMPILE; fail_nth = 1;
    CHECK(br_meistertask_init(&d, &error) == -1 && !d && error && fault == NONE && freed_patterns == 1); free(error); error = NULL;
    CHECK(!br_meistertask_init(&d, &error) && d && !error && !br_meistertask_init(&again, NULL) && again == d);
    CHECK(d->type == 656 && !d->version && !strcmp(d->name, "Meistertask") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Meistertask is a task management tool that allows users to manage projects and tasks. Meistertask API keys can be used to access and modify project and task data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "meistertask"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 656, token, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static void extract(const br_detector *d, const void *input, size_t len, const char *token)
{
    size_t sent = sends, released = releases, set = setters;
    br_results out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == (token ? 1u : 0u) && sends == sent && releases == released && setters == set);
    if (token) result_is(&out.items[0], token, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[300], changed[45];
    const char *good[] = {"meistertask '%s'", "MeIsTeRtAsK=-%s-", "myMEISTERTASKsuffix\r\n%s", "meistertask\r%s", "meistertask\n%s", "meistertask \t%s\t ", "meistertask é%sé"};
    const char *bad[] = {"%s", "meister task %s", "%s meistertask", "meistertask%s", "meistertask _%s", "meistertask %s_", "meistertask %sa", "meistertask %.42s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract(d, input, strlen(input), key); }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract(d, input, strlen(input), NULL); }
    const char invalid[] = "_-+/ ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[21] = invalid[i]; snprintf(input, sizeof(input), "meistertask %s", changed); extract(d, input, strlen(input), NULL);
    }
    memset(changed, 'A', 43); changed[43] = 0; snprintf(input, sizeof(input), "meistertask %s", changed); extract(d, input, strlen(input), changed);
    memset(changed, '0', 43); snprintf(input, sizeof(input), "meistertask %s", changed); extract(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "meistertask", 11); memset(input + 11, ':', gap); memcpy(input + 11 + gap, key, 43); extract(d, input, 54 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 11 + 4 * i, "💡", 4);
        memcpy(input + 11 + 4 * gap, key, 43); extract(d, input, 54 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "meistertask\0", 12); memcpy(input + 12, key, 43); extract(d, input, 55, key);
    snprintf(input, sizeof(input), "meistertask %s %s", key, other); extract(d, input, strlen(input), key);
    extract(d, NULL, 0, NULL);
}

typedef struct { const char *keys[3], *agent; size_t count; } expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(provider_request && ctx == provider_ctx && at < e->count); request_values(r, true);
    CHECK(!strcmp(r->headers[0].value + 7, e->keys[at]));
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, e->agent));
}
static void occurrences(const br_detector *d)
{
    char input[200]; snprintf(input, sizeof(input), "meistertask %s\nmeistertask %s\nmeistertask %s", key, other, key);
    expected e = {.keys = {key, other, key}, .count = 3, .agent = "TruffleHog meistertask-offline"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "meistertask-offline"};
    for (size_t pass = 0; pass < 3; ++pass) {
        http.calls = http.releases = 0; http.send_rc = pass == 2 ? 1 : 0; http.send_error = pass == 2 ? "cannot create Meistertask finding" : NULL;
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], e.keys[i], pass == 1);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    }
    size_t sent = sends, released = releases;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && sends == sent && releases == released); br_results_clear(&out);
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void status_send_and_preparation(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "meistertask %s", key);
    expected e = {.keys = {key}, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500}; static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "ignored partial read" : NULL};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {"timeout", "out of memory constructing HTTP headers", "cannot create Meistertask finding", "net/http: nil Context", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i]; http.response.status = 200;
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t sent = sends, released = releases; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], false, input, strlen(input));
        CHECK(out.len == 1 && sends == sent && releases == released && !http.calls && !http.releases); result_is(&out.items[0], key, false); br_results_clear(&out);
        out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && !http.calls && http.releases == (i ? 1u : 0u)); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !setters);
}
static void owned_failures(const br_detector *d)
{
    char input[150]; snprintf(input, sizeof(input), "meistertask %s\nmeistertask %s", key, other);
    expected e = {.keys = {key, other}, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}, .send_rc = 1, .send_error = "synthetic Do failure"};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; bool nov, nil; } cases[] = {
        {CAPTURE, 1, false, true}, {FINDING, 1, false, true}, {FINDING, 2, false, false},
        {FINDING, 2, true, true}, {PUSH, 1, false, false}, {PUSH, 2, false, false}, {PUSH, 2, true, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        size_t failed = failures, sent = sends, released = releases; http.calls = http.releases = 0; http.send_rc = i == 4 ? 0 : 1;
        fault = cases[i].kind; fail_nth = cases[i].nth; char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, !cases[i].nov, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
        CHECK(error && fault == NONE && failures == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request && !setters); if (cases[i].nov || cases[i].nil) CHECK(sends == sent);
        free(error); active_result = NULL;
    }
    char *error = NULL;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    (void)checked_setter;
    test_secret(key, 43, 0); key[0] = 'A'; key[42] = 'Z'; test_secret(other, 43, 7); other[0] = 'Q'; other[42] = 'G';
    const br_detector *d = descriptor(); extraction(d); occurrences(d); status_send_and_preparation(d); owned_failures(d);
    CHECK(fault == NONE && !setters && sends == releases && !provider_request);
    return test_finish("Meistertask");
}
