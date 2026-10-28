/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[57], b[57];
static size_t fail_size, fail_after, fail_add, fail_text_after, rotations, freed_rotations;
static const char *fail_text, *borrowed_auth, *expected_key;
static bool watch_order;
static test_http *active_http;

/* Real allocation/add failures, confined to this executable. */
void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}
char *strdup(const char *s)
{
    if (fail_text && !strcmp(s, fail_text) && fail_text_after && --fail_text_after == 0) {
        if (watch_order && !strcmp(s, "unexpected HTTP response status 503"))
            CHECK(!rotations && active_http->releases == active_http->calls);
        fail_text = NULL;
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
static void rotation_freed(br_json *object, void *user)
{
    (void)object; (void)user;
    CHECK(rotations > 0);
    if (watch_order) CHECK(active_http && active_http->releases >= active_http->calls);
    --rotations; ++freed_rotations;
}
int json_object_object_add(br_json *object, const char *name, br_json *value)
{
    if (!strcmp(name, "rotation_guide")) {
        if (fail_add && --fail_add == 0) return 7;
        if (watch_order) CHECK(!rotations);
        ++rotations;
        json_object_set_userdata(object, NULL, rotation_freed);
    }
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *key, bool verified, bool nov)
{
    br_result view = *r;
    view.extra_data = NULL;
    test_key_result(&view, 988, key, "key");
    CHECK(r->raw.len == 56 && r->verified == verified);
    if (nov) {
        br_json *guide = NULL;
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
        CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &guide));
        CHECK(json_object_is_type(guide, json_type_string));
        CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/groq/"));
    } else CHECK(!r->extra_data);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_groq_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_groq_init(NULL, NULL) != 0);
    CHECK(!br_groq_init(&d, &error) && d && !error);
    CHECK(!br_groq_init(&again, NULL) && again == d);
    CHECK(d->type == 988 && !d->version && !strcmp(d->name, "Groq") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Groq is a company that creates data processing hardware and software. Groq API keys can be used to access their services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gsk_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extract(const br_detector *d, const char *input, const char *key)
{
    br_results r = test_scan(d, NULL, false, input, strlen(input));
    CHECK(r.len == (key ? 1u : 0u));
    if (key) { result_is(&r.items[0], key, false, true); CHECK(!r.items[0].verification_error); }
    br_results_clear(&r); CHECK(!rotations);
}
static void grammar(const br_detector *d)
{
    char input[256], changed[57];
    const struct { const char *format; bool match; } cases[] = {
        {"%s", true}, {"'%s'", true}, {" \r\n%s\t", true}, {"x%s", false}, {"_%s", false},
        {"%s_", false}, {"%s9", false}, {"%s-", true}, {"%.55s", false},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a);
        extract(d, input, cases[i].match ? a : NULL);
    }
    memcpy(changed, a, sizeof(changed)); changed[0] = 'G'; extract(d, changed, NULL);
    memcpy(changed, a, sizeof(changed)); changed[1] = 'S'; extract(d, changed, NULL);
    const char invalid[] = "_-/+=";
    for (size_t i = 0; i < sizeof(invalid)-1; ++i) {
        memcpy(changed, a, sizeof(changed)); changed[20] = invalid[i]; extract(d, changed, NULL);
    }
    memcpy(changed, "gsk_", 4); memset(changed + 4, 'A', 52); changed[56] = 0;
    extract(d, changed, changed); /* No entropy/JWT/Base64 filter. */
    br_results empty = test_scan(d, NULL, false, NULL, 0); CHECK(!empty.len); br_results_clear(&empty);
    snprintf(input, sizeof(input), "%s%c%s", a, 0, a);
    br_results r = test_scan(d, NULL, false, input, 113); CHECK(r.len == 1); br_results_clear(&r);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    CHECK(ctx && http->releases + 1 == http->calls && !borrowed_auth && rotations == 1);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.groq.com/openai/v1/models"));
    CHECK(r->profile == BR_HTTP_SANE && r->timeout_ms == 5000 && r->detector_type == 988);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == 2 && !strcmp(r->headers[0].name, "Authorization") && !strcmp(r->headers[1].name, "User-Agent"));
    CHECK(strlen(r->headers[0].value) == 63 && !memcmp(r->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(r->headers[0].value + 7, expected_key));
    CHECK(!strcmp(r->headers[1].value, ctx->user_agent ? "TruffleHog groq-offline" : "TruffleHog"));
    borrowed_auth = r->headers[0].value; /* Original provider bytes ONLY. */
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    CHECK(rotations == 1);
    if (borrowed_auth) {
        CHECK(!memcmp(borrowed_auth, "Bearer ", 7) && !strcmp(borrowed_auth + 7, expected_key));
        borrowed_auth = NULL;
    } else if (http->calls == http->releases)
        CHECK(!response->status && !response->body.data && !response->body.len);
    test_http_release(http, response);
}
static void unique(const br_detector *d)
{
    /* Different original casing stays distinct; exact duplicates collapse. */
    char input[240]; snprintf(input, sizeof(input), "%s %s %s %s", a, b, a, b);
    br_results r = test_scan(d, NULL, true, input, strlen(input));
    CHECK(r.len == 2);
    result_is(&r.items[0], a, false, false); result_is(&r.items[1], b, false, false);
    CHECK(!strcmp(r.items[0].verification_error, "net/http: nil Context"));
    CHECK(!strcmp(r.items[1].verification_error, "net/http: nil Context"));
    br_results_clear(&r);
    test_http http = {.response = {.status = 200}}; br_transport t = test_transport(&http);
    br_scan_ctx ctx = {.transport = &t};
    r = test_scan(d, &ctx, false, input, strlen(input)); CHECK(r.len == 2 && !http.calls && !http.releases);
    br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 2 && http.calls == 2 && http.releases == 2);
    result_is(&r.items[0], a, true, false); result_is(&r.items[1], b, true, false); br_results_clear(&r);
}
static bool arm_headers(void *unused) { (void)unused; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool cancelled(void *unused) { (void)unused; return true; }
static void verification(const br_detector *d)
{
    test_http http = {.inspect = inspect}; br_transport t = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &t, .user_agent = "groq-offline"};
    active_http = &http; expected_key = a; watch_order = true;
    const int statuses[] = {200, 201, 204, 401, 403, 503};
    const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read failure"};
        br_results r = test_scan(d, &ctx, true, a, 56);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !rotations);
        result_is(&r.items[0], a, statuses[i] == 200, false);
        if (statuses[i] == 200 || statuses[i] == 401) CHECK(!r.items[0].verification_error);
        else { char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]); CHECK(!strcmp(r.items[0].verification_error, cause)); }
        br_results_clear(&r);
    }
    char cause[180]; snprintf(cause, sizeof(cause), "wrapped %s + %s", a, a);
    const char *causes[] = {cause, "cannot create Groq finding", "out of memory constructing HTTP headers", "net/http: nil Context", NULL};
    for (size_t i = 0; i < sizeof(causes)/sizeof(*causes); ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? 7 : -7; http.send_error = causes[i];
        br_results r = test_scan(d, &ctx, true, a, 56);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], a, false, false); CHECK(r.items[0].verification_error);
        CHECK(!strcmp(r.items[0].verification_error, i == 0 ? "wrapped [REDACTED] + [REDACTED]" : causes[i] ? causes[i] : "HTTP transport failed"));
        br_results_clear(&r);
    }
    http.inspect = NULL;
    br_scan_ctx contexts[] = {{0}, {.transport=&t,.cancelled=arm_headers}, {.transport=&t,.cancelled=cancelled}, {.transport=&t,.deadline_monotonic_ms=1}, {.transport=&t,.user_agent="bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        br_results r = test_scan(d, &contexts[i], true, a, 56);
        CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_after);
        result_is(&r.items[0], a, false, false); CHECK(r.items[0].verification_error); br_results_clear(&r);
    }
    watch_order = false; active_http = NULL;
}
static void resources(const br_detector *d)
{
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key"));
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r = {0}; CHECK(!br_results_push(&r, &prior)); prior = r.items[0];
    CHECK(!br_result_set_verification_error(&r.items[0], NULL, NULL, 0) && !memcmp(&r.items[0], &prior, sizeof(prior)));
    br_result probe = {0}; fail_text = "probe"; fail_text_after = 1;
    CHECK(br_result_set_verification_error(&probe, "probe", NULL, 0) == 1 && !fail_text);
    char input[120]; snprintf(input, sizeof(input), "%s %s", a, b);
    test_http http = {.response = {.status = 503}}; br_transport t = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &t}; active_http = &http; watch_order = true;
    for (size_t i = 0; i < 8; ++i) {
        http.calls = http.releases = 0; size_t cap = r.cap;
        if (i == 0) { fail_size = 57; fail_after = 2; } /* All captures precede findings. */
        if (i == 1) { fail_size = 56; fail_after = 2; } /* Roll back an earlier appended finding. */
        if (i == 2) fail_add = 2;
        if (i == 3) { fail_size = 80; fail_after = 1; }
        if (i == 4) { fail_text = "unexpected HTTP response status 503"; fail_text_after = 1; }
        if (i == 5) { fail_text = "net/http: nil Context"; fail_text_after = 1; }
        if (i == 6) fail_add = 1; /* Rotation must be constructed BEFORE nil context. */
        if (i == 7) r.cap = 0; /* Real +1 push failure. */
        char *error = NULL;
        CHECK(d->scan(d, i == 5 || i == 6 ? NULL : &ctx, true, text(input), &r, &error) != 0 && error);
        r.cap = cap;
        CHECK(!fail_after && !fail_add && !fail_text && !rotations && !borrowed_auth);
        CHECK(r.len == 1 && !memcmp(&r.items[0], &prior, sizeof(prior)));
        CHECK(http.releases == http.calls);
        CHECK(http.calls == (i == 0 || i == 5 || i == 6 ? 0u : 1u));
        free(error);
    }
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    watch_order = false; active_http = NULL; br_results_clear(&r);
}
int main(void)
{
    memcpy(a, "gsk_", 4); test_secret(a + 4, 52, 0); a[10] = 'Z';
    memcpy(b, a, sizeof(b)); b[10] = 'z';
    const br_detector *d = descriptor(); grammar(d); unique(d); verification(d); resources(d);
    CHECK(!rotations && freed_rotations && !borrowed_auth && !fail_after && !fail_add && !fail_text);
    return test_finish("Groq grammar/unique/case/metadata/nil/order/request/status/read/send/redaction/resources/rollback");
}
