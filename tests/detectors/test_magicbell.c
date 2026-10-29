/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/email_pattern.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_magicbell_init(const br_detector **out, char **error);
static char key[41], other[41];
static const char email[] = "User@Example.test";
static const char case_email[] = "user@Example.test";
static const char quoted[] = "\"A\\ B\"@Example.test";
static const char control_email[] = "\"A\\ B+\x01Z\"@Example.test";
static const char bracketed[] = "user@[127.0.0.1]";

typedef enum { NONE, PREFIX, EMAIL_COMPILE, CAPTURE, FINDING, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, compiled_frees, key_collections, email_collections;
static size_t sends, releases, setters;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static br_result *active_result;
static char saved_email[128];
static size_t saved_email_len;

static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
/* Existing module-local positive-return seams, not a new test framework. */
static int checked_prefix(const char *const *keywords, size_t count, const char *capture,
                           br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "magicbell") && !strcmp(capture, "\\b([a-zA-Z-0-9]{40})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, capture, out, error);
    if (rc == 0 && hit(PREFIX)) { if (error) *error = strdup("synthetic prefix failure"); return 1; }
    return rc;
}
static int checked_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(!strcmp(pattern, br_email_pattern));
    int rc = br_regex_compile(pattern, out, error);
    if (rc == 0 && hit(EMAIL_COMPILE)) { if (error) *error = strdup("synthetic email compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *pattern)
{
    if (pattern) ++compiled_frees;
    br_regex_free(pattern);
}
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out,
                            bool unique, char **error)
{
    if (unique) ++email_collections;
    else ++key_collections;
    int rc = br_captures_find(pattern, input, out, unique, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    int rc = br_finding_key_bytes(r, type, token, part);
    active_result = r;
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && r->detector_type == 786 && r->profile == BR_HTTP_SANE);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.magicbell.com/notification_preferences"));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && r->nheaders == (effective ? 3u : 2u));
    CHECK(!strcmp(r->headers[0].name, "X-Magicbell-Api-Key") && strlen(r->headers[0].value) == active_result->raw.len);
    CHECK(!memcmp(r->headers[0].value, active_result->raw.data, active_result->raw.len));
    CHECK(!strcmp(r->headers[1].name, "X-Magicbell-User-Email"));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request && active_result && !active_result->verification_error);
    request_values(r, false);
    saved_email_len = strlen(r->headers[1].value) + 1;
    CHECK(saved_email_len <= sizeof(saved_email));
    memcpy(saved_email, r->headers[1].value, saved_email_len);
    provider_request = r; provider_ctx = ctx; ++sends;
    return br_http_send(ctx, r, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_ctx && !active_result->verification_error);
    /* Only the provider ORIGINAL request/header array is retained here. */
    request_values(provider_request, false);
    CHECK(!memcmp(provider_request->headers[1].value, saved_email, saved_email_len));
    br_http_release(ctx, response); ++releases;
    provider_request = NULL; provider_ctx = NULL;
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

#define br_regex_compile_prefixed checked_prefix
#define br_regex_compile checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error checked_setter
#include "../../src/detectors/magicbell.c"
#undef br_regex_compile_prefixed
#undef br_regex_compile
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other) == 40);
    CHECK(br_magicbell_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_magicbell_init(NULL, NULL) == -1);
    const fault_kind kinds[] = {PREFIX, EMAIL_COMPILE};
    for (size_t i = 0; i < 2; ++i) {
        size_t freed = compiled_frees; fault = kinds[i]; fail_nth = 1;
        CHECK(br_magicbell_init(&d, &error) == -1 && !d && error && fault == NONE);
        CHECK(compiled_frees == freed + i + 1); free(error); error = NULL;
    }
    CHECK(!br_magicbell_init(&d, &error) && d && !error && !br_magicbell_init(&again, NULL) && again == d);
    CHECK(d->type == 786 && !d->version && !strcmp(d->name, "MagicBell") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "MagicBell is a notification service. API keys can be used to manage and send notifications."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "magicbell"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 786, token, "key");
    CHECK(r->verified == verified && !r->verification_error);
}
static void extract(const br_detector *d, const void *input, size_t len, const char *token)
{
    size_t sent = sends, released = releases, set = setters, keys = key_collections, emails = email_collections;
    br_results out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == (token ? 1u : 0u) && sends == sent && releases == released && setters == set);
    CHECK(key_collections == keys + 1 && email_collections == emails + 1);
    if (token) result_is(&out.items[0], token, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[2500], changed[42];
    snprintf(input, sizeof(input), "magicbell %s", key); extract(d, input, strlen(input), NULL);
    extract(d, email, strlen(email), NULL); extract(d, NULL, 0, NULL);
    const char *good[] = {"magicbell '%s'", "MaGiCbElL=-%s-", "myMAGICBELLsuffix\r\n%s", "magicbell\r%s", "magicbell\n%s", "magicbell \t%s\t ", "magicbell é%sé"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        int n = snprintf(input, sizeof(input), good[i], key); snprintf(input + n, sizeof(input) - (size_t)n, " %s", email);
        extract(d, input, strlen(input), key);
    }
    const char *bad[] = {"%s", "magic bell %s", "magicbell%s", "magicbell _%s", "magicbell %s_", "magicbell %sX", "magicbell %.39s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        int n = snprintf(input, sizeof(input), bad[i], key); snprintf(input + n, sizeof(input) - (size_t)n, " %s", email);
        extract(d, input, strlen(input), NULL);
    }
    const char invalid[] = "_+/ ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[19] = invalid[i];
        snprintf(input, sizeof(input), "magicbell %s %s", changed, email); extract(d, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[19] = '-';
    snprintf(input, sizeof(input), "magicbell %s %s", changed, email); extract(d, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "magicbell%s %s", changed, email); extract(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "magicbell %s %s", changed, email); extract(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[39] = '-';
    snprintf(input, sizeof(input), "magicbell %sZ %s", changed, email); extract(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "magicbell %s %s", changed, email); extract(d, input, strlen(input), NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "magicbell", 9); memset(input + 9, ':', gap); memcpy(input + 9 + gap, key, 40);
        size_t at = 49 + gap; input[at++] = ' '; memcpy(input + at, email, sizeof(email));
        extract(d, input, at + strlen(email), gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 9 + 4 * i, "💡", 4);
        memcpy(input + 9 + 4 * gap, key, 40); at = 49 + 4 * gap; input[at++] = ' '; memcpy(input + at, email, sizeof(email));
        extract(d, input, at + strlen(email), gap == 40 ? key : NULL);
    }
    memcpy(input, "magicbell\0", 10); memcpy(input + 10, key, 40); input[50] = ' '; memcpy(input + 51, email, sizeof(email));
    extract(d, input, 51 + strlen(email), key);
    int n = snprintf(input, sizeof(input), "magicbell %s", key); memset(input + n, ' ', 1800); memcpy(input + n + 1800, email, sizeof(email));
    extract(d, input, (size_t)n + 1800 + strlen(email), key);
    const struct { const char *address, *prefix, *suffix; bool found; } addresses[] = {
        {quoted, "X", "", true}, {control_email, "X", "", true}, {bracketed, "", "x", true},
        {bracketed, "", "", false}, {quoted, " ", "", false},
        {"a+b.c@Sub.Example.test", "", "", true}, {"no-at-address", "", "", false},
    };
    for (size_t i = 0; i < sizeof(addresses) / sizeof(*addresses); ++i) {
        snprintf(input, sizeof(input), "magicbell %s\n%s%s%s", key, addresses[i].prefix, addresses[i].address, addresses[i].suffix);
        extract(d, input, strlen(input), addresses[i].found ? key : NULL);
    }
}

typedef struct { const char *keys[3], *emails[3]; size_t nkeys, nemails; const char *agent; } expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(ctx == provider_ctx && provider_request && at < e->nkeys * e->nemails);
    request_values(r, true);
    CHECK(!strcmp(r->headers[0].value, e->keys[at / e->nemails]));
    CHECK(!strcmp(r->headers[1].value, e->emails[at % e->nemails]));
    CHECK(!strcmp(r->headers[2].name, "User-Agent") && !strcmp(r->headers[2].value, e->agent));
}
static void products(const br_detector *d)
{
    char input[500]; snprintf(input, sizeof(input), "magicbell %s\nmagicbell %s\nmagicbell %s\n%s %s %s", key, other, key, email, email, case_email);
    expected e = {.keys = {key, other, key}, .emails = {email, case_email}, .nkeys = 3, .nemails = 2, .agent = "TruffleHog magicbell-offline"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "magicbell-offline"};
    for (size_t pass = 0; pass < 3; ++pass) {
        http.calls = http.releases = 0; http.send_rc = pass == 2 ? -7 : 0; http.send_error = pass == 2 ? "cannot create MagicBell finding" : NULL;
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 6 && http.calls == (pass ? 6u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 6; ++i) result_is(&out.items[i], e.keys[i / 2], pass == 1);
        CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts);
        br_results_clear(&out);
    }
    size_t sent = sends, set = setters;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && sends == sent && setters == set); br_results_clear(&out);
}
static void statuses_and_header_errors(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "magicbell %s %s", key, email);
    expected e = {.keys = {key}, .emails = {email}, .nkeys = 1, .nemails = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {199, 200, 201, 299, 300, 401, 500};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "ignored read error" : NULL};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {"timeout", "out of memory constructing HTTP headers", "cannot create MagicBell finding", "net/http: nil Context", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i]; http.response.status = 200;
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *addresses[] = {quoted, bracketed, control_email};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(input, sizeof(input), "magicbell %s %s%s%s", key, i == 1 ? "" : "X", addresses[i], i == 1 ? "x" : "");
        e.emails[0] = addresses[i]; http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL;
        size_t sent = sends, released = releases;
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && http.releases == 1 && http.calls == (i == 2 ? 0u : 1u));
        result_is(&out.items[0], key, i != 2); br_results_clear(&out);
    }
    CHECK(!setters);
}
static void owned_failures(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "magicbell %s %s %s", key, email, case_email);
    expected e = {.keys = {key}, .emails = {email, case_email}, .nkeys = 1, .nemails = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}, .send_rc = 1, .send_error = "synthetic Do failure"};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key"));
    prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; bool nov, nil, no_keys; } cases[] = {
        {CAPTURE, 1, false, true, false}, {CAPTURE, 2, true, true, false}, {CAPTURE, 2, true, true, true},
        {FINDING, 1, false, true, false}, {FINDING, 2, false, false, false}, {FINDING, 2, true, true, false},
        {PUSH, 1, false, false, false}, {PUSH, 2, false, false, false}, {PUSH, 2, true, true, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        size_t failed = failures, sent = sends, released = releases;
        http.calls = http.releases = 0; http.send_rc = i == 6 ? 0 : 1;
        fault = cases[i].kind; fail_nth = cases[i].nth; char *error = NULL;
        const char *data = cases[i].no_keys ? email : input;
        int rc = d->scan(d, cases[i].nil ? NULL : &ctx, !cases[i].nov, (br_slice){(const unsigned char *)data, strlen(data)}, &out, &error);
        CHECK(rc == -1 && error && fault == NONE && failures == failed + 1);
        CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request && !setters);
        if (cases[i].nov || cases[i].nil) CHECK(sends == sent);
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
    (void)checked_setter; /* No source setter call is expected or synthesized. */
    test_secret(key, 40, 0); key[0] = 'A'; key[39] = 'Z';
    test_secret(other, 40, 7); other[0] = 'Q'; other[39] = 'R';
    const br_detector *d = descriptor();
    extraction(d); products(d); statuses_and_header_errors(d); owned_failures(d);
    CHECK(fault == NONE && !setters && sends == releases && !provider_request);
    return test_finish("MagicBell");
}
