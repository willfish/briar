/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_loggly_init(const br_detector **out, char **error);

#define br_result_set_verification_error loggly_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static const char key[] = "ghijklmn-opqr-stuv-wxyz-0123456789ab";
static const char other[] = "zyxwvuts-rqpo-nmlk-jihg-fedcba987654";
static const char domain[] = "Team-1.loggly.com";
static const char other_domain[] = "other--.loggly.com";
static const br_detector *detector;
static size_t fail_size, fail_after, fail_key_after, fail_domain_after, fail_setter_after;
static size_t fail_request_after_domain, fail_module_alloc_after, setter_calls;
static const char *fail_strdup_text;
static size_t fail_strdup_after;
static bool fail_agent;

typedef struct {
    test_http http;
    br_transport transport;
    br_scan_ctx ctx;
    br_results *out;
    size_t original_len, count, setters_before;
    const char *keys[4], *domains[4], *causes[4], *urls[4], *auth[4];
    int statuses[4], send_rc[4];
    br_header markers[4];
    size_t release_ids[4], release_lengths[4], release_calls[4], release_setters[4];
} script;
static script *active;

void *malloc(size_t size)
{
    if ((fail_module_alloc_after && --fail_module_alloc_after == 0) ||
        (size == fail_size && fail_after && --fail_after == 0)) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if ((fail_agent && !strcmp(text, "TruffleHog")) ||
        (fail_strdup_after && fail_strdup_text && !strcmp(text, fail_strdup_text) && --fail_strdup_after == 0)) {
        fail_agent = false;
        return NULL;
    }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if ((!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) ||
        (!strcmp(name, "domain") && fail_domain_after && --fail_domain_after == 0)) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "domain") && fail_request_after_domain && --fail_request_after_domain == 0)
        fail_module_alloc_after = 2; /* Literal URL, then request/auth storage. */
    return rc;
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    CHECK(cause && secrets && count == 1 && secrets[0].len == 36);
    CHECK(!memcmp(secrets[0].data, result->raw.data, 36) && !result->verified);
    if (active) {
        size_t at = active->http.calls ? active->http.calls - 1 : 0;
        CHECK(at < active->count && !memcmp(secrets[0].data, active->keys[at], 36));
        CHECK(active->out && active->out->len == active->original_len + at);
        if (active->http.calls) CHECK(active->send_rc[at] || (active->statuses[at] != 401 && !(active->statuses[at] >= 200 && active->statuses[at] < 300)));
    }
    ++setter_calls;
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return loggly_real_setter(result, cause, secrets, count);
}

static void check_result(const br_result *result, const char *value, const char *host, bool verified, const char *cause)
{
    size_t host_len = strlen(host);
    CHECK(result->detector_type == 944 && result->raw.len == 36 && !memcmp(result->raw.data, value, 36));
    CHECK(result->raw_v2.len == host_len + 37 && result->raw_v2.data);
    CHECK(!memcmp(result->raw_v2.data, host, host_len) && result->raw_v2.data[host_len] == ':');
    CHECK(!memcmp(result->raw_v2.data + host_len + 1, value, 36));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set && !result->verification_from_cache);
    br_json *part = NULL;
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 36 && !memcmp(json_object_get_string(part), value, 36));
    CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == host_len && !memcmp(json_object_get_string(part), host, host_len));
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void check_originals(script *s, size_t at)
{
    char url[128], authorization[44];
    snprintf(url, sizeof(url), "https://%s/apiv2/customer", s->domains[at]);
    snprintf(authorization, sizeof(authorization), "Bearer %s", s->keys[at]);
    CHECK(s->urls[at] && !strcmp(s->urls[at], url));
    CHECK(s->auth[at] && !strcmp(s->auth[at], authorization));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && !s->urls[at] && !s->auth[at]);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 944);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog loggly-offline"));
    /* Retain only provider-original URL/auth pointers, not prepared headers/UA. */
    s->urls[at] = request->url; s->auth[at] = request->headers[0].value; check_originals(s, at);
    s->markers[at] = (br_header){"synthetic-attempt", s->domains[at]};
    http->response = (br_http_response){.status = s->statuses[at], .headers = &s->markers[at], .nheaders = 1,
        .body = {binary, sizeof(binary)}, .body_error = "ignored read failure"};
    http->send_rc = s->send_rc[at]; http->send_error = s->causes[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    size_t at = 0;
    while (at < s->count && response->headers != &s->markers[at]) ++at;
    CHECK(http->releases < 4 && s->out);
    if (at < s->count) { check_originals(s, at); s->urls[at] = s->auth[at] = NULL; }
    else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_ids[http->releases] = at;
    s->release_lengths[http->releases] = s->out->len;
    s->release_calls[http->releases] = http->calls;
    s->release_setters[http->releases] = setter_calls - s->setters_before;
    test_http_release(user, response);
}

static void setup(script *s, size_t count, int status)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) { s->keys[i] = key; s->domains[i] = domain; s->statuses[i] = status; }
    s->http = (test_http){.inspect = inspect_request, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "loggly-offline"};
}

static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    s->out = out; s->original_len = out->len; s->setters_before = setter_calls; active = s;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    active = NULL; s->out = NULL;
    return rc;
}

static br_results run(script *s, const br_scan_ctx *ctx, bool verify, const char *input)
{
    br_results out = {0}; char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    return out;
}

static void extract_case(const void *input, size_t len, const char *expected_domain)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = setter_calls;
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected_domain ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected_domain) check_result(&out.items[0], key, expected_domain, false, NULL);
    br_results_clear(&out);
}

static void descriptor_and_extraction(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    char *error = NULL; const br_detector *again = NULL;
    CHECK(br_loggly_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Loggly detector output")); free(error);
    CHECK(br_loggly_init(NULL, NULL) != 0);
    CHECK(br_loggly_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_loggly_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 944 && detector->version == 0 && !strcmp(detector->name, "Loggly") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Loggly is a cloud-based log management service. Loggly API keys can be used to send, search, and analyze log data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "loggly"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    char input[400], changed[37];
    const char *good[] = {"loggly %s %s", "LoGgLy '%s' %s", "prelogglysuffix\r\n%s %s", "loggly\r%s %s", "loggly\n%s %s", "loggly \xc3\xa9%s\xc3\xa9 %s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key, domain); extract_case(input, strlen(input), domain);
    }
    const char *bad[] = {"%s %s", "loggly%s %s", "loggly _%s %s", "loggly %s_ %s", "loggly %sx %s", "loggly %.35s %s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key, domain); extract_case(input, strlen(input), NULL);
    }
    snprintf(input, sizeof(input), "%s %s", domain, key); extract_case(input, strlen(input), domain); /* Domain itself can supply PrefixRegex's keyword. */
    memcpy(changed, key, sizeof(changed)); changed[4] = 'A';
    snprintf(input, sizeof(input), "LOGGLY %s %s", changed, domain); extract_case(input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loggly %s", key); extract_case(input, strlen(input), NULL);
    extract_case(domain, strlen(domain), NULL); extract_case(NULL, 0, NULL);
    const struct { const char *text, *capture; } domains[] = {
        {"Team-1.loggly.com", domain}, {"-Team-1.loggly.com", domain}, {"x--.loggly.com", "x--.loggly.com"},
        {"a.Team-1.loggly.com", domain}, {"Team-1.loggly.com.EXTRA", domain},
        {"Team-1.LOGGLY.com", NULL}, {"Team-1.loggly.COM", NULL}, {"Team-1.loggly.com_", NULL}, {"abc..loggly.com", NULL},
    };
    for (size_t i = 0; i < sizeof(domains) / sizeof(*domains); ++i) {
        snprintf(input, sizeof(input), "loggly %s %s", key, domains[i].text); extract_case(input, strlen(input), domains[i].capture);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "loggly", 6); memset(input + 6, '-', gap); memcpy(input + 6 + gap, key, 36);
        input[42 + gap] = ' '; memcpy(input + 43 + gap, domain, sizeof(domain));
        extract_case(input, 43 + gap + strlen(domain), gap == 40 ? domain : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 6 + 4 * gap, key, 36); input[42 + 4 * gap] = ' ';
        memcpy(input + 43 + 4 * gap, domain, sizeof(domain)); extract_case(input, 43 + 4 * gap + strlen(domain), gap == 40 ? domain : NULL);
    }
    memcpy(input, "loggly\0", 7); memcpy(input + 7, key, 36); input[43] = ' '; memcpy(input + 44, domain, sizeof(domain));
    extract_case(input, 44 + strlen(domain), domain);
    char far[2300]; int n = snprintf(far, sizeof(far), "loggly %s", key); CHECK(n > 0);
    memset(far + n, ' ', 2048); memcpy(far + n + 2048, domain, sizeof(domain));
    extract_case(far, (size_t)n + 2048 + strlen(domain), domain);
}

static void product_and_deferred_order(void)
{
    char input[200]; snprintf(input, sizeof(input), "loggly %s\nloggly %s\n%s %s", key, other, domain, other_domain);
    for (size_t mixed = 0; mixed < 2; ++mixed) {
        script s; setup(&s, 4, 200);
        s.keys[2] = s.keys[3] = other; s.domains[1] = s.domains[3] = other_domain;
        s.statuses[1] = 401; s.statuses[2] = 500; s.statuses[3] = 299;
        if (mixed) { s.send_rc[1] = 7; s.causes[1] = "cannot create Loggly result"; }
        size_t before = setter_calls;
        br_results out = run(&s, NULL, false, input); CHECK(out.len == 4 && !s.http.calls && !s.http.releases && setter_calls == before);
        for (size_t i = 0; i < 4; ++i) check_result(&out.items[i], s.keys[i], s.domains[i], false, NULL);
        br_results_clear(&out);
        out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 4 && s.http.calls == 4 && s.http.releases == 4 && setter_calls == before + (mixed ? 2u : 1u));
        for (size_t i = 0; i < 4; ++i) {
            const char *cause = i == 2 ? "unexpected HTTP response status 500" : mixed && i == 1 ? s.causes[1] : NULL;
            check_result(&out.items[i], s.keys[i], s.domains[i], i == 0 || i == 3, cause);
            CHECK(!s.urls[i] && !s.auth[i]);
            CHECK(s.release_ids[i] == (mixed ? (i == 0 ? 1u : i == 1 ? 3u : i == 2 ? 2u : 0u) : 3 - i));
            CHECK(s.release_lengths[i] == (mixed && i == 0 ? 1u : 4u));
            CHECK(s.release_calls[i] == (mixed && i == 0 ? 2u : 4u));
            CHECK(s.release_setters[i] == (mixed ? (i == 0 ? 1u : 2u) : 1u));
        }
        br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "loggly %s\nloggly %s\n%s %s", key, key, domain, domain);
    br_results out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&out.items[i], key, domain, false, NULL);
    CHECK(out.items[0].raw_v2.data != out.items[3].raw_v2.data && out.items[0].secret_parts != out.items[3].secret_parts);
    br_results_clear(&out);
    script s; setup(&s, 4, 200); size_t before = setter_calls;
    out = run(&s, NULL, true, input); CHECK(!out.len && !s.http.calls && !s.http.releases && setter_calls == before); br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void statuses_and_shared_failures(void)
{
    char input[100]; snprintf(input, sizeof(input), "loggly %s %s", key, domain);
    const int statuses[] = {199, 200, 201, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script s; setup(&s, 1, statuses[i]); size_t before = setter_calls;
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        bool verified = statuses[i] >= 200 && statuses[i] < 300, has_cause = !verified && statuses[i] != 401;
        char cause[96]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        check_result(&out.items[0], key, domain, verified, has_cause ? cause : NULL);
        CHECK(setter_calls == before + has_cause && s.release_lengths[0] == 1); br_results_clear(&out);
    }
    char key_cause[160], redacted[160];
    snprintf(key_cause, sizeof(key_cause), "timeout %s on %s; %s", key, domain, key);
    snprintf(redacted, sizeof(redacted), "timeout [REDACTED] on %s; [REDACTED]", domain);
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Loggly RawV2"}, {7, "unsupported: native curl HTTP client profile"}, {-1, NULL}, {1, key_cause},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        script s; setup(&s, 1, 200); s.send_rc[0] = failures[i].rc; s.causes[0] = failures[i].cause;
        br_results out = run(&s, &s.ctx, true, input); CHECK(out.len == 1 && s.http.calls == 1 && s.http.releases == 1);
        check_result(&out.items[0], key, domain, false, i == 4 ? redacted : failures[i].cause ? failures[i].cause : "HTTP transport failed");
        CHECK(s.release_lengths[0] == 0 && s.release_setters[0] == 1); br_results_clear(&out);
    }
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        script s; setup(&s, 1, 200);
        if (i == 0) s.ctx.transport = NULL;
        if (i == 1) s.transport.send = NULL;
        if (i == 2) s.ctx.cancelled = cancelled;
        if (i == 3) s.ctx.deadline_monotonic_ms = 1;
        if (i == 4) s.ctx.user_agent = "bad\r\nagent";
        if (i == 5) s.ctx.cancelled = arm_headers;
        if (i == 6) { s.ctx.cancelled = arm_agent; s.ctx.user_agent = NULL; }
        br_results out = run(&s, &s.ctx, true, input);
        CHECK(out.len == 1 && !s.http.calls && s.http.releases == (i ? 1u : 0u) && !fail_after && !fail_agent);
        check_result(&out.items[0], key, domain, false, causes[i]); br_results_clear(&out);
    }
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->verified && prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_construction(void)
{
    char input[140]; snprintf(input, sizeof(input), "loggly %s\nloggly %s\n%s", key, key, domain);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    for (size_t failure = 0; failure < 9; ++failure) {
        script s; setup(&s, 2, failure == 7 ? 403 : 200);
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 37; fail_after = 2; }
        if (failure == 2) { fail_size = 36; fail_after = 2; }
        if (failure == 3) { fail_size = strlen(domain) + 37; fail_after = 2; }
        if (failure == 4) fail_domain_after = 2;
        if (failure == 5) { fail_size = strlen(domain) + sizeof("https:///apiv2/customer"); fail_after = 2; }
        if (failure == 6) fail_request_after_domain = 2;
        if (failure == 7) fail_setter_after = 2;
        if (failure == 8) {
            s.send_rc[0] = s.send_rc[1] = 1; s.causes[0] = s.causes[1] = "synthetic Loggly setter allocation";
            fail_strdup_text = s.causes[0]; fail_strdup_after = 4;
        }
        char *error = NULL;
        CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_domain_after && !fail_request_after_domain && !fail_module_alloc_after && !fail_setter_after && !fail_strdup_after);
        CHECK(s.http.calls == (failure < 2 ? 0u : failure < 7 ? 1u : 2u) && s.http.releases == s.http.calls);
        if (failure >= 7) CHECK(!strcmp(error, "cannot store Loggly verification error"));
        if (failure >= 2 && failure < 7) CHECK(s.release_lengths[0] == 2);
        for (size_t i = 0; i < s.count; ++i) CHECK(!s.urls[i] && !s.auth[i]);
        check_prior(&out, &prior); free(error); fail_strdup_text = NULL;
    }
    /* The second independent regex runs even when the first finds no keys. */
    script s; setup(&s, 1, 200); fail_size = 2 * sizeof(br_span); fail_after = 2; char *error = NULL;
    CHECK(invoke(&s, NULL, false, (br_slice){0}, &out, &error) != 0 && error && !fail_after);
    check_prior(&out, &prior); free(error); error = NULL;
    snprintf(input, sizeof(input), "loggly %s %s", key, domain); data.len = strlen(input);
    /* URL construction is reached before nil drop, request/Bearer allocation is not. */
    fail_size = strlen(domain) + sizeof("https:///apiv2/customer"); fail_after = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "cannot construct Loggly URL")); check_prior(&out, &prior); free(error); error = NULL;
    fail_request_after_domain = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) == 0 && !error && !fail_request_after_domain && fail_module_alloc_after == 1);
    fail_module_alloc_after = 0; check_prior(&out, &prior);
    /* NoV does not build a URL at all. */
    fail_size = strlen(domain) + sizeof("https:///apiv2/customer"); fail_after = 1;
    CHECK(invoke(&s, NULL, false, data, &out, &error) == 0 && !error && fail_after == 1);
    fail_after = 0; CHECK(out.len == 2); br_result_clear(&out.items[--out.len]); check_prior(&out, &prior);
    fail_key_after = 1;
    CHECK(invoke(&s, NULL, true, data, &out, &error) != 0 && error && !fail_key_after);
    check_prior(&out, &prior); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0;
    CHECK(invoke(&s, &s.ctx, true, data, &out, &error) != 0 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append Loggly result") && s.http.calls == 1 && s.http.releases == 1);
    check_prior(&out, &prior); free(error);
    fail_domain_after = 1;
    CHECK(invoke(&s, NULL, false, data, &out, NULL) != 0 && !fail_domain_after);
    check_prior(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    descriptor_and_extraction(); product_and_deferred_order(); statuses_and_shared_failures(); owned_failures_and_construction();
    CHECK(!active && !fail_after && !fail_key_after && !fail_domain_after && !fail_setter_after && !fail_request_after_domain && !fail_module_alloc_after && !fail_strdup_after && !fail_agent);
    return test_finish("Loggly");
}
