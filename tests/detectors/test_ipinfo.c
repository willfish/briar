/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <pthread.h>
#include <stdarg.h>
#include <time.h>

/* Observe original storage without removing keys or bypassing shared policy. */
#define br_http_send ipinfo_real_send
#define br_http_release ipinfo_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

static bool fail_growth;
static void *ipinfo_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc ipinfo_realloc
#define br_result_set_verification_error ipinfo_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

/* A named-test inclusion seam makes impossible formatter returns observable
 * without relying on interposition of Nix's fortified snprintf builtin. All
 * normal extraction and verification cases use the compiled library factory. */
static int checked_snprintf(char *, size_t, const char *, ...);
#define snprintf checked_snprintf
#define br_ipinfo_init observed_ipinfo_init
#include "../../src/detectors/ipinfo.c"
#undef snprintf
#undef br_ipinfo_init

/* Entirely synthetic lowercase-hex bytes, never sent outside injected backends. */
static const char key1[] = "b7c9d2e5f6a8d3", key2[] = "9d2e5f6a8d3b7c";
static size_t fail_size, fail_after, fail_part_after, fail_setter_after;
static bool inside_send, inside_setter, fail_guard_copy, clobber_cause;
static const char *guard_echo;
static int fail_format;
static size_t sends, releases, setters, setters_before_send;
static const char *const *expected_keys;
static size_t expected_count;
static const br_scan_ctx *expected_context;
static const br_http_request *provider_request;
static br_result *pending_result;
static br_slice pending_secret;
static const char *pending_cause;
static int setter_rc, send_rc, send_status;
static bool format_failed;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

char *strdup(const char *text)
{
    if (inside_send && !strcmp(text, "unsupported HTTP request coalescing")) {
        if (fail_guard_copy) { fail_guard_copy = false; return NULL; }
        if (guard_echo) text = guard_echo;
    }
    if (inside_setter && fail_setter_after && --fail_setter_after == 0) return NULL;
    size_t n = strlen(text) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, text, n);
    return copy;
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && !strcmp(format, "unexpected HTTP response status %d")) {
        int rc = fail_format; fail_format = 0; format_failed = true;
        return rc;
    }
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, n, format, args);
    va_end(args);
    return rc;
}

int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(o, name, v, 0);
}

static void check_request(const br_http_request *r, const char *key, bool effective)
{
    static const char base[] = "https://ipinfo.io/json?token=";
    CHECK(r && !strcmp(r->method, "GET") && strlen(r->url) == 43);
    CHECK(!memcmp(r->url, base, sizeof(base) - 1));
    CHECK(!memcmp(r->url + sizeof(base) - 1, key, 15));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 939);
    CHECK(effective ? r->timeout_ms > 0 && r->timeout_ms <= 5000 : !r->timeout_ms);
    CHECK(!r->body.data && !r->body.len);
    CHECK(r->dedup_key.len == 18 && !memcmp(r->dedup_key.data, "939:", 4));
    CHECK(!memcmp(r->dedup_key.data + 4, key, 14));
    if (effective) {
        CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "User-Agent"));
        CHECK(!strcmp(r->headers[0].value, "TruffleHog ipinfo-offline"));
    } else CHECK(!r->headers && !r->nheaders);
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r,
                 br_http_response *response, char **error)
{
    CHECK(ctx && ctx == expected_context && !provider_request && sends < expected_count);
    check_request(r, expected_keys[sends], false);
    provider_request = r; ++sends; setters_before_send = setters;
    inside_send = true;
    send_rc = ipinfo_real_send(ctx, r, response, error);
    inside_send = false; send_status = response->status;
    if (!br_http_client_is_owned(ctx->transport)) {
        CHECK(send_rc != 0);
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    } else CHECK(!response->body_error); /* Keyed ReadAll errors precede Do success. */
    return send_rc;
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t n)
{
    CHECK(provider_request && !pending_result && n == 1 && secrets);
    CHECK(secrets[0].len == 14 && !memcmp(secrets[0].data, expected_keys[releases], 14));
    pending_result = r; pending_secret = secrets[0]; pending_cause = cause; ++setters;
    inside_setter = true;
    setter_rc = ipinfo_real_setter(r, cause, secrets, n);
    inside_setter = false;
    return setter_rc; /* Real setter allocation failures return +1. */
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == expected_context && provider_request && sends == releases + 1);
    check_request(provider_request, expected_keys[releases], false);
    const bool reached_error = send_rc != 0 ||
        ((send_status < 200 || send_status >= 300) && send_status != 403);
    /* Observe source calls, not merely the setter's NULL-cause no-op: 2xx and
     * quiet 403 make zero calls; a Do error still calls once with NULL cause. */
    CHECK(setters - setters_before_send == (reached_error && !format_failed ? 1u : 0u));
    if (format_failed || !reached_error) CHECK(!pending_result);
    else {
        CHECK(pending_result && pending_secret.len == 14);
        test_key_result(pending_result, 939, expected_keys[releases], "key");
        CHECK(!memcmp(pending_secret.data, expected_keys[releases], 14));
        CHECK(pending_result->verified == (!send_rc && send_status >= 200 && send_status < 300));
        if (pending_cause && !setter_rc) {
            CHECK(pending_result->verification_error);
            CHECK(!strstr(pending_result->verification_error, expected_keys[releases]));
        } else CHECK(!pending_result->verification_error);
        /* The setter has already copied/redacted before ordinary release. Only
         * provider values survive here, never ordinary prepared headers/UA. */
        if (clobber_cause && pending_cause && *pending_cause)
            ((char *)pending_cause)[0] = '~';
    }
    ipinfo_real_release(ctx, response);
    provider_request = NULL; pending_result = NULL; pending_secret = (br_slice){0}; pending_cause = NULL;
    format_failed = false; ++releases;
}

static void expect(const br_scan_ctx *ctx, const char *const *keys, size_t n)
{
    CHECK(!provider_request && !pending_result && !pending_cause && !format_failed);
    expected_context = ctx; expected_keys = keys; expected_count = n;
    sends = releases = setters = 0;
}

static void forbidden(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; (void)ctx; (void)r;
    CHECK(!"borrowed keyed transport must be rejected before raw I/O");
}

static void check_result(const br_result *r, const char *key, bool verified, const char *cause)
{
    test_key_result(r, 939, key, "key");
    CHECK(r->raw.len == 14 && r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_ipinfo_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid IPInfo detector output")); free(error); error = NULL;
    CHECK(br_ipinfo_init(NULL, NULL) == -1);
    CHECK(!br_ipinfo_init(&d, &error) && d && !error);
    CHECK(!br_ipinfo_init(&again, NULL) && again == d);
    CHECK(d->type == 939 && !d->version && !strcmp(d->name, "IPInfo"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "IPInfo provides detailed information about IP addresses. IPInfo API keys can be used to access and retrieve this information."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ipinfo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    /* Parent integrates the exact IPInfoDetectorEnabled feature/default gate. */
    return d;
}

static void extraction_case(const br_detector *d, const void *input, size_t n, const char *key)
{
    test_http http = {.inspect = forbidden}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; expect(&ctx, NULL, 0);
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(r.len == (key ? 1u : 0u) && !sends && !releases && !setters && !http.calls && !http.releases);
    if (key) check_result(&r.items[0], key, false, NULL);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[160], changed[15];
    const struct { const char *format; bool match; } cases[] = {
        {"ipinfo '%s'", true}, {"IpInFo=%s", true}, {"preipinfosuffix:%s", true},
        {"ipinfo\r\n%s", true}, {"ipinfo\r%s", true}, {"ipinfo\n%s", true},
        {"%s", false}, {"%s ipinfo", false}, {"ip info %s", false},
        {"ipinfo%s", false}, {"ipinfo x%s", false}, {"ipinfo _%s", false},
        {"ipinfo %s_", false}, {"ipinfo %s9", false}, {"ipinfo %.13s", false},
        {"ipinfo -%s!", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(d, input, strlen(input), cases[i].match ? key1 : NULL);
    }
    const char invalid[] = {'A', 'F', 'g', 'z', '-', '_'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[6] = invalid[i];
        snprintf(input, sizeof(input), "ipinfo %s", changed);
        extraction_case(d, input, strlen(input), NULL); /* Actual hex, not lower-alnum or CI capture. */
    }
    extraction_case(d, "ipinfo aaaaaaaaaaaaaa", 21, "aaaaaaaaaaaaaa");
    extraction_case(d, "ipinfo 00000000000000", 21, "00000000000000");
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ipinfo", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, key1, 14);
        extraction_case(d, input, 6 + gap + 14, gap == 40 ? key1 : NULL);
    }
    snprintf(input, sizeof(input), "ipinfo %s %s", key1, key2);
    extraction_case(d, input, strlen(input), key1); /* FindAll consumes the first prefix. */
    int n = snprintf(input, sizeof(input), "ipinfo%c%s", 0, key1);
    extraction_case(d, input, (size_t)n, key1); extraction_case(d, NULL, 0, NULL);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void occurrences_and_guard(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "ipinfo %s\nIPINFO %s\nipinfo %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    test_http http = {.response = {.status = 200, .body_error = "unreachable"}, .inspect = forbidden};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect(&ctx, NULL, 0);
    br_results r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases && !setters && !http.calls && !http.releases);
    for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], keys[i], false, NULL);
    CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts);
    br_results_clear(&r);
    clobber_cause = true;
    for (int pass = 0; pass < 2; ++pass) {
        expect(&ctx, keys, 3); http.releases = 0;
        r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 3 && sends == 3 && releases == 3 && setters == 3 && !http.calls && http.releases == 3);
        for (size_t i = 0; i < r.len; ++i)
            check_result(&r.items[i], keys[i], false, "unsupported HTTP request coalescing");
        br_results_clear(&r);
    }
    expect(NULL, NULL, 0);
    r = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!r.len && !sends && !releases && !setters); br_results_clear(&r);
    r = test_scan(d, NULL, false, input, strlen(input));
    CHECK(r.len == 3 && !sends && !releases && !setters); br_results_clear(&r);
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    snprintf(input, sizeof(input), "ipinfo %s", key1);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        expect(&contexts[i], keys, 1); http.releases = 0; if (i == 4) fail_guard_copy = true;
        r = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_guard_copy);
        check_result(&r.items[0], key1, false, i == 4 ? NULL : i ? "unsupported HTTP request coalescing" : "HTTP transport not installed");
        br_results_clear(&r);
    }
    CHECK(!cancellations); /* Guard precedes borrowed shared preparation. */
    char echo[128], first[128], second[128];
    snprintf(input, sizeof(input), "ipinfo %s\nipinfo %s", key1, key2);
    snprintf(echo, sizeof(echo), "out of memory %s / %s / %s", key1, key2, key1);
    snprintf(first, sizeof(first), "out of memory [REDACTED] / %s / [REDACTED]", key2);
    snprintf(second, sizeof(second), "out of memory %s / [REDACTED] / %s", key1, key1);
    guard_echo = echo; expect(&ctx, keys, 2); http.releases = 0;
    r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 2 && sends == 2 && releases == 2 && !http.calls && http.releases == 2);
    check_result(&r.items[0], key1, false, first); check_result(&r.items[1], key2, false, second);
    br_results_clear(&r); guard_echo = NULL; clobber_cause = false;
}

typedef struct {
    pthread_mutex_t mutex;
    test_http http;
    const br_http_request *raw_request;
    const br_scan_ctx *raw_context;
    bool destroyed;
} owned_fixture;

static int64_t monotonic_ms(void)
{
    struct timespec ts; CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void check_owned(const owned_fixture *f)
{
    CHECK(f->raw_context && f->raw_context->transport->user == f);
    CHECK(!f->raw_context->cancelled && !f->raw_context->cancel_user && f->raw_context->deadline_monotonic_ms > 0);
    check_request(f->raw_request, key1, true);
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *r,
                       br_http_response *response, char **error)
{
    owned_fixture *f = user;
    /* Serialize byte operations through release; safe for multiple workers,
     * deadline-aware and never synchronously re-entering any owned client. */
    CHECK(!pthread_mutex_lock(&f->mutex));
    CHECK(!f->destroyed && !f->raw_request);
    f->raw_request = r; f->raw_context = ctx; check_owned(f);
    if (monotonic_ms() >= ctx->deadline_monotonic_ms) {
        ++f->http.calls; *error = strdup("context deadline exceeded"); CHECK(*error); return 1;
    }
    return test_http_send(&f->http, ctx, r, response, error);
}

static void owned_release(void *user, br_http_response *response)
{
    owned_fixture *f = user;
    check_owned(f); /* Actual owned raw snapshot alone retains effective headers/UA. */
    f->raw_request = NULL; f->raw_context = NULL; test_http_release(&f->http, response);
    CHECK(!pthread_mutex_unlock(&f->mutex));
}

static void owned_destroy(void *user)
{
    owned_fixture *f = user; CHECK(!pthread_mutex_lock(&f->mutex));
    CHECK(!f->destroyed && !f->raw_request && f->http.calls == f->http.releases);
    f->destroyed = true; CHECK(!pthread_mutex_unlock(&f->mutex));
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(5); CHECK(prior.raw.data); memcpy(prior.raw.data, "prior", 5); prior.raw.len = 5;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r = {0}; CHECK(!br_results_push(&r, &prior)); return r;
}

static void check_prior(const br_results *r, const br_result *prior)
{
    CHECK(r->len == 1 && r->items[0].raw.data == prior->raw.data && r->items[0].raw.len == 5);
    CHECK(r->items[0].verified && r->items[0].detector_type == 777 && !memcmp(r->items[0].raw.data, "prior", 5));
    CHECK(r->items[0].verification_error == prior->verification_error && !strcmp(r->items[0].verification_error, "caller-owned"));
}

static void owned_verification(const br_detector *d)
{
    static const unsigned char body[] = "not JSON\0ignored arbitrary body";
    char echo[96]; snprintf(echo, sizeof(echo), "synthetic failure %s / %s", key1, key1);
    const struct { int status, rc; const char *read_error, *send_error, *cause; bool verified, setter; } cases[] = {
        {200, 0, NULL, NULL, NULL, true, false}, {201, 0, NULL, NULL, NULL, true, false},
        {204, 0, NULL, NULL, NULL, true, false}, {299, 0, NULL, NULL, NULL, true, false},
        {403, 0, NULL, NULL, NULL, false, false},
        {199, 0, NULL, NULL, "unexpected HTTP response status 199", false, true},
        {300, 0, NULL, NULL, "unexpected HTTP response status 300", false, true},
        {401, 0, NULL, NULL, "unexpected HTTP response status 401", false, true},
        {500, 0, NULL, NULL, "unexpected HTTP response status 500", false, true},
        {200, 1, NULL, "synthetic timeout", "synthetic timeout", false, true},
        {299, -1, NULL, "out of memory in shared Do", "out of memory in shared Do", false, true},
        {200, 1, NULL, NULL, "HTTP transport failed", false, true},
        {200, -1, NULL, echo, "synthetic failure [REDACTED] / [REDACTED]", false, true},
        {200, 0, echo, NULL, "synthetic failure [REDACTED] / [REDACTED]", false, true},
        {403, 0, "synthetic partial read", NULL, "synthetic partial read", false, true},
        {401, 0, "", NULL, "", false, true},
    };
    owned_fixture f = {0}; CHECK(!pthread_mutex_init(&f.mutex, NULL));
    br_http_owned_backend backend = {.transport = {&f, owned_send, owned_release}, .destroy = owned_destroy};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "ipinfo-offline"};
    char input[96]; snprintf(input, sizeof(input), "ipinfo %s", key1); const char *keys[] = {key1, key1};
    clobber_cause = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        f.http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body) - 1}, .body_error = cases[i].read_error};
        f.http.send_rc = cases[i].rc; f.http.send_error = cases[i].send_error;
        expect(&ctx, keys, 1);
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == (cases[i].setter ? 1u : 0u) && f.http.calls == i + 1 && f.http.releases == i + 1);
        check_result(&r.items[0], key1, cases[i].verified, cases[i].cause); br_results_clear(&r);
    }
    size_t calls = f.http.calls;
    ctx.user_agent = "invalid\r\nagent"; expect(&ctx, keys, 1);
    br_results r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == 1 && f.http.calls == calls && f.http.releases == calls);
    check_result(&r.items[0], key1, false, "invalid HTTP user agent"); br_results_clear(&r);
    ctx.user_agent = "ipinfo-offline";
    f.http.response = (br_http_response){.status = 500}; f.http.send_rc = 0; f.http.send_error = NULL;
    const br_detector *observed = NULL;
    CHECK(!observed_ipinfo_init(&observed, &error) && observed && !error);
    const int format_errors[] = {-1, 80};
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        r = prior_results(); br_result prior = r.items[0];
        expect(&ctx, keys, 1); fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format IPInfo verification status") && !fail_format && sends == 1 && releases == 1 && !setters);
        check_prior(&r, &prior); free(error); error = NULL; br_results_clear(&r);
    }
    char twice[96]; snprintf(twice, sizeof(twice), "%s\n%s", input, input);
    r = prior_results(); br_result prior = r.items[0]; expect(&ctx, keys, 2); fail_setter_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)twice, strlen(twice)}, &r, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set IPInfo verification error") && !fail_setter_after && setter_rc == 1 && sends == 2 && releases == 2);
    check_prior(&r, &prior); free(error); error = NULL; br_results_clear(&r);
    /* A first verified result cannot mask a later finding-construction failure. */
    f.http.response.status = 200; expect(&ctx, keys, 2); r = prior_results(); prior = r.items[0]; fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)twice, strlen(twice)}, &r, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create IPInfo result") && !fail_part_after && sends == 1 && releases == 1);
    check_prior(&r, &prior); free(error); error = NULL; br_results_clear(&r);
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); /* Drain before destroy; fixture is still live. */
    CHECK(f.destroyed && !pthread_mutex_destroy(&f.mutex)); clobber_cause = false;
}

static void resources(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "ipinfo %s\nipinfo %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results r = prior_results(); br_result prior = r.items[0]; char *error = NULL;
    expect(NULL, NULL, 0); fail_size = 15; fail_after = 2;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture")); check_prior(&r, &prior); free(error); error = NULL;
    fail_size = 2 * sizeof(br_span); fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, NULL) == -1 && !fail_after); check_prior(&r, &prior);
    fail_size = 14; fail_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot create IPInfo result")); check_prior(&r, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, data, &r, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create IPInfo result")); check_prior(&r, &prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; test_http http = {.inspect = forbidden};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect(&ctx, keys, 2); fail_setter_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_setter_after && setter_rc == 1);
    CHECK(!strcmp(error, "cannot set IPInfo verification error") && sends == 2 && releases == 2 && !http.calls && http.releases == 2);
    check_prior(&r, &prior); free(error); error = NULL;
    /* Fail the real redaction allocation, after the cause copy succeeded. */
    char echo[96]; snprintf(echo, sizeof(echo), "synthetic redaction %s", key1);
    guard_echo = echo; fail_size = strlen("synthetic redaction [REDACTED]") + 1; fail_after = 1;
    expect(&ctx, keys, 1);
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_after && setter_rc == 1);
    CHECK(!strcmp(error, "cannot set IPInfo verification error") && sends == 1 && releases == 1);
    check_prior(&r, &prior); free(error); error = NULL; guard_echo = NULL;
    size_t cap = r.cap; r.cap = 2; expect(&ctx, keys, 2); fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &r, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append IPInfo result") && sends == 2 && releases == 2 && !http.calls);
    check_prior(&r, &prior); r.cap = cap; free(error); br_results_clear(&r);
}

int main(void)
{
    const br_detector *d = descriptor();
    grammar(d); occurrences_and_guard(d); owned_verification(d); resources(d);
    return test_finish("IPInfo lower-hex/metadata/occurrences/guard/owned status/read promotion/conditional pre-release setter/rollback");
}
