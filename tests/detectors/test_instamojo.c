/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

/* Observe provider-owned failures and before-close ordering using the existing
 * named-test inclusion technique, without changing shared helpers or ABI1. */
static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_snprintf(char *, size_t, const char *, ...);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_instamojo_init observed_instamojo_init
#include "../../src/detectors/instamojo.c"
#undef malloc
#undef free
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_instamojo_init

static char id_a[41], id_b[41], secret_a[129], secret_b[129];
static const char form_prefix[] = "grant_type=client_credentials&client_id=";
static const char form_middle[] = "&client_secret=";
enum { FORM_SIZE = sizeof(form_prefix) - 1 + 40 + sizeof(form_middle) - 1 + 128 + 1 };
static const unsigned char marker_body[] = {'x', 0, 'a','c','c','e','s','s','_','t','o','k','e','n', 0xff};

typedef enum { NONE, CAPTURE, FINDING, FORM, STATUS_ALLOC, STATUS_MEASURE, STATUS_FORMAT, SETTER, PUSH } fault_site;
static fault_site fault;
static size_t nth;
static bool fault_hit, omit_cause;
static size_t captures, forms, form_frees, sends, releases, setters, pushes;
static br_captures *original_secrets, *original_ids;
static br_result *candidate;
static const br_http_request *original_request;
static char *original_form;
static const char *original_cause;
static br_results *published;
static bool should_drop, should_verify, should_set, did_set, did_push;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_form);
    captures = forms = form_frees = sends = releases = setters = pushes = 0;
    original_secrets = original_ids = NULL; candidate = NULL;
    original_cause = NULL; published = NULL;
    fault_hit = omit_cause = false; fault = NONE; nth = 0;
}

static void form_bytes(br_slice body, const char *id, const char *secret)
{
    CHECK(body.data && body.len == FORM_SIZE - 1);
    size_t at = sizeof(form_prefix) - 1;
    CHECK(!memcmp(body.data, form_prefix, at));
    CHECK(!memcmp(body.data + at, id, 40)); at += 40;
    CHECK(!memcmp(body.data + at, form_middle, sizeof(form_middle) - 1)); at += sizeof(form_middle) - 1;
    CHECK(!memcmp(body.data + at, secret, 128));
}

static void original_values(void)
{
    CHECK(original_request && original_form && original_secrets && original_ids);
    CHECK(forms && original_ids->len && original_secrets->len);
    size_t pair = forms - 1;
    const char *id = original_ids->items[pair % original_ids->len];
    const char *secret = original_secrets->items[pair / original_ids->len];
    CHECK(original_ids->lengths[pair % original_ids->len] == 40);
    CHECK(original_secrets->lengths[pair / original_ids->len] == 128);
    CHECK(original_request->body.data == (const unsigned char *)original_form);
    form_bytes(original_request->body, id, secret);
    CHECK(original_request->nheaders == 1 && !strcmp(original_request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(original_request->headers[0].value, "application/x-www-form-urlencoded"));
}

static void *checked_malloc(size_t size)
{
    if (size == FORM_SIZE) {
        CHECK(candidate && candidate->raw.len == 40 && candidate->secret_parts);
        CHECK(!candidate->verified && !candidate->verification_error && !original_form);
        ++forms;
        if (hit(FORM)) return NULL;
        original_form = malloc(size);
        return original_form;
    }
    if (hit(STATUS_ALLOC)) return NULL;
    return malloc(size);
}

static void checked_free(void *value)
{
    CHECK(!original_request); /* Original form and cause may not die before release. */
    if (value && value == original_form) {
        size_t pair = forms - 1;
        CHECK(original_secrets && original_ids && original_ids->len);
        form_bytes((br_slice){value, FORM_SIZE - 1}, original_ids->items[pair % original_ids->len],
                   original_secrets->items[pair / original_ids->len]);
        CHECK(original_form[FORM_SIZE - 1] == '\0');
        original_form = NULL; ++form_frees;
    }
    free(value);
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    CHECK(!strcmp(format, "unexpected HTTP response status %d"));
    if (hit(out ? STATUS_FORMAT : STATUS_MEASURE)) return out ? (int)size : -1;
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && captures < 2);
    CHECK(regex == (captures ? instamojo_compiled.id : instamojo_compiled.secret));
    if (captures++) original_ids = out; else original_secrets = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1; /* Positive owned failures are fatal, not ordinary drops. */
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    candidate = result;
    return hit(FINDING) ? 1 : br_finding_key_bytes(result, type, key, part);
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && captures == 2);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 941);
    original_request = request; original_values(); ++sends;
    did_set = did_push = false; published = NULL;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) { free(*error); *error = NULL; }
    should_drop = rc == 0 && response->body_error != NULL;
    should_verify = rc == 0 && !should_drop && response->status >= 200 && response->status < 300 &&
        br_slice_find(response->body, (br_slice){(const unsigned char *)"access_token", 12}, 0) != SIZE_MAX;
    should_set = !should_drop && !should_verify;
    original_cause = *error;
    return rc;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(original_request && result == candidate && should_set && !did_set && !should_drop);
    original_values();
    CHECK(count == 1 && secrets && secrets[0].len == 128);
    CHECK(!memcmp(secrets[0].data, original_request->body.data + FORM_SIZE - 1 - 128, 128));
    CHECK(!result->verified && !result->verification_error);
    original_cause = cause; did_set = true; ++setters;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_push(br_results *out, br_result *result)
{
    ++pushes;
    if (original_request) {
        original_values();
        CHECK(!should_drop && result == candidate && result->verified == should_verify);
        CHECK(did_set == should_set && !did_push);
        did_push = true;
    }
    if (hit(PUSH)) return 1;
    int rc = br_results_push(out, result);
    if (rc == 0 && original_request) published = out;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && sends == releases + 1); original_values();
    if (original_cause) CHECK(strlen(original_cause) < 2048);
    if (!fault_hit) CHECK(did_push == !should_drop && did_set == should_set);
    if (published) {
        CHECK(did_push && published->len);
        const br_result *last = &published->items[published->len - 1];
        CHECK(last->verified == should_verify && last->raw.len == 40);
        CHECK(!memcmp(last->raw.data, original_ids->items[(forms - 1) % original_ids->len], 40));
        CHECK(!original_cause || last->verification_error);
    }
    br_http_release(ctx, response);
    original_request = NULL; original_cause = NULL; ++releases;
}

static size_t pair_input(char *out, size_t size, const char *id, const char *secret)
{
    int n = snprintf(out, size, "instamojo %s\ninstamojo %s", id, secret);
    CHECK(n > 0 && (size_t)n < size);
    return (size_t)n;
}

static void finding(const br_result *result, const char *id, bool verified, const char *cause)
{
    test_key_result(result, 941, id, "key");
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void extraction(const br_detector *d, const void *input, size_t len, size_t count, const char *id)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) finding(&out.items[i], id, false, NULL);
    br_results_clear(&out);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 941 && !d->version && !strcmp(d->name, "Instamojo") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "An Ecommerce service, API keys can be used to create and access customer data"));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "instamojo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void grammar_and_span(const br_detector *d)
{
    char input[5000]; size_t len = pair_input(input, sizeof(input), id_a, secret_a);
    extraction(d, input, len, 1, id_a);
    int n = snprintf(input, sizeof(input), "InStAmOjO\t'%s'\r\nINSTAMOJO\r\n\"%s\"", id_a, secret_a);
    CHECK(n > 0); extraction(d, input, (size_t)n, 1, id_a);
    const char *bad[] = {"%s\ninstamojo %s", "instamojo %s\n%s", "instamojo _%s\ninstamojo %s",
        "instamojo %s_\ninstamojo %s", "instamojo %sX\ninstamojo %s", "instamojo %s\ninstamojo _%s",
        "instamojo %s\ninstamojo %s_", "instamojo %s\ninstamojo %sX"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        n = snprintf(input, sizeof(input), bad[i], id_a, secret_a);
        CHECK(n > 0); extraction(d, input, (size_t)n, 0, NULL);
    }
    for (size_t which = 0; which < 2; ++which) {
        for (size_t gap = 40; gap <= 41; ++gap) {
            n = snprintf(input, sizeof(input), "instamojo %s\ninstamojo", which ? id_a : secret_a);
            size_t at = (size_t)n; memset(input + at, ':', gap); at += gap;
            const char *token = which ? secret_a : id_a; size_t bytes = strlen(token);
            memcpy(input + at, token, bytes);
            extraction(d, input, at + bytes, gap == 40 ? 1 : 0, id_a);
        }
    }
    n = snprintf(input, sizeof(input), "instamojo %s\ninstamojo", secret_a);
    for (size_t i = 0; i < 40; ++i) memcpy(input + n + 4 * i, "\xf0\x9f\x92\xa1", 4);
    memcpy(input + n + 160, id_a, 40); extraction(d, input, (size_t)n + 200, 1, id_a);
    n = snprintf(input, sizeof(input), "instamojo %s\ninstamojo", secret_a);
    input[n] = '\0'; memcpy(input + n + 1, id_a, 40); extraction(d, input, (size_t)n + 41, 1, id_a);
    n = snprintf(input, sizeof(input), "instamojo %s %s\ninstamojo %s", id_a, id_b, secret_a);
    extraction(d, input, (size_t)n, 1, id_a); /* Prefix consumption is not reusable. */
    n = snprintf(input, sizeof(input), "instamojo %s", secret_a);
    memset(input + n, ':', 3000); n += 3000;
    n += snprintf(input + n, sizeof(input) - (size_t)n, "instamojo %s", id_a);
    extraction(d, input, (size_t)n, 1, id_a); /* Direct scans do not apply span1024. */
    char broken[129]; memcpy(broken, secret_a, sizeof(broken)); broken[70] = '-';
    len = pair_input(input, sizeof(input), id_a, broken); extraction(d, input, len, 0, NULL);
    extraction(d, NULL, 0, 0, NULL);
    puts("Instamojo grammar/independent prefixes/word boundaries/rune gap/binary input/span hint: 0 failures");
}

typedef struct {
    const char *const *ids, *const *secrets;
    size_t nids, nsecrets;
    const br_scan_ctx *ctx;
    const char *agent;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *s = http->user;
    CHECK(ctx == s->ctx && http->calls == http->releases + 1);
    CHECK(http->calls <= s->nids * s->nsecrets);
    size_t pair = http->calls - 1;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.instamojo.com/oauth2/token/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 941);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->agent));
    form_bytes(request->body, s->ids[pair % s->nids], s->secrets[pair / s->nids]);
    /* Never retain effective request, header-array or synthesized UA storage. */
}

static void products(const br_detector *d)
{
    char input[1200];
    int n = snprintf(input, sizeof(input), "instamojo %s\ninstamojo %s\ninstamojo %s\ninstamojo %s\ninstamojo %s\ninstamojo %s",
                     secret_b, id_b, secret_a, id_a, secret_b, id_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *ids[] = {id_b, id_a, id_a}, *secrets[] = {secret_b, secret_a, secret_b};
    request_script script = {.ids = ids, .secrets = secrets, .nids = 3, .nsecrets = 3, .agent = "TruffleHog instamojo-offline"};
    test_http http = {.user = &script, .inspect = inspect, .response = {.status = 299, .body = {marker_body, sizeof(marker_body)}}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "instamojo-offline"}; script.ctx = &ctx;
    br_results out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 9 && !http.calls && !http.releases);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], ids[i % 3], false, NULL);
    br_results_clear(&out);
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], ids[i % 3], true, NULL);
    br_results_clear(&out);
    puts("Instamojo secret-major complete occurrence products/duplicates/ID-only metadata/exact POST: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[220]; size_t len = pair_input(input, sizeof(input), id_a, secret_a);
    const char *ids[] = {id_a}, *secrets[] = {secret_a};
    request_script script = {.ids = ids, .secrets = secrets, .nids = 1, .nsecrets = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; script.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {marker_body, sizeof(marker_body)}};
        br_results out = test_scan(d, &ctx, true, input, len);
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        bool ok = statuses[i] >= 200 && statuses[i] < 300;
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], id_a, ok, ok ? NULL : cause); br_results_clear(&out);
    }
    const char *bodies[] = {"", "access_toke", "ACCESS_TOKEN", "not-JSON-prefixaccess_tokensuffix"};
    for (size_t i = 0; i < sizeof(bodies) / sizeof(*bodies); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)bodies[i], strlen(bodies[i])}};
        br_results out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], id_a, i == 3, i == 3 ? NULL : "unexpected HTTP response status 200"); br_results_clear(&out);
    }
    const int read_statuses[] = {200, 401, 500};
    for (size_t i = 0; i < sizeof(read_statuses) / sizeof(*read_statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = read_statuses[i], .body = {marker_body, sizeof(marker_body)}, .body_error = i == 1 ? "" : "synthetic read failure"};
        br_results out = test_scan(d, &ctx, true, input, len);
        CHECK(!out.len && http.calls == 1 && http.releases == 1 && !setters && !pushes);
        br_results_clear(&out);
    }
    char cause[450], redacted[150];
    snprintf(cause, sizeof(cause), "ID=%s SECRET=%s AGAIN=%s", id_a, secret_a, secret_a);
    snprintf(redacted, sizeof(redacted), "ID=%s SECRET=[REDACTED] AGAIN=[REDACTED]", id_a);
    const char *causes[] = {cause, "cannot allocate Instamojo form", "context canceled", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        reset_observation(); http.calls = http.releases = 0; http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i];
        http.response = (br_http_response){.status = 200, .body = {marker_body, sizeof(marker_body)}, .body_error = "ignored on send failure"};
        br_results out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], id_a, false, i == 0 ? redacted : causes[i] ? causes[i] : "HTTP transport failed");
        br_results_clear(&out);
    }
    puts("Instamojo all-status reads/binary marker/read-error drops/whole Do/secret-only errors: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_and_null(const br_detector *d)
{
    char input[220]; size_t len = pair_input(input, sizeof(input), id_a, secret_a);
    test_http http = {0}; br_transport transport = test_transport(&http), missing_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, len);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && setters == 1 && pushes == 1 && form_frees == 1);
        finding(&out.items[0], id_a, false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, len);
    CHECK(!out.len && forms == 1 && form_frees == 1 && !sends && !setters && !pushes); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == 1 && !forms && !sends && !setters); finding(&out.items[0], id_a, false, NULL); br_results_clear(&out);
    br_scan_ctx ctx = {.transport = &transport}; http.send_rc = 1;
    reset_observation(); omit_cause = true;
    out = test_scan(d, &ctx, true, input, len);
    CHECK(out.len == 1 && setters == 1 && sends == 1 && releases == 1);
    finding(&out.items[0], id_a, false, NULL); br_results_clear(&out);
    puts("Instamojo shared setup/NULL setter/nil constructor/full-form-before-drop/before-close publication: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                        int send_rc, bool no_cause, const char *message, size_t attempts)
{
    char input[300];
    int n = snprintf(input, sizeof(input), "instamojo %s\ninstamojo %s\ninstamojo %s", id_a, id_b, secret_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "synthetic Do error" : NULL,
        .response = {.status = site == PUSH ? 200 : 503, .body = {marker_body, sizeof(marker_body)},
                     .body_error = site == FINDING ? "synthetic read failure" : NULL}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence; omit_cause = no_cause;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == -1);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_form);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(form_frees + (site == FORM ? 1u : 0u) == forms);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, false, 0, false, "synthetic capture failure", 0);
    own_failure(d, CAPTURE, 2, false, false, 0, false, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, false, "cannot create Instamojo finding", 0);
    own_failure(d, FINDING, 2, true, false, 0, false, "cannot create Instamojo finding", 1);
    own_failure(d, FORM, 1, true, true, 0, false, "cannot allocate Instamojo form", 0);
    own_failure(d, FORM, 2, true, false, 0, false, "cannot allocate Instamojo form", 1);
    own_failure(d, STATUS_MEASURE, 2, true, false, 0, false, "cannot format Instamojo status cause", 2);
    own_failure(d, STATUS_ALLOC, 2, true, false, 0, false, "cannot allocate Instamojo status cause", 2);
    own_failure(d, STATUS_FORMAT, 2, true, false, 0, false, "cannot format Instamojo status cause", 2);
    own_failure(d, SETTER, 2, true, false, 0, false, "cannot set Instamojo verification error", 2);
    own_failure(d, SETTER, 2, true, false, -7, false, "cannot set Instamojo verification error", 2);
    own_failure(d, SETTER, 2, true, false, 1, true, "cannot set Instamojo verification error", 2);
    own_failure(d, PUSH, 2, true, false, 0, false, "cannot append Instamojo finding", 2);
    own_failure(d, PUSH, 2, false, false, 0, false, "cannot append Instamojo finding", 0);
    reset_observation();
    br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(!out.len && !forms && !sends);
    puts("Instamojo owned nonzero failures/one release on fatal/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    test_secret(secret_a, 128, 3); test_secret(secret_b, 128, 17); test_secret(id_b, 40, 11);
    secret_a[4] = 'Z'; secret_b[5] = 'Y'; id_b[6] = 'X';
    memcpy(id_a, secret_a, 40); id_a[40] = '\0'; /* No containment/inequality filter. */
    const br_detector *d = descriptor(br_instamojo_init);
    grammar_and_span(d); products(d); response_policy(d);
    const br_detector *observed = descriptor(observed_instamojo_init);
    reset_observation(); response_policy(observed);
    setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_form && fault == NONE);
    return test_finish("Instamojo ABI1 focused checks");
}
