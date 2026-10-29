/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

/* Existing named-test inclusion seam: observe provider ownership and failures
 * without changing shared helpers or retaining synthesized HTTP preparation. */
static void *checked_malloc(size_t);
static char *checked_strdup(const char *);
static void checked_free(void *);
static int checked_snprintf(char *, size_t, const char *, ...);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define strdup checked_strdup
#define free checked_free
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_intra42_init observed_intra42_init
#include "../../src/detectors/intra42.c"
#undef malloc
#undef strdup
#undef free
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_intra42_init

static char id_a[74], id_b[74], secret_a[74], secret_b[74];
enum { FORM_BYTES = 201 };
typedef enum { NONE, CAPTURE, FINDING, FORM, LENGTH, CONSTRUCTOR_CAUSE,
               STATUS_MEASURE, STATUS_ALLOC, STATUS_FORMAT, SETTER, PUSH } fault_site;
static fault_site fault;
static size_t nth, captures, forms, form_frees, lengths, sends, releases, setters, pushes;
static bool fault_hit, omit_cause, truncate_length, expected_verified;
static br_captures *original_secrets, *original_ids;
static br_result *candidate;
static const br_http_request *original_request;
static char *original_form;
static const char *original_cause;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_form && !original_cause);
    captures = forms = form_frees = lengths = sends = releases = setters = pushes = 0;
    original_secrets = original_ids = NULL; candidate = NULL;
    fault = NONE; nth = 0;
    fault_hit = omit_cause = truncate_length = expected_verified = false;
}

static void form_is(br_slice body, const char *id, const char *secret)
{
    char expected[FORM_BYTES + 1];
    CHECK(snprintf(expected, sizeof(expected), "client_id=%s&client_secret=%s&grant_type=client_credentials", id, secret) == FORM_BYTES);
    CHECK(body.data && body.len == FORM_BYTES && !memcmp(body.data, expected, FORM_BYTES));
}

static void original_values(void)
{
    CHECK(original_form && original_secrets && original_ids && forms && original_ids->len);
    size_t pair = forms - 1;
    const char *id = original_ids->items[pair % original_ids->len];
    const char *secret = original_secrets->items[pair / original_ids->len];
    CHECK(original_ids->lengths[pair % original_ids->len] == 73);
    CHECK(original_secrets->lengths[pair / original_ids->len] == 73);
    form_is((br_slice){(const unsigned char *)original_form, FORM_BYTES}, id, secret);
    CHECK(original_form[FORM_BYTES] == '\0');
    if (original_request) {
        CHECK(original_request->body.data == (const unsigned char *)original_form);
        CHECK(original_request->body.len == FORM_BYTES && original_request->nheaders == 2);
        CHECK(!strcmp(original_request->headers[0].name, "Content-Type"));
        CHECK(!strcmp(original_request->headers[0].value, "application/x-www-form-urlencoded"));
        CHECK(!strcmp(original_request->headers[1].name, "Content-Length"));
        CHECK(!strcmp(original_request->headers[1].value, "201"));
    }
}

static void *checked_malloc(size_t size)
{
    if (size == FORM_BYTES + 1) {
        CHECK(candidate && candidate->raw.len == 73 && candidate->secret_parts);
        CHECK(!candidate->verified && !candidate->verification_error && !original_form);
        ++forms;
        if (hit(FORM)) return NULL;
        original_form = malloc(size);
        return original_form;
    }
    CHECK(original_request); /* Only the reached status cause is allocated here. */
    if (hit(STATUS_ALLOC)) return NULL;
    return malloc(size);
}

static char *checked_strdup(const char *text)
{
    if (!strcmp(text, "net/http: nil Context")) {
        original_values();
        CHECK(!original_request && lengths == 0 && sends == 0);
        if (hit(CONSTRUCTOR_CAUSE)) return NULL;
    }
    return strdup(text);
}

static void checked_free(void *value)
{
    CHECK(!original_request); /* Neither cause nor original form dies before release. */
    if (value && value == original_form) {
        original_values(); original_form = NULL; ++form_frees;
    }
    if (value && value == original_cause) original_cause = NULL;
    free(value);
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    bool length = !strcmp(format, "%zu");
    CHECK(length || !strcmp(format, "unexpected http response status %d"));
    if (length) {
        original_values(); CHECK(!original_request); ++lengths;
        if (hit(LENGTH)) return truncate_length ? (int)size : -1;
    } else if (hit(out ? STATUS_FORMAT : STATUS_MEASURE)) {
        if (out) { CHECK(size >= sizeof("partial")); memcpy(out, "partial", sizeof("partial")); original_cause = out; }
        return out ? (int)size : -1;
    }
    va_list args; va_start(args, format);
    char measure_only;
    int rc = vsnprintf(out ? out : &measure_only, out ? size : 0, format, args);
    va_end(args);
    if (!length && out) original_cause = out;
    return rc;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && captures < 2);
    CHECK(regex == (captures ? intra42_compiled.id : intra42_compiled.secret));
    if (captures++) original_ids = out; else original_secrets = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1;
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
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 987);
    original_request = request; original_values(); ++sends;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) { free(*error); *error = NULL; }
    original_cause = *error;
    expected_verified = rc == 0 && response->status == 200;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && sends == releases + 1); original_values();
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(setters == releases && pushes == releases); /* Helper returns before publication. */
    if (original_cause) CHECK(strlen(original_cause) < 1024);
    br_http_release(ctx, response);
    original_request = NULL; ++releases;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(!original_request && !original_form && sends == releases);
    CHECK(result == candidate && result->verified == expected_verified && !result->verification_error);
    CHECK(count == 1 && secrets && secrets[0].len == 73);
    CHECK(!memcmp(secrets[0].data, result->raw.data, 73));
    CHECK(!cause || !original_cause || cause == original_cause);
    ++setters;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_form && sends == releases);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 987 && !d->version && !strcmp(d->name, "Intra42") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Intra42 is an API service used to interact with the 42 school's internal systems. Intra42 API keys can be used to access and modify data within these systems."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "s-s4t2ud-") && !strcmp(d->keywords[1], "s-s4t2af-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *secret, bool verified, const char *cause)
{
    test_key_result(r, 987, secret, "key");
    CHECK(r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}

static void extract(const br_detector *d, const void *input, size_t len, size_t count, const char *secret)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) finding(&out.items[i], secret, false, NULL);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[5000], changed[74];
    int n = snprintf(input, sizeof(input), "%s\r\n'%s'", id_a, secret_a);
    CHECK(n > 0); extract(d, input, (size_t)n, 1, secret_a); /* No provider prefix; cross flavor. */
    const char *bad[] = {"_%s %s", "%s_ %s", "X%s %s", "%sX %s", "%s _%s", "%s %s_", "%s X%s", "%s %sX"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        n = snprintf(input, sizeof(input), bad[i], id_a, secret_a);
        CHECK(n > 0); extract(d, input, (size_t)n, 0, NULL);
    }
    for (size_t which = 0; which < 2; ++which) {
        const char *token = which ? secret_a : id_a;
        const size_t positions[] = {0, 2, 6, 9, 72};
        for (size_t i = 0; i < sizeof(positions) / sizeof(*positions); ++i) {
            memcpy(changed, token, sizeof(changed)); changed[positions[i]] = 'A';
            n = snprintf(input, sizeof(input), "%s %s", which ? id_a : changed, which ? changed : secret_a);
            CHECK(n > 0); extract(d, input, (size_t)n, 0, NULL);
        }
        memcpy(changed, token, sizeof(changed)); changed[30] = 'g';
        n = snprintf(input, sizeof(input), "%s %s", which ? id_a : changed, which ? changed : secret_a);
        CHECK(n > 0); extract(d, input, (size_t)n, 0, NULL);
        n = snprintf(input, sizeof(input), "%s %.72s", which ? id_a : secret_a, token);
        CHECK(n > 0); extract(d, input, (size_t)n, 0, NULL);
    }
    n = snprintf(input, sizeof(input), "%s", secret_a);
    memset(input + n, ':', 3000); n += 3000;
    memcpy(input + n, id_b, 73); extract(d, input, (size_t)n + 73, 1, secret_a);
    memcpy(input, id_a, 73); input[73] = '\0'; memcpy(input + 74, secret_a, 73);
    extract(d, input, 147, 1, secret_a);
    n = snprintf(input, sizeof(input), "s-s4t2ud- %s %s", secret_a, id_a);
    CHECK(n > 0); extract(d, input, (size_t)n, 1, secret_a); /* No reusable keyword-prefix consumption. */
    extract(d, id_a, 73, 0, NULL); extract(d, secret_a, 73, 0, NULL); extract(d, NULL, 0, 0, NULL);
    puts("Intra42 direct case-sensitive grammar/boundaries/independent flavors/binary input/span hint: 0 failures");
}

typedef struct {
    const char *const *ids, *const *secrets;
    size_t nids, nsecrets;
    const br_scan_ctx *ctx;
    const char *agent;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *s = http->user; size_t pair = http->calls - 1;
    CHECK(ctx == s->ctx && http->calls == http->releases + 1 && pair < s->nids * s->nsecrets);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.intra.42.fr/oauth/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 987);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Content-Length") && !strcmp(request->headers[1].value, "201"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, s->agent));
    form_is(request->body, s->ids[pair % s->nids], s->secrets[pair / s->nids]);
    /* Never retain the effective request, header-array or synthesized UA. */
}

static void products(const br_detector *d)
{
    char input[500];
    int n = snprintf(input, sizeof(input), "%s %s %s\n%s\n%s %s", id_b, secret_b, secret_a, id_a, secret_b, id_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *ids[] = {id_b, id_a, id_a}, *secrets[] = {secret_b, secret_a, secret_b};
    request_script s = {.ids = ids, .secrets = secrets, .nids = 3, .nsecrets = 3, .agent = "TruffleHog intra42-offline"};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "intra42-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, (size_t)n);
        CHECK(out.len == 9 && http.calls == (pass ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], secrets[i / 3], pass != 0, NULL);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    puts("Intra42 secret-major complete occurrence products/duplicates/secret-only metadata/exact POST: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[150]; CHECK(snprintf(input, sizeof(input), "%s %s", id_a, secret_a) == 147);
    const char *ids[] = {id_a}, *secrets[] = {secret_a};
    request_script s = {.ids = ids, .secrets = secrets, .nids = 1, .nsecrets = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &s}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 500, 200, 401};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored partial read"};
        br_results out = test_scan(d, &ctx, true, input, 147);
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected http response status %d", statuses[i]);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], secret_a, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause);
        br_results_clear(&out);
    }
    char cause[400], redacted[180];
    snprintf(cause, sizeof(cause), "ID=%s SECRET=%s AGAIN=%s", id_a, secret_a, secret_a);
    snprintf(redacted, sizeof(redacted), "ID=%s SECRET=[REDACTED] AGAIN=[REDACTED]", id_a);
    const char *causes[] = {cause, "cannot allocate Intra42 form", "context canceled", "net/http: nil Context", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i];
        http.response = (br_http_response){.status = 200, .body_error = "ignored on Do error"};
        br_results out = test_scan(d, &ctx, true, input, 147);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], secret_a, false, i == 0 ? redacted : causes[i] ? causes[i] : "HTTP transport failed");
        br_results_clear(&out);
    }
    puts("Intra42 200-only/401-quiet/lowercase status errors/ignored bodies/whole Do/secret-only redaction: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_and_null(const br_detector *d)
{
    char input[150]; CHECK(snprintf(input, sizeof(input), "%s %s", id_a, secret_a) == 147);
    test_http http = {0}; br_transport transport = test_transport(&http), missing_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, 147);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && setters == 1 && pushes == 1 && form_frees == 1);
        finding(&out.items[0], secret_a, false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, 147);
    CHECK(out.len == 1 && forms == 1 && form_frees == 1 && !lengths && !sends && !releases && setters == 1 && pushes == 1);
    finding(&out.items[0], secret_a, false, "net/http: nil Context"); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, 147);
    CHECK(out.len == 1 && !forms && !sends && !setters); finding(&out.items[0], secret_a, false, NULL); br_results_clear(&out);
    reset_observation(); http.send_rc = 1; omit_cause = true;
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(d, &ctx, true, input, 147);
    CHECK(out.len == 1 && setters == 1 && sends == 1 && releases == 1);
    finding(&out.items[0], secret_a, false, NULL); br_results_clear(&out);
    puts("Intra42 shared setup/nil-context kept/full-form-before-constructor/release-before-setter/NULL no-op: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, bool verify, bool nil,
                        int send_rc, bool no_cause, bool truncate, const char *message, size_t attempts)
{
    char input[225]; int n = snprintf(input, sizeof(input), "%s %s %s", id_a, id_b, secret_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "synthetic Do error" : NULL,
        .response = {.status = site == SETTER || site == PUSH ? 200 : 503, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site;
    nth = site == CAPTURE || nil ? 1 : 2; omit_cause = no_cause; truncate_length = truncate;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == -1);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_form && !original_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(form_frees + (site == FORM ? 1u : 0u) == forms);
    br_results_clear(&out);
}

static void owned_failures(const br_detector *d)
{
    own_failure(d, CAPTURE, true, false, 0, false, false, "synthetic capture failure", 0);
    own_failure(d, FINDING, true, true, 0, false, false, "cannot create Intra42 finding", 0);
    own_failure(d, FINDING, true, false, 0, false, false, "cannot create Intra42 finding", 1);
    own_failure(d, FORM, true, true, 0, false, false, "cannot allocate Intra42 form", 0);
    own_failure(d, FORM, true, false, 0, false, false, "cannot allocate Intra42 form", 1);
    own_failure(d, CONSTRUCTOR_CAUSE, true, true, 0, false, false, "cannot allocate Intra42 constructor cause", 0);
    own_failure(d, LENGTH, true, false, 0, false, false, "cannot format Intra42 content length", 1);
    own_failure(d, LENGTH, true, false, 0, false, true, "cannot format Intra42 content length", 1);
    own_failure(d, STATUS_MEASURE, true, false, 0, false, false, "cannot format Intra42 status cause", 2);
    own_failure(d, STATUS_ALLOC, true, false, 0, false, false, "cannot allocate Intra42 status cause", 2);
    own_failure(d, STATUS_FORMAT, true, false, 0, false, false, "cannot format Intra42 status cause", 2);
    own_failure(d, SETTER, true, false, 0, false, false, "cannot set Intra42 verification error", 2);
    own_failure(d, SETTER, true, false, -7, false, false, "cannot set Intra42 verification error", 2);
    own_failure(d, SETTER, true, false, 1, true, false, "cannot set Intra42 verification error", 2);
    own_failure(d, SETTER, true, true, 0, false, false, "cannot set Intra42 verification error", 0);
    own_failure(d, PUSH, true, false, 0, false, false, "cannot append Intra42 finding", 2);
    own_failure(d, PUSH, false, false, 0, false, false, "cannot append Intra42 finding", 0);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(!out.len && !forms && !sends);
    puts("Intra42 owned nonzero failures/NULL setter +1 fatal/one release/invocation-only caller-preserving rollback: 0 failures");
}

static void token(char out[74], const char *prefix, size_t shift)
{
    static const char hex[] = "0123456789abcdef";
    CHECK(strlen(prefix) == 9); memcpy(out, prefix, 9);
    for (size_t i = 0; i < 64; ++i) out[9 + i] = hex[(i + shift) % 16];
    out[73] = '\0';
}

int main(void)
{
    token(id_a, "u-s4t2ud-", 0); token(id_b, "u-s4t2af-", 7);
    token(secret_a, "s-s4t2af-", 0); token(secret_b, "s-s4t2ud-", 11);
    const br_detector *d = descriptor(br_intra42_init);
    grammar(d); products(d); response_policy(d);
    const br_detector *observed = descriptor(observed_intra42_init);
    reset_observation(); response_policy(observed); setup_and_null(observed); owned_failures(observed);
    CHECK(!original_request && !original_form && !original_cause && fault == NONE);
    return test_finish("Intra42 ABI1 focused checks");
}
