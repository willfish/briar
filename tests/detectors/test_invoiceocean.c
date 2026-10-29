/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

#include <curl/curl.h>

/* Reuse the existing named-test inclusion seams for owned nonzero failures and
 * provider-original lifetimes, without extending ordinary prepared storage. */
static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_invoiceocean_init observed_invoiceocean_init
#include "../../src/detectors/invoiceocean.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_invoiceocean_init

static const char key_a[] = "Ab2Cd4Ef6Gh8Ij0Kl2Mn", key_b[] = "Zy9Xw7Vu5Ts3Rq1Po0Nm";
static const char host_a[] = "hiddena.invoiceocean.com", host_b[] = "hiddenb.invoiceocean.com";
static const char url_format[] = "https://%s/invoices.json?period=this_month&api_token=%s";
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, captures, findings, urls, url_frees, sends, releases, pushes;
static bool fault_hit;
static br_captures *original_keys, *original_hosts;
static br_result *candidate;
static const br_http_request *original_request;
static char *original_url;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_url);
    captures = findings = urls = url_frees = sends = releases = pushes = 0;
    original_keys = original_hosts = NULL; candidate = NULL;
    fault = NONE; nth = 0; fault_hit = false;
}

static void url_is(const char *url, const char *host, const char *key)
{
    int needed = snprintf(NULL, 0, url_format, host, key);
    CHECK(needed > 0);
    char *expected = malloc((size_t)needed + 1); CHECK(expected);
    CHECK(snprintf(expected, (size_t)needed + 1, url_format, host, key) == needed);
    CHECK(!strcmp(url, expected)); free(expected);
}

static void original_values(void)
{
    CHECK(original_url && original_keys && original_hosts && original_hosts->len && findings);
    size_t pair = findings - 1;
    const char *key = original_keys->items[pair / original_hosts->len];
    const char *host = original_hosts->items[pair % original_hosts->len];
    CHECK(original_keys->lengths[pair / original_hosts->len] == 20);
    CHECK(original_hosts->lengths[pair % original_hosts->len] == strlen(host));
    url_is(original_url, host, key);
    if (original_request) {
        CHECK(original_request->url == original_url && original_request->nheaders == 1);
        CHECK(!strcmp(original_request->headers[0].name, "Content-Type"));
        CHECK(!strcmp(original_request->headers[0].value, "application/json"));
    }
}

static void *checked_malloc(size_t size)
{
    CHECK(candidate && candidate->raw.len == 20 && candidate->secret_parts);
    CHECK(!candidate->verified && !candidate->verification_error && !original_url);
    CHECK(original_hosts && original_hosts->len && findings);
    size_t pair = findings - 1;
    const char *key = original_keys->items[pair / original_hosts->len];
    const char *host = original_hosts->items[pair % original_hosts->len];
    CHECK(size == (size_t)snprintf(NULL, 0, url_format, host, key) + 1);
    ++urls;
    if (hit(URL)) return NULL;
    original_url = malloc(size);
    return original_url;
}

static void checked_free(void *value)
{
    CHECK(!original_request); /* Original URL/captures/headers survive release. */
    if (value && value == original_url) {
        original_values(); original_url = NULL; ++url_frees;
    }
    free(value);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && captures < 2);
    CHECK(regex == (captures ? invoiceocean_compiled.host : invoiceocean_compiled.key));
    if (captures++) original_hosts = out; else original_keys = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    ++findings; candidate = result;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && captures == 2);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && !request->timeout_ms && request->detector_type == 689);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    original_request = request; original_values(); ++sends;
    return br_http_send(ctx, request, response, error);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && sends == releases + 1 && !candidate->verification_error);
    original_values(); br_http_release(ctx, response);
    original_request = NULL; ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_url);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 689 && !d->version && !strcmp(d->name, "InvoiceOcean") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "InvoiceOcean is an online invoicing service. InvoiceOcean API tokens can be used to access and manage invoices and other financial data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "invoiceocean"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding_is(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 689, key, "key");
    CHECK(result->raw.len == 20 && result->verified == verified && !result->verification_error);
}

static void extract(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding_is(&out.items[0], key, false);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[5000], changed[21];
    const char *good[] = {"invoiceocean '%s'\nhiddena.invoiceocean.com", "InVoIcEoCeAn\r\n\"%s\" hiddena.invoiceocean.com",
        "myINVOICEOCEANsuffix:%s\nhiddena.invoiceocean.com", "invoiceocean-%s-\nhiddena.invoiceocean.com"};
    const char *bad[] = {"%s\nhiddena.invoiceocean.com", "invoice-ocean %s\nhiddena.invoiceocean.com",
        "invoiceocean%s\nhiddena.invoiceocean.com", "invoiceocean %.19s\nhiddena.invoiceocean.com",
        "invoiceocean X%s\nhiddena.invoiceocean.com", "invoiceocean %sX\nhiddena.invoiceocean.com",
        "invoiceocean _%s\nhiddena.invoiceocean.com", "invoiceocean %s_\nhiddena.invoiceocean.com", "invoiceocean %s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        int n = snprintf(input, sizeof(input), good[i], key_a); CHECK(n > 0); extract(d, input, (size_t)n, key_a);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        int n = snprintf(input, sizeof(input), bad[i], key_a); CHECK(n > 0); extract(d, input, (size_t)n, NULL);
    }
    const char *plain[] = {"AAAAAAAAAAAAAAAAAAAA", "00000000000000000000", "zzzzzzzzzzzzzzzzzzzz"};
    for (size_t i = 0; i < sizeof(plain) / sizeof(*plain); ++i) {
        int n = snprintf(input, sizeof(input), good[0], plain[i]); extract(d, input, (size_t)n, plain[i]);
    }
    const char invalid[] = "-_+/. ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[10] = invalid[i];
        int n = snprintf(input, sizeof(input), good[0], changed); extract(d, input, (size_t)n, NULL);
    }
    const struct { const char *host; bool found; } hosts[] = {
        {"a.invoiceocean.com", true}, {"0.invoiceocean.com", true}, {"https://abc.invoiceocean.com", true},
        {"Hidden.invoiceocean.com", false}, {"hidden.InvoiceOcean.com", false}, {"hidden.invoiceocean.COM", false},
        {"_hidden.invoiceocean.com", false}, {"hidden.invoiceocean.com_", false}, {"hidden.invoiceocean.comX", false},
        {".invoiceocean.com", false}, {"left-right.invoiceocean.com", true}, {"hidden.invoiceocean.com.extra", true},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(*hosts); ++i) {
        int n = snprintf(input, sizeof(input), "invoiceocean %s\n%s", key_a, hosts[i].host);
        extract(d, input, (size_t)n, hosts[i].found ? key_a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "invoiceocean", 12); memset(input + 12, ':', gap); memcpy(input + 12 + gap, key_a, 20);
        size_t n = 32 + gap; memcpy(input + n, "\n", 1); memcpy(input + n + 1, host_a, sizeof(host_a));
        extract(d, input, n + sizeof(host_a), gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 12 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 12 + 2 * gap, key_a, 20); n = 32 + 2 * gap;
        input[n++] = '\n'; memcpy(input + n, host_a, sizeof(host_a));
        extract(d, input, n + sizeof(host_a) - 1, gap == 40 ? key_a : NULL);
    }
    memcpy(input, "invoiceocean\0", 13); memcpy(input + 13, key_a, 20); input[33] = '\n';
    memcpy(input + 34, host_a, sizeof(host_a)); extract(d, input, 34 + sizeof(host_a) - 1, key_a);
    int n = snprintf(input, sizeof(input), "invoiceocean %s %s\n%s", key_a, key_b, host_a);
    extract(d, input, (size_t)n, key_a); /* A consumed prefix is not reusable. */
    n = snprintf(input, sizeof(input), "invoiceocean %s", key_a);
    memset(input + n, ':', 3000); n += 3000; memcpy(input + n, host_a, sizeof(host_a));
    extract(d, input, (size_t)n + sizeof(host_a) - 1, key_a); /* No direct span cap. */
    extract(d, NULL, 0, NULL);
    puts("InvoiceOcean prefix/case/boundaries/host-required/binary input/span hint: 0 failures");
}

typedef struct {
    const char *const *keys, *const *hosts;
    size_t nkeys, nhosts;
    const char *agent;
    const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_type;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *s = http->user; size_t pair = http->calls - 1;
    CHECK(ctx == s->ctx && http->calls == http->releases + 1 && pair < s->nkeys * s->nhosts);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && request->detector_type == 689);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->agent));
    url_is(request->url, s->hosts[pair % s->nhosts], s->keys[pair / s->nhosts]);
    CHECK(!s->borrowed_url && !s->borrowed_type);
    /* Retain provider-original values only, never effective request/array/UA. */
    s->borrowed_url = request->url; s->borrowed_type = request->headers[0].value;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; request_script *s = http->user;
    if (s && s->borrowed_url) {
        size_t pair = http->calls - 1;
        url_is(s->borrowed_url, s->hosts[pair % s->nhosts], s->keys[pair / s->nhosts]);
        CHECK(!strcmp(s->borrowed_type, "application/json"));
        s->borrowed_url = s->borrowed_type = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void products_and_hidden_hosts(const br_detector *d)
{
    char input[5000];
    int n = snprintf(input, sizeof(input), "invoiceocean %s\n%s\ninvoiceocean %s\n%s\ninvoiceocean %s\n%s",
                     key_b, host_b, key_a, host_a, key_b, host_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key_b, key_a, key_b}, *hosts[] = {host_b, host_a, host_a};
    request_script s = {.keys = keys, .hosts = hosts, .nkeys = 3, .nhosts = 3, .agent = "TruffleHog invoiceocean-offline"};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 299, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "invoiceocean-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, pass != 0, input, (size_t)n);
        CHECK(out.len == 9 && http.calls == (pass ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < out.len; ++i) finding_is(&out.items[i], keys[i / 3], pass != 0);
        CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts);
        br_results_clear(&out);
    }
    char long_host[1500]; memset(long_host, 'a', 1300); memcpy(long_host + 1300, ".invoiceocean.com", sizeof(".invoiceocean.com"));
    const char *special[] = {long_host, "right.invoiceocean.com", "hiddena.invoiceocean.com"};
    const char *source[] = {long_host, "left-right.invoiceocean.com", "hiddena.invoiceocean.com.extra"};
    s.keys = (const char *const[]){key_a}; s.nkeys = s.nhosts = 1;
    for (size_t i = 0; i < sizeof(source) / sizeof(*source); ++i) {
        s.hosts = &special[i]; http.calls = http.releases = 0; reset_observation();
        n = snprintf(input, sizeof(input), "invoiceocean %s\n%s", key_a, source[i]);
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); finding_is(&out.items[0], key_a, true);
        br_results_clear(&out);
    }
    puts("InvoiceOcean key-major products/duplicates/key-only metadata/unbounded literal host URLs/PUBLIC10: 0 failures");
}

static void status_and_do(const br_detector *d)
{
    char input[100]; int n = snprintf(input, sizeof(input), "invoiceocean %s\n%s", key_a, host_a);
    const char *keys[] = {key_a}, *hosts[] = {host_a};
    request_script s = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.user = &s, .inspect = inspect}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    static const unsigned char junk[] = {0xff, 0, '{'};
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 302, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {junk, sizeof(junk)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "synthetic read failure"};
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding_is(&out.items[0], key_a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "cannot allocate InvoiceOcean URL"},
        {-1, "cannot create InvoiceOcean finding"}, {1, "out of memory constructing HTTP headers"},
        {-1, "net/http: nil Context"}, {1, key_a}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body_error = "ignored on Do failure"};
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding_is(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("InvoiceOcean every-2xx/status-only/body-read ignored/whole mixed Do false-kept/no errors: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_and_constructor(const br_detector *d)
{
    char input[100]; int n = snprintf(input, sizeof(input), "invoiceocean %s\n%s", key_a, host_a);
    test_http http = {0}; br_transport transport = {&http, test_http_send, release_response};
    br_transport missing_send = {&http, NULL, release_response}; size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, (size_t)n);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && urls == 1 && url_frees == 1);
        finding_is(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, (size_t)n);
    CHECK(!out.len && findings == 1 && urls == 1 && url_frees == 1 && !sends && !releases && !pushes);
    br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1 && findings == 1 && !urls && !sends && pushes == 1);
    finding_is(&out.items[0], key_a, false); br_results_clear(&out);
    char *error = NULL; const br_transport *native = br_curl_transport_init(&error);
    CHECK(native && !error); br_scan_ctx native_ctx = {.transport = native};
    reset_observation(); out = test_scan(d, &native_ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && sends == 1 && releases == 1 && url_frees == 1);
    finding_is(&out.items[0], key_a, false); br_results_clear(&out); curl_global_cleanup();
    puts("InvoiceOcean setup/constructor URL-before-nil-drop/one release/native PUBLIC guard: 0 failures");
}

static void owned_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                          int send_rc, size_t attempts, bool no_error)
{
    char input[180]; int n = snprintf(input, sizeof(input), "invoiceocean %s\ninvoiceocean %s\n%s", key_a, key_b, host_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot create InvoiceOcean finding" : NULL,
        .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence; char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, (size_t)n}, &out,
                  no_error ? NULL : &error) == -1);
    const char *message = site == CAPTURE ? "synthetic capture failure" : site == FINDING ? "cannot create InvoiceOcean finding" :
                          site == URL ? "cannot allocate InvoiceOcean URL" : "cannot append InvoiceOcean finding";
    CHECK(no_error ? !error : error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls); br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    owned_failure(d, CAPTURE, 1, true, true, 0, 0, false);
    owned_failure(d, CAPTURE, 2, false, false, 0, 0, false);
    owned_failure(d, FINDING, 1, true, true, 0, 0, false);
    owned_failure(d, FINDING, 2, true, false, 0, 1, false);
    owned_failure(d, URL, 1, true, true, 0, 0, false);
    owned_failure(d, URL, 2, true, false, 1, 1, false);
    owned_failure(d, PUSH, 2, true, false, 0, 2, false);
    owned_failure(d, PUSH, 2, true, false, -7, 2, false);
    owned_failure(d, PUSH, 2, false, true, 0, 0, true);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !urls && !sends);
    puts("InvoiceOcean owned nonzero failures/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 20 && strlen(key_b) == 20);
    const br_detector *d = descriptor(br_invoiceocean_init);
    grammar(d); products_and_hidden_hosts(d); status_and_do(d);
    const br_detector *observed = descriptor(observed_invoiceocean_init);
    products_and_hidden_hosts(observed); status_and_do(observed);
    setup_and_constructor(observed); owned_resources(observed);
    CHECK(!original_request && !original_url && fault == NONE);
    return test_finish("InvoiceOcean ABI1 focused checks");
}
