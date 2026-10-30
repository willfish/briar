/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <stdarg.h>

int br_qubole_init(const br_detector **out, char **error);

static int fail_push_on, push_calls, setter_calls, release_count;
static const char *setter_cause;
static size_t setter_secrets;

static int (*real_set)(br_result *, const char *, const br_slice *, size_t) = br_result_set_verification_error;
static void (*real_release)(const br_scan_ctx *, br_http_response *) = br_http_release;

static int observe_set(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_cause = cause;
    setter_secrets = nsecrets;
    return real_set(result, cause, secrets, nsecrets);
}

static void observe_release(const br_scan_ctx *ctx, br_http_response *response)
{
    ++release_count;
    real_release(ctx, response);
}

static int push_hook(br_results *out, br_result *owned)
{
    ++push_calls;
    if (fail_push_on && push_calls == fail_push_on) return 1;
    return br_results_push(out, owned);
}

#define br_result_set_verification_error observe_set
#define br_http_release observe_release
#define br_results_push push_hook
#include "../../src/detectors/qubole.c"
#undef br_results_push
#undef br_http_release
#undef br_result_set_verification_error

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char other[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

static void reset_hooks(void)
{
    fail_push_on = push_calls = setter_calls = release_count = 0;
    setter_cause = NULL;
    setter_secrets = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64);
    CHECK(br_qubole_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Qubole detector output"));
    free(error);
    error = NULL;
    CHECK(br_qubole_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_qubole_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 577 && detector->version == 0 && !strcmp(detector->name, "Qubole"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Qubole is a cloud-based data platform that provides data processing, management, and analytics services. Qubole API keys can be used to access and manage data workflows and resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "qubole"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

typedef struct {
    test_http http;
    const char *expect;
    int status;
    const char *send_error;
    int send_rc;
} probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    probe *p = http->user;
    CHECK(ctx && request && p);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://us.qubole.com/api/v1.2/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 577);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "X-AUTH-TOKEN") &&
          (!strcmp(request->headers[2].value, p->expect) || !strcmp(request->headers[2].value, other)));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog"));
    http->response.status = p->status;
    http->send_error = p->send_error;
    http->send_rc = p->send_rc;
}

static int probe_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    return test_http_send(&((probe *)user)->http, ctx, request, response, error);
}

static void probe_release(void *user, br_http_response *response)
{
    test_http_release(&((probe *)user)->http, response);
}

static br_results scan_probe(const br_detector *detector, const char *input, bool verify, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, probe_send, probe_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, verify, input, strlen(input));
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "qubole '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !setter_calls && !release_count);
    test_key_result(&results.items[0], 577, key, "key");
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "QUBOLE=%s\nqubole %s\nqubole %s", key, key, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    test_key_result(&results.items[0], 577, key, "key");
    test_key_result(&results.items[1], 577, key, "key");
    test_key_result(&results.items[2], 577, other, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    char window[160];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(window, "qubole", 6);
        memset(window + 6, '.', gap);
        memcpy(window + 6 + gap, key, 65);
        results = test_scan(detector, NULL, false, window, 6 + gap + 64);
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        if (gap == 40) test_key_result(&results.items[0], 577, key, "key");
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "qubole %sA", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "qubole %c%s", 'A', key + 1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "qubole %s", key);
    const struct { int status; int rc; const char *send; bool verified; const char *cause; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "no such host", false, "no such host"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_hooks();
        probe p = {.expect = key, .status = cases[i].status, .send_rc = cases[i].rc, .send_error = cases[i].send};
        br_results results = scan_probe(detector, input, true, &p);
        CHECK(results.len == 1 && p.http.calls == 1 && p.http.releases == 1 && release_count == 1);
        test_key_result(&results.items[0], 577, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (!results.items[0].verification_error && cases[i].cause) {
            fprintf(stderr, "case %zu missing error, want %s\n", i, cases[i].cause);
            CHECK(0);
        }
        if (results.items[0].verification_error && (!cases[i].cause || strcmp(results.items[0].verification_error, cases[i].cause))) {
            fprintf(stderr, "case %zu error %s\n", i, results.items[0].verification_error);
            CHECK(0);
        }
        CHECK(setter_calls == 1 && setter_secrets == 1);
        CHECK((cases[i].cause == NULL) == (setter_cause == NULL));
        br_results_clear(&results);
    }
    reset_hooks();
    br_results dropped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(dropped.len == 1 && setter_calls == 1 && !release_count);
    test_key_result(&dropped.items[0], 577, key, "key");
    CHECK(!dropped.items[0].verified && dropped.items[0].verification_error &&
          !strcmp(dropped.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&dropped);
}

static void rollback_and_prior(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "qubole %s qubole %s", key, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    reset_hooks();
    fail_push_on = 2;
    char *error = NULL;
    probe p = {.expect = key, .status = 200};
    p.http.inspect = inspect;
    p.http.user = &p;
    br_transport transport = {&p, probe_send, probe_release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Qubole finding"));
    free(error);
    CHECK(results.len == 1 && results.items[0].raw.len == 5);
    CHECK(!memcmp(results.items[0].raw.data, "prior", 5));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback_and_prior(detector);
    return test_finish("qubole");
}
