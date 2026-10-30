/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <stdarg.h>

int br_photoroom_init(const br_detector **out, char **error);

static int force_null_send, force_format_fail, setter_force_rc, fail_push_on, push_calls;
static int setter_calls, setter_after_release, release_before_setter, release_count, release_saw_clean;
static int setter_cause_was_null;
static const char *setter_cause;
static char setter_secret[96];
static size_t setter_secret_len;

static int (*real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *, char **) = br_http_send;
static void (*real_release)(const br_scan_ctx *, br_http_response *) = br_http_release;
static int (*real_set)(br_result *, const char *, const br_slice *, size_t) = br_result_set_verification_error;

static int injected_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    if (force_null_send) {
        force_null_send = 0;
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return real_send(ctx, request, response, error);
}

static void observe_release(const br_scan_ctx *ctx, br_http_response *response, br_result *result)
{
    release_saw_clean = result && !result->verified && !result->verification_error;
    CHECK(release_saw_clean);
    release_before_setter = 1;
    ++release_count;
    real_release(ctx, response);
}

static int observe_setter(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_cause = cause;
    setter_cause_was_null = cause == NULL;
    setter_secret_len = 0;
    if (nsecrets == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(setter_secret)) {
        memcpy(setter_secret, secrets[0].data, secrets[0].len);
        setter_secret[secrets[0].len] = '\0';
        setter_secret_len = secrets[0].len;
    }
    if (release_before_setter) {
        ++setter_after_release;
        release_before_setter = 0;
    }
    if (setter_force_rc) {
        int forced = setter_force_rc;
        setter_force_rc = 0;
        return forced;
    }
    return real_set(result, cause, secrets, nsecrets);
}

static int inject_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    if (force_format_fail) {
        force_format_fail = 0;
        return -1;
    }
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return n;
}

static int push_hook(br_results *out, br_result *owned)
{
    ++push_calls;
    if (fail_push_on && push_calls == fail_push_on) return 1;
    return br_results_push(out, owned);
}

#define snprintf inject_snprintf
#define br_http_send injected_send
#define br_http_release(ctx, response) observe_release(ctx, response, result)
#define br_result_set_verification_error observe_setter
#define br_results_push push_hook
#include "../../src/detectors/photoroom.c"
#undef br_results_push
#undef br_result_set_verification_error
#undef br_http_release
#undef br_http_send
#undef snprintf

static const char key[] = "sk_pr_mykey_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2";
static const char other[] = "sk_pr_mykey2_509b8c07454aca248a0a381b46e07f467b84c77d";

typedef struct {
    test_http http;
    br_results *live;
    const char *expect_key;
    const int *statuses;
    int status_at_release[4];
    size_t len_at_release[4];
    size_t nrelease;
    const char *url;
    const char *apikey;
} probe;

static br_slice text(const char *value)
{
    return (br_slice){(const unsigned char *)value, strlen(value)};
}

static void reset_hooks(void)
{
    force_null_send = force_format_fail = setter_force_rc = fail_push_on = 0;
    setter_calls = setter_after_release = release_before_setter = release_count = release_saw_clean = 0;
    push_calls = setter_cause_was_null = 0;
    setter_cause = NULL;
    setter_secret_len = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    probe *p = http->user;
    CHECK(ctx && request);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://image-api.photoroom.com/v1/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1038);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, p->expect_key));
    CHECK(strcmp(request->headers[0].name, "x-api-key") != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    p->url = request->url;
    p->apikey = request->headers[0].value;
    if (p->statuses) http->response.status = p->statuses[http->calls - 1];
}

static int probe_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    return test_http_send(&((probe *)user)->http, ctx, request, response, error);
}

static void probe_release(void *user, br_http_response *response)
{
    probe *p = user;
    CHECK(response && p->nrelease < 4);
    p->status_at_release[p->nrelease] = response->status;
    p->len_at_release[p->nrelease] = p->live ? p->live->len : 0;
    ++p->nrelease;
    ++p->http.releases;
    if (p->url) {
        CHECK(!strcmp(p->url, "https://image-api.photoroom.com/v1/account"));
        CHECK(p->apikey && !strcmp(p->apikey, p->expect_key));
    }
}

static void bind(probe *p, br_scan_ctx *ctx, br_transport *transport)
{
    p->http.inspect = inspect;
    p->http.user = p;
    p->http.calls = p->http.releases = p->nrelease = 0;
    *transport = (br_transport){p, probe_send, probe_release};
    ctx->transport = transport;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_photoroom_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Photoroom detector output"));
    free(error);
    error = NULL;
    CHECK(br_photoroom_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_photoroom_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1038 && detector->version == 0 && !strcmp(detector->name, "Photoroom"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Photoroom is an AI photo editing platform that provides a suite of tools and services for creating and enhancing images. "
                  "Photoroom API keys can be used to access these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "photoroom"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean);
    CHECK(strlen(key) == 52 && strlen(other) == 53);
    return detector;
}

static int seed(br_results *results)
{
    br_result prior = {0};
    br_slice raw = {(const unsigned char *)"prior", 5};
    if (br_finding_key_bytes(&prior, 1, raw, "key") != 0) return -1;
    return br_results_push(results, &prior);
}

static void extraction(const br_detector *detector)
{
    char input[320];
    snprintf(input, sizeof(input), "photoroom Key=%s", key);
    probe p = {0};
    br_transport transport = {0};
    br_scan_ctx ctx = {0};
    bind(&p, &ctx, &transport);
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !p.http.calls && !p.http.releases && !release_count);
    test_key_result(&results.items[0], 1038, key, "key");
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "photoroom Key=sandbox_%s", key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !p.http.calls);
    test_key_result(&results.items[0], 1038, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "photoroom sandbox_%s photoroom %s", key, key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1038, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "photoroom %s\nphotoroom %s\nphotoroom %s", key, other, key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && !p.http.calls && !p.http.releases);
    test_key_result(&results.items[0], 1038, key, "key");
    test_key_result(&results.items[1], 1038, other, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "photoroom Key=sk_pr_my_key_fa02df705055df9e4d159fe3bad0cf3bb8cd1dc2");
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "photoroom keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    char window[160];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(window, "photoroom", 9);
        memset(window + 9, '.', gap);
        memcpy(window + 9 + gap, key, strlen(key));
        results = test_scan(detector, &ctx, false, window, 9 + gap + strlen(key));
        CHECK(results.len == (gap == 40 ? 1 : 0));
        br_results_clear(&results);
    }
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "photoroom %s", key);
    static const unsigned char body[] = {'o', 'k'};
    const int ok = 200;
    reset_hooks();
    probe p = {.expect_key = key, .statuses = &ok,
               .http = {.response = {.body = {body, sizeof(body)}, .body_error = "ignored read"}}};
    br_transport transport = {0};
    br_scan_ctx ctx = {0};
    bind(&p, &ctx, &transport);
    br_results results = {0};
    CHECK(seed(&results) == 0);
    p.live = &results;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 2 && results.items[0].detector_type == 1);
    test_key_result(&results.items[1], 1038, key, "key");
    CHECK(results.items[1].verified && !results.items[1].verification_error);
    CHECK(p.http.calls == 1 && p.nrelease == 1 && release_count == 1);
    CHECK(p.len_at_release[0] == 1 && p.status_at_release[0] == 200);
    CHECK(setter_calls == 1 && setter_after_release == 1 && setter_cause_was_null);
    CHECK(setter_secret_len == strlen(key) && !memcmp(setter_secret, key, strlen(key)));
    br_results_clear(&results);

    const int quiet = 403;
    reset_hooks();
    p = (probe){.expect_key = key, .statuses = &quiet,
                .http = {.response = {.body = {body, sizeof(body)}, .body_error = "ignored read"}}};
    bind(&p, &ctx, &transport);
    results = (br_results){0};
    p.live = &results;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 1 && setter_after_release == 1 && setter_cause_was_null);
    CHECK(p.len_at_release[0] == 0);
    br_results_clear(&results);

    const int other_status[] = {401, 500};
    for (size_t i = 0; i < sizeof(other_status) / sizeof(other_status[0]); ++i) {
        const int status = other_status[i];
        char want[64];
        snprintf(want, sizeof(want), "unexpected HTTP response status %d", status);
        reset_hooks();
        p = (probe){.expect_key = key, .statuses = &status};
        bind(&p, &ctx, &transport);
        results = (br_results){0};
        p.live = &results;
        CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) == 0 && !error);
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, want));
        CHECK(setter_after_release == 1 && p.len_at_release[0] == 0);
        br_results_clear(&results);
    }

    char cause[96], redacted[96];
    snprintf(cause, sizeof(cause), "dial %s refused", key);
    snprintf(redacted, sizeof(redacted), "dial [REDACTED] refused");
    reset_hooks();
    p = (probe){.expect_key = key, .http = {.send_rc = 1, .send_error = cause}};
    bind(&p, &ctx, &transport);
    results = (br_results){0};
    p.live = &results;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, redacted));
    CHECK(setter_after_release == 1 && release_count == 1 && p.len_at_release[0] == 0);
    br_results_clear(&results);

    reset_hooks();
    force_null_send = 1;
    p = (probe){.expect_key = key};
    bind(&p, &ctx, &transport);
    results = (br_results){0};
    p.live = &results;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 1 && setter_cause_was_null && setter_after_release == 1);
    CHECK(release_count == 1 && p.http.calls == 0);
    CHECK(setter_secret_len == strlen(key) && !memcmp(setter_secret, key, strlen(key)));
    br_results_clear(&results);

    reset_hooks();
    results = (br_results){0};
    CHECK(seed(&results) == 0);
    CHECK(detector->scan(detector, NULL, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 2 && results.items[0].detector_type == 1);
    CHECK(!results.items[1].verified);
    CHECK(results.items[1].verification_error && !strcmp(results.items[1].verification_error, "net/http: nil Context"));
    CHECK(setter_calls == 1 && release_count == 0 && !setter_after_release);
    br_results_clear(&results);

    reset_hooks();
    br_scan_ctx empty = {0};
    results = (br_results){0};
    CHECK(detector->scan(detector, &empty, true, text(input), &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    CHECK(release_count == 1 && setter_after_release == 1);
    br_results_clear(&results);
}

static void fatal_paths(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "photoroom %s", key);
    const int status = 401;
    reset_hooks();
    force_format_fail = 1;
    probe p = {.expect_key = key, .statuses = &status};
    br_transport transport = {0};
    br_scan_ctx ctx = {0};
    bind(&p, &ctx, &transport);
    br_results results = {0};
    CHECK(seed(&results) == 0);
    p.live = &results;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot format Photoroom verification status"));
    free(error);
    CHECK(results.len == 1 && results.items[0].detector_type == 1);
    CHECK(release_count == 1 && setter_calls == 0 && p.nrelease == 1);
    br_results_clear(&results);

    reset_hooks();
    fail_push_on = 1;
    p = (probe){.expect_key = key, .statuses = &status};
    bind(&p, &ctx, &transport);
    results = (br_results){0};
    CHECK(seed(&results) == 0);
    p.live = &results;
    CHECK(detector->scan(detector, &ctx, true, text(input), &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Photoroom finding"));
    free(error);
    CHECK(results.len == 1 && results.items[0].detector_type == 1);
    CHECK(release_count == 1 && setter_calls == 1 && setter_after_release == 1);
    br_results_clear(&results);
    fail_push_on = 0;
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    fatal_paths(detector);
    return test_finish("Photoroom");
}
