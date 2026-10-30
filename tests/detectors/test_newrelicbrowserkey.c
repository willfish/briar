/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error browser_real_setter
#define br_results_push browser_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newrelicbrowserkey_init(const br_detector **out, char **error);

static int checked_snprintf(char *, size_t, const char *, ...);
static int browser_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send browser_seam_send
#define br_newrelicbrowserkey_init observed_browser_init
#include "../../src/detectors/newrelicbrowserkey.c"
#undef snprintf
#undef br_http_send
#undef br_newrelicbrowserkey_init

static const char key[] = "NRBR-0123456789abcdef012";
static const char other[] = "NRBR-aaaaaaaaaaaaaaaaaaa";
static const char description[] =
    "A New Relic Browser API key is used to authenticate and enable browser monitoring, allowing New Relic to collect performance data, page views, and user interactions from web applications to track and optimize front-end performance.";
static const char us_prefix[] = "https://bam.nr-data.net/1/";
static const char eu_prefix[] = "https://bam.eu01.nr-data.net/1/";
static size_t fail_key_after, fail_region_after, fail_push_after, fail_setter_after, setter_calls, seen_secrets;
static size_t setters_before_format, null_send_setters_before;
static bool format_before_release, null_send_cause, setter_saw_null;
static int fail_format;
static test_http *null_send_http;
static const char *seam_url;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    if (!strcmp(name, "region") && fail_region_after && --fail_region_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    (void)secrets;
    ++setter_calls;
    setter_saw_null = cause == NULL;
    seen_secrets = count;
    if (fail_setter_after && --fail_setter_after == 0) {
        if (null_send_cause) {
            CHECK(null_send_http && null_send_http->releases == 2);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return browser_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return browser_real_push(out, owned);
}

static void result_is(const br_result *result, const char *expected, const char *region,
                      bool verified, const char *cause)
{
    char shown[12];
    memcpy(shown, expected, 8);
    memcpy(shown + 8, "...", 4);
    CHECK(result->detector_type == 1065 && !result->detector_name);
    CHECK(result->raw.len == 24 && !memcmp(result->raw.data, expected, 24));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && result->verified == verified);
    CHECK(result->redacted && !strcmp(result->redacted, shown));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause)
               : !result->verification_error);
    CHECK(result->secret_parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 24 && !memcmp(json_object_get_string(part), expected, 24));
    if (region) {
        CHECK(json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
    } else {
        CHECK(json_object_object_length(result->secret_parts) == 1);
        CHECK(!json_object_object_get_ex(result->secret_parts, "region", &part));
        CHECK(!result->extra_data);
    }
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 25 && sizeof(other) == 25);
    CHECK(br_newrelicbrowserkey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicBrowserKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_newrelicbrowserkey_init(NULL, NULL) == -1);
    CHECK(br_newrelicbrowserkey_init(&d, &error) == 0 && d && !error);
    CHECK(br_newrelicbrowserkey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1065 && d->version == 0 && !strcmp(d->name, "NewRelicBrowserKey"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->description[strlen(d->description) - 1] == '.');
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nrbr-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, text, len);
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[160];
    int n = snprintf(input, sizeof(input), "%s %s %s", key, key, other);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 3 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], key, NULL, false, NULL);
    result_is(&out.items[1], key, NULL, false, NULL);
    result_is(&out.items[2], other, NULL, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    CHECK(out.items[0].redacted != out.items[1].redacted);
    br_results_clear(&out);

    out = test_scan(d, &ctx, false, key, 24);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, NULL, false, NULL);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "x%s", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%sx", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "NRBR-0123456789abcdef01");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "NRBR-0123456789abcdef0123");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "nrbr-0123456789abcdef012");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "NRBR-0123456789ABCDEF012");
    expect_none(d, input, (size_t)n);
    expect_none(d, "nrbr-", 5);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

typedef struct {
    const char *borrowed_url;
    char expect_url[80];
    int status, send_rc;
    const char *send_error, *body_error;
    bool order_us_eu, status_set[2], send_set[2];
    int statuses[2], send_rcs[2];
    const char *send_errors[2];
} script;

static void expect_url(const char *url, size_t call)
{
    const char *prefix = call == 1 ? us_prefix : eu_prefix;
    char want[80];
    int n = snprintf(want, sizeof(want), "%s%s", prefix, key);
    CHECK(n > 0 && url && !strcmp(url, want) && !strchr(url, '?'));
}

static void remember_url(script *s, const br_http_request *request, bool us, const char *token)
{
    const char *prefix = us ? us_prefix : eu_prefix;
    int n = snprintf(s->expect_url, sizeof(s->expect_url), "%s%s", prefix, token);
    CHECK(n > 0 && (size_t)n < sizeof(s->expect_url));
    CHECK(request->url && !strcmp(request->url, s->expect_url) && !strchr(request->url, '?'));
    s->borrowed_url = request->url;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    CHECK(ctx && http->calls == http->releases + 1 && http->calls <= 2);
    remember_url(s, request, !s->order_us_eu || http->calls == 1,
                 s->order_us_eu || http->calls == 1 ? key : other);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1065);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog browser-offline"));
    size_t at = http->calls - 1;
    int status = s->status_set[at] ? s->statuses[at] : s->status;
    static const unsigned char body[] = {0xff, 0, '{'};
    http->response = (br_http_response){
        .status = status, .body = {body, sizeof(body)}, .body_error = s->body_error,
    };
    http->send_rc = s->send_set[at] ? s->send_rcs[at] : s->send_rc;
    http->send_error = s->send_set[at] ? s->send_errors[at] : s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (null_send_cause) {
        CHECK(setter_calls == null_send_setters_before);
        expect_url(seam_url, http->releases + 1);
        seam_url = NULL;
    }
    if (format_before_release)
        CHECK(!fail_format && setter_calls == setters_before_format);
    if (s && s->borrowed_url) {
        CHECK(s->expect_url[0] && !strcmp(s->borrowed_url, s->expect_url));
        s->borrowed_url = NULL;
    }
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.status = 400, .order_us_eu = true};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "browser-offline"};
    size_t before = setter_calls;
    s.body_error = "ignored copy error";
    br_results out = test_scan(d, &ctx, true, key, 24);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_url);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, "us", true, NULL);
    br_results_clear(&out);

    s.body_error = NULL;
    s.status_set[0] = true;
    s.statuses[0] = 403;
    s.status_set[1] = true;
    s.statuses[1] = 400;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 24);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !s.borrowed_url);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, "eu", true, NULL);
    br_results_clear(&out);

    s.statuses[1] = 403;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 24);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, NULL, false, NULL);
    br_results_clear(&out);

    s.statuses[0] = 500;
    s.statuses[1] = 403;
    s.body_error = "ignored copy error";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 24);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !setter_saw_null);
    result_is(&out.items[0], key, NULL, false, "error verifying region us: unexpected status code: 500");
    CHECK(!strchr(out.items[0].verification_error, '\n'));
    CHECK(strcmp(out.items[0].verification_error, "ignored copy error") != 0);
    br_results_clear(&out);

    s.statuses[1] = 401;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 24);
    const char *joined =
        "error verifying region us: unexpected status code: 500\n"
        "error verifying region eu: unexpected status code: 401";
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    result_is(&out.items[0], key, NULL, false, joined);
    CHECK(out.items[0].verification_error[strlen(out.items[0].verification_error) - 1] != '\n');
    br_results_clear(&out);

    s.statuses[0] = 500;
    s.statuses[1] = 400;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 24);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == before + 1 && setter_saw_null);
    result_is(&out.items[0], key, "eu", true, NULL);
    br_results_clear(&out);

    char rejected[64];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", key) > 0);
    s.statuses[0] = 400;
    s.statuses[1] = 403;
    s.send_set[0] = true;
    s.send_rcs[0] = -1;
    s.send_errors[0] = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 24);
    char wrapped[96];
    CHECK(snprintf(wrapped, sizeof(wrapped), "error verifying region us: error making request: %s", rejected) > 0);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !seen_secrets && !setter_saw_null);
    result_is(&out.items[0], key, NULL, false, wrapped);
    CHECK(strstr(out.items[0].verification_error, key) != NULL);
    CHECK(!strstr(out.items[0].verification_error, "[REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "browser-offline", .cancelled = cancelled};
    s.send_set[0] = false;
    s.send_error = NULL;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, key, 24);
    const char *cancelled_cause =
        "error verifying region us: error making request: context canceled\n"
        "error verifying region eu: error making request: context canceled";
    CHECK(out.len == 1 && !http.calls && http.releases == 2 && !seen_secrets);
    result_is(&out.items[0], key, NULL, false, cancelled_cause);
    br_results_clear(&out);

    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, NULL, true, key, 24);
    const char *nil_cause =
        "error verifying region us: error constructing request: net/http: nil Context\n"
        "error verifying region eu: error constructing request: net/http: nil Context";
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == before + 1 && !seen_secrets);
    result_is(&out.items[0], key, NULL, false, nil_cause);
    br_results_clear(&out);

    before = setter_calls;
    out = test_scan(d, NULL, false, other, 24);
    CHECK(out.len == 1 && setter_calls == before && !http.calls);
    result_is(&out.items[0], other, NULL, false, NULL);
    br_results_clear(&out);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(out->items[0].verified && !strcmp(out->items[0].verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char text[80];
    int n = snprintf(text, sizeof(text), "%s %s", key, other);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.status = 400};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "browser-offline"};
    char *error = NULL;
    size_t setters = setter_calls;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicBrowserKey finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicBrowserKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_region_after = 1;
    http.calls = http.releases = 0;
    setters = setter_calls;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicBrowserKey region") && !fail_region_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicBrowserKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_url);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
}

static int browser_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                             br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    seam_url = request ? request->url : NULL;
    if (response) memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    return -1;
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && format && !strcmp(format, "unexpected status code: %d")) {
        int rc = fail_format;
        fail_format = 0;
        return rc;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, n, format, args);
    va_end(args);
    return rc;
}

static void format_and_null_send(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_browser_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_newrelicbrowserkey_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    script s = {.status = 500};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "browser-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_url = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)key, 24}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format NewRelicBrowserKey verification status") && !fail_format);
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_url);
        CHECK(setter_calls == setters_before_format);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    format_before_release = false;

    null_send_cause = true;
    null_send_http = &http;
    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results sent = test_scan(observed, &ctx, true, key, 24);
    CHECK(sent.len == 1 && !http.calls && http.releases == 2 && !seam_url);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    result_is(&sent.items[0], key, NULL, false, NULL);
    CHECK(!sent.items[0].verification_error || !strstr(sent.items[0].verification_error, "HTTP transport failed"));
    br_results_clear(&sent);

    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)key, 24}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicBrowserKey verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 2 && !seam_url);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    prior_unchanged(&out, &prior);
    free(error);
    null_send_cause = false;
    null_send_http = NULL;
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    format_and_null_send();
    return test_finish("NewRelicBrowserKey");
}
