/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error license_real_setter
#define br_results_push license_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newreliclicensekey_init(const br_detector **out, char **error);

static int checked_snprintf(char *, size_t, const char *, ...);
static int license_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send license_seam_send
#define br_newreliclicensekey_init observed_license_init
#include "../../src/detectors/newreliclicensekey.c"
#undef snprintf
#undef br_http_send
#undef br_newreliclicensekey_init

static const char us[] = "0123456789abcdef0123456789abcdefFFFFNRAL";
static const char eu[] = "eu01xx0123456789abcdef0123456789FFFFNRAL";
static const char description[] =
    "New Relic license keys are unique authentication tokens used to send telemetry data (metrics, logs, and traces) from your applications and infrastructure to New Relic.";
static const char us_url[] = "https://metric-api.newrelic.com/metric/v1";
static const char eu_url[] = "https://metric-api.eu.newrelic.com/metric/v1";
static size_t fail_key_after, fail_region_after, fail_push_after, fail_setter_after, setter_calls, seen_secrets;
static size_t setters_at_send, setters_before_format, null_send_setters_before;
static bool request_alive, format_before_release, null_send_cause, setter_saw_null;
static int fail_format;
static test_http *null_send_http;
static const char *alive_url, *alive_key, *seam_url, *seam_key;

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
            CHECK(null_send_http && null_send_http->releases == 1);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return license_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return license_real_push(out, owned);
}

static void result_is(const br_result *result, const char *key, const char *region,
                      bool verified, const char *cause)
{
    char shown[12];
    memcpy(shown, key, 8);
    memcpy(shown + 8, "...", 4);
    CHECK(result->detector_type == 1064 && !result->detector_name);
    CHECK(result->raw.len == 40 && !memcmp(result->raw.data, key, 40));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && result->verified == verified);
    CHECK(result->redacted && !strcmp(result->redacted, shown));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause)
               : !result->verification_error);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 40 && !memcmp(json_object_get_string(part), key, 40));
    CHECK(json_object_object_get_ex(result->secret_parts, "region", &part));
    CHECK(!strcmp(json_object_get_string(part), region));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "region", &part));
    CHECK(!strcmp(json_object_get_string(part), region));
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(us) == 41 && sizeof(eu) == 41);
    CHECK(br_newreliclicensekey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicLicenseKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_newreliclicensekey_init(NULL, NULL) == -1);
    CHECK(br_newreliclicensekey_init(&d, &error) == 0 && d && !error);
    CHECK(br_newreliclicensekey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1064 && d->version == 0 && !strcmp(d->name, "NewRelicLicenseKey"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ffffnral"));
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
    char input[320];
    int n = snprintf(input, sizeof(input), "%s %s %s", us, us, eu);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 3 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], us, "us", false, NULL);
    result_is(&out.items[1], us, "us", false, NULL);
    result_is(&out.items[2], eu, "eu", false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    CHECK(out.items[0].redacted != out.items[1].redacted);
    br_results_clear(&out);

    memset(input, '.', 200);
    memcpy(input + 200, us, 40);
    out = test_scan(d, &ctx, false, input, 240);
    CHECK(out.len == 1);
    result_is(&out.items[0], us, "us", false, NULL);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "x%s", us);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%sx", us);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaFFFFNRAL");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "0123456789abcdef0123456789abcdefffffnral");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "0123456789ABCDEF0123456789abcdefFFFFNRAL");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "EU01XX0123456789abcdef0123456789FFFFNRAL");
    expect_none(d, input, (size_t)n);
    expect_none(d, "ffffnral", 8);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

typedef struct {
    const char *keys[2];
    const char *borrowed_key;
    int status, send_rc;
    const char *send_error, *body_error;
} script;

static const char *expected_key(const script *s, size_t call)
{
    return s->keys[1] && call == 2 ? s->keys[1] : s->keys[0];
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = expected_key(s, http->calls);
    const char *url = want && !memcmp(want, "eu01xx", 6) ? eu_url : us_url;
    CHECK(ctx && http->calls == http->releases + 1 && want);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1064);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Api-Key") && !strcmp(request->headers[1].value, want));
    CHECK(!strstr(request->headers[1].value, "..."));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog license-offline"));
    setters_at_send = setter_calls;
    alive_url = request->url;
    alive_key = request->headers[1].value;
    request_alive = true;
    s->borrowed_key = request->headers[1].value;
    static const unsigned char body[] = {0xff, 0, '{'};
    http->response = (br_http_response){
        .status = s->status, .body = {body, sizeof(body)}, .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (request_alive) {
        const char *want = expected_key(s, http->releases + 1);
        const char *url = want && !memcmp(want, "eu01xx", 6) ? eu_url : us_url;
        CHECK(setter_calls == setters_at_send);
        CHECK(alive_url && !strcmp(alive_url, url));
        CHECK(alive_key && want && !strcmp(alive_key, want));
        alive_url = alive_key = NULL;
        request_alive = false;
    }
    if (format_before_release) {
        CHECK(!fail_format && setter_calls == setters_before_format);
    }
    if (null_send_cause) {
        CHECK(setter_calls == null_send_setters_before);
        CHECK(seam_url && !strcmp(seam_url, us_url));
        CHECK(seam_key && !strcmp(seam_key, us));
        seam_url = seam_key = NULL;
    }
    if (s && s->borrowed_key) {
        CHECK(!strcmp(s->borrowed_key, expected_key(s, http->releases + 1)));
        s->borrowed_key = NULL;
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
    script s = {.keys = {us}, .status = 202};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "license-offline"};
    const int statuses[] = {199, 202, 403, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i];
        s.body_error = "ignored copy error";
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        size_t before = setter_calls;
        br_results out = test_scan(d, &ctx, true, us, 40);
        char want[48];
        const char *cause = NULL;
        if (statuses[i] != 202 && statuses[i] != 403) {
            CHECK(snprintf(want, sizeof(want), "unexpected status code: %d", statuses[i]) > 0);
            cause = want;
        }
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_key);
        CHECK(!request_alive && !alive_url && !alive_key);
        CHECK(setter_calls == before + 1 && !seen_secrets);
        CHECK(setter_saw_null == (statuses[i] == 202 || statuses[i] == 403));
        result_is(&out.items[0], us, "us", statuses[i] == 202, cause);
        br_results_clear(&out);
    }

    char rejected[96];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", us) == 49);
    s.status = 202;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, us, 40);
    char wrapped[112];
    CHECK(snprintf(wrapped, sizeof(wrapped), "error making request: %s", rejected) > 0);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !seen_secrets);
    result_is(&out.items[0], us, "us", false, wrapped);
    CHECK(strstr(out.items[0].verification_error, us) != NULL);
    CHECK(!strstr(out.items[0].verification_error, "[REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "license-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, us, 40);
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    result_is(&out.items[0], us, "us", false, "error making request: context canceled");
    br_results_clear(&out);

    char pair[96];
    int n = snprintf(pair, sizeof(pair), "%s %s", us, eu);
    s.keys[0] = us;
    s.keys[1] = eu;
    s.status = 202;
    s.body_error = "ignored copy error";
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    size_t before = setter_calls;
    out = test_scan(d, &ctx, true, pair, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    CHECK(setter_calls == before + 2 && !seen_secrets);
    result_is(&out.items[0], us, "us", true, NULL);
    result_is(&out.items[1], eu, "eu", true, NULL);
    br_results_clear(&out);

    s.keys[1] = NULL;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, NULL, true, us, 40);
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == before + 1 && !seen_secrets);
    CHECK(setter_saw_null == false);
    result_is(&out.items[0], us, "us", false, "error constructing request: net/http: nil Context");
    br_results_clear(&out);

    before = setter_calls;
    out = test_scan(d, NULL, false, eu, 40);
    CHECK(out.len == 1 && setter_calls == before && !http.calls);
    result_is(&out.items[0], eu, "eu", false, NULL);
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
    char text[96];
    int n = snprintf(text, sizeof(text), "%s %s", us, eu);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.keys = {us, eu}, .status = 202};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "license-offline"};
    char *error = NULL;
    size_t setters = setter_calls;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicLicenseKey finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_region_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicLicenseKey region") && !fail_region_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicLicenseKey verification error"));
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && !fail_setter_after);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicLicenseKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(http.calls == 1 && http.releases == 1);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
    CHECK(!fail_key_after && !fail_region_after && !fail_setter_after && !fail_push_after);
}

static int license_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                             br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    /* Bypass the shared helper, which would invent "HTTP transport failed". */
    seam_url = request ? request->url : NULL;
    seam_key = request && request->nheaders > 1 && request->headers ? request->headers[1].value : NULL;
    CHECK(request && !request->body.data && !request->body.len);
    CHECK(request->nheaders >= 2 && request->headers && !strcmp(request->headers[1].name, "Api-Key"));
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

static void format_failures(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_license_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_newreliclicensekey_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    script s = {.keys = {us}, .status = 500, .send_error = "leftover"};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "license-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_key = NULL;
        request_alive = false;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)us, 40}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format NewRelicLicenseKey verification status") && !fail_format);
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_key);
        CHECK(!request_alive && !alive_url && !alive_key);
        CHECK(setter_calls == setters_before_format);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    format_before_release = false;
    br_results_clear(&out);
}

static void null_send_cause_reaches_setter(void)
{
    const br_detector *observed = NULL;
    char *error = NULL;
    CHECK(observed_license_init(&observed, &error) == 0 && observed && !error);
    script s = {.keys = {us}};
    test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "license-offline"};
    null_send_cause = true;
    null_send_http = &http;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results out = test_scan(observed, &ctx, true, us, 40);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !seam_url && !seam_key);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], us, "us", false, NULL);
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)us, 40}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicLicenseKey verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 1 && !seam_url && !seam_key);
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
    format_failures();
    null_send_cause_reaches_setter();
    return test_finish("NewRelicLicenseKey");
}
