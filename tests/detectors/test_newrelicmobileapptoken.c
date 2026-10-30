/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error mobile_real_setter
#define br_results_push mobile_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newrelicmobileapptoken_init(const br_detector **out, char **error);

static int checked_snprintf(char *, size_t, const char *, ...);
static int mobile_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send mobile_seam_send
#define br_newrelicmobileapptoken_init observed_mobile_init
#include "../../src/detectors/newrelicmobileapptoken.c"
#undef snprintf
#undef br_http_send
#undef br_newrelicmobileapptoken_init

static const char us[] = "AA0123456789abcdef0123456789abcdef01234567-NRMA";
static const char eu[] = "eu01xx0123456789abcdef0123456789abcdef0123-NRMA";
static const char description[] =
    "A New Relic Mobile App Token is an authentication key used to send mobile application telemetry data (such as performance metrics, crashes, and events) from iOS and Android apps to New Relic for monitoring and analysis. It is specific to each mobile app and ensures secure data ingestion.";
static const char us_url[] = "https://mobile-collector.newrelic.com/mobile/v5/connect";
static const char eu_url[] = "https://mobile-collector.eu01.nr-data.net/mobile/v5/connect";
static size_t fail_key_after, fail_region_after, fail_push_after, fail_setter_after, setter_calls, seen_secrets;
static size_t setters_before_format, null_send_setters_before;
static bool format_before_release, null_send_cause, setter_saw_null;
static int fail_format;
static test_http *null_send_http;
static const char *seam_header, *seam_key;

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
    return mobile_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return mobile_real_push(out, owned);
}

static void result_is(const br_result *result, const char *key, const char *region,
                      bool verified, const char *cause)
{
    char shown[12];
    memcpy(shown, key, 8);
    memcpy(shown + 8, "...", 4);
    CHECK(result->detector_type == 1068 && !result->detector_name);
    CHECK(result->raw.len == 47 && !memcmp(result->raw.data, key, 47));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && result->verified == verified);
    CHECK(result->redacted && !strcmp(result->redacted, shown));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause)
               : !result->verification_error);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 47 && !memcmp(json_object_get_string(part), key, 47));
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
    CHECK(BR_ABI_REVISION == 1 && sizeof(us) == 48 && sizeof(eu) == 48);
    CHECK(br_newrelicmobileapptoken_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicMobileAppToken detector output"));
    free(error);
    error = NULL;
    CHECK(br_newrelicmobileapptoken_init(NULL, NULL) == -1);
    CHECK(br_newrelicmobileapptoken_init(&d, &error) == 0 && d && !error);
    CHECK(br_newrelicmobileapptoken_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1068 && d->version == 0 && !strcmp(d->name, "NewRelicMobileAppToken"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->description[strlen(d->description) - 1] == '.');
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "-nrma"));
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
    char input[240];
    int n = snprintf(input, sizeof(input), "%s %s %s", us, us, eu);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 3 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], us, "us", false, NULL);
    result_is(&out.items[1], us, "us", false, NULL);
    result_is(&out.items[2], eu, "eu", false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    CHECK(out.items[0].redacted != out.items[1].redacted);
    br_results_clear(&out);

    out = test_scan(d, &ctx, false, us, 47);
    CHECK(out.len == 1);
    result_is(&out.items[0], us, "us", false, NULL);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "x%s", us);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%sx", us);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "AA0123456789abcdef0123456789abcdef0123456-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "AA0123456789abcdef0123456789abcdef012345678-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "aa0123456789abcdef0123456789abcdef01234567-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "AA0123456789ABCDEF0123456789abcdef01234567-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "eu01xx0123456789abcdef0123456789abcdef012-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "EU01XX0123456789abcdef0123456789abcdef0123-NRMA");
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%s-nrma", "AA0123456789abcdef0123456789abcdef01234567");
    expect_none(d, input, (size_t)n);
    expect_none(d, "-nrma", 5);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

typedef struct {
    const char *keys[2];
    const char *borrowed_key;
    int status, send_rc;
    const char *send_error, *body_error;
    bool status_set[2];
    int statuses[2];
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
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1068);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-App-License-Key") && !strcmp(request->headers[1].value, want));
    CHECK(!strstr(request->headers[1].value, "..."));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog mobile-offline"));
    s->borrowed_key = request->headers[1].value;
    int status = s->status_set[http->calls - 1] ? s->statuses[http->calls - 1] : s->status;
    static const unsigned char body[] = {0xff, 0, '{'};
    http->response = (br_http_response){
        .status = status, .body = {body, sizeof(body)}, .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (null_send_cause)
        CHECK(setter_calls == null_send_setters_before);
    if (format_before_release && http->releases == 1)
        CHECK(!fail_format && setter_calls == setters_before_format + 1);
    if (seam_header) {
        CHECK(seam_key && !strcmp(seam_header, seam_key));
        seam_header = NULL;
    }
    if (s->borrowed_key) {
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
    script s = {.keys = {us}, .status = 400};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mobile-offline"};
    const int statuses[] = {0, 200, 400, 401, 402, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s.status = statuses[i];
        s.body_error = "ignored copy error";
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        size_t before = setter_calls;
        br_results out = test_scan(d, &ctx, true, us, 47);
        char want[64];
        const char *cause = NULL;
        if (statuses[i] != 400 && statuses[i] != 401) {
            CHECK(snprintf(want, sizeof(want), "unexpected status code: %d", statuses[i]) > 0);
            cause = want;
        }
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_key);
        CHECK(setter_calls == before + 1 && !seen_secrets && setter_saw_null == (cause == NULL));
        result_is(&out.items[0], us, "us", statuses[i] == 400, cause);
        if (cause) CHECK(strcmp(out.items[0].verification_error, "ignored copy error") != 0);
        br_results_clear(&out);
    }

    char rejected[80];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", us) == 56);
    s.status = 400;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, us, 47);
    char wrapped[96];
    CHECK(snprintf(wrapped, sizeof(wrapped), "error making request: %s", rejected) > 0);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !seen_secrets && !setter_saw_null);
    result_is(&out.items[0], us, "us", false, wrapped);
    CHECK(strstr(out.items[0].verification_error, us) != NULL);
    CHECK(!strstr(out.items[0].verification_error, "[REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "mobile-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, us, 47);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !seen_secrets);
    result_is(&out.items[0], us, "us", false, "error making request: context canceled");
    br_results_clear(&out);

    char pair[120];
    int n = snprintf(pair, sizeof(pair), "%s %s", us, us);
    s.keys[0] = us;
    s.keys[1] = us;
    s.status = 400;
    s.body_error = "ignored copy error";
    http.calls = http.releases = 0;
    size_t before = setter_calls;
    out = test_scan(d, &ctx, true, pair, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    CHECK(setter_calls == before + 2 && !seen_secrets);
    result_is(&out.items[0], us, "us", true, NULL);
    result_is(&out.items[1], us, "us", true, NULL);
    br_results_clear(&out);

    n = snprintf(pair, sizeof(pair), "%s %s", us, eu);
    s.keys[1] = eu;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, pair, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    CHECK(setter_calls == before + 2 && !seen_secrets);
    result_is(&out.items[0], us, "us", true, NULL);
    result_is(&out.items[1], eu, "eu", true, NULL);
    br_results_clear(&out);

    s.keys[1] = NULL;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, NULL, true, eu, 47);
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == before + 1 && !seen_secrets);
    result_is(&out.items[0], eu, "eu", false, "error constructing request: net/http: nil Context");
    br_results_clear(&out);

    before = setter_calls;
    out = test_scan(d, NULL, false, eu, 47);
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
    char text[120];
    int n = snprintf(text, sizeof(text), "%s %s", us, eu);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.keys = {us, eu}, .status = 400};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mobile-offline"};
    char *error = NULL;
    size_t setters = setter_calls;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicMobileAppToken finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_region_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicMobileAppToken region") && !fail_region_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicMobileAppToken verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicMobileAppToken verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
}

static int mobile_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                            br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    /* Bypass the shared helper, which would invent "HTTP transport failed". */
    seam_header = request && request->nheaders > 1 ? request->headers[1].value : NULL;
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
    CHECK(observed_mobile_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_newrelicmobileapptoken_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char text[120];
    int n = snprintf(text, sizeof(text), "%s %s", us, eu);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.keys = {us, eu}, .status = 400, .body_error = "ignored copy error"};
    s.status_set[1] = true;
    s.statuses[1] = 500;
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mobile-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_key = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format NewRelicMobileAppToken verification status") && !fail_format);
        CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_key);
        CHECK(setter_calls == setters_before_format + 1);
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
    CHECK(observed_mobile_init(&observed, &error) == 0 && observed && !error);
    script s = {.keys = {us}};
    test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mobile-offline"};
    null_send_cause = true;
    null_send_http = &http;
    seam_key = us;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results out = test_scan(observed, &ctx, true, us, 47);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !seam_header);
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
    seam_key = us;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)us, 47}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicMobileAppToken verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 1 && !seam_header);
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
    return test_finish("NewRelicMobileAppToken");
}
