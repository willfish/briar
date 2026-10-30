/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error query_real_setter
#define br_results_push query_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newrelicinsightsquerykey_init(const br_detector **out, char **error);

static int checked_snprintf(char *, size_t, const char *, ...);
static int query_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send query_seam_send
#define br_newrelicinsightsquerykey_init observed_query_init
#include "../../src/detectors/newrelicinsightsquerykey.c"
#undef snprintf
#undef br_http_send
#undef br_newrelicinsightsquerykey_init

static const char key[] = "NRIQ-Xc_V8HruIZ271_l9FQm-_nJ7_";
static const char other[] = "NRIQ-aaaaaaaaaaaaaaaaaaaaaaaaa";
static const char account[] = "7746934";
static const char second_account[] = "1001";
static const char description[] =
    "A New Relic Insights Query Key is a read-only API key used to execute NRQL queries against your account's event data via the legacy Insights Query API. It allows secure retrieval of analytics data without permitting any data ingestion or modification.";
static const char us_head[] = "https://insights-api.newrelic.com/v1/accounts/";
static const char eu_head[] = "https://insights-api.eu.newrelic.com/v1/accounts/";
static size_t fail_key_after, fail_account_after, fail_region_after, fail_push_after, fail_setter_after;
static size_t setter_calls, seen_secrets, setters_before_format, null_send_setters_before;
static bool format_before_release, null_send_cause, setter_saw_null;
static int fail_format;
static test_http *null_send_http;
static const char *seam_url, *seam_key;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    if (!strcmp(name, "account_id") && fail_account_after && --fail_account_after == 0) return 1;
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
    if (r->verified) {
        br_json *part = NULL;
        CHECK(r->extra_data && json_object_object_get_ex(r->extra_data, "region", &part));
        CHECK(part && json_object_get_string(part) && json_object_get_string(part)[0]);
        CHECK(r->secret_parts && json_object_object_get_ex(r->secret_parts, "region", &part));
        CHECK(part && json_object_get_string(part) && json_object_get_string(part)[0]);
    }
    if (fail_setter_after && --fail_setter_after == 0) {
        if (null_send_cause) {
            CHECK(null_send_http && null_send_http->releases == 2);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return query_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return query_real_push(out, owned);
}

static void result_is(const br_result *result, const char *expected, const char *id,
                      const char *region, bool verified, const char *cause)
{
    char shown[12], raw_v2[48];
    memcpy(shown, expected, 8);
    memcpy(shown + 8, "...", 4);
    int n = snprintf(raw_v2, sizeof(raw_v2), "%s%s", expected, id);
    CHECK(n == 30 + (int)strlen(id));
    CHECK(result->detector_type == 1067 && !result->detector_name);
    CHECK(result->raw.len == 30 && !memcmp(result->raw.data, expected, 30));
    CHECK(result->raw_v2.len == (size_t)n && !memcmp(result->raw_v2.data, raw_v2, (size_t)n));
    CHECK(result->verified == verified && result->redacted && !strcmp(result->redacted, shown));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause)
               : !result->verification_error);
    CHECK(result->secret_parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 30 && !memcmp(json_object_get_string(part), expected, 30));
    CHECK(json_object_object_get_ex(result->secret_parts, "account_id", &part));
    CHECK(!strcmp(json_object_get_string(part), id));
    if (region) {
        CHECK(json_object_object_length(result->secret_parts) == 3);
        CHECK(json_object_object_get_ex(result->secret_parts, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
    } else {
        CHECK(json_object_object_length(result->secret_parts) == 2);
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
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 31 && sizeof(other) == 31);
    CHECK(br_newrelicinsightsquerykey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicInsightsQueryKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_newrelicinsightsquerykey_init(NULL, NULL) == -1);
    CHECK(br_newrelicinsightsquerykey_init(&d, &error) == 0 && d && !error);
    CHECK(br_newrelicinsightsquerykey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1067 && d->version == 0 && !strcmp(d->name, "NewRelicInsightsQueryKey"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->description[strlen(d->description) - 1] == '.');
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nriq-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    br_results out = test_scan(d, NULL, false, text, len);
    CHECK(!out.len && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[1280];
    int n = snprintf(input, sizeof(input), "%s %s account %s relic %s account %s",
                     key, other, second_account, account, second_account);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 4 && !setter_calls);
    result_is(&out.items[0], key, second_account, NULL, false, NULL);
    result_is(&out.items[1], key, account, NULL, false, NULL);
    result_is(&out.items[2], other, second_account, NULL, false, NULL);
    result_is(&out.items[3], other, account, NULL, false, NULL);
    CHECK(out.items[0].raw.data != out.items[2].raw.data);
    CHECK(out.items[0].redacted != out.items[2].redacted);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "%s %s account %s", key, key, account);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    result_is(&out.items[1], key, account, NULL, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "%sZ id %s", key, account);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    br_results_clear(&out);

    memset(input, 'x', 1100);
    memcpy(input, key, 30);
    n = snprintf(input + 1100, sizeof(input) - 1100, " account %s", account);
    out = test_scan(d, NULL, false, input, 1100 + (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    br_results_clear(&out);

    expect_none(d, key, 30);
    n = snprintf(input, sizeof(input), "account %s", account);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "x%s account %s", key, account);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "NRIQ-Xc_V8HruIZ271_l9FQm-_nJ7 account %s", account);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%s account1234", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%s id 123", key);
    expect_none(d, input, (size_t)n);
    char gap[48];
    memset(gap, ' ', 41);
    gap[41] = '\0';
    n = snprintf(input, sizeof(input), "%s account%s%s", key, gap, account);
    expect_none(d, input, (size_t)n);
    memset(gap, ' ', 40);
    gap[40] = '\0';
    n = snprintf(input, sizeof(input), "%s account%s%s", key, gap, account);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "%s RELIC %s", key, account);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    br_results_clear(&out);
}

typedef struct {
    const char *borrowed_key, *token, *accounts[2];
    int status, send_rc;
    const char *send_error, *body_error;
    bool order_us_eu, status_set[2], send_set[2];
    int statuses[2], send_rcs[2];
    const char *send_errors[2];
} script;

static void expect_url(const char *url, bool us, const char *id)
{
    char want[128];
    int n = snprintf(want, sizeof(want), "%s%s/query?nrql=SELECT%%201", us ? us_head : eu_head, id);
    CHECK(n > 0 && url && !strcmp(url, want));
    CHECK(strstr(url, "%20") && !strstr(url, "%2520") && !strstr(url, "NRIQ-"));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *id = s->order_us_eu ? s->accounts[0] : s->accounts[http->calls - 1];
    bool us = !s->order_us_eu || http->calls == 1;
    CHECK(ctx && http->calls == http->releases + 1 && http->calls <= 2);
    expect_url(request->url, us, id);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1067);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "X-Query-Key"));
    CHECK(request->headers[0].value && strlen(request->headers[0].value) == 30);
    CHECK(!memcmp(request->headers[0].value, s->token ? s->token : key, 30));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog query-offline"));
    s->borrowed_key = request->headers[0].value;
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
        expect_url(seam_url, http->releases == 0, account);
        CHECK(seam_key && !memcmp(seam_key, key, 30));
        seam_url = NULL;
        seam_key = NULL;
    }
    if (format_before_release)
        CHECK(!fail_format && setter_calls == setters_before_format);
    if (s && s->borrowed_key) {
        CHECK(!memcmp(s->borrowed_key, s->token ? s->token : key, 30));
        s->borrowed_key = NULL;
    }
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static int with_account(char *out, size_t cap, const char *token)
{
    return snprintf(out, cap, "%s account %s", token, account);
}

static void verification(const br_detector *d)
{
    script s = {.status = 200, .order_us_eu = true, .accounts = {account, account}};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "query-offline"};
    char input[80];
    int n = with_account(input, sizeof(input), key);
    size_t before = setter_calls;
    s.body_error = "ignored copy error";
    br_results out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_key);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, account, "us", true, NULL);
    br_results_clear(&out);

    s.body_error = NULL;
    s.status_set[0] = true;
    s.statuses[0] = 401;
    s.status_set[1] = true;
    s.statuses[1] = 200;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, account, "eu", true, NULL);
    br_results_clear(&out);

    s.statuses[1] = 401;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, account, NULL, false, NULL);
    br_results_clear(&out);

    s.statuses[0] = 500;
    s.statuses[1] = 401;
    s.body_error = "ignored copy error";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !setter_saw_null);
    result_is(&out.items[0], key, account, NULL, false,
              "error verifying region us: unexpected status code: 500");
    CHECK(!strchr(out.items[0].verification_error, '\n'));
    CHECK(strcmp(out.items[0].verification_error, "ignored copy error") != 0);
    br_results_clear(&out);

    s.statuses[1] = 403;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    const char *joined =
        "error verifying region us: unexpected status code: 500\n"
        "error verifying region eu: unexpected status code: 403";
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    result_is(&out.items[0], key, account, NULL, false, joined);
    CHECK(out.items[0].verification_error[strlen(out.items[0].verification_error) - 1] != '\n');
    br_results_clear(&out);

    s.statuses[0] = 500;
    s.statuses[1] = 200;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == before + 1 && setter_saw_null);
    result_is(&out.items[0], key, account, "eu", true, NULL);
    br_results_clear(&out);

    char rejected[80];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", key) > 0);
    s.statuses[0] = 200;
    s.statuses[1] = 401;
    s.send_set[0] = true;
    s.send_rcs[0] = -1;
    s.send_errors[0] = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    char wrapped[128];
    CHECK(snprintf(wrapped, sizeof(wrapped), "error verifying region us: error making request: %s", rejected) > 0);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !seen_secrets && !setter_saw_null);
    result_is(&out.items[0], key, account, NULL, false, wrapped);
    CHECK(strstr(out.items[0].verification_error, key) != NULL);
    CHECK(!strstr(out.items[0].verification_error, "[REDACTED]"));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "query-offline", .cancelled = cancelled};
    s.send_set[0] = false;
    s.send_error = NULL;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, input, (size_t)n);
    const char *cancelled_cause =
        "error verifying region us: error making request: context canceled\n"
        "error verifying region eu: error making request: context canceled";
    CHECK(out.len == 1 && !http.calls && http.releases == 2 && !seen_secrets);
    result_is(&out.items[0], key, account, NULL, false, cancelled_cause);
    br_results_clear(&out);

    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, NULL, true, input, (size_t)n);
    const char *nil_cause =
        "error verifying region us: error constructing request: net/http: nil Context\n"
        "error verifying region eu: error constructing request: net/http: nil Context";
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == before + 1 && !seen_secrets);
    result_is(&out.items[0], key, account, NULL, false, nil_cause);
    br_results_clear(&out);

    before = setter_calls;
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1 && setter_calls == before && !http.calls);
    result_is(&out.items[0], key, account, NULL, false, NULL);
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
    int n = snprintf(text, sizeof(text), "%s account %s id %s", key, second_account, account);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.status = 200, .accounts = {second_account, account}};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "query-offline"};
    char *error = NULL;
    size_t setters = setter_calls;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicInsightsQueryKey finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_account_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicInsightsQueryKey finding") && !fail_account_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicInsightsQueryKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    char one[80];
    int one_n = with_account(one, sizeof(one), key);
    br_slice one_data = {(const unsigned char *)one, (size_t)one_n};
    s.accounts[0] = account;
    s.order_us_eu = true;
    fail_region_after = 1;
    http.calls = http.releases = 0;
    setters = setter_calls;
    CHECK(d->scan(d, &ctx, true, one_data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicInsightsQueryKey region") && !fail_region_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    s.order_us_eu = false;
    s.accounts[0] = second_account;
    s.accounts[1] = account;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicInsightsQueryKey verification error") && !fail_setter_after);
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

static int query_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                           br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    seam_url = request ? request->url : NULL;
    seam_key = request && request->nheaders && request->headers ? request->headers[0].value : NULL;
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
    CHECK(observed_query_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_newrelicinsightsquerykey_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[80];
    int n = with_account(input, sizeof(input), key);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.status = 500, .accounts = {account, account}};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "query-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_key = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format NewRelicInsightsQueryKey verification status") && !fail_format);
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_key);
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
    br_results sent = test_scan(observed, &ctx, true, input, (size_t)n);
    CHECK(sent.len == 1 && !http.calls && http.releases == 2 && !seam_url && !seam_key);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    result_is(&sent.items[0], key, account, NULL, false, NULL);
    CHECK(!sent.items[0].verification_error || !strstr(sent.items[0].verification_error, "HTTP transport failed"));
    br_results_clear(&sent);

    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicInsightsQueryKey verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 2 && !seam_url && !seam_key);
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
    return test_finish("NewRelicInsightsQueryKey");
}
