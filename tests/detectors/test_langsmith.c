/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error langsmith_real_setter
#define br_results_push langsmith_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_langsmith_init(const br_detector **out, char **error);

/* A named-test inclusion seam makes impossible formatter returns observable
 * without interposing Nix's fortified snprintf. Existing cases keep the
 * library factory, which remains the only production export. */
static int checked_snprintf(char *, size_t, const char *, ...);
static int langsmith_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send langsmith_seam_send
#define br_langsmith_init observed_langsmith_init
#include "../../src/detectors/langsmith.c"
#undef snprintf
#undef br_http_send
#undef br_langsmith_init

static char pt[52], sk[52];
static const char description[] =
    "LangSmith is a unified observability & evals platform where teams can debug, test, and monitor AI app performance \xe2\x80\x94 whether building with LangChain or not";
static const char url[] = "https://api.smith.langchain.com/api/v1/api-key";
static size_t fail_key_after, fail_push_after, fail_setter_after, setter_calls;
static size_t setters_before_format, null_send_setters_before, seen_secret_len, seen_secret_count;
static bool format_before_release, null_send_cause, setter_saw_null;
static int fail_format;
static test_http *null_send_http;
static const char *seam_header, *seam_key;
static char seen_secret[52];

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_saw_null = cause == NULL;
    seen_secret_count = count;
    seen_secret_len = 0;
    if (count == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(seen_secret)) {
        memcpy(seen_secret, secrets[0].data, secrets[0].len);
        seen_secret[secrets[0].len] = '\0';
        seen_secret_len = secrets[0].len;
    }
    if (fail_setter_after && --fail_setter_after == 0) {
        if (null_send_cause) {
            CHECK(null_send_http && null_send_http->releases == 1);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return langsmith_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return langsmith_real_push(out, owned);
}

static void fill_key(char *out, const char *prefix, char fill)
{
    memcpy(out, prefix, 8);
    memset(out + 8, fill, 32);
    out[40] = '_';
    memset(out + 41, fill, 10);
    out[51] = '\0';
}

static void result_is(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 1028, expected, "key");
    CHECK(result->raw.len == 51 && result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 51);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    fill_key(pt, "lsv2_pt_", 'a');
    fill_key(sk, "lsv2_sk_", 'b');
    CHECK(BR_ABI_REVISION == 1 && strlen(pt) == 51 && strlen(sk) == 51);
    CHECK(br_langsmith_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LangSmith detector output"));
    free(error);
    error = NULL;
    CHECK(br_langsmith_init(NULL, NULL) == -1);
    CHECK(br_langsmith_init(&d, &error) == 0 && d && !error);
    CHECK(br_langsmith_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1028 && d->version == 0 && !strcmp(d->name, "LangSmith") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(strstr(d->description, "performance \xe2\x80\x94 whether") != NULL);
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "lsv2_pt_") && !strcmp(d->keywords[1], "lsv2_sk_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[240];
    br_results out = test_scan(d, &ctx, false, pt, 51);
    CHECK(out.len == 1 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], pt, false, NULL);
    br_results_clear(&out);
    out = test_scan(d, &ctx, false, sk, 51);
    CHECK(out.len == 1);
    result_is(&out.items[0], sk, false, NULL);
    br_results_clear(&out);

    int n = snprintf(input, sizeof(input), "note %s\n%s %s", sk, pt, sk);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 2);
    result_is(&out.items[0], sk, false, NULL);
    result_is(&out.items[1], pt, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);

    char upper[52];
    memcpy(upper, pt, 52);
    upper[0] = 'L';
    out = test_scan(d, &ctx, false, upper, 51);
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(upper, pt, 52);
    upper[8] = 'A';
    out = test_scan(d, &ctx, false, upper, 51);
    CHECK(!out.len);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "x%s", pt);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "%sx", pt);
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, pt, 51);
    CHECK(out.len == 1);
    result_is(&out.items[0], pt, false, NULL);
    br_results_clear(&out);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

typedef struct {
    const char *keys[2];
    size_t nkeys;
    const char *borrowed_url, *borrowed_header;
    int status, send_rc;
    const char *send_error, *body_error;
    bool status_set[2];
    int statuses[2];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *want = s->keys[http->calls - 1];
    CHECK(ctx && http->calls == http->releases + 1 && want);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1028);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key") && !strcmp(request->headers[0].value, want));
    CHECK(strcmp(request->headers[0].name, "X-API-Key") != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog langsmith-offline"));
    s->borrowed_url = request->url;
    s->borrowed_header = request->headers[0].value;
    static const unsigned char body[] = {0xff, 0, '{'};
    int status = s->status_set[http->calls - 1] ? s->statuses[http->calls - 1] : s->status;
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
    /* The earlier 200 already called the setter. This attempt formatted first. */
    if (format_before_release && http->releases == 1)
        CHECK(!fail_format && setter_calls == setters_before_format + 1);
    if (seam_header) {
        CHECK(seam_key && !strcmp(seam_header, seam_key));
        seam_header = NULL;
    }
    if (s->borrowed_header) {
        CHECK(!strcmp(s->borrowed_url, url));
        CHECK(!strcmp(s->borrowed_header, s->keys[http->releases]));
        s->borrowed_url = s->borrowed_header = NULL;
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
    script s = {.keys = {pt}, .nkeys = 1, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langsmith-offline"};
    const int determinate[] = {200, 401, 403};
    for (size_t i = 0; i < sizeof(determinate) / sizeof(determinate[0]); ++i) {
        s.status = determinate[i];
        s.body_error = i == 0 ? "ignored read failure" : NULL;
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        size_t before = setter_calls;
        br_results out = test_scan(d, &ctx, true, pt, 51);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_header);
        CHECK(setter_calls == before + 1);
        result_is(&out.items[0], pt, determinate[i] == 200, NULL);
        br_results_clear(&out);
    }

    const int other_status[] = {0, 402, 500};
    for (size_t i = 0; i < sizeof(other_status) / sizeof(other_status[0]); ++i) {
        s.status = other_status[i];
        s.body_error = "ignored read failure";
        http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, pt, 51);
        char cause[64];
        CHECK(snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", other_status[i]) > 0);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], pt, false, cause);
        CHECK(strcmp(out.items[0].verification_error, "ignored read failure") != 0);
        br_results_clear(&out);
    }

    char rejected[80];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", pt) == 60);
    s.status = 200;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, pt, 51);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], pt, false, "rejected [REDACTED]");
    CHECK(!strstr(out.items[0].verification_error, pt));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "langsmith-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, pt, 51);
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    result_is(&out.items[0], pt, false, "context canceled");
    br_results_clear(&out);

    size_t before = setter_calls;
    out = test_scan(d, NULL, true, pt, 51);
    CHECK(out.len == 1 && !http.calls && setter_calls == before + 1);
    result_is(&out.items[0], pt, false, "net/http: nil Context");
    br_results_clear(&out);

    char input[180];
    int n = snprintf(input, sizeof(input), "%s %s %s", sk, pt, sk);
    s.keys[0] = sk;
    s.keys[1] = pt;
    s.nkeys = 2;
    s.status = 200;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !s.borrowed_header);
    result_is(&out.items[0], sk, true, NULL);
    result_is(&out.items[1], pt, true, NULL);
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
    char input[120];
    int n = snprintf(input, sizeof(input), "%s %s", pt, sk);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.keys = {pt, sk}, .nkeys = 2, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langsmith-offline"};
    char *error = NULL;

    fail_key_after = 1;
    size_t before = setter_calls;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LangSmith finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == before);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record LangSmith verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record LangSmith verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_header);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
    CHECK(!fail_key_after && !fail_setter_after && !fail_push_after);
}

static int langsmith_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                               br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    /* Bypass the shared helper, which would invent "HTTP transport failed". */
    seam_header = request && request->nheaders ? request->headers[0].value : NULL;
    if (response) memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    return -1;
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && format && !strcmp(format, "unexpected HTTP response status %d")) {
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
    CHECK(observed_langsmith_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_langsmith_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[120];
    int n = snprintf(input, sizeof(input), "%s %s", pt, sk);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.keys = {pt, sk}, .nkeys = 2, .status = 200, .body_error = "ignored read failure"};
    s.status_set[1] = true;
    s.statuses[1] = 500;
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langsmith-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_url = s.borrowed_header = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format LangSmith verification status") && !fail_format);
        CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_header);
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
    CHECK(observed_langsmith_init(&observed, &error) == 0 && observed && !error);
    script s = {.keys = {pt}, .nkeys = 1};
    test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langsmith-offline"};
    null_send_cause = true;
    null_send_http = &http;
    seam_key = pt;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results out = test_scan(observed, &ctx, true, pt, 51);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !seam_header);
    CHECK(setter_calls == setters + 1 && setter_saw_null && seen_secret_count == 1);
    CHECK(seen_secret_len == 51 && !strcmp(seen_secret, pt));
    result_is(&out.items[0], pt, false, NULL);
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    http.calls = http.releases = 0;
    seam_key = pt;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)pt, 51}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record LangSmith verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 1 && !seam_header);
    CHECK(setter_calls == setters + 1 && setter_saw_null && seen_secret_count == 1);
    CHECK(seen_secret_len == 51 && !strcmp(seen_secret, pt));
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
    return test_finish("LangSmith");
}
