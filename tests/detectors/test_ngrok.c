/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <stdarg.h>

int br_ngrok_init(const br_detector **out, char **error);

static void note_unverified(const br_result *);
static int checked_snprintf(char *, size_t, const char *, ...);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
#define NGROK_BEFORE_RELEASE(result) note_unverified(result)
#undef snprintf
#define snprintf checked_snprintf
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_ngrok_init observed_ngrok_init
#include "../../src/detectors/ngrok.c"
#undef NGROK_BEFORE_RELEASE
#undef snprintf
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_ngrok_init

static const char valid[] = "2WIRSIHOQyHSVklZnoz2k6bTYdH_0E7z0Ta9QEyR1fZvQ0KU9";
static const char over[] = "2abcdefgabcdefgabcdefgabcde_4fgabcdefgabcdefgabcd";
static const char under[] = "2abcdefabcdefabcdefabcdefab_4cdefabcdefabcdefabcd";
static const char url[] = "https://api.ngrok.com/agent_ingresses";
static char low[50];
static char read_buf[32];
static const br_http_request *live_request;
static const char *live_auth;
static const char *setter_cause;
static unsigned char setter_bytes[49];
static size_t setter_calls, before_release;
static int stage, fail_setter, fail_format, null_do;
static bool clobber_read, require_release, expect_verified, saw_unverified;

static void reset_observation(void)
{
    live_request = NULL;
    live_auth = NULL;
    setter_cause = NULL;
    memset(setter_bytes, 0, sizeof(setter_bytes));
    setter_calls = before_release = 0;
    stage = fail_setter = fail_format = null_do = 0;
    clobber_read = require_release = expect_verified = saw_unverified = false;
}

static void note_unverified(const br_result *result)
{
    CHECK(result && !result->verified);
    saw_unverified = true;
    ++before_release;
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && format && !strcmp(format, "ngrok: unexpected status code: %d")) {
        fail_format = 0;
        return -1;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, n, format, args);
    va_end(args);
    return rc;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    stage = 0;
    live_request = request;
    live_auth = request && request->nheaders ? request->headers[0].value : NULL;
    if (null_do) {
        null_do = 0;
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return br_http_send(ctx, request, response, error);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(stage == 0 && live_request && !strcmp(live_request->url, url));
    CHECK(live_request->nheaders == 2 && live_request->profile == BR_HTTP_SANE && !live_request->timeout_ms);
    CHECK(!strcmp(live_request->headers[0].name, "Authorization"));
    CHECK(live_auth && live_auth == live_request->headers[0].value && !strncmp(live_auth, "Bearer ", 7));
    CHECK(!strcmp(live_request->headers[1].name, "Ngrok-Version") && !strcmp(live_request->headers[1].value, "2"));
    if (clobber_read) memcpy(read_buf, "clobbered", 10);
    br_http_release(ctx, response);
    CHECK(live_request->url[0] == 'h' && live_auth[0] == 'B');
    stage = 1;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(result && count == 1 && secrets && secrets[0].len == 49 && secrets[0].data);
    CHECK(result->verified == expect_verified);
    CHECK(require_release ? stage == 1 : stage == 0);
    setter_cause = cause;
    memcpy(setter_bytes, secrets[0].data, 49);
    ++setter_calls;
    stage = 2;
    if (fail_setter && --fail_setter == 0) return 1;
    return br_result_set_verification_error(result, cause, secrets, count);
}

static void low_key(void)
{
    low[0] = '2';
    memset(low + 1, 'a', 26);
    low[27] = '_';
    low[28] = '1';
    memset(low + 29, 'a', 20);
    low[49] = '\0';
}

static const char *part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->secret_parts && json_object_object_get_ex(result->secret_parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void expect_key(const br_result *result, const char *key, bool verified, const char *verification_error)
{
    CHECK(result->detector_type == 966 && !result->detector_name && !result->raw_v2.data && !result->extra_data);
    CHECK(!result->redacted && !result->structured_data && result->verified == verified);
    CHECK(result->raw.len == 49 && !memcmp(result->raw.data, key, 49));
    CHECK(!strcmp(part(result, "key"), key));
    CHECK(verification_error ? result->verification_error && !strcmp(result->verification_error, verification_error)
                             : !result->verification_error);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 966);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 56 && !memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[0].value + 7, key, 49));
    CHECK(!strcmp(request->headers[1].name, "Ngrok-Version") && !strcmp(request->headers[1].value, "2"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Ngrok detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 966 && detector->version == 0 && !strcmp(detector->name, "Ngrok"));
    CHECK(!strcmp(detector->description, "Ngrok is a service that provides secure introspectable tunnels to localhost. Ngrok keys can be used to manage and control these tunnels."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ngrok"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && !detector->clean && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[400];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_slice under_slice = {(const unsigned char *)under, 49};
    br_slice over_slice = {(const unsigned char *)over, 49};
    br_slice low_slice = {(const unsigned char *)low, 49};
    CHECK(br_ascii_shannon_entropy(under_slice) < 3);
    CHECK(br_ascii_shannon_entropy(low_slice) < 3);
    CHECK(br_ascii_shannon_entropy(over_slice) >= 3);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)valid, 49}) >= 3);
    /* First-seen order is ours. Go map order is unspecified and is not claimed. */
    snprintf(input, sizeof(input), "ngrok %s\nngrok %s\nNGROK %s\nNgrok %s", under, over, valid, over);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls && !http.releases);
    expect_key(&out.items[0], over, false, NULL);
    expect_key(&out.items[1], valid, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok %s", low);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok token = '%s'", valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], valid, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok token = '%s' | '%s'", valid, valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok keyword is not close to the real key in the data\n = '%s'", valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok = '%s'", "2WIRSIHOQyHSVklZnoz2k6bT?dH_0E7z0Ta9QEyR1fZvQ0KU9");
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ngrok %s", "2WIRSIHOQyHSVklZnoz2k6bTYdH_AE7z0Ta9QEyR1fZvQ0KU9");
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

static void verify_policy(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "ngrok %s", valid);
    static const unsigned char nul_body[] = {'x', 0, 'E', 'R', 'R', '_', 'N', 'G', 'R', 'O', 'K', '_', '2', '0', '6', 'y'};
    const char marker[] = "partial ERR_NGROK_206 still present";
    test_http http = {.user = (void *)valid, .inspect = inspect};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; const char *body; size_t len; const char *read_error; bool verified; const char *error; } cases[] = {
        {200, "ignored", 7, NULL, true, NULL},
        {200, NULL, 1, NULL, true, NULL},
        {401, marker, sizeof(marker) - 1, NULL, false, NULL},
        {401, NULL, 1, NULL, false, NULL},
        {403, marker, sizeof(marker) - 1, NULL, false, NULL},
        {403, NULL, 1, NULL, false, NULL},
        {400, (const char *)nul_body, sizeof(nul_body), NULL, true, NULL},
        {400, marker, sizeof(marker) - 1, "read failed", false, "read failed"},
        {400, NULL, 1, "read failed", false, "read failed"},
        {400, NULL, 0, NULL, false, "ngrok: unexpected status code: 400"},
        {400, "ERR_NGROK_207", 13, NULL, false, "ngrok: unexpected status code: 400"},
        {201, marker, sizeof(marker) - 1, NULL, false, "ngrok: unexpected status code: 201"},
        {201, NULL, 1, NULL, false, "ngrok: unexpected status code: 201"},
        {202, "", 0, NULL, false, "ngrok: unexpected status code: 202"},
        {404, marker, sizeof(marker) - 1, NULL, false, "ngrok: unexpected status code: 404"},
        {500, "", 0, "ignored", false, "ngrok: unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, cases[i].len},
            .body_error = cases[i].read_error,
        };
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        expect_key(&out.items[0], valid, cases[i].verified, cases[i].error);
        br_results_clear(&out);
    }
    char leaked[80];
    snprintf(leaked, sizeof(leaked), "bad %s", valid);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = leaked;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !out.items[0].verified);
    CHECK(out.items[0].verification_error && strstr(out.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(out.items[0].verification_error, valid));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    expect_key(&out.items[0], valid, false, "net/http: nil Context");
    br_results_clear(&out);
}

static void seam(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "ngrok %s", valid);
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    require_release = true;
    expect_verified = true;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && setter_calls == 1 && !setter_cause && saw_unverified && before_release == 1);
    CHECK(http.calls == 1 && http.releases == 1 && stage == 2);
    expect_key(&out.items[0], valid, true, NULL);
    br_results_clear(&out);
    reset_observation();
    expect_verified = false;
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == 1 && !saw_unverified);
    CHECK(setter_cause && !strcmp(setter_cause, "net/http: nil Context"));
    CHECK(!memcmp(setter_bytes, valid, 49));
    expect_key(&out.items[0], valid, false, "net/http: nil Context");
    br_results_clear(&out);
    memcpy(read_buf, "read failed", 12);
    http.response = (br_http_response){
        .status = 400,
        .body = {(const unsigned char *)"ERR_NGROK_206", 13},
        .body_error = read_buf,
    };
    reset_observation();
    require_release = true;
    clobber_read = true;
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1 && setter_calls == 1 && !out.items[0].verified);
    expect_key(&out.items[0], valid, false, "read failed");
    CHECK(!strcmp(read_buf, "clobbered"));
    br_results_clear(&out);
    reset_observation();
    null_do = 1;
    require_release = true;
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && setter_calls == 1 && !setter_cause);
    expect_key(&out.items[0], valid, false, NULL);
    br_results_clear(&out);
    br_result prior = {0};
    br_results kept = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    reset_observation();
    fail_format = 1;
    http.response = (br_http_response){.status = 404};
    http.calls = http.releases = 0;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot format Ngrok status"));
    free(error);
    CHECK(saw_unverified && !setter_calls && http.calls == 1 && http.releases == 1 && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fail_setter = 2;
    require_release = true;
    expect_verified = true;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "ngrok %s\nngrok %s", valid, over);
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot record Ngrok verification error"));
    free(error);
    CHECK(setter_calls == 2 && http.calls == 2 && http.releases == 2 && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&kept);
    reset_observation();
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !setter_calls && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void invalid_body(const br_detector *detector, bool wrapped)
{
    char input[80];
    snprintf(input, sizeof(input), "ngrok %s", valid);
    test_http http = {.response = {.status = 400, .body = {NULL, 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_result prior = {0};
    br_results kept = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    if (wrapped) reset_observation();
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "invalid Ngrok response body"));
    free(error);
    CHECK(http.calls == 1 && http.releases == 1 && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
    if (wrapped) CHECK(!setter_calls && saw_unverified && before_release == 1);
    br_results_clear(&kept);
    if (wrapped) reset_observation();
}

int main(void)
{
    low_key();
    CHECK(strlen(valid) == 49 && strlen(over) == 49 && strlen(under) == 49 && strlen(low) == 49);
    const br_detector *detector = open_detector(br_ngrok_init);
    grammar(detector);
    verify_policy(detector);
    invalid_body(detector, false);
    const br_detector *observed = open_detector(observed_ngrok_init);
    seam(observed);
    invalid_body(observed, true);
    CHECK(!live_request && !fail_format && !fail_setter && !null_do);
    return test_finish("Ngrok");
}
