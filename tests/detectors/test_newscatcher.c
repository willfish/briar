/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_newscatcher_init(const br_detector **out, char **error);

#define br_result_set_verification_error news_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_newscatcher_init observed_init
#include "../../src/detectors/newscatcher.c"
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_newscatcher_init

static const char valid[] = "vW_6rXfYJcjXRU8Z92B9RR6WRpVUN5ebSX07I8_QQDi";
static const char other[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
static const char url[] = "https://api.newscatcherapi.com/v2/search?q=Tesla";
typedef enum { NONE, CAPTURE, FINDING, PUSH } fault_site;
static fault_site fault;
static size_t nth, finding_calls, push_calls, setter_calls;
static bool fault_hit;
static const br_http_request *live_request;
static const char *live_key;
static br_result *candidate;
static bool release_before_push;
static br_results *watch_out;
typedef struct {
    const char *url, *header_name, *key;
    const br_header *headers;
} sent_view;
static sent_view sent[8];
static size_t sent_n, release_n, rows_at[8];
static int order_at[8];

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return news_real_setter(result, cause, secrets, count);
}

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE;
    fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!live_request && !live_key);
    fault = NONE;
    nth = finding_calls = push_calls = setter_calls = sent_n = release_n = 0;
    fault_hit = release_before_push = false;
    candidate = NULL;
    watch_out = NULL;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure");
        CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    ++finding_calls;
    candidate = result;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void check_request(const br_http_request *request)
{
    CHECK(request && !strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 543);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(strcmp(request->headers[0].name, "x-api-key"));
    CHECK(request->headers[0].value == live_key && live_key[43] == '\0');
    CHECK(candidate && !memcmp(live_key, candidate->raw.data, 43));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(candidate && !candidate->verified && !candidate->verification_error && sent_n < 8);
    live_request = request;
    live_key = request->headers[0].value;
    check_request(request);
    sent[sent_n] = (sent_view){request->url, request->headers[0].name, request->headers[0].value, request->headers};
    int rc = br_http_send(ctx, request, response, error);
    /* Send frees its synthesized User-Agent array. The provider request stays one header. */
    CHECK(request->nheaders == 1 && request->headers == sent[sent_n].headers);
    CHECK(request->url == sent[sent_n].url && request->headers[0].value == sent[sent_n].key);
    check_request(request);
    ++sent_n;
    live_request = NULL;
    live_key = NULL;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(!live_request && sent_n && release_n < 8);
    for (size_t i = 0; i < sent_n; ++i) {
        CHECK(sent[i].url && !strcmp(sent[i].url, url));
        CHECK(sent[i].header_name && !strcmp(sent[i].header_name, "X-Api-Key"));
        CHECK(sent[i].key && sent[i].key[43] == '\0');
    }
    if (watch_out) {
        rows_at[release_n] = watch_out->len;
        order_at[release_n] = response && response->status >= 200 ? response->status - 200 : 0;
    }
    ++release_n;
    br_http_release(ctx, response);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(release_before_push ? release_n == sent_n : release_n == 0);
    ++push_calls;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Newscatcher detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 543 && !detector->version && !strcmp(detector->name, "Newscatcher"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Newscatcher is an API service used to search and retrieve news articles from various sources. Newscatcher API keys can be used to access and query this service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "newscatcher"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 543, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void grammar(const br_detector *detector)
{
    char input[280];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "newscatcher token = '%s'", valid);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    expect_key(&out.items[0], valid, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher token = '%s' | '%s'", valid, valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], valid, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher %s newscatcher %s", valid, valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].raw.data != out.items[1].raw.data);
    expect_key(&out.items[0], valid, false);
    expect_key(&out.items[1], valid, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "NEWSCATCHER %s", other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], other, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher keyword is not close to the real key in the data\n = '%s'", valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher = '%s'", "vW_6rXfYJcjX?U8Z92B9RR6WRpVUN5ebSX07I8_QQDi");
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher %s", "vW_6rXfYJcjXRU8Z92B9RR6WRpVUN5ebSX07I8_QQD");
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "newscatcher %sa", valid);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 543);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, valid));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len);
}

static void verify_policy(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "newscatcher %s", valid);
    test_http http = {.inspect = inspect};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; const char *body; const char *read_error; bool verified; } cases[] = {
        {199, "Tesla", "ignored", false},
        {200, NULL, NULL, true},
        {204, "not read", "read failed", true},
        {299, "", "", true},
        {300, "redirect", NULL, false},
        {401, "denied", "ignored", false},
        {500, NULL, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, cases[i].body ? strlen(cases[i].body) : 0},
            .body_error = cases[i].read_error,
        };
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        expect_key(&out.items[0], valid, cases[i].verified);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.response = (br_http_response){.status = 200, .body_error = "ignored after Do"};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    expect_key(&out.items[0], valid, false);
    br_results_clear(&out);
    br_transport missing = {&http, NULL, test_http_release};
    br_scan_ctx bare = {.transport = &missing};
    http.calls = http.releases = 0;
    out = test_scan(detector, &bare, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    expect_key(&out.items[0], valid, false);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    expect_key(&out.items[0], valid, false);
    br_results_clear(&out);
}

static void keep_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void seam(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "newscatcher %s newscatcher %s", valid, other);
    test_http http = {.response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && finding_calls == 2 && !push_calls && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && finding_calls == 2 && push_calls == 2 && http.calls == 2 && http.releases == 2);
    CHECK(release_n == 2 && !release_before_push && !setter_calls && !live_request);
    expect_key(&out.items[0], valid, true);
    expect_key(&out.items[1], other, true);
    br_results_clear(&out);
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    reset_observation();
    fault = PUSH;
    nth = 1;
    http.calls = http.releases = 0;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Newscatcher result"));
    free(error);
    CHECK(fault_hit && http.calls == 1 && http.releases == 1 && !setter_calls && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
    reset_observation();
    fault = FINDING;
    nth = 1;
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create Newscatcher result"));
    free(error);
    CHECK(fault_hit && !http.calls && !http.releases && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fault = CAPTURE;
    nth = 1;
    error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "synthetic capture failure"));
    free(error);
    CHECK(fault_hit && !finding_calls && !push_calls && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
}

typedef struct {
    br_results *out;
    size_t calls, releases, rows[4];
    int order[4], send_rc, status;
    const char *send_error;
} news_script;

static int news_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                     br_http_response *response, char **error)
{
    (void)ctx;
    news_script *script = user;
    CHECK(request && request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(request->url && !strcmp(request->url, url) && request->headers[0].value);
    ++script->calls;
    if (script->send_rc) {
        *error = script->send_error ? strdup(script->send_error) : NULL;
        CHECK(!script->send_error || *error);
        return script->send_rc;
    }
    *response = (br_http_response){.status = script->status ? script->status : 200 + (int)script->calls};
    *error = NULL;
    return 0;
}

static void news_release(void *user, br_http_response *response)
{
    news_script *script = user;
    CHECK(script->releases < 4 && script->out);
    script->rows[script->releases] = script->out->len;
    script->order[script->releases] = response && response->status >= 200 ? response->status - 200 : 0;
    ++script->releases;
}

static void lifo_and_failed_send(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "newscatcher %s newscatcher %s", valid, valid);
    br_results out = {0};
    br_result prior = {0};
    keep_caller(&out, &prior);
    news_script script = {.out = &out};
    br_transport transport = {&script, news_send, news_release};
    br_scan_ctx ctx = {.transport = &transport};
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && script.calls == 2 && script.releases == 2);
    CHECK(script.order[0] == 2 && script.order[1] == 1);
    CHECK(script.rows[0] == 3 && script.rows[1] == 3);
    expect_key(&out.items[1], valid, true);
    expect_key(&out.items[2], valid, true);
    CHECK(out.items[0].raw.data == prior.raw.data && out.items[0].verification_error == prior.verification_error);
    CHECK(!strcmp(prior.verification_error, "caller-owned") && !setter_calls);
    br_results_clear(&out);
    keep_caller(&out, &prior);
    snprintf(input, sizeof(input), "newscatcher %s", valid);
    script = (news_script){.out = &out, .send_rc = 1, .send_error = "timeout"};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && script.calls == 1 && script.releases == 1 && script.rows[0] == 1);
    expect_key(&out.items[1], valid, false);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    br_transport missing = {&script, NULL, news_release};
    br_scan_ctx bare = {.transport = &missing};
    script = (news_script){.out = &out};
    error = NULL;
    CHECK(detector->scan(detector, &bare, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && !script.calls && script.releases == 1 && script.rows[0] == 1);
    expect_key(&out.items[1], valid, false);
    CHECK(out.items[0].verification_error == prior.verification_error);
    br_results_clear(&out);
}

static void later_fatal_drain(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "newscatcher %s newscatcher %s newscatcher %s", valid, other, valid);
    br_results out = {0};
    br_result prior = {0};
    keep_caller(&out, &prior);
    news_script script = {.out = &out};
    br_transport transport = {&script, news_send, news_release};
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    watch_out = &out;
    release_before_push = false;
    fault = PUSH;
    nth = 3;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Newscatcher result"));
    free(error);
    CHECK(fault_hit && script.calls == 3 && script.releases == 3 && release_n == 3);
    CHECK(script.order[0] == 3 && script.order[1] == 2 && script.order[2] == 1);
    CHECK(script.rows[0] == 3 && script.rows[1] == 3 && script.rows[2] == 3);
    CHECK(rows_at[0] == 3 && order_at[0] == 3 && rows_at[2] == 3 && order_at[2] == 1);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(!strcmp(prior.verification_error, "caller-owned") && !setter_calls);
    br_results_clear(&out);
    reset_observation();
}

int main(void)
{
    CHECK(strlen(valid) == 43 && strlen(other) == 43);
    const br_detector *detector = open_detector(br_newscatcher_init);
    grammar(detector);
    verify_policy(detector);
    lifo_and_failed_send(detector);
    const br_detector *observed = open_detector(observed_init);
    grammar(observed);
    seam(observed);
    later_fatal_drain(observed);
    CHECK(!live_request && !fault && !setter_calls);
    return test_finish("Newscatcher");
}
