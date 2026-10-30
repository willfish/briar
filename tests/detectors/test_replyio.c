/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

static int force_null_send, setter_rc, setter_calls;
static const char *setter_cause;

static int (*real_set)(br_result *, const char *, const br_slice *, size_t) = br_result_set_verification_error;
static int (*real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *, char **) = br_http_send;

static int observe_set(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_cause = cause;
    if (setter_rc) return setter_rc;
    return real_set(result, cause, secrets, nsecrets);
}

static int observe_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    if (force_null_send) {
        if (error) *error = NULL;
        return 1;
    }
    return real_send(ctx, request, response, error);
}

#define br_result_set_verification_error observe_set
#define br_http_send observe_send
#include "../../src/detectors/replyio.c"
#undef br_result_set_verification_error
#undef br_http_send

static const char key[] = "aaaaaaaaaaaaaaaaaaaaaaaa";
static const char other[] = "bbbbbbbbbbbbbbbbbbbbbbbb";

typedef struct {
    test_http http;
    const char *url_part;
    const char *header_name;
    const char *header_value;
    int nheaders;
    uint32_t timeout;
    int status;
    const char *body;
    const char *send_error;
    int send_rc;
} probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    probe *p = http->user;
    CHECK(ctx && request && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == p->timeout);
    CHECK(request->detector_type == 956);
    CHECK(!request->body.data && !request->body.len);
    if (p->url_part) CHECK(strstr(request->url, p->url_part));
    CHECK(request->nheaders == (size_t)p->nheaders);
    if (p->header_name) {
        bool found = false;
        for (size_t i = 0; i < request->nheaders; ++i)
            if (!strcmp(request->headers[i].name, p->header_name) &&
                !strcmp(request->headers[i].value, p->header_value)) found = true;
        CHECK(found);
    }
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent"));
    http->response.status = p->status;
    http->response.body = p->body ? (br_slice){(const unsigned char *)p->body, strlen(p->body)} : (br_slice){0};
    http->send_error = p->send_error;
    http->send_rc = p->send_rc;
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_replyio_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_replyio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_replyio_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 956 && !strcmp(detector->name, "ReplyIO"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "replyio"));
    CHECK(!strcmp(detector->description, "Reply.io is a sales engagement platform used for automating communication with prospects. The API key can be used to access and manage communication data."));
    CHECK(detector->scan && detector->state);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "replyio %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 956, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "replyio %s\nreplyio %s", key, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[1], 956, other, "key");
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "replyio %s", key);
    probe ok = {.url_part = "https://api.reply.io/v1/people", .header_name = "X-Api-Key",
                 .header_value = "aaaaaaaaaaaaaaaaaaaaaaaa", .nheaders = 2, .timeout = 5000,
                 .status = 200, .body = NULL, .send_rc = 0};
    br_results results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.calls == 1 && ok.http.releases == 1);
    br_results_clear(&results);
    probe quiet = ok;
    quiet.status = 401;
    quiet.body = "no";
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = ok;
    bad.status = 500;
    bad.body = "no";
    results = scan_probe(detector, input, &bad);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    probe down = ok;
    down.send_rc = 1;
    down.send_error = "no such host";
    results = scan_probe(detector, input, &down);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "no such host"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void null_diagnostic_regressions(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "replyio %s", key);
    br_scan_ctx ctx = {0};
    br_results results = {0};
    char *error = NULL;
    force_null_send = 1;
    setter_rc = 0;
    setter_calls = 0;
    setter_cause = "unset";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == 0 && !error);
    CHECK(results.len == 1 && setter_calls == 1 && !setter_cause);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    setter_rc = 1;
    setter_calls = 0;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) != 0);
    CHECK(results.len == 0 && setter_calls == 1);
    free(error);
    force_null_send = 0;
    setter_rc = 0;
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    null_diagnostic_regressions(detector);
    return test_finish("replyio");
}
