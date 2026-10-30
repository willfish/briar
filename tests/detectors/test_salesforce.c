/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_salesforce_init(const br_detector **out, char **error);

static char token[113];
static const char instance[] = "https://acme.my.salesforce.com";

static void make_token(void)
{
    memcpy(token, "00", 2);
    memset(token + 2, 'a', 13);
    token[15] = '!';
    memset(token + 16, 'b', 96);
    token[112] = '\0';
}

typedef struct { test_http http; int status; const char *body; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://acme.my.salesforce.com/services/data/v58.0/query?q=SELECT+name+from+Account"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->nheaders == 2 && !strncmp(request->headers[0].value, "Bearer ", 7));
    probe *p = http->user;
    http->response.status = p->status;
    if (p->body) http->response.body = (br_slice){(const unsigned char *)p->body, strlen(p->body)};
    http->send_rc = p->send_rc;
    http->send_error = p->send_error;
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

int main(void)
{
    make_token();
    CHECK(strlen(token) == 112);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salesforce_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 925 && !strcmp(detector->keywords[0], "salesforce"));
    CHECK(detector->max_credential_span == 1024);
    char input[256];
    snprintf(input, sizeof(input), "%s %s", instance, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 925, token, "key");
    br_results_clear(&results);
    probe ok = {.status = 200, .body = "records"};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe split = {.status = 200, .body = "reco\nrds"};
    results = scan_probe(detector, input, &split);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe quiet = {.status = 401, .body = "no"};
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = {.status = 500, .body = "no"};
    results = scan_probe(detector, input, &bad);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "returned status 500 with error <nil>"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("salesforce");
}
