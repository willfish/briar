/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_stripo_init(const br_detector **out, char **error);

static char key[196];
static char other[196];

static void make_key(char *out, char fill)
{
    const char *prefix = "eyJhbGciOiJIUzI1NiJ9.";
    size_t n = strlen(prefix);
    memcpy(out, prefix, n);
    memset(out + n, fill, 130);
    out[n + 130] = '.';
    memset(out + n + 131, fill, 43);
    out[n + 174] = '\0';
}

typedef struct { test_http http; int status; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://stripo.email/emailgeneration/v1/emails?parameters=sortingAsc=true"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 955);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Stripo-Api-Auth") && !strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    probe *p = http->user;
    http->response.status = p->status;
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
    make_key(key, 'a');
    make_key(other, 'b');
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_stripo_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 955 && !strcmp(detector->keywords[0], "stripo"));
    char input[512];
    snprintf(input, sizeof(input), "stripo %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 955, key, "key");
    br_results_clear(&results);
    probe ok = {.status = 204};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe quiet = {.status = 401};
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = {.status = 500};
    results = scan_probe(detector, input, &bad);
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    (void)other;
    return test_finish("stripo");
}
