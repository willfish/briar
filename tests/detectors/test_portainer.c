/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_portainer_init(const br_detector **out, char **error);

static const char endpoint[] = "http://>xC'w//b7U@CtF|>|Fqw'2Z";
static const char token[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EHHJE6Aht7Exhje8rUMLScr2bxcoTvWBl9bjMYZhCMYMLPD3EpUZL9SNd839DcI95lYtMfclPffpFrrJ0BbgryxnrfUSeeSKHu.W9Ur5_DLIBpXO3mfh404_7Kt9o8XZRnLTLyam2fdhB_";

typedef struct { test_http http; int status; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "http://>xC'w/api/endpoints"));
    CHECK(request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    http->response.status = ((probe *)http->user)->status;
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
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_portainer_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 942 && !strcmp(detector->keywords[0], "portainer"));
    CHECK(detector->max_credential_span == 1024);
    char input[512];
    snprintf(input, sizeof(input), "portainer %s portainer %s", endpoint, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(token) && !memcmp(results.items[0].raw.data, token, strlen(token)));
    CHECK(results.items[0].raw_v2.len == strlen(token) + strlen(endpoint));
    CHECK(!memcmp(results.items[0].raw_v2.data, token, strlen(token)));
    CHECK(!memcmp(results.items[0].raw_v2.data + strlen(token), endpoint, strlen(endpoint)));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "portainer http://bad portainer %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0 || results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "portainer %s portainer %s", endpoint, token);
    probe ok = {.status = 200};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe quiet = {.status = 403};
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = {.status = 500};
    results = scan_probe(detector, input, &bad);
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("portainer");
}
