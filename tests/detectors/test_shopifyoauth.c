/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_shopifyoauth_init(const br_detector **out, char **error);

static const char id[] = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
static const char secret[] = "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";
static const char domain[] = "my-test-store.myshopify.com";
static const char want[] = "my-test-store.myshopify.com:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6: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";

typedef struct { test_http http; int status; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://my-test-store.myshopify.com/admin/oauth/access_token"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(request->body.len && strstr((const char *)request->body.data,
          "client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6&client_secret=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&grant_type=client_credentials"));
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

static const char *input =
    "SHOPIFY_CLIENT_ID=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"
    "SHOPIFY_CLIENT_SECRET=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\n"
    "SHOPIFY_STORE=my-test-store.myshopify.com\n";

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shopifyoauth_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1044 && detector->nkeywords == 2);
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "shpss_") && !strcmp(detector->keywords[1], "myshopify.com"));
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(secret) && !memcmp(results.items[0].raw.data, secret, strlen(secret)));
    CHECK(results.items[0].raw_v2.len == strlen(want) && !memcmp(results.items[0].raw_v2.data, want, strlen(want)));
    br_results_clear(&results);
    const char *missing = "shopify_client_id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\nstore: test-store.myshopify.com\n";
    results = test_scan(detector, NULL, false, missing, strlen(missing));
    CHECK(results.len == 0);
    br_results_clear(&results);
    probe ok = {.status = 200};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe quiet = {.status = 400};
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe missing_store = {.status = 404};
    results = scan_probe(detector, input, &missing_store);
    CHECK(results.len == 1 && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = {.status = 500};
    results = scan_probe(detector, input, &bad);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    probe down = {.send_rc = 1, .send_error = "no such host"};
    results = scan_probe(detector, input, &down);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "no such host"));
    br_results_clear(&results);
    char leaked[96];
    snprintf(leaked, sizeof(leaked), "dial %s refused", secret);
    probe redacted = {.send_rc = 1, .send_error = leaked};
    results = scan_probe(detector, input, &redacted);
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(results.items[0].verification_error, "failed to perform request"));
    CHECK(!strstr(results.items[0].verification_error, secret));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    (void)id; (void)domain;
    return test_finish("shopifyoauth");
}
