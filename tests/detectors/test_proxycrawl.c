/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_proxycrawl_init(const br_detector **out, char **error);

static char key[23], other[23];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    test_secret(key, 22, 0);
    test_secret(other, 22, 3);
    key[2] = '_';
    other[4] = 'Z';
    CHECK(br_proxycrawl_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_proxycrawl_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_proxycrawl_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 440 && !strcmp(detector->name, "ProxyCrawl"));
    CHECK(!strcmp(detector->keywords[0], "proxycrawl"));
    CHECK(!strcmp(detector->description,
                  "ProxyCrawl is a service that provides web scraping and crawling capabilities. "
                  "ProxyCrawl tokens can be used to access and control these services."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean && !detector->validate_endpoints);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) test_key_result(&results.items[i], 440, keys[i], "key");
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], bad[23];
    const char *one[] = {key}, *dups[] = {key, key};
    snprintf(input, sizeof(input), "proxycrawl %s", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "PROXYCRAWL %s", key);
    expect_keys(detector, input, one, 1);
    expect_keys(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "proxycrawl%*s%s", 40, "", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "proxycrawl%*s%s", 41, "", key);
    expect_keys(detector, input, NULL, 0);
    memcpy(bad, key, sizeof(bad));
    bad[5] = '-';
    snprintf(input, sizeof(input), "proxycrawl %s", bad);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "proxycrawl %s\nproxycrawl %s", key, key);
    expect_keys(detector, input, dups, 2);
}

typedef struct { int status, send_rc; const char *send_error; } owned_case;
typedef struct {
    const owned_case *script; const char *key; size_t calls, releases; bool *destroyed;
} owned_http;

static void inspect_owned(const br_http_request *request, const char *expected)
{
    char url[96], dedup[27];
    snprintf(url, sizeof(url), "https://api.proxycrawl.com/leads?token=%s&domain=slack.com", expected);
    memcpy(dedup, "440:", 4);
    memcpy(dedup + 4, expected, 22);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->detector_type == 440 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms > 5000 && request->timeout_ms <= 10000);
    CHECK(request->dedup_key.len == 26 && !memcmp(request->dedup_key.data, dedup, 26));
    CHECK(!request->body.len && request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    owned_http *http = user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    inspect_owned(request, http->key);
    ++http->calls;
    *response = (br_http_response){.status = http->script->status};
    *error = http->script->send_error ? strdup(http->script->send_error) : NULL;
    return http->script->send_rc;
}

static void owned_release(void *user, br_http_response *response)
{
    owned_http *http = user;
    ++http->releases;
    *response = (br_http_response){0};
}

static void owned_destroy(void *user)
{
    owned_http *http = user;
    *http->destroyed = true;
    free(http);
}

static void verification(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "proxycrawl %s", key);
    const owned_case cases[] = {{200, 0, NULL}, {299, 0, NULL}, {199, 0, NULL}, {401, 0, NULL}, {500, 1, "down"}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        bool destroyed = false;
        owned_http *http = calloc(1, sizeof(*http));
        CHECK(http);
        http->script = &cases[i];
        http->key = key;
        http->destroyed = &destroyed;
        br_http_owned_backend backend = {{http, owned_send, owned_release}, owned_destroy};
        br_http_client *client = NULL;
        char *error = NULL;
        CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &error) == 0 && client && !error);
        br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
        test_key_result(&results.items[0], 440, key, "key");
        CHECK(results.items[0].verified == (cases[i].send_rc == 0 && cases[i].status >= 200 && cases[i].status < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
        CHECK(br_http_client_drain(client, &error) == 0 && !error);
        br_http_client_destroy(client);
        CHECK(destroyed);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    test_http borrowed = {.response = {.status = 200}};
    br_transport transport = test_transport(&borrowed);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !borrowed.calls && borrowed.releases == 1 && !results.items[0].verified);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("ProxyCrawl");
}
