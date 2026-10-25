/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const br_transport *br_curl_transport_init(char **error);

static size_t assertions;
#define CHECK(expr) do { ++assertions; if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)

typedef struct {
    const br_transport *curl;
    size_t sends, releases;
    int send_rc, status;
    bool body_error;
} observed_transport;

static int send_observed(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    observed_transport *observed = user;
    ++observed->sends;
    observed->send_rc = observed->curl->send(observed->curl->user, ctx, request, response, error);
    observed->status = response->status;
    observed->body_error = response->body_error != NULL;
    return observed->send_rc;
}

static void release_observed(void *user, br_http_response *response)
{
    observed_transport *observed = user;
    ++observed->releases;
    observed->curl->release(observed->curl->user, response);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    CHECK(getenv("BRIAR_TEST_ISOLATED_NET") && !strcmp(getenv("BRIAR_TEST_ISOLATED_NET"), "1"));
    const char *proxy = getenv("https_proxy");
    CHECK(proxy && !strncmp(proxy, "http://127.0.0.1:", strlen("http://127.0.0.1:")));
    CHECK(!strcmp(argv[1], "239") || !strcmp(argv[1], "384"));
    int32_t type = !strcmp(argv[1], "239") ? 239 : 384;
    char *error = NULL;
    const br_detector *const *registry = NULL;
    size_t count = 0;
    CHECK(!br_registry(&registry, &count, &error) && !error);
    const br_detector *detector = NULL;
    for (size_t i = 0; i < count; ++i)
        if (registry[i]->type == type) detector = registry[i];
    CHECK(detector != NULL);
    observed_transport observed = { .curl = br_curl_transport_init(&error) };
    CHECK(observed.curl && !error);
    const br_transport transport = { &observed, send_observed, release_observed };
    br_scan_ctx ctx = { .transport = &transport };
    char key[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y";
    key[type == 239 ? 40 : 32] = '\0';
    char input[96];
    int n = snprintf(input, sizeof(input), "%s key = %s", detector->keywords[0], key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = {0};
    CHECK(!detector->scan(detector, &ctx, true,
                          (br_slice){ (const unsigned char *)input, (size_t)n }, &results, &error));
    CHECK(!error && results.len == 1);
    const br_result *result = &results.items[0];
    printf("%s CONNECT 200 then TLS failure: transport_rc=%d, origin_status=%d, body_error=%d, verified=%d, verification_error=%d\n",
           detector->name, observed.send_rc, observed.status, observed.body_error,
           result->verified, result->verification_error != NULL);
    CHECK(observed.sends == 1 && observed.releases == 1);
    CHECK(observed.send_rc != 0);
    CHECK(observed.status == 0 && !observed.body_error);
    CHECK(!result->verified);
    CHECK(result->verification_error && *result->verification_error);
    CHECK(!strstr(result->verification_error, key));
    br_results_clear(&results);
    curl_global_cleanup();
    printf("proxy CONNECT regression: %zu assertions, 0 failures\n", assertions);
    return 0;
}
