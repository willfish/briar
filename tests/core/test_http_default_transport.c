/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL default HTTP boundary:%d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

typedef struct { unsigned calls, releases, empty_releases; bool destroyed, send_error; } fixture;
static const unsigned char body[] = {'x', 0, 'y'};

static int injected_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    fixture *f = user; CHECK(!f->destroyed); ++f->calls;
    /* Ordinary injection preserves the caller context; the represented client
     * budget is in request.timeout_ms, not an owned-flight context deadline. */
    CHECK(ctx && ctx->deadline_monotonic_ms == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "http://127.0.0.1:1/offline"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms > 0 && request->timeout_ms <= 5000);
    CHECK(!request->dedup_key.len && !request->body.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog default-fixture"));
    *response = (br_http_response){.status = 201, .body = {body, sizeof(body)}, .body_error = "read failure"};
    *error = f->send_error ? strdup("send failure") : NULL;
    CHECK(!f->send_error || *error);
    return f->send_error ? 1 : 0;
}

static void injected_release(void *user, br_http_response *response)
{
    fixture *f = user; CHECK(!f->destroyed);
    if (!response->status) {
        CHECK(!response->body.data && !response->body.len && !response->body_error);
        ++f->empty_releases;
        return;
    }
    ++f->releases;
    CHECK(response->status == 201 && response->body.len == sizeof(body) && response->body_error);
    memset(response, 0, sizeof(*response));
}

static void injected_destroy(void *user)
{
    fixture *f = user; CHECK(!f->destroyed && f->calls == f->releases); f->destroyed = true;
}

static void rejected(const br_scan_ctx *ctx, const br_http_request *request, const char *cause)
{
    br_http_response response = {.status = 123}; char *error = NULL;
    CHECK(br_http_default_transport_5s_send(ctx, request, &response, &error) && error && !strcmp(error, cause));
    CHECK(!response.status && !response.body.data && !response.body.len && !response.body_error);
    free(error);
    br_http_release(ctx, &response); /* Every send, including an empty rejected response. */
}

int main(void)
{
    fixture f = {0}; br_transport transport = {&f, injected_send, injected_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "default-fixture"};
    br_http_request request = {.method = "GET", .url = "http://127.0.0.1:1/offline",
        .profile = BR_HTTP_SANE, .timeout_ms = 5000};
    rejected(NULL, &request, "invalid HTTP arguments");
    br_scan_ctx missing = {0}; rejected(&missing, &request, "HTTP transport not installed");
    for (unsigned i = 0; i < 2; ++i) {
        br_http_response response = {0}; char *error = NULL; f.send_error = i != 0;
        CHECK((br_http_default_transport_5s_send(&ctx, &request, &response, &error) != 0) == f.send_error);
        CHECK(f.send_error ? error && !strcmp(error, "send failure") : error == NULL);
        CHECK(response.status == 201 && response.body.len == sizeof(body) && !memcmp(response.body.data, body, sizeof(body)));
        CHECK(response.body_error && !strcmp(response.body_error, "read failure"));
        free(error); br_http_release(&ctx, &response);
    }
    CHECK(f.calls == 2 && f.releases == 2);
    request.timeout_ms = 0;
    rejected(&ctx, &request, "unsupported: default-transport request projection");
    request.timeout_ms = 5000; request.profile = BR_HTTP_DETECTOR_LOCAL;
    rejected(&ctx, &request, "unsupported: default-transport request projection");
    request.profile = BR_HTTP_SANE; request.dedup_key = (br_slice){(const unsigned char *)"key", 3};
    rejected(&ctx, &request, "unsupported HTTP request coalescing"); request.dedup_key = (br_slice){0};
    CHECK(f.calls == 2 && f.releases == 2 && f.empty_releases == 3);
    br_http_client *owned = NULL; char *error = NULL;
    br_http_owned_backend backend = {.transport = transport, .destroy = injected_destroy};
    CHECK(!br_http_client_init(&owned, backend, BR_HTTP_SANE, &error) && owned && !error);
    ctx.transport = br_http_client_transport(owned);
    rejected(&ctx, &request, "unsupported: default-transport HTTP client policy");
    CHECK(f.calls == 2 && f.releases == 2);
    br_http_client_destroy(owned); CHECK(f.destroyed);
    const br_transport *raw = br_curl_transport_init(&error); CHECK(raw && !error);
    ctx.transport = raw; rejected(&ctx, &request, "unsupported: default-transport HTTP client policy");
    br_transport copied = *raw; ctx.transport = &copied;
    rejected(&ctx, &request, "unsupported: default-transport HTTP client policy");
    backend = (br_http_owned_backend){.transport = *raw}; owned = NULL;
    CHECK(!br_http_client_init(&owned, backend, BR_HTTP_SANE, &error) && owned && !error);
    ctx.transport = br_http_client_transport(owned);
    rejected(&ctx, &request, "unsupported: default-transport HTTP client policy");
    br_http_client_destroy(owned); curl_global_cleanup();
    printf("Default-transport five-second byte boundary: %u assertions, 0 failures; known native/owned paths rejected before I/O\n", assertions);
    return 0;
}
