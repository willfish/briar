/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"

#include <curl/curl.h>
#include <json-c/json.h>
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

static const br_http_request *post_request;
static const br_transport *post_transport;

static bool caller_cancelled(void *user) { ++*(unsigned *)user; return true; }

static int post_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    fixture *f = user; CHECK(!f->destroyed); ++f->calls;
    CHECK(ctx && ctx->transport == post_transport && !ctx->cancelled && !ctx->cancel_user);
    CHECK(!ctx->deadline_monotonic_ms && !ctx->user_agent && !ctx->endpoints && !ctx->options);
    CHECK(request == post_request && request->profile == BR_HTTP_PRIVATE_DEFAULT_CLIENT && !request->timeout_ms);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "http://127.0.0.1:1/offline"));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json") && !request->dedup_key.len);
    CHECK(request->body.data == body && request->body.len == sizeof(body));
    *response = (br_http_response){.status = 201, .body = {body, sizeof(body)}, .body_error = "ignored read failure"};
    *error = f->send_error ? strdup("unmodified DefaultClient cause") : NULL;
    CHECK(!f->send_error || *error);
    return f->send_error ? -7 : 0;
}

static void rejected_default(const br_scan_ctx *ctx, const br_http_request *request, const char *cause)
{
    br_http_response response = {.status = 123}; char *error = NULL;
    CHECK(br_http_default_client_send(ctx, request, &response, &error) != 0 && error && !strcmp(error, cause));
    CHECK(!response.status && !response.body.data && !response.body.len && !response.body_error);
    free(error); br_http_release(ctx, &response);
}

static void default_client(void)
{
    fixture f = {0}; br_transport transport = {&f, post_send, injected_release};
    br_json *options = json_object_new_object(); CHECK(options);
    br_endpoints endpoints = {0}; unsigned cancellations = 0;
    br_scan_ctx ctx = {.transport = &transport, .cancelled = caller_cancelled, .cancel_user = &cancellations,
        .deadline_monotonic_ms = 1, .user_agent = "bad\r\nignored", .options = options, .endpoints = &endpoints};
    const br_header headers[] = {{"Content-Type", "application/json"}};
    br_http_request request = {.method = "POST", .url = "http://127.0.0.1:1/offline", .headers = headers,
        .nheaders = 1, .body = {body, sizeof(body)}, .profile = BR_HTTP_PRIVATE_DEFAULT_CLIENT, .detector_type = 355};
    post_request = &request; post_transport = &transport;
    rejected_default(NULL, &request, "HTTP transport not installed");
    br_scan_ctx missing = {0}; rejected_default(&missing, &request, "HTTP transport not installed");
    rejected_default(&ctx, NULL, "invalid HTTP arguments");
    for (unsigned i = 0; i < 2; ++i) {
        br_http_response response = {0}; char *error = NULL; f.send_error = i != 0;
        CHECK(br_http_default_client_send(&ctx, &request, &response, &error) == (i ? -7 : 0));
        CHECK(!cancellations && f.calls == i + 1 && f.releases == i);
        CHECK(i ? error && !strcmp(error, "unmodified DefaultClient cause") : !error);
        CHECK(response.status == 201 && response.body.data == body && response.body_error);
        CHECK(ctx.cancelled == caller_cancelled && ctx.deadline_monotonic_ms == 1 && ctx.options == options && ctx.endpoints == &endpoints);
        free(error); br_http_release(&ctx, &response);
    }
    br_http_request invalid = request; invalid.timeout_ms = 5000;
    rejected_default(&ctx, &invalid, "unsupported: default-client request projection");
    invalid = request; invalid.profile = BR_HTTP_SANE;
    rejected_default(&ctx, &invalid, "unsupported: default-client request projection");
    invalid = request; invalid.dedup_key = (br_slice){body, sizeof(body)};
    rejected_default(&ctx, &invalid, "unsupported HTTP request coalescing");
    const br_header extra[] = {{"Content-Type", "application/json"}, {"User-Agent", "TruffleHog"}};
    invalid = request; invalid.headers = extra; invalid.nheaders = 2;
    rejected_default(&ctx, &invalid, "unsupported: default-client request projection");
    CHECK(f.calls == 2 && f.releases == 2 && !cancellations);
    /* This tag can never slip through ordinary public profile preparation. */
    br_http_response response = {0}; char *error = NULL;
    CHECK(br_http_send(&ctx, &request, &response, &error) != 0 && error && !strcmp(error, "unsupported HTTP client profile"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    const br_http_profile profiles[] = {BR_HTTP_SANE, BR_HTTP_DETECTOR_LOCAL, BR_HTTP_DETECTOR_PUBLIC};
    for (size_t i = 0; i < sizeof(profiles) / sizeof(*profiles); ++i) {
        fixture backend_fixture = {0};
        br_http_owned_backend backend = {.transport = {&backend_fixture, injected_send, injected_release}, .destroy = injected_destroy};
        br_http_client *client = NULL;
        CHECK(!br_http_client_init(&client, backend, profiles[i], &error) && client && !error);
        br_scan_ctx owned_ctx = {.transport = br_http_client_transport(client)};
        rejected_default(&owned_ctx, &request, "unsupported: default-client HTTP policy");
        br_transport copied = *owned_ctx.transport; owned_ctx.transport = &copied;
        rejected_default(&owned_ctx, &request, "unsupported: default-client HTTP policy");
        CHECK(!backend_fixture.calls && !backend_fixture.releases);
        br_http_client_destroy(client); CHECK(backend_fixture.destroyed);
    }
    const br_transport *raw = br_curl_transport_init(&error); CHECK(raw && !error);
    br_scan_ctx native = {.transport = raw};
    rejected_default(&native, &request, "unsupported: default-client HTTP policy");
    br_transport copied = *raw; native.transport = &copied;
    rejected_default(&native, &request, "unsupported: default-client HTTP policy");
    curl_global_cleanup();
    CHECK(f.calls == 2 && f.releases == 2 && !cancellations);
    json_object_put(options); post_request = NULL; post_transport = NULL;
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
    default_client();
    printf("Default-transport five-second and DefaultClient background byte boundaries: %u assertions, 0 failures; known native/owned paths rejected before I/O\n", assertions);
    return 0;
}
