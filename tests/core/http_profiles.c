/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"
#include "../../src/detectors/detectors.h"

#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned assertions;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL native HTTP profile:%d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static int64_t now_ms(void)
{
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

typedef struct { int fd; int64_t at; unsigned calls; } cancellation;
static bool cancel_waiter(void *user)
{
    cancellation *cancel = user;
    CHECK(++cancel->calls == 1);
    cancel->at = now_ms();
    CHECK(write(cancel->fd, "c", 1) == 1);
    return true; /* Work is already registered; its cloned context is detached. */
}

static bool cancel_on_request(void *user)
{
    int *fd = user;
    char byte;
    ssize_t n = read(*fd, &byte, 1);
    CHECK((n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) || (n == 1 && byte == 'r'));
    return n == 1;
}

static int failure_case(const char *mode, const char *url)
{
    char *error = NULL;
    const br_transport *raw = br_curl_transport_init(&error);
    CHECK(raw && !error);
    bool owned = !strcmp(mode, "failure-owned-short");
    br_http_client *client = NULL;
    if (owned) {
        br_http_owned_backend backend = {.transport = *raw};
        CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    }
    br_scan_ctx ctx = {.transport = owned ? br_http_client_transport(client) : raw,
                       .user_agent = "native-http-fixture"};
    int ready_fd = -1;
    if (!strcmp(mode, "failure-cancel")) {
        CHECK(getenv("BRIAR_TEST_READY_FD"));
        ready_fd = atoi(getenv("BRIAR_TEST_READY_FD"));
        ctx.cancelled = cancel_on_request; ctx.cancel_user = &ready_fd;
    }
    br_header authorization = {"Authorization", "Bearer synthetic-only"};
    bool sensitive = !strcmp(mode, "failure-sensitive");
    br_http_request request = {.method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .headers = sensitive ? &authorization : NULL, .nheaders = sensitive ? 1 : 0,
        .timeout_ms = strstr(mode, "timeout") ? 500 : 5000};
    if (owned) request.dedup_key = (br_slice){(const unsigned char *)"offline", 7};
    if (!strcmp(mode, "failure-method")) request.method = "PUT";
    if (!strcmp(mode, "failure-get-body")) request.body = (br_slice){(const unsigned char *)"x", 1};
    br_http_response response = {0};
    int rc = br_http_send(&ctx, &request, &response, &error);
    bool body_error = !strcmp(mode, "failure-short") || !strcmp(mode, "failure-body-limit") ||
                      !strcmp(mode, "failure-body-timeout") || !strcmp(mode, "failure-gzip");
    bool status = !strncmp(mode, "failure-status-", 15);
    bool informational = !strcmp(mode, "failure-informational");
    bool gzip = !strcmp(mode, "failure-gzip-ok");
    if (body_error || status || informational || gzip) {
        CHECK(!rc && !error);
        CHECK(response.status == (status ? atoi(mode + 15) : 200));
        CHECK((response.body_error != NULL) == body_error);
        if (body_error) CHECK(*response.body_error);
        if (!strcmp(mode, "failure-short") || !strcmp(mode, "failure-body-timeout"))
            CHECK(response.body.len == 1 && response.body.data[0] == 'r');
        if (!strcmp(mode, "failure-body-limit")) {
            CHECK(!strcmp(response.body_error, "unsupported: HTTP body exceeds 8 MiB"));
            CHECK(response.body.len > 0 && response.body.len <= 8 * 1024 * 1024);
        }
        if (gzip) {
            static const char decoded[] = "decoded\0body";
            CHECK(response.body.len == sizeof(decoded) - 1 && !memcmp(response.body.data, decoded, sizeof(decoded) - 1));
        }
        if (informational) {
            unsigned duplicates = 0;
            for (size_t i = 0; i < response.nheaders; ++i) {
                CHECK(strcmp(response.headers[i].name, "X-Old"));
                if (!strcmp(response.headers[i].name, "X-Repeat")) ++duplicates;
            }
            CHECK(duplicates == 2);
        }
    } else {
        CHECK(rc != 0 && error && *error);
        CHECK(!response.body_error);
        if (owned) CHECK(!response.status && !response.body.data);
        if (!strcmp(mode, "failure-method") || !strcmp(mode, "failure-get-body"))
            CHECK(!strcmp(error, "unsupported: curl adapter supports bodyless GET or POST"));
        if (!strcmp(mode, "failure-incomplete")) {
            CHECK(response.status == 200 && !response.body.data);
            CHECK(!strcmp(error, "incomplete HTTP response headers"));
        }
        if (!strcmp(mode, "failure-refused"))
            CHECK(!strcmp(error, curl_easy_strerror(CURLE_COULDNT_CONNECT)));
        if (!strcmp(mode, "failure-timeout"))
            CHECK(!strcmp(error, "context deadline exceeded") || !strcmp(error, curl_easy_strerror(CURLE_OPERATION_TIMEDOUT)));
        if (!strcmp(mode, "failure-headers")) CHECK(!strcmp(error, "unsupported: HTTP headers exceed 64 KiB"));
        if (!strcmp(mode, "failure-loop")) CHECK(!strcmp(error, "stopped after 10 redirects"));
        if (sensitive) CHECK(!strcmp(error, "unsupported: redirects with sensitive HTTP headers"));
        if (!strcmp(mode, "failure-cancel")) CHECK(!strcmp(error, "context canceled"));
        CHECK(!strstr(error, "synthetic-only"));
    }
    free(error);
    br_http_release(&ctx, &response);
    CHECK(!response.status && !response.body.data && !response.body_error && !response.headers && !response.nheaders);
    br_http_client_destroy(client);
    curl_global_cleanup();
    printf("Native HTTP %s: %u assertions, 0 failures\n", mode, assertions);
    return 0;
}

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    CHECK(getenv("BRIAR_TEST_ISOLATED_NET") && !strcmp(getenv("BRIAR_TEST_ISOLATED_NET"), "1"));
    CHECK(!strncmp(argv[2], "http://127.0.0.1:", sizeof("http://127.0.0.1:") - 1));
    if (!strncmp(argv[1], "failure-", 8)) return failure_case(argv[1], argv[2]);
    bool runtime_gitter = !strcmp(argv[1], "runtime-gitter");
    bool runtime_unknown = !strcmp(argv[1], "runtime-unknown");
    bool runtime_cancel = !strcmp(argv[1], "runtime-cancel-drain");
    bool runtime_mode = !strcmp(argv[1], "runtime-success") || !strcmp(argv[1], "runtime-redirect") || runtime_unknown || runtime_cancel || runtime_gitter;
    bool owned_mode = !strcmp(argv[1], "SANE-owned") || !strcmp(argv[1], "SANE-owned-redirect") || runtime_mode;
    bool owned_redirect = !strcmp(argv[1], "SANE-owned-redirect") || !strcmp(argv[1], "runtime-redirect");
    bool sane = !strcmp(argv[1], "SANE") || owned_mode, public = !strcmp(argv[1], "PUBLIC");
    bool short_body = !strcmp(argv[1], "LOCAL-short");
    bool length_get = !strcmp(argv[1], "SANE-length-GET");
    bool length_post = !strcmp(argv[1], "SANE-length-POST");
    bool post = !strcmp(argv[1], "SANE-POST") || !strcmp(argv[1], "LOCAL-POST") ||
                !strcmp(argv[1], "SANE-POST-empty") || !strcmp(argv[1], "SANE-POST-type") ||
                !strcmp(argv[1], "SANE-POST-redirect") || length_post;
    bool post_empty = !strcmp(argv[1], "SANE-POST-empty");
    bool post_type = !strcmp(argv[1], "SANE-POST-type");
    bool post_redirect = !strcmp(argv[1], "SANE-POST-redirect");
    if ((post && strcmp(argv[1], "LOCAL-POST")) || length_get) sane = true;
    CHECK(sane || public || short_body || !strcmp(argv[1], "LOCAL") || post);
    char *error = NULL;
    br_native_http *runtime = NULL;
    if (runtime_mode) CHECK(!br_native_http_init(&runtime, &error) && runtime && !error);
    const br_transport *transport = runtime_mode ? br_native_http_raw(runtime) : br_curl_transport_init(&error);
    CHECK(transport != NULL && error == NULL);
    br_http_client *client = NULL;
    if (owned_mode && !runtime_mode) {
        br_http_owned_backend backend = {.transport = *transport}; /* Null curl userdata; process lifetime. */
        CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
        transport = br_http_client_transport(client);
    }
    br_scan_ctx ctx = {.transport = transport, .user_agent = "native-http-fixture"};
    br_detector unknown = {0};
    if (runtime_mode) {
        const br_detector *detector = NULL;
        int init = runtime_gitter ? br_gitter_init(&detector, &error) : br_geocode_init(&detector, &error);
        CHECK(!init && detector && !error);
        if (runtime_unknown) { unknown = *detector; detector = &unknown; }
        br_native_http_bind(runtime, detector, &ctx);
        CHECK(br_http_client_is_owned(ctx.transport) == !runtime_unknown);
    }
    cancellation cancel = {0};
    if (runtime_cancel) {
        CHECK(getenv("BRIAR_TEST_CANCEL_FD"));
        cancel.fd = atoi(getenv("BRIAR_TEST_CANCEL_FD"));
        ctx.cancelled = cancel_waiter; ctx.cancel_user = &cancel;
    }
    static const unsigned char payload[] = "synthetic\0body";
    const br_header content_type = {"Content-Type", "application/json"};
    const br_header length_override = {"Content-Length", "9999"};
    br_http_request request = {
        .method = post ? "POST" : "GET", .url = argv[2],
        .headers = post_type ? &content_type : length_get || length_post ? &length_override : NULL,
        .nheaders = post_type || length_get || length_post ? 1 : 0,
        .body = {post ? payload : NULL, post && !post_empty ? sizeof(payload) - 1 : 0},
        .profile = public ? BR_HTTP_DETECTOR_PUBLIC : sane ? BR_HTTP_SANE : BR_HTTP_DETECTOR_LOCAL,
    };
    if (owned_mode) request.dedup_key = runtime_gitter ?
        (br_slice){(const unsigned char *)"555:native", sizeof("555:native") - 1} :
        (br_slice){(const unsigned char *)"486:native", sizeof("486:native") - 1};
    br_http_response response = {0};
    int rc = br_http_send(&ctx, &request, &response, &error);
    if (runtime_unknown || runtime_cancel) {
        CHECK(rc != 0 && error && !strcmp(error, runtime_unknown ? "unsupported HTTP request coalescing" : "context canceled"));
        CHECK(!response.status && !response.body.data && !response.body_error);
        if (runtime_cancel) CHECK(cancel.calls == 1 && cancel.at > 0);
    } else if (owned_redirect) {
        CHECK(rc != 0 && error && !strcmp(error, "unsupported: native coalesced HTTP redirects"));
        CHECK(response.status == 0 && !response.body.data && !response.body_error);
    } else if (post_redirect) {
        CHECK(rc != 0);
        CHECK(error && !strcmp(error, "unsupported: redirects for native HTTP POST"));
        CHECK(response.status == 302 && response.body_error == NULL);
    } else if (public) {
        CHECK(rc != 0);
        CHECK(error && !strcmp(error, "unsupported: native curl HTTP client profile"));
        CHECK(response.status == 0 && response.body.data == NULL);
    } else {
        CHECK(rc == 0 && error == NULL);
        CHECK(response.status == (sane || post ? 200 : 302));
        if (short_body) {
            CHECK(response.body_error != NULL);
            CHECK(response.body.len == 1 && response.body.data[0] == 'r');
        } else {
            const char *expected = post ? "posted-body" : sane ? "destination-body" : "redirect-body";
            CHECK(response.body_error == NULL);
            CHECK(response.body.len == strlen(expected));
            CHECK(!memcmp(response.body.data, expected, response.body.len));
        }
    }
    free(error);
    br_http_release(&ctx, &response);
    CHECK(response.status == 0 && response.body.data == NULL && response.body_error == NULL);
    if (public) {
        /* Owned coalescing must preserve PUBLIC, not turn its native rejection
         * into either a borrowed-key guard or an accidental SANE request. */
        br_http_owned_backend backend = {.transport = *transport};
        error = NULL;
        CHECK(!br_http_client_init(&client, backend, BR_HTTP_DETECTOR_PUBLIC, &error) && client && !error);
        br_scan_ctx owned = ctx; owned.transport = br_http_client_transport(client);
        request.dedup_key = (br_slice){(const unsigned char *)"1061:PUBLIC:token", sizeof("1061:PUBLIC:token") - 1};
        CHECK(br_http_send(&owned, &request, &response, &error) != 0);
        CHECK(error && !strcmp(error, "unsupported: native curl HTTP client profile"));
        CHECK(!response.status && !response.body.data && !response.body_error);
        free(error); br_http_release(&owned, &response);
    }
    br_http_client_destroy(client); /* Drain workers before the curl lifetime ends. */
    br_native_http_destroy(runtime);
    if (!runtime_mode) curl_global_cleanup();
    /* The server waits for the cancellation byte, then delays its response.
     * Measure from that event, not from a scheduler-sensitive destroy entry. */
    if (runtime_cancel) CHECK(now_ms() - cancel.at >= 50);
    printf("Native HTTP %s: %u assertions, 0 failures\n", argv[1], assertions);
    return 0;
}
