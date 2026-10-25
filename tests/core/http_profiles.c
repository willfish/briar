/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const br_transport *br_curl_transport_init(char **error);
static unsigned assertions;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL native HTTP profile:%d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    CHECK(getenv("BRIAR_TEST_ISOLATED_NET") && !strcmp(getenv("BRIAR_TEST_ISOLATED_NET"), "1"));
    CHECK(!strncmp(argv[2], "http://127.0.0.1:", sizeof("http://127.0.0.1:") - 1));
    bool sane = !strcmp(argv[1], "SANE"), public = !strcmp(argv[1], "PUBLIC");
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
    const br_transport *transport = br_curl_transport_init(&error);
    CHECK(transport != NULL && error == NULL);
    br_scan_ctx ctx = {.transport = transport, .user_agent = "native-http-fixture"};
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
    br_http_response response = {0};
    int rc = br_http_send(&ctx, &request, &response, &error);
    if (post_redirect) {
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
    curl_global_cleanup();
    printf("Native HTTP %s: %u assertions, 0 failures\n", argv[1], assertions);
    return 0;
}
