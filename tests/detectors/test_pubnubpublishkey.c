/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_pubnubpublishkey_init(const br_detector **out, char **error);

static void pub(char *out, char fill)
{
    memcpy(out, "pub-c-", 6);
    memset(out + 6, fill, 8);
    out[14] = '-';
    memset(out + 15, fill, 4);
    out[19] = '-';
    memset(out + 20, fill, 4);
    out[24] = '-';
    memset(out + 25, fill, 4);
    out[29] = '-';
    memset(out + 30, fill, 12);
    out[42] = '\0';
}

static void sub(char *out, char fill)
{
    memcpy(out, "sub-c-", 6);
    memset(out + 6, fill, 8);
    out[14] = '-';
    memset(out + 15, fill, 4);
    out[19] = '-';
    memset(out + 20, fill, 4);
    out[24] = '-';
    memset(out + 25, fill, 4);
    out[29] = '-';
    memset(out + 30, fill, 12);
    out[42] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *const *parts = http->user;
    char url[192];
    snprintf(url, sizeof(url),
             "https://ps.pndsn.com/signal/%s/%s/0/ch1/0/%%22typing_on%%22?uuid=user-123",
             parts[0], parts[1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 82 && request->nheaders == 1);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_pubnubpublishkey_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 82 && !strcmp(detector->keywords[0], "sub-c-"));
    CHECK(detector->max_credential_span == 1024);
    char publish[43], subscribe[43], input[256];
    pub(publish, 'a');
    sub(subscribe, 'b');
    snprintf(input, sizeof(input), "%s %s", publish, subscribe);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    CHECK(found.items[0].raw.len == 42 && !memcmp(found.items[0].raw.data, publish, 42));
    CHECK(found.items[0].raw_v2.len == 85 && found.items[0].raw_v2.data[42] == '/');
    CHECK(!memcmp(found.items[0].raw_v2.data, publish, 42));
    CHECK(!memcmp(found.items[0].raw_v2.data + 43, subscribe, 42));
    br_results_clear(&found);
    snprintf(input, sizeof(input), "%s", publish);
    br_results alone = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(alone.len == 0);
    br_results_clear(&alone);
    snprintf(input, sizeof(input), "%s %s %s %s", publish, publish, subscribe, subscribe);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 4);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "%s %s", publish, subscribe);
    const char *parts[] = {publish, subscribe};
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {299, true, NULL}, {400, false, NULL}, {403, false, NULL},
        {401, false, "unexpected HTTP response status 401"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect_request, .user = parts};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && http.calls == 1);
        if (cases[i].cause) CHECK(!strcmp(results.items[0].verification_error, cases[i].cause));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 1 && !nil.items[0].verified);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(!strcmp(nil.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil);
    return test_finish("PubNubPublishKey");
}
