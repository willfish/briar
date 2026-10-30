/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_json;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
#define br_json_first_document first_hook
#include "../../src/detectors/spotifykey.c"
#undef br_json_first_document

static const char secret[] = "MJsy6euxw0GKljGYZLZGnn0PvKuZB0V8";
static const char id[] = "JykXADk7r8ZegkS0emhtpFSWNqGVAIgm";
static int check_lifetime;
static const unsigned char *held_body;
static size_t held_len;
static const char *held_auth;

static void spotify_release(void *user, br_http_response *response)
{
    if (check_lifetime) {
        CHECK(held_body && held_len == strlen("grant_type=client_credentials"));
        CHECK(!memcmp(held_body, "grant_type=client_credentials", held_len));
        CHECK(held_auth && !strncmp(held_auth, "Basic ", 6));
    }
    test_http_release(user, response);
}

static int spotify_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    test_http *http = user;
    int mode = http->user ? *(int *)http->user : 0;
    bool header = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization")) header = true;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://accounts.spotify.com/api/token"));
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 90);
    CHECK(!ctx->cancelled && !strcmp(ctx->user_agent, "spotify-offline"));
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    if (header) {
        char *authorization = NULL; char *auth_error = NULL;
        CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, 32},
                                 (br_slice){(const unsigned char *)secret, 32},
                                 &authorization, &auth_error) == 0 && !auth_error);
        CHECK(request->nheaders == 3 && !strcmp(request->headers[1].value, authorization));
        CHECK(request->body.len == strlen("grant_type=client_credentials") &&
              !memcmp(request->body.data, "grant_type=client_credentials", request->body.len));
        free(authorization);
    } else {
        char body[128];
        snprintf(body, sizeof(body), "client_id=%s&client_secret=%s&grant_type=client_credentials", id, secret);
        CHECK(request->nheaders == 2 && request->body.len == strlen(body) &&
              !memcmp(request->body.data, body, request->body.len));
    }
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent") &&
          !strcmp(request->headers[request->nheaders - 1].value, "TruffleHog spotify-offline"));
    static const char bearer[] = "{\"access_token\":\"tok\"}";
    static const char mac[] = "{\"access_token\":\"tok\",\"token_type\":\"mac\"}";
    static const char form_body[] = "access_token=tok&token_type=bearer";
    static const br_header form_headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    http->response.headers = NULL; http->response.nheaders = 0;
    http->response.status = 200;
    http->response.body = (br_slice){(const unsigned char *)bearer, sizeof(bearer) - 1};
    if (mode == 1) http->response.body = (br_slice){(const unsigned char *)mac, sizeof(mac) - 1};
    if (mode == 4) {
        http->response.headers = form_headers; http->response.nheaders = 1;
        http->response.body = (br_slice){(const unsigned char *)form_body, sizeof(form_body) - 1};
    }
    if (mode == 5) {
        static const char kept[] = "{\"access_token\":\"keep\",\"access_token\":null}";
        http->response.body = (br_slice){(const unsigned char *)kept, sizeof(kept) - 1};
    }
    if (mode == 6) {
        static const char nul_access[] = "{\"access_token\":\"\\u0000tok\"}";
        http->response.body = (br_slice){(const unsigned char *)nul_access, sizeof(nul_access) - 1};
    }
    if (mode == 7) {
        static const char nul_type[] = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\\u0000x\"}";
        http->response.body = (br_slice){(const unsigned char *)nul_type, sizeof(nul_type) - 1};
    }
    if (mode == 8) {
        static const char kept_mac[] = "{\"token_type\":\"mac\",\"token_type\":null,\"access_token\":\"tok\"}";
        http->response.body = (br_slice){(const unsigned char *)kept_mac, sizeof(kept_mac) - 1};
    }
    if (mode == 9) {
        static const char nul_error[] = "{\"access_token\":\"tok\",\"error\":\"\\u0000\"}";
        http->response.body = (br_slice){(const unsigned char *)nul_error, sizeof(nul_error) - 1};
    }
    if (check_lifetime && header) {
        held_body = request->body.data;
        held_len = request->body.len;
        held_auth = NULL;
        for (size_t i = 0; i < request->nheaders; ++i)
            if (!strcmp(request->headers[i].name, "Authorization")) held_auth = request->headers[i].value;
    }
    if ((mode == 2 && header) || mode == 3) {
        http->response.status = 401;
        http->response.body = (br_slice){0};
    }
    return test_http_send(http, ctx, request, response, error);
}

int main(void)
{
    CHECK(strlen(secret) == 32 && strlen(id) == 32);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_spotifykey_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 90 && !strcmp(detector->name, "SpotifyKey"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "spotify"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(br_spotifykey_init(NULL, &error) != 0 && error); free(error);
    char input[180];
    snprintf(input, sizeof(input), "secret %s%*s id %s", secret, 41, "", id);
    br_results results = {0};
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "cannot create context from nil parent") && !results.len);
    free(error); error = NULL;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                        &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "cannot create context from nil parent"));
    free(error);
    br_scan_ctx quiet = {0};
    results = test_scan(detector, &quiet, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 90, secret, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "secret %s secret %s%*s id %s", secret, secret, 41, "", id);
    results = test_scan(detector, &quiet, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "spotify %s id %s", secret, id);
    results = test_scan(detector, &quiet, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "secret %s%*s id %s", secret, 41, "", id);

    int mode = 0;
    test_http http = {.user = &mode};
    br_transport transport = {&http, spotify_send, spotify_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "spotify-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    mode = 1; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);
    mode = 2; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 2);
    br_results_clear(&results);
    mode = 3; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == 2);
    br_results_clear(&results);
    mode = 4; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    mode = 5; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    mode = 6; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    mode = 7; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);
    mode = 8; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);
    mode = 9; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == 2);
    br_results_clear(&results);
    mode = 0; check_lifetime = 1; held_body = NULL; held_auth = NULL; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    check_lifetime = 0;
    http.calls = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    br_results_clear(&results);
    force_json = 2;
    mode = 0;
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("SpotifyKey");
}
