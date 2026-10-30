/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_redhatpyxis_init(const br_detector **out, char **error);

static const char token[] = "0123456789abcdef0123456789abcdef";
static const char other[] = "abcdefabcdefabcdefabcdefabcdefab";
static const char url[] =
    "https://catalog.redhat.com/api/containers/v1/projects/certification/requests/images?page_size=1&page=0";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 5);
    char copy[33]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 1055, expected, "key");
    CHECK(result->verified == verified);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(token) == 32 && strlen(other) == 32);
    CHECK(br_redhatpyxis_init(NULL, &error) == -1); free(error);
    CHECK(!br_redhatpyxis_init(&detector, &error) && !error);
    CHECK(detector->type == 1055 && !strcmp(detector->name, "RedHatPyxis") && detector->version == 0);
    CHECK(!strcmp(detector->description, "Red Hat Pyxis is a container certification and metadata management platform. Red Hat Pyxis API keys can be used to authenticate against the Red Hat Ecosystem Catalog APIs and access container certification resources and metadata."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "redhat") && !strcmp(detector->keywords[1], "pyxis"));
    CHECK(detector->max_credential_span == -1 && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "pyxis %s\nREDHAT %s\npyxis %s", token, other, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], token, false, NULL);
    check_result(&results.items[1], other, false, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "pyxis %s", "0123456789ABCDEF0123456789ABCDEF");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "catalog %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void borrowed_rejection(const br_detector *detector)
{
    char input[48]; snprintf(input, sizeof(input), "pyxis %s", token);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], token, false, "net/http: nil Context");
    br_results_clear(&results);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!http.calls && http.releases == 1 && results.len == 1);
    check_result(&results.items[0], token, false, "unsupported HTTP request coalescing");
    br_results_clear(&results);
}

typedef struct { int status; const char *body_error, *send_error; int fail_without_text; size_t calls, releases; const br_http_request *held; bool *destroyed; } owned_http;

static void inspect_owned(const br_http_request *request)
{
    unsigned char dedup[37];
    memcpy(dedup, "1055:", 5); memcpy(dedup + 5, token, 32);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->detector_type == 1055 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 5000);
    CHECK(request->dedup_key.len == 37 && !memcmp(request->dedup_key.data, dedup, 37));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    owned_http *http = user;
    CHECK(ctx && br_http_client_is_owned(ctx->transport) == false);
    CHECK(!http->held && http->calls == http->releases);
    inspect_owned(request);
    http->held = request; ++http->calls;
    *response = (br_http_response){.status = http->status, .body_error = http->body_error};
    *error = http->send_error ? strdup(http->send_error) : NULL;
    CHECK(!http->send_error || *error);
    if (http->fail_without_text) return 1;
    return http->send_error ? -1 : 0;
}

static void owned_release(void *user, br_http_response *response)
{
    owned_http *http = user;
    CHECK(http->held && response);
    http->held = NULL; ++http->releases;
    *response = (br_http_response){0};
}

static void owned_destroy(void *user)
{
    owned_http *http = user;
    CHECK(!http->held && http->calls == http->releases && !*http->destroyed);
    *http->destroyed = true; free(http);
}

static void owned_verification(const br_detector *detector)
{
    char input[48]; snprintf(input, sizeof(input), "redhat %s", token);
    const int codes[] = {200, 401, 403, 500};
    for (size_t i = 0; i < 4; ++i) {
        bool destroyed = false;
        owned_http *http = calloc(1, sizeof(*http)); CHECK(http);
        http->status = codes[i]; http->destroyed = &destroyed;
        br_http_owned_backend backend = {{http, owned_send, owned_release}, owned_destroy};
        br_http_client *client = NULL; char *error = NULL;
        CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
        br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
        CHECK(br_http_client_is_owned(ctx.transport));
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
        char cause[80]; const char *expected = NULL;
        if (codes[i] != 200 && codes[i] != 401) {
            snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", codes[i]);
            expected = cause;
        }
        check_result(&results.items[0], token, codes[i] == 200, expected);
        br_results_clear(&results);
        CHECK(!br_http_client_drain(client, &error) && !error);
        br_http_client_destroy(client); CHECK(destroyed);
    }
    bool destroyed = false;
    owned_http *http = calloc(1, sizeof(*http)); CHECK(http);
    http->status = 200; http->body_error = "read failed"; http->destroyed = &destroyed;
    br_http_owned_backend backend = {{http, owned_send, owned_release}, owned_destroy};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], token, false, "read failed");
    br_results_clear(&results);
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); CHECK(destroyed);
    destroyed = false;
    http = calloc(1, sizeof(*http)); CHECK(http);
    http->fail_without_text = 1; http->destroyed = &destroyed;
    backend = (br_http_owned_backend){{http, owned_send, owned_release}, owned_destroy};
    client = NULL; error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && !error);
    ctx = (br_scan_ctx){.transport = br_http_client_transport(client)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1);
    /* br_http_send supplies this when the mock diagnostic is NULL. */
    check_result(&results.items[0], token, false, "HTTP transport failed");
    br_results_clear(&results);
    CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); CHECK(destroyed);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); borrowed_rejection(detector); owned_verification(detector);
    return test_finish("RedHatPyxis dedup key + 200/401 + borrowed coalescing rejection");
}
