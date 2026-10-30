/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_octopusdeploy_init(const br_detector **out, char **error);

static char token[39], other[34];
static const char domain[] = "fixture-a.octopus.app";
static const char other_domain[] = "fixture-b.octopus.app";

static void make_token(char *out, size_t count, size_t shift)
{
    static const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    memcpy(out, "API-", 4);
    for (size_t i = 0; i < count; ++i) out[4 + i] = chars[(i + shift) % (sizeof(chars) - 1)];
    out[4 + count] = '\0';
}

static const char *part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void finding(const br_result *result, const char *key, const char *host,
                    bool verified, const char *cause)
{
    size_t k = strlen(key), d = strlen(host);
    CHECK(result->detector_type == 1056);
    CHECK(result->raw.len == k && !memcmp(result->raw.data, key, k));
    CHECK(result->raw_v2.len == d + 1 + k);
    CHECK(!memcmp(result->raw_v2.data, host, d) && result->raw_v2.data[d] == ':');
    CHECK(!memcmp(result->raw_v2.data + d + 1, key, k));
    CHECK(result->redacted && !strncmp(result->redacted, key, 8) && !strcmp(result->redacted + 8, "..."));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(!strcmp(part(result, "key"), key) && !strcmp(part(result, "url"), host));
    CHECK(!result->detector_name && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    make_token(token, 29, 1);
    make_token(other, 34, 5);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_octopusdeploy_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_octopusdeploy_init(NULL, NULL) == -1);
    CHECK(br_octopusdeploy_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_octopusdeploy_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 1056 && detector->version == 0);
    CHECK(!strcmp(detector->name, "OctopusDeploy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Octopus Deploy is a DevOps deployment automation platform. Octopus Deploy API keys can be used to automate deployments, manage projects, environments, and infrastructure resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "octopus"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void extraction_case(const br_detector *detector, const void *input, size_t length,
                            const char *key, const char *host)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, length);
    CHECK(out.len == (key && host ? 1u : 0u) && !http.calls && !http.releases);
    if (out.len) finding(&out.items[0], key, host, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[41];
    snprintf(input, sizeof(input), "%s %s", domain, token);
    extraction_case(detector, input, strlen(input), token, domain);
    snprintf(input, sizeof(input), "%s %s", domain, other);
    extraction_case(detector, input, strlen(input), other, domain);
    extraction_case(detector, token, strlen(token), NULL, NULL);
    extraction_case(detector, domain, strlen(domain), NULL, NULL);
    extraction_case(detector, NULL, 0, NULL, NULL);
    for (size_t n = 28; n <= 35; ++n) {
        make_token(changed, n, 0);
        snprintf(input, sizeof(input), "%s %s", domain, changed);
        extraction_case(detector, input, strlen(input),
                        n >= 29 && n <= 34 ? changed : NULL, domain);
    }
    memcpy(changed, token, sizeof(token));
    changed[4] = 'a';
    snprintf(input, sizeof(input), "%s %s", domain, changed);
    extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "%s _%s %s_", domain, token, token);
    extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "UPPER.octopus.app %s", token);
    extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "fixture-a.Octopus.app %s", token);
    extraction_case(detector, input, strlen(input), NULL, NULL);
    /* A leading hyphen is outside the word boundary, so the label starts at 's'. */
    snprintf(input, sizeof(input), "-start.octopus.app %s", token);
    extraction_case(detector, input, strlen(input), token, "start.octopus.app");
    snprintf(input, sizeof(input), "sub.%s %s", domain, token);
    extraction_case(detector, input, strlen(input), token, domain);
    /* Keyword is an engine prefilter, not an extraction requirement. */
    snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", other_domain, domain, other, token);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    const char *hosts[] = {other_domain, other_domain, domain, domain};
    const char *keys[] = {other, token, other, token};
    for (size_t i = 0; i < 4; ++i) finding(&out.items[i], keys[i], hosts[i], false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s %s", domain, token, token);
    extraction_case(detector, input, strlen(input), token, domain);
}

static void nil_context(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "%s %s", domain, token);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    finding(&out.items[0], token, domain, false, "net/http: nil Context");
    br_results_clear(&out);
}

static void borrowed_dedup(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "%s %s", domain, token);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "octopus-test"};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    finding(&out.items[0], token, domain, false, "unsupported HTTP request coalescing");
    br_results_clear(&out);
}

static const br_http_request *held;
static void inspect_owned(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && ctx->deadline_monotonic_ms > 0);
    CHECK(!strcmp(request->method, "GET"));
    char url[128];
    snprintf(url, sizeof(url), "https://%s/api/users/me", domain);
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->detector_type == 1056);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 10000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Octopus-Apikey"));
    CHECK(!strcmp(request->headers[0].value, token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog octopus-test"));
    char credential[96];
    snprintf(credential, sizeof(credential), "%s:%s", domain, token);
    CHECK(request->dedup_key.len == 5 + strlen(credential));
    CHECK(!memcmp(request->dedup_key.data, "1056:", 5));
    CHECK(!memcmp(request->dedup_key.data + 5, credential, strlen(credential)));
    held = request;
}

static void release_owned(void *user, br_http_response *response)
{
    CHECK(held);
    held = NULL;
    test_http_release(user, response);
}

static void destroy_backend(void *user)
{
    test_http *http = user;
    CHECK(http->calls == http->releases);
}

static void owned_status(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "%s %s", domain, token);
    const struct { int status; const char *read_error; int rc; const char *send_error;
                    bool verified; const char *cause; } cases[] = {
        {200, NULL, 0, NULL, true, NULL},
        {403, NULL, 0, NULL, true, NULL},
        {401, NULL, 0, NULL, false, NULL},
        {500, NULL, 0, NULL, false, "unexpected HTTP response status 500"},
        {201, "ignored-if-promoted", 0, NULL, false, "ignored-if-promoted"},
        {200, NULL, -1, "synthetic transport failure", false, "synthetic transport failure"},
        {200, NULL, 1, NULL, false, "HTTP transport failed"},
    };
    test_http http = {.inspect = inspect_owned};
    br_http_owned_backend backend = {
        .transport = {&http, test_http_send, release_owned}, .destroy = destroy_backend,
    };
    br_http_client *client = NULL;
    char *error = NULL;
    CHECK(br_http_client_init(&client, backend, BR_HTTP_DETECTOR_PUBLIC, &error) == 0 && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "octopus-test"};
    static const unsigned char body[] = {0x21, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.response = (br_http_response){
            .status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error,
        };
        http.send_rc = cases[i].rc;
        http.send_error = cases[i].send_error;
        http.calls = http.releases;
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == http.releases);
        finding(&out.items[0], token, domain, cases[i].verified, cases[i].cause);
        br_results_clear(&out);
    }
    char sensitive[160];
    snprintf(sensitive, sizeof(sensitive), "request failed for %s", token);
    http.response = (br_http_response){.status = 200};
    http.send_rc = 1;
    http.send_error = sensitive;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1);
    finding(&out.items[0], token, domain, false, "request failed for [REDACTED]");
    br_results_clear(&out);
    CHECK(br_http_client_drain(client, &error) == 0 && !error);
    br_http_client_destroy(client);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    nil_context(detector);
    borrowed_dedup(detector);
    owned_status(detector);
    return test_finish("OctopusDeploy");
}
