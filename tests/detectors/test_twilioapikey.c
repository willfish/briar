/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

static int force_json;
static int twilio_visit_mode;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int (*real_each_element)(br_slice, br_json_element_fn, void *) = br_json_each_element;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
static int element_hook(br_slice array, br_json_element_fn callback, void *user)
{
    int rc = real_each_element(array, callback, user);
    if (rc) return rc;
    return twilio_visit_mode ? 1 : 0;
}
#define br_json_first_document first_hook
#define br_json_each_element element_hook
#include "../../src/detectors/twilioapikey.c"
#undef br_json_first_document
#undef br_json_each_element

static const char key1[] = "SKbddcfb88fake8f7c4d9aefake7de1fc5";
static const char secret1[] = "k7JXtY3WBtUqthisisfakeZDqVcjZxYI";
static const char auth[] = "Basic U0tiZGRjZmI4OGZha2U4ZjdjNGQ5YWVmYWtlN2RlMWZjNTprN0pYdFkzV0J0VXF0aGlzaXNmYWtlWkRxVmNqWnhZSQ==";

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value)) return NULL;
    return json_object_get_string(value);
}

static void destroy_owned(void *user) { (void)user; }

static br_results owned_scan(const br_detector *detector, test_http *http, const char *input)
{
    br_http_owned_backend backend = {.transport = test_transport(http), .destroy = destroy_owned};
    br_http_client *client = NULL;
    char *error = NULL;
    CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &error) == 0 && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
    CHECK(br_http_client_is_owned(ctx.transport));
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(br_http_client_drain(client, &error) == 0 && !error);
    br_http_client_destroy(client);
    return results;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    unsigned char dedup[72];
    memcpy(dedup, "1011:", 5);
    memcpy(dedup + 5, key1, 34);
    memcpy(dedup + 39, secret1, 32);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len && request->detector_type == 1011);
    CHECK(!strcmp(request->url, "https://verify.twilio.com/v2/Services"));
    CHECK(request->dedup_key.len == 71 && !memcmp(request->dedup_key.data, dedup, 71));
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].value, "*/*"));
    CHECK(!strcmp(request->headers[2].value, auth));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_twilioapikey_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1011 && !strcmp(detector->name, "TwilioApiKey"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "twilio"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Twilio is a cloud communications platform that allows software developers to programmatically make and receive phone calls, send and receive text messages, and perform other communication functions using its web service APIs."));
    return detector;
}

static void check_pair(const br_result *result)
{
    char joined[67];
    memcpy(joined, key1, 34);
    memcpy(joined + 34, secret1, 32);
    CHECK(result->detector_type == 26 && result->raw.len == 34 && !memcmp(result->raw.data, key1, 34));
    CHECK(result->raw_v2.len == 66 && !memcmp(result->raw_v2.data, joined, 66));
    CHECK(result->redacted && !strcmp(result->redacted, "k7JXt..."));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key1));
    CHECK(json_object_object_get_ex(result->secret_parts, "sid", &part) && !strcmp(json_object_get_string(part), secret1));
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[128];
    snprintf(input, sizeof(input), "twilio %s %s %s", key1, secret1, secret1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_pair(&results.items[0]);
    CHECK(!results.items[0].verified && results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);
    const char invalid[] = "twilio SK_bddcfb88fake8f7c4d9aefake7de1fc k6JXtY3WBtU$thisisfakeZDqVcjZxYI";
    results = test_scan(detector, NULL, false, invalid, sizeof(invalid) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s", key1, secret1);
    const char body[] = "{\"services\":[{\"friendly_name\":\"Verify\",\"sid\":\"VA1\",\"account_sid\":\"AC1\"}]} junk";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}, .inspect = inspect};
    results = owned_scan(detector, &http, input);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    CHECK(extra(&results.items[0], "friendly_name") && !strcmp(extra(&results.items[0], "friendly_name"), "Verify"));
    CHECK(extra(&results.items[0], "account_sid") && !strcmp(extra(&results.items[0], "account_sid"), "AC1"));
    br_results_clear(&results);
    const char bad[] = "{";
    http.response.body = (br_slice){(const unsigned char *)bad, 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.len == 1 && results.items[0].verified && !extra(&results.items[0], "friendly_name"));
    br_results_clear(&results);
    http.response = (br_http_response){.status = 403};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.send_rc = -1;
    http.send_error = "dial failed";
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    force_json = 2;
    http.send_rc = 0; http.send_error = NULL;
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.response.body_error = NULL;
    br_http_owned_backend backend = {.transport = test_transport(&http), .destroy = destroy_owned};
    br_http_client *client = NULL;
    char *client_error = NULL;
    CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &client_error) == 0 && client && !client_error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    br_http_client_destroy(client);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);

    force_json = 0;
    http.send_rc = 0; http.send_error = NULL;
    const char later[] = "{\"services\":[{\"friendly_name\":\"A\",\"account_sid\":\"AC1\"},{\"friendly_name\":1}]}";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)later, sizeof(later) - 1}};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(!extra(&results.items[0], "friendly_name") && !extra(&results.items[0], "account_sid"));
    br_results_clear(&results);

    const char sticky[] = "{\"services\":[1],\"services\":[{\"friendly_name\":\"A\"}]}";
    http.response.body = (br_slice){(const unsigned char *)sticky, sizeof(sticky) - 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verified && !extra(&results.items[0], "friendly_name"));
    br_results_clear(&results);

    const char reused[] =
        "{\"services\":[{\"friendly_name\":\"A\",\"account_sid\":\"AC1\"}],"
        "\"services\":[{\"account_sid\":null}]}";
    http.response.body = (br_slice){(const unsigned char *)reused, sizeof(reused) - 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verified);
    CHECK(extra(&results.items[0], "friendly_name") && !strcmp(extra(&results.items[0], "friendly_name"), "A"));
    CHECK(extra(&results.items[0], "account_sid") && !strcmp(extra(&results.items[0], "account_sid"), "AC1"));
    br_results_clear(&results);

    const char emptied[] = "{\"services\":[{\"friendly_name\":\"A\"}],\"services\":[]}";
    http.response.body = (br_slice){(const unsigned char *)emptied, sizeof(emptied) - 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verified && !extra(&results.items[0], "friendly_name"));
    br_results_clear(&results);

    const char nul_body[] = "{\"services\":[{\"friendly_name\":\"a\\u0000b\",\"account_sid\":\"x\\u0000\"}]}";
    http.response.body = (br_slice){(const unsigned char *)nul_body, sizeof(nul_body) - 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verified);
    br_json *field = NULL;
    const char friendly_bytes[] = {'a', '\0', 'b'};
    const char account_bytes[] = {'x', '\0'};
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &field));
    CHECK((size_t)json_object_get_string_len(field) == sizeof(friendly_bytes));
    CHECK(!memcmp(json_object_get_string(field), friendly_bytes, sizeof(friendly_bytes)));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "account_sid", &field));
    CHECK((size_t)json_object_get_string_len(field) == sizeof(account_bytes));
    CHECK(!memcmp(json_object_get_string(field), account_bytes, sizeof(account_bytes)));
    br_results_clear(&results);

    const char trailing[] = "{\"services\":[{\"friendly_name\":\"Verify\",\"account_sid\":\"AC1\"}]}{\"services\":[1]}";
    http.response.body = (br_slice){(const unsigned char *)trailing, sizeof(trailing) - 1};
    http.calls = http.releases = 0;
    results = owned_scan(detector, &http, input);
    CHECK(results.items[0].verified);
    CHECK(extra(&results.items[0], "friendly_name") && !strcmp(extra(&results.items[0], "friendly_name"), "Verify"));
    br_results_clear(&results);

    twilio_visit_mode = 1;
    http.response.body = (br_slice){(const unsigned char *)later, sizeof(later) - 1};
    CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &client_error) == 0 && client && !client_error);
    ctx = (br_scan_ctx){.transport = br_http_client_transport(client)};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&failed, &prior) == 0);
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &failed, &scan_error) != 0);
    br_http_client_destroy(client);
    CHECK(failed.len == 1 && failed.items[0].detector_type == 9);
    free(scan_error);
    br_results_clear(&failed);
    br_result_clear(&prior);
    return test_finish("TwilioApiKey");
}
