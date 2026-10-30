/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_snykkey_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "abcdef01-2345-6789-abcd-ef0123456789";

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value)) return NULL;
    return json_object_get_string(value);
}

static void result_is(const br_result *result, const char *capture, bool verified, const char *cause)
{
    CHECK(result->detector_type == 89);
    CHECK(result->raw.len == strlen(capture) && !memcmp(result->raw.data, capture, result->raw.len));
    CHECK(!result->raw_v2.data && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), capture));
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_snykkey_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_snykkey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_snykkey_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 89 && !strcmp(detector->name, "SnykKey"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "snyk"));
    CHECK(!strcmp(detector->description,
                  "Snyk is a developer security platform that helps developers find and fix vulnerabilities in their code. Snyk API keys can be used to access and manage Snyk services."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "snyk %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, NULL);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "SNYK %s snyk %s SNYK %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    result_is(&out.items[0], key, false, NULL);
    result_is(&out.items[1], other, false, NULL);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "snyk 01234567-89AB-cdef-0123-456789abcdef");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "token %s", key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, "https://snyk.io/api/v1/user/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 89);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    (void)http;
}

static br_results verify_body(const br_detector *detector, int status, const char *body, const char *read_error)
{
    test_http http = {.response = {.status = status, .body_error = read_error}, .inspect = inspect};
    if (body) http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "snyk-test"};
    char input[48];
    snprintf(input, sizeof(input), "snyk %s", key);
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    return out;
}

static void verification(const br_detector *detector)
{
    char input[48];
    snprintf(input, sizeof(input), "snyk %s", key);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false, "net/http: nil Context");
    CHECK(!out.items[0].extra_data);
    br_results_clear(&out);

    out = verify_body(detector, 200,
                      "{\"Username\":\"Ada\",\"EMAIL\":\"ada@example.test\",\"Orgs\":[{\"Name\":\"one\"},null,{\"name\":\"two\"}],\"extra\":1e9999} trailing",
                      NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(json_object_object_length(out.items[0].extra_data) == 3);
    CHECK(!strcmp(extra(&out.items[0], "Username"), "Ada"));
    CHECK(!strcmp(extra(&out.items[0], "Email"), "ada@example.test"));
    CHECK(!strcmp(extra(&out.items[0], "Organizations"), "one,,two"));
    br_results_clear(&out);

    out = verify_body(detector, 200, "{\"username\":\"Ada\",\"orgs\":[]}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(json_object_object_length(out.items[0].extra_data) == 2 && !extra(&out.items[0], "Organizations"));
    CHECK(!strcmp(extra(&out.items[0], "Email"), ""));
    br_results_clear(&out);

    out = verify_body(detector, 200, "{\"username\":\"alice\",\"username\":null}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!strcmp(extra(&out.items[0], "Username"), "alice"));
    br_results_clear(&out);
    out = verify_body(detector, 200,
                      "{\"username\":\"alice\",\"email\":\"ada@example.test\",\"email\":null}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!strcmp(extra(&out.items[0], "Email"), "ada@example.test"));
    br_results_clear(&out);
    out = verify_body(detector, 200,
                      "{\"username\":\"alice\",\"orgs\":[{\"name\":\"kept\"}],\"orgs\":[{}]}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!strcmp(extra(&out.items[0], "Organizations"), "kept"));
    br_results_clear(&out);
    out = verify_body(detector, 200,
                      "{\"username\":\"alice\",\"orgs\":[{\"name\":\"a\"},{\"name\":\"b\"}],\"orgs\":[{},{}]}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!strcmp(extra(&out.items[0], "Organizations"), "a,b"));
    br_results_clear(&out);
    out = verify_body(detector, 200,
                      "{\"username\":\"alice\",\"orgs\":[{\"name\":\"kept\"}],\"orgs\":null}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!extra(&out.items[0], "Organizations"));
    br_results_clear(&out);
    out = verify_body(detector, 200,
                      "{\"username\":\"alice\",\"orgs\":[{\"name\":\"kept\"}],\"orgs\":[]}", NULL);
    result_is(&out.items[0], key, true, NULL);
    CHECK(!extra(&out.items[0], "Organizations"));
    br_results_clear(&out);

    out = verify_body(detector, 200, "null", NULL);
    result_is(&out.items[0], key, false, "failed to decode JSON response");
    CHECK(!out.items[0].extra_data);
    br_results_clear(&out);

    out = verify_body(detector, 200, "{\"username\":1}", NULL);
    result_is(&out.items[0], key, true,
              "json: cannot unmarshal number into Go struct field userDetailsResponse.username of type string");
    CHECK(!out.items[0].extra_data);
    br_results_clear(&out);

    out = verify_body(detector, 200, "{\"username\":\"Ada\",\"orgs\":[\"x\"]}", NULL);
    result_is(&out.items[0], key, true,
              "json: cannot unmarshal string into Go struct field userDetailsResponse.orgs of type snykkey.organization");
    br_results_clear(&out);

    out = verify_body(detector, 200, "", "synthetic read failure");
    result_is(&out.items[0], key, true, "synthetic read failure");
    br_results_clear(&out);

    out = verify_body(detector, 200, "", NULL);
    result_is(&out.items[0], key, true, "EOF");
    br_results_clear(&out);

    out = verify_body(detector, 401, "{\"username\":\"Ada\"}", NULL);
    result_is(&out.items[0], key, false, NULL);
    CHECK(!out.items[0].extra_data);
    br_results_clear(&out);

    out = verify_body(detector, 500, "", NULL);
    result_is(&out.items[0], key, false, "unexpected HTTP response status 500");
    br_results_clear(&out);

    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "failed %s", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    result_is(&out.items[0], key, false, "failed [REDACTED]");
    br_results_clear(&out);
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
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("SnykKey");
}
