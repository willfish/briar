/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <limits.h>
#include <time.h>

int br_openai_init(const br_detector **out, char **error);
int br_finding_key(br_result *result, int32_t type, const char *key, const char *part_name);
static void openai_seams(void);

typedef struct {
    int statuses[4];
    size_t n, at;
    const char *body;
    const char *send_error;
    int calls;
    bool null_error;
    const char *authorization;
} openai_http;

static int openai_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    openai_http *http = user;
    (void)ctx;
    ++http->calls;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.openai.com/v1/me"));
    CHECK(request->timeout_ms == 10000 && request->detector_type == 201);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, http->authorization));
    size_t index = http->at < http->n ? http->at : http->n - 1;
    ++http->at;
    if (http->statuses[index] < 0 && (http->send_error || http->null_error)) {
        *error = http->send_error ? strdup(http->send_error) : NULL;
        CHECK(!http->send_error || *error);
        return 1;
    }
    *response = (br_http_response){.status = http->statuses[index]};
    if (http->body) response->body = (br_slice){(const unsigned char *)http->body, strlen(http->body)};
    return 0;
}

static void openai_release(void *user, br_http_response *response)
{
    (void)user;
    CHECK(response);
}

static const char *field(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, name, &value));
    return json_object_get_string(value);
}

static void expect_field_bytes(const br_result *result, const char *name, const void *bytes, size_t len)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == len);
    if (len) CHECK(!memcmp(json_object_get_string(value), bytes, len));
}

static br_results scan_body(const br_detector *detector, const char *input, const char *authorization,
                            const char *body)
{
    openai_http http = {.statuses = {200}, .n = 1, .body = body, .authorization = authorization};
    br_transport transport = {.user = &http, .send = openai_send, .release = openai_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_openai_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 201 && !strcmp(detector->keywords[0], "T3BlbkFJ"));
    const char *user = "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";
    const char *project = "sk-proj-mpjtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiagE8K";
    const char *service = "sk-service-account-name-Ofbtr05CFsJqs4TAeKlCT3BlbkFJsh1KtN0SUjTPeJiaglyC";
    const char *svcacct = "sk-svcacct-IUXtc5gIZK-2cBfB-nTgEWbD8mi-fi-gc20oGtq8ve51sET3BlbkFJCg8iQkCVz_nmE_q1dCWlMpemoaoMqHzQ6D-FnWGqlz4C8A";
    const char *admin = "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";
    char input[512];
    snprintf(input, sizeof(input), "openai %s %s %s %s %s", user, project, service, svcacct, admin);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 4);
    CHECK(!strcmp(found.items[0].redacted, "sk-...Us19"));
    CHECK(found.items[1].redacted && !strncmp(found.items[1].redacted, "sk-...", 6));
    br_results_clear(&found);
    snprintf(input, sizeof(input), "%s %s", user, user);
    br_results unique = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(unique.len == 1);
    br_results_clear(&unique);
    br_results admin_only = test_scan(detector, NULL, false, admin, strlen(admin));
    CHECK(admin_only.len == 0);
    br_results_clear(&admin_only);

    setenv("TZ", "UTC", 1);
    tzset();
    const char *body = "{\"id\":\"user_1\",\"created\":0,\"mfa_flag_enabled\":true,"
                       "\"orgs\":{\"data\":[{\"description\":\"desk\",\"personal\":true,\"is_default\":false}]}}";
    char authorization[256];
    snprintf(authorization, sizeof(authorization), "Bearer %s", user);
    openai_http http = {.statuses = {500, 500, 200}, .n = 3, .body = body, .authorization = authorization};
    br_transport transport = {.user = &http, .send = openai_send, .release = openai_release};
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", user);
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified && http.calls == 3);
    CHECK(!strcmp(field(&verified.items[0], "id"), "user_1"));
    CHECK(!strcmp(field(&verified.items[0], "total_orgs"), "1"));
    CHECK(!strcmp(field(&verified.items[0], "mfa_enabled"), "true"));
    CHECK(!strcmp(field(&verified.items[0], "created_at"), "1970-01-01T00:00:00Z"));
    CHECK(!strcmp(field(&verified.items[0], "description"), "desk"));
    CHECK(!strcmp(field(&verified.items[0], "is_personal"), "true"));
    CHECK(!strcmp(field(&verified.items[0], "is_default"), "false"));
    br_results_clear(&verified);

    openai_http exhausted = {.statuses = {500, 500, 500}, .n = 3, .authorization = authorization};
    br_transport exhausted_transport = {.user = &exhausted, .send = openai_send, .release = openai_release};
    br_scan_ctx exhausted_ctx = {.transport = &exhausted_transport};
    br_results given_up = test_scan(detector, &exhausted_ctx, true, input, strlen(input));
    CHECK(given_up.len == 1 && !given_up.items[0].verified && exhausted.calls == 3);
    CHECK(!strcmp(given_up.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&given_up);

    openai_http denied = {.statuses = {401}, .n = 1, .authorization = authorization};
    br_transport denied_transport = {.user = &denied, .send = openai_send, .release = openai_release};
    br_scan_ctx denied_ctx = {.transport = &denied_transport};
    br_results invalid = test_scan(detector, &denied_ctx, true, input, strlen(input));
    CHECK(invalid.len == 1 && !invalid.items[0].verified && !invalid.items[0].verification_error && denied.calls == 1);
    br_results_clear(&invalid);

    openai_http unimplemented = {.statuses = {501}, .n = 1, .authorization = authorization};
    br_transport unimplemented_transport = {.user = &unimplemented, .send = openai_send, .release = openai_release};
    br_scan_ctx unimplemented_ctx = {.transport = &unimplemented_transport};
    br_results once = test_scan(detector, &unimplemented_ctx, true, input, strlen(input));
    CHECK(once.len == 1 && unimplemented.calls == 1);
    CHECK(!strcmp(once.items[0].verification_error, "unexpected HTTP response status 501"));
    br_results_clear(&once);

    const char *bad_json = "{\"id\":1}";
    openai_http typed = {.statuses = {200}, .n = 1, .body = bad_json, .authorization = authorization};
    br_transport typed_transport = {.user = &typed, .send = openai_send, .release = openai_release};
    br_scan_ctx typed_ctx = {.transport = &typed_transport};
    br_results type_error = test_scan(detector, &typed_ctx, true, input, strlen(input));
    CHECK(type_error.len == 1 && !type_error.items[0].verified && !type_error.items[0].extra_data);
    CHECK(!strcmp(type_error.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field response.id of type string"));
    br_results_clear(&type_error);

    const char *float_json = "{\"created\":1.5}";
    openai_http floated = {.statuses = {200}, .n = 1, .body = float_json, .authorization = authorization};
    br_transport floated_transport = {.user = &floated, .send = openai_send, .release = openai_release};
    br_scan_ctx floated_ctx = {.transport = &floated_transport};
    br_results float_error = test_scan(detector, &floated_ctx, true, input, strlen(input));
    CHECK(!strcmp(float_error.items[0].verification_error,
                  "json: cannot unmarshal number 1.5 into Go struct field response.created of type int"));
    br_results_clear(&float_error);

    openai_http dial = {.statuses = {-1, -1, -1}, .n = 3, .send_error = "dial failed", .authorization = authorization};
    br_transport dial_transport = {.user = &dial, .send = openai_send, .release = openai_release};
    br_scan_ctx dial_ctx = {.transport = &dial_transport};
    br_results transport_error = test_scan(detector, &dial_ctx, true, input, strlen(input));
    CHECK(transport_error.len == 1 && dial.calls == 3);
    CHECK(!strcmp(transport_error.items[0].verification_error, "dial failed"));
    br_results_clear(&transport_error);

    openai_http silent = {.statuses = {-1, -1, -1}, .n = 3, .null_error = true, .authorization = authorization};
    br_transport silent_transport = {.user = &silent, .send = openai_send, .release = openai_release};
    br_scan_ctx silent_ctx = {.transport = &silent_transport};
    br_results silent_error = test_scan(detector, &silent_ctx, true, input, strlen(input));
    CHECK(silent_error.len == 1 && !silent_error.items[0].verified);
    /* br_http_send supplies this when the mock diagnostic is NULL. */
    CHECK(silent_error.items[0].verification_error &&
          !strcmp(silent_error.items[0].verification_error, "HTTP transport failed"));
    CHECK(silent.calls == 3);
    br_results_clear(&silent_error);

    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 1 && !nil.items[0].verified);
    CHECK(!strcmp(nil.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil);

    const char *overflows[] = {
        "{\"email\":1e10000}", "response.email",
        "{\"name\":1e10000}", "response.name",
        "{\"picture\":1e10000}", "response.picture",
        "{\"phone_number\":1e10000}", "response.phone_number",
        "{\"amr\":[1e10000]}", "response.amr",
        "{\"orgs\":{\"data\":[{\"parent_org_id\":1e10000}]}}", "data.orgs.data.parent_org_id",
        "{\"orgs\":{\"data\":[{\"projects\":{\"data\":[1e10000]}}]}}", "projects.orgs.data.projects.data",
    };
    for (size_t i = 0; i < sizeof(overflows) / sizeof(overflows[0]); i += 2) {
        char expected[160];
        snprintf(expected, sizeof(expected),
                 "json: cannot unmarshal number 1e10000 into Go struct field %s of type float64",
                 overflows[i + 1]);
        br_results bad = scan_body(detector, input, authorization, overflows[i]);
        CHECK(bad.len == 1 && !bad.items[0].verified && !bad.items[0].extra_data);
        CHECK(bad.items[0].verification_error && !strcmp(bad.items[0].verification_error, expected));
        br_results_clear(&bad);
    }
    br_results ignored = scan_body(detector, input, authorization, "{\"ignored\":1e10000,\"id\":\"u\"}");
    CHECK(ignored.len == 1 && ignored.items[0].verified);
    CHECK(!strcmp(field(&ignored.items[0], "id"), "u"));
    CHECK(!strcmp(field(&ignored.items[0], "total_orgs"), "0"));
    CHECK(!json_object_object_get_ex(ignored.items[0].extra_data, "description", NULL));
    br_results_clear(&ignored);

    br_results reused = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"first\",\"personal\":true,\"is_default\":false},"
        "{\"description\":\"second\"}],\"data\":[{\"description\":\"third\"}]}}");
    CHECK(reused.items[0].verified);
    CHECK(!strcmp(field(&reused.items[0], "total_orgs"), "1"));
    CHECK(!strcmp(field(&reused.items[0], "description"), "third"));
    CHECK(!strcmp(field(&reused.items[0], "is_personal"), "true"));
    CHECK(!strcmp(field(&reused.items[0], "is_default"), "false"));
    br_results_clear(&reused);

    br_results emptied = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"first\",\"personal\":true}],\"data\":[]}}");
    CHECK(emptied.items[0].verified && !strcmp(field(&emptied.items[0], "total_orgs"), "0"));
    CHECK(!json_object_object_get_ex(emptied.items[0].extra_data, "description", NULL));
    br_results_clear(&emptied);

    br_results nulled = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"first\"}],\"data\":null}}");
    CHECK(nulled.items[0].verified && !strcmp(field(&nulled.items[0], "total_orgs"), "0"));
    br_results_clear(&nulled);

    br_results kept_orgs = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"first\",\"personal\":true}]},\"orgs\":null}");
    CHECK(kept_orgs.items[0].verified);
    CHECK(!strcmp(field(&kept_orgs.items[0], "description"), "first"));
    CHECK(!strcmp(field(&kept_orgs.items[0], "is_personal"), "true"));
    CHECK(!strcmp(field(&kept_orgs.items[0], "total_orgs"), "1"));
    br_results_clear(&kept_orgs);

    br_results reset = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"a\",\"personal\":true,\"is_default\":true}],"
        "\"data\":[],\"data\":[{\"is_default\":false}]}}");
    CHECK(reset.items[0].verified);
    CHECK(!strcmp(field(&reset.items[0], "description"), ""));
    CHECK(!strcmp(field(&reset.items[0], "is_personal"), "false"));
    CHECK(!strcmp(field(&reset.items[0], "is_default"), "false"));
    br_results_clear(&reset);

    br_results null_element = scan_body(detector, input, authorization,
        "{\"orgs\":{\"data\":[{\"description\":\"a\",\"personal\":true}],\"data\":[null]}}");
    CHECK(null_element.items[0].verified);
    CHECK(!strcmp(field(&null_element.items[0], "description"), "a"));
    CHECK(!strcmp(field(&null_element.items[0], "is_personal"), "true"));
    br_results_clear(&null_element);

    const char id_bytes[] = {'a', '\0', 'b'};
    const char desc_bytes[] = {'x', '\0', 'y'};
    br_results nuls = scan_body(detector, input, authorization,
        "{\"id\":\"a\\u0000b\",\"orgs\":{\"data\":[{\"description\":\"x\\u0000y\"}]}}");
    CHECK(nuls.items[0].verified);
    expect_field_bytes(&nuls.items[0], "id", id_bytes, sizeof(id_bytes));
    expect_field_bytes(&nuls.items[0], "description", desc_bytes, sizeof(desc_bytes));
    br_results_clear(&nuls);

    const char *times[] = {
        "-62167219200", "0000-01-01T00:00:00Z",
        "-62167219201", "-0001-12-31T23:59:59Z",
        "9223372036854775807", "292277026596-12-04T15:30:07Z",
    };
    for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i += 2) {
        char body[96];
        snprintf(body, sizeof(body), "{\"created\":%s}", times[i]);
        br_results when = scan_body(detector, input, authorization, body);
        CHECK(when.items[0].verified);
        CHECK(!strcmp(field(&when.items[0], "created_at"), times[i + 1]));
        br_results_clear(&when);
    }

    openai_seams();
    return test_finish("OpenAI");
}

static int openai_hook_mode;
static int openai_type_calls;

static int openai_hook_document(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (openai_hook_mode == 1) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return 1;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

static int openai_hook_visit(br_slice object, br_json_member_fn visit, void *user)
{
    if (openai_hook_mode == 4) return 1;
    return br_json_each_member(object, visit, user);
}

static int openai_hook_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++openai_type_calls;
    if (openai_hook_mode == 2 && openai_type_calls == 1) {
        if (cause) *cause = NULL;
        return 0;
    }
    if (openai_hook_mode == 3 && openai_type_calls == 2) return 1;
    return br_json_type_cause(value, field, expected, cause);
}

#define br_json_first_document openai_hook_document
#define br_json_each_member openai_hook_visit
#define br_json_type_cause openai_hook_type
#define br_openai_init openai_seam_init
#include "../../src/detectors/openai.c"
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_type_cause
#undef br_openai_init

static void openai_seams(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(openai_seam_init(&detector, &error) == 0 && detector && !error);
    const char *user = "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";
    char authorization[256];
    snprintf(authorization, sizeof(authorization), "Bearer %s", user);
    openai_hook_mode = 1;
    br_results quiet = scan_body(detector, user, authorization, "{\"id\":\"ignored\"}");
    CHECK(quiet.len == 1 && !quiet.items[0].verified && !quiet.items[0].verification_error);
    br_results_clear(&quiet);

    openai_hook_mode = 2;
    openai_type_calls = 0;
    br_results continued = scan_body(detector, user, authorization, "{\"object\":1,\"id\":1}");
    CHECK(openai_type_calls >= 2);
    CHECK(continued.len == 1 && !continued.items[0].verified && !continued.items[0].verification_error);
    br_results_clear(&continued);

    openai_hook_mode = 3;
    openai_type_calls = 0;
    openai_http fatal_http = {.statuses = {200}, .n = 1, .body = "{\"object\":1,\"id\":1}",
                              .authorization = authorization};
    br_transport fatal_transport = {.user = &fatal_http, .send = openai_send, .release = openai_release};
    br_scan_ctx fatal_ctx = {.transport = &fatal_transport};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    error = NULL;
    CHECK(detector->scan(detector, &fatal_ctx, true, (br_slice){(const unsigned char *)user, strlen(user)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot project OpenAI response"));
    CHECK(kept.len == 1 && kept.items[0].detector_type == 9 && !kept.items[0].verified);
    free(error);
    br_results_clear(&kept);
    br_result_clear(&prior);

    openai_hook_mode = 4;
    openai_http visit_http = {.statuses = {200}, .n = 1, .body = "{\"id\":\"user\"}",
                              .authorization = authorization};
    br_transport visit_transport = {.user = &visit_http, .send = openai_send, .release = openai_release};
    br_scan_ctx visit_ctx = {.transport = &visit_transport};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&kept, &prior) == 0);
    error = NULL;
    CHECK(detector->scan(detector, &visit_ctx, true, (br_slice){(const unsigned char *)user, strlen(user)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot project OpenAI response"));
    CHECK(kept.len == 1 && kept.items[0].detector_type == 9);
    free(error);
    br_results_clear(&kept);
    br_result_clear(&prior);

    openai_doc huge = {.norgs = (size_t)INT_MAX + 1};
    br_result counted = {0};
    error = NULL;
    CHECK(openai_metadata(&counted, &huge, &error) == 0 && !error);
    CHECK(!strcmp(field(&counted, "total_orgs"), "2147483648"));
    br_result_clear(&counted);
}
