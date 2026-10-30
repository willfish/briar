/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

static int force_json;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
#define br_json_first_document first_hook
static int later_type;
static int type_calls;
static int force_float;
static int (*real_type_cause)(br_json *, const char *, const char *, char **) = br_json_type_cause;
static int type_hook(br_json *value, const char *field, const char *expected, char **cause)
{
    int n = ++type_calls;
    if (later_type && n > 1) { if (cause) *cause = NULL; return 1; }
    return real_type_cause(value, field, expected, cause);
}
static int (*real_float)(br_slice, char **) = br_json_check_float64_numbers;
static int float_hook(br_slice document, char **cause)
{
    if (force_float) { if (cause) *cause = NULL; return force_float; }
    return real_float(document, cause);
}
#define br_json_type_cause type_hook
#define br_json_check_float64_numbers float_hook
#include "../../src/detectors/openrouter.c"
#undef br_json_check_float64_numbers
#undef br_json_type_cause
#undef br_json_first_document

static char token[74];

static void make_token(void)
{
    memcpy(token, "sk-or-v1-", 9);
    memset(token + 9, 'a', 64);
    token[73] = '\0';
}

typedef struct { test_http http; int status; const char *body; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://openrouter.ai/api/v1/key"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char expect[96];
    snprintf(expect, sizeof(expect), "Bearer %s", token);
    CHECK(!strcmp(request->headers[0].value, expect));
    probe *p = http->user;
    http->response.status = p->status;
    if (p->body) http->response.body = (br_slice){(const unsigned char *)p->body, strlen(p->body)};
    http->send_rc = p->send_rc;
    http->send_error = p->send_error;
}

static br_results scan_probe(const br_detector *detector, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, token, strlen(token));
}

static const char *extra(const br_result *result, const char *key)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, key, &part));
    return json_object_get_string(part);
}

int main(void)
{
    make_token();
    CHECK(strlen(token) == 73);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_openrouter_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1057 && !strcmp(detector->keywords[0], "sk-or-v1-"));
    char input[160];
    snprintf(input, sizeof(input), "%s %s", token, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].detector_type == 1057);
    CHECK(results.items[0].raw.len == 73 && !memcmp(results.items[0].raw.data, token, 73));
    CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, "sk-or-v1-aaa...aaa"));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), token));
    br_results_clear(&results);

    probe ok = {.status = 200, .body = "{\"data\":{\"label\":\"prod\",\"limit\":2,\"usage\":1.5,\"is_free_tier\":true,\"limit_remaining\":null}}"};
    results = scan_probe(detector, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    CHECK(!strcmp(extra(&results.items[0], "label"), "prod"));
    CHECK(!strcmp(extra(&results.items[0], "limit"), "2.000000"));
    CHECK(!strcmp(extra(&results.items[0], "usage"), "1.500000"));
    CHECK(!strcmp(extra(&results.items[0], "is_free_tier"), "true"));
    CHECK(!strcmp(extra(&results.items[0], "limit_remaining"), "<nil>"));
    br_results_clear(&results);

    probe kept = {.status = 200, .body = "{\"data\":{\"label\":\"ab\",\"label\":null,\"usage\":1.5,\"usage\":null,\"is_free_tier\":true,\"is_free_tier\":null,\"limit\":2,\"limit\":null,\"limit_remaining\":3,\"limit_remaining\":null}}"};
    results = scan_probe(detector, &kept);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "label"), "ab"));
    CHECK(!strcmp(extra(&results.items[0], "usage"), "1.500000"));
    CHECK(!strcmp(extra(&results.items[0], "is_free_tier"), "true"));
    CHECK(!strcmp(extra(&results.items[0], "limit"), "<nil>"));
    CHECK(!strcmp(extra(&results.items[0], "limit_remaining"), "<nil>"));
    br_results_clear(&results);

    probe overflow = {.status = 200, .body = "{\"data\":{\"usage\":1e10000,\"label\":\"keep\"}}"};
    results = scan_probe(detector, &overflow);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "1e10000") &&
          strstr(results.items[0].verification_error, "key.data.usage") &&
          !strstr(results.items[0].verification_error, "inf"));
    br_results_clear(&results);

    probe nul = {.status = 200, .body = "{\"data\":{\"label\":\"ab\\u0000c\"}}"};
    results = scan_probe(detector, &nul);
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *label = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "label", &label));
    CHECK(json_object_get_string_len(label) == 4);
    CHECK(!memcmp(json_object_get_string(label), "ab\0c", 4));

    probe empty = {.status = 200, .body = "{}"};
    results = scan_probe(detector, &empty);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "label"), ""));
    CHECK(!strcmp(extra(&results.items[0], "usage"), "0.000000"));
    CHECK(!strcmp(extra(&results.items[0], "is_free_tier"), "false"));
    br_results_clear(&results);

    probe bad_json = {.status = 200, .body = "[]"};
    results = scan_probe(detector, &bad_json);
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error,
                  "json: cannot unmarshal array into Go value of type openrouter.keyResponse"));
    br_results_clear(&results);

    probe quiet = {.status = 401};
    results = scan_probe(detector, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    probe other = {.status = 500};
    results = scan_probe(detector, &other);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, token, strlen(token));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    later_type = 1;
    type_calls = 0;
    probe later = {.status = 200, .body = "{\"data\":{\"label\":1,\"usage\":\"x\"}}"};
    later.http.inspect = inspect;
    later.http.user = &later;
    br_transport later_transport = {&later, test_http_send, test_http_release};
    br_scan_ctx later_ctx = {.transport = &later_transport};
    br_results kept_prior = {0};
    br_result prior = {0};
    CHECK(br_finding_key_bytes(&prior, detector->type, (br_slice){(const unsigned char *)"prior", 5}, "key") == 0);
    CHECK(br_results_push(&kept_prior, &prior) == 0);
    br_result_clear(&prior);
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &later_ctx, true, (br_slice){(const unsigned char *)token, strlen(token)}, &kept_prior, &scan_error) != 0);
    CHECK(type_calls == 2 && kept_prior.len == 1 && kept_prior.items[0].raw.len == 5);
    CHECK(!memcmp(kept_prior.items[0].raw.data, "prior", 5));
    free(scan_error);
    br_results_clear(&kept_prior);
    later_type = 0;
    type_calls = 0;
    force_float = 2;
    probe plus2 = {.status = 200, .body = "{\"data\":{\"label\":1,\"usage\":1}}"};
    plus2.http.inspect = inspect;
    plus2.http.user = &plus2;
    br_transport plus_transport = {&plus2, test_http_send, test_http_release};
    br_scan_ctx plus_ctx = {.transport = &plus_transport};
    CHECK(br_finding_key_bytes(&prior, detector->type, (br_slice){(const unsigned char *)"prior", 5}, "key") == 0);
    CHECK(br_results_push(&kept_prior, &prior) == 0);
    br_result_clear(&prior);
    scan_error = NULL;
    CHECK(detector->scan(detector, &plus_ctx, true, (br_slice){(const unsigned char *)token, strlen(token)}, &kept_prior, &scan_error) != 0);
    CHECK(type_calls == 1 && kept_prior.len == 1);
    free(scan_error);
    br_results_clear(&kept_prior);
    force_float = 0;
    force_json = 2;
    probe fatal = {.status = 200, .body = "{}"};
    fatal.http.inspect = inspect;
    fatal.http.user = &fatal;
    br_transport transport = {&fatal, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)token, strlen(token)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("openrouter");
}
