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
static int (*real_type_cause)(br_json *, const char *, const char *, char **) = br_json_type_cause;
static int type_hook(br_json *value, const char *field, const char *expected, char **cause)
{
    int n = ++type_calls;
    if (later_type && n > 1) { if (cause) *cause = NULL; return 1; }
    return real_type_cause(value, field, expected, cause);
}
#define br_json_type_cause type_hook
#include "../../src/detectors/xai.c"
#undef br_json_type_cause
#undef br_json_first_document

static char token[85];

static void make_token(void)
{
    memcpy(token, "xai-", 4);
    memset(token + 4, 'A', 80);
    token[84] = '\0';
}

typedef struct { test_http http; int status; const char *body; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.x.ai/v1/api-key"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char expect[96];
    snprintf(expect, sizeof(expect), "Bearer %s", token);
    CHECK(!strcmp(request->headers[1].value, expect));
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
    CHECK(strlen(token) == 84);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_xai_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1023 && !strcmp(detector->keywords[0], "xai-"));
    char input[180];
    snprintf(input, sizeof(input), "%s %s", token, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1023, token, "key");
    br_results_clear(&results);

    probe ok = {.status = 200, .body = "{\"name\":\"bot\",\"acls\":[\"read\",\"write\"]}"};
    results = scan_probe(detector, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    CHECK(!strcmp(extra(&results.items[0], "name"), "bot"));
    CHECK(!strcmp(extra(&results.items[0], "acls"), "read,write"));
    br_results_clear(&results);

    probe nulls = {.status = 200, .body = "{\"acls\":[null,\"b\"]}"};
    results = scan_probe(detector, &nulls);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "name"), ""));
    CHECK(!strcmp(extra(&results.items[0], "acls"), ",b"));
    br_results_clear(&results);

    probe bad_json = {.status = 200, .body = "[]"};
    results = scan_probe(detector, &bad_json);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "json: cannot unmarshal array into Go value of type struct { Name string") &&
          !strstr(results.items[0].verification_error, "failed to decode response:"));
    br_results_clear(&results);

    probe kept = {.status = 200, .body = "{\"name\":\"A\\u0000B\",\"name\":null,\"acls\":[\"x\\u0000y\",\"z\"]}"};
    results = scan_probe(detector, &kept);
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "name", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), "A\0B", 3));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "acls", &part));
    CHECK(json_object_get_string_len(part) == 5 && !memcmp(json_object_get_string(part), "x\0y,z", 5));
    br_results_clear(&results);

    probe null_slot = {.status = 200, .body = "{\"name\":\"bot\",\"acls\":[\"keep\",\"drop\"],\"acls\":[null]}"};
    results = scan_probe(detector, &null_slot);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "acls"), "keep"));
    br_results_clear(&results);

    probe null_clear = {.status = 200, .body = "{\"acls\":[\"keep\"],\"acls\":null,\"acls\":[null]}"};
    results = scan_probe(detector, &null_clear);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "acls"), ""));
    br_results_clear(&results);

    probe empty_clear = {.status = 200, .body = "{\"acls\":[\"keep\"],\"acls\":[],\"acls\":[null]}"};
    results = scan_probe(detector, &empty_clear);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "acls"), ""));
    br_results_clear(&results);

    probe backing = {.status = 200, .body = "{\"acls\":[\"a\",\"b\"],\"acls\":[\"c\"],\"acls\":[null,null]}"};
    results = scan_probe(detector, &backing);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "acls"), "c,b"));
    br_results_clear(&results);

    probe nul_reuse = {.status = 200, .body = "{\"acls\":[\"x\\u0000y\",\"z\"],\"acls\":[null,\"w\"]}"};
    results = scan_probe(detector, &nul_reuse);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "acls", &part));
    CHECK(json_object_get_string_len(part) == 5 && !memcmp(json_object_get_string(part), "x\0y,w", 5));
    br_results_clear(&results);

    probe quiet = {.status = 400};
    results = scan_probe(detector, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    probe unauthorized = {.status = 401};
    results = scan_probe(detector, &unauthorized);
    CHECK(results.len == 1 && !results.items[0].verification_error);
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
    probe later = {.status = 200, .body = "{\"name\":1,\"acls\":1}"};
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
    return test_finish("xai");
}
