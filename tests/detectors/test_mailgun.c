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
#include "../../src/detectors/mailgun.c"
#undef br_json_type_cause
#undef br_json_first_document

static char long_key[73];
static char short_key[37];
static char hex_key[51];

static void make_keys(void)
{
    memset(long_key, 'A', 72);
    long_key[72] = '\0';
    memcpy(short_key, "key-", 4);
    memset(short_key + 4, 'a', 32);
    short_key[36] = '\0';
    memset(hex_key, 'b', 32);
    hex_key[32] = '-';
    memset(hex_key + 33, 'c', 8);
    hex_key[41] = '-';
    memset(hex_key + 42, 'd', 8);
    hex_key[50] = '\0';
}

typedef struct { test_http http; int status; const char *body; const char *expect_auth; int send_rc; const char *send_error; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.mailgun.net/v3/domains"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, ((probe *)http->user)->expect_auth));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    probe *p = http->user;
    http->response.status = p->status;
    if (p->body) http->response.body = (br_slice){(const unsigned char *)p->body, strlen(p->body)};
    http->send_rc = p->send_rc;
    http->send_error = p->send_error;
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

static bool has_raw(const br_results *results, const char *key)
{
    for (size_t i = 0; i < results->len; ++i)
        if (results->items[i].raw.len == strlen(key) && !memcmp(results->items[i].raw.data, key, strlen(key)))
            return true;
    return false;
}

int main(void)
{
    make_keys();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_mailgun_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 34 && detector->nkeywords == 2);
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "mailgun") && !strcmp(detector->keywords[1], "key-"));
    char input[256];
    snprintf(input, sizeof(input), "mailgun %s %s %s %s", long_key, short_key, hex_key, short_key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    CHECK(has_raw(&results, long_key) && has_raw(&results, short_key) && has_raw(&results, hex_key));
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, long_key, strlen(long_key));
    CHECK(results.len == 0);
    br_results_clear(&results);

    char auth[80];
    snprintf(auth, sizeof(auth), "Basic %s", long_key);
    probe ok = {.status = 200, .expect_auth = auth,
                .body = "{\"total_count\":1,\"items\":[{\"name\":\"a.example\",\"state\":\"active\",\"type\":\"domain\",\"is_disabled\":true}]}"};
    snprintf(input, sizeof(input), "mailgun %s", long_key);
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), "a.example (active,domain,disabled)"));
    br_results_clear(&results);

    probe empty = {.status = 200, .expect_auth = auth, .body = "{\"items\":[]}"};
    results = scan_probe(detector, input, &empty);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data);
    br_results_clear(&results);

    probe bad_json = {.status = 200, .expect_auth = auth, .body = "[]"};
    results = scan_probe(detector, input, &bad_json);
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error,
                  "json: cannot unmarshal array into Go value of type mailgun.domainResponse"));
    br_results_clear(&results);

    probe kept = {.status = 200, .expect_auth = auth,
                  .body = "{\"items\":[{\"name\":\"kept\",\"state\":\"active\",\"type\":\"domain\",\"is_disabled\":true,\"name\":null}]}"};
    results = scan_probe(detector, input, &kept);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), "kept (active,domain,disabled)"));
    br_results_clear(&results);

    probe quiet = {.status = 401, .expect_auth = auth};
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    probe other = {.status = 500, .expect_auth = auth};
    results = scan_probe(detector, input, &other);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);

    probe down = {.expect_auth = "Basic YXBpOmtleS1hYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
                  .send_rc = 1, .send_error = "dial tcp: refused"};
    results = scan_probe(detector, short_key, &down);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "dial tcp: refused"));
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, short_key, strlen(short_key));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    probe reused = {.status = 200, .expect_auth = auth,
                    .body = "{\"items\":[{\"name\":\"old\",\"state\":\"s\",\"type\":\"t\",\"is_disabled\":true},{\"name\":\"drop\",\"state\":\"x\",\"type\":\"y\"}],\"items\":[{\"name\":\"new\"}]}"};
    results = scan_probe(detector, input, &reused);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), "new (s,t,disabled)"));
    br_results_clear(&results);

    probe backing = {.status = 200, .expect_auth = auth,
                     .body = "{\"items\":[{\"name\":\"a\",\"state\":\"s\",\"type\":\"t\"},{\"name\":\"b\",\"state\":\"S\",\"type\":\"T\"}],\"items\":[{\"name\":\"c\"}],\"items\":[null,null]}"};
    results = scan_probe(detector, input, &backing);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), "c (s,t), b (S,T)"));
    br_results_clear(&results);

    probe null_slice = {.status = 200, .expect_auth = auth,
                        .body = "{\"items\":[{\"name\":\"old\",\"state\":\"s\",\"type\":\"t\"}],\"items\":null}"};
    results = scan_probe(detector, input, &null_slice);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data);
    br_results_clear(&results);

    probe cleared = {.status = 200, .expect_auth = auth,
                     .body = "{\"items\":[{\"name\":\"a\",\"state\":\"s\",\"type\":\"t\"}],\"items\":null,\"items\":[null]}"};
    results = scan_probe(detector, input, &cleared);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), " (,)"));
    br_results_clear(&results);

    probe nul = {.status = 200, .expect_auth = auth,
                 .body = "{\"items\":[{\"name\":\"A\\u0000B\",\"state\":\"s\\u0000t\",\"type\":\"u\"}]}"};
    results = scan_probe(detector, input, &nul);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(json_object_get_string_len(part) == 11 &&
          !memcmp(json_object_get_string(part), "A\0B (s\0t,u)", 11));
    br_results_clear(&results);

    probe overflow = {.status = 200, .expect_auth = auth,
                      .body = "{\"total_count\":9223372036854775808,\"items\":[{\"name\":\"x\",\"state\":\"s\",\"type\":\"t\"}]}"};
    results = scan_probe(detector, input, &overflow);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error,
                  "json: cannot unmarshal number 9223372036854775808 into Go struct field domainResponse.total_count of type int"));
    br_results_clear(&results);

    probe under = {.status = 200, .expect_auth = auth, .body = "{\"total_count\":-9223372036854775809}"};
    results = scan_probe(detector, input, &under);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "-9223372036854775809") &&
          !strstr(results.items[0].verification_error, "-9223372036854775808 into"));
    br_results_clear(&results);

    probe max_int = {.status = 200, .expect_auth = auth,
                     .body = "{\"total_count\":9223372036854775807,\"items\":[{\"name\":\"x\",\"state\":\"s\",\"type\":\"t\"}]}"};
    results = scan_probe(detector, input, &max_int);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "Domains", &part));
    CHECK(!strcmp(json_object_get_string(part), "x (s,t)"));
    br_results_clear(&results);
    later_type = 1;
    type_calls = 0;
    probe later = {.status = 200, .expect_auth = auth, .body = "{\"total_count\":true,\"items\":1}"};
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
    CHECK(detector->scan(detector, &later_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept_prior, &scan_error) != 0);
    CHECK(type_calls == 2 && kept_prior.len == 1 && kept_prior.items[0].raw.len == 5);
    CHECK(!memcmp(kept_prior.items[0].raw.data, "prior", 5));
    free(scan_error);
    br_results_clear(&kept_prior);
    later_type = 0;
    force_json = 2;
    probe fatal = {.status = 200, .body = "{}", .expect_auth = auth};
    fatal.http.inspect = inspect;
    fatal.http.user = &fatal;
    br_transport transport = {&fatal, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("mailgun");
}
