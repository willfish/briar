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
#include "../../src/detectors/slack.c"
#undef br_json_type_cause
#undef br_json_first_document

static const char bot[] = "xoxb-65677559833-9613778673399u";

typedef struct { test_http http; int status; const char *body; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://slack.com/api/auth.test"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json; charset=utf-8"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7));
    probe *p = http->user;
    http->response.status = p->status;
    if (p->body) http->response.body = (br_slice){(const unsigned char *)p->body, strlen(p->body)};
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

static const char *extra(const br_result *result, const char *key)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, key, &part));
    return json_object_get_string(part);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_slack_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 13 && detector->nkeywords == 4);
    CHECK(detector->max_credential_span == 1024);
    br_results results = test_scan(detector, NULL, false, bot, strlen(bot));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(bot) && !memcmp(results.items[0].raw.data, bot, strlen(bot)));
    CHECK(!strcmp(extra(&results.items[0], "token_type"), "Slack Bot Token"));
    CHECK(strstr(extra(&results.items[0], "rotation_guide"), "howtorotate.com"));
    br_results_clear(&results);
    probe ok = {.status = 200, .body = "{\"ok\":true,\"team\":\"T\",\"user\":\"U\"}"};
    results = scan_probe(detector, bot, &ok);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "team"), "T") && !strcmp(extra(&results.items[0], "name"), "U"));
    br_results_clear(&results);
    probe kept = {.status = 200, .body = "{\"ok\":true,\"ok\":null,\"team\":\"T\",\"team\":null,\"user\":\"U\\u0000X\"}"};
    results = scan_probe(detector, bot, &kept);
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "team"), "T"));
    br_json *name = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "name", &name));
    CHECK(json_object_get_string_len(name) == 3 && !memcmp(json_object_get_string(name), "U\0X", 3));
    br_results_clear(&results);
    probe not_quiet = {.status = 200, .body = "{\"ok\":false,\"error\":\"invalid_auth\\u0000X\"}"};
    results = scan_probe(detector, bot, &not_quiet);
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "unexpected error auth response invalid_auth"));
    br_results_clear(&results);
    probe quiet = {.status = 200, .body = "{\"ok\":false,\"error\":\"invalid_auth\"}"};
    results = scan_probe(detector, bot, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    probe bad = {.status = 200, .body = "{\"ok\":false,\"error\":\"ratelimited\"}"};
    results = scan_probe(detector, bot, &bad);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unexpected error auth response"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, bot, strlen(bot));
    CHECK(results.len == 0);
    br_results_clear(&results);
    later_type = 1;
    type_calls = 0;
    probe later = {.status = 200, .body = "{\"ok\":1,\"error\":1}"};
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
    CHECK(detector->scan(detector, &later_ctx, true, (br_slice){(const unsigned char *)bot, strlen(bot)}, &kept_prior, &scan_error) != 0);
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
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)bot, strlen(bot)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("slack");
}
