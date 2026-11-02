/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error user_real_setter
#define br_results_push user_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_newrelicuserkey_init(const br_detector **out, char **error);

static int checked_snprintf(char *, size_t, const char *, ...);
static int user_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static int user_first_document(br_slice, const char *, br_json **, size_t *, char **);
static int seam_user_id_copy(const void *, size_t, char **);
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
#define snprintf checked_snprintf
#define br_http_send user_seam_send
#define br_json_first_document user_first_document
#define user_id_copy seam_user_id_copy
#define br_newrelicuserkey_init observed_user_init
#include "../../src/detectors/newrelicuserkey.c"
#undef snprintf
#undef br_http_send
#undef br_json_first_document
#undef user_id_copy
#undef br_newrelicuserkey_init

static const char key[] = "NRAK-GDJSS4QZORUYIC1OGTRNGQMT5VH";
static const char other[] = "NRAK-AAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char description[] =
    "A New Relic User API Key is an authentication token used to query data from New Relic via the NerdGraph API or REST API, allowing users to access account data and perform read operations securely. It is primarily used for interacting with New Relic\xe2\x80\x99s query and configuration services.";
static const char us_url[] = "https://api.newrelic.com/graphql";
static const char eu_url[] = "https://api.eu.newrelic.com/graphql";
static const char query_body[] = "{\"query\": \"{ requestContext { userId } }\"}";
static const char user_body[] = "{\"data\":{\"requestContext\":{\"userId\":\"user-1\"}}}";
static size_t fail_key_after, fail_region_after, fail_push_after, fail_setter_after;
static size_t setter_calls, seen_secrets, setters_before_format, null_send_setters_before;
static bool format_before_release, null_send_cause, null_body_cause, setter_saw_null;
static int fail_format, fail_user_copy;
static test_http *null_send_http;
static const char *seam_key;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    if (!strcmp(name, "region") && fail_region_after && --fail_region_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    (void)secrets;
    ++setter_calls;
    setter_saw_null = cause == NULL;
    seen_secrets = count;
    if (r->verified) {
        br_json *part = NULL;
        CHECK(r->extra_data && json_object_object_get_ex(r->extra_data, "region", &part));
        const char *region = json_object_get_string(part);
        CHECK(region && (!strcmp(region, "us") || !strcmp(region, "eu")));
        CHECK(json_object_object_get_ex(r->extra_data, "user_id", &part));
        CHECK(r->secret_parts && json_object_object_get_ex(r->secret_parts, "region", &part));
        CHECK(!json_object_object_get_ex(r->secret_parts, "user_id", &part));
    }
    if (fail_setter_after && --fail_setter_after == 0) {
        if (null_send_cause) {
            CHECK(null_send_http && null_send_http->releases == 2);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return user_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return user_real_push(out, owned);
}

static void result_is(const br_result *result, const char *expected, const char *region,
                      const char *user_id, bool verified, const char *cause)
{
    char shown[12];
    memcpy(shown, expected, 8);
    memcpy(shown + 8, "...", 4);
    CHECK(result->detector_type == 1066 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, expected, 32));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && result->verified == verified);
    CHECK(result->redacted && !strcmp(result->redacted, shown));
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause)
               : !result->verification_error);
    CHECK(result->secret_parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected, 32));
    CHECK(!json_object_object_get_ex(result->secret_parts, "user_id", &part));
    if (region) {
        CHECK(json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 2);
        CHECK(json_object_object_get_ex(result->extra_data, "region", &part));
        CHECK(!strcmp(json_object_get_string(part), region));
        CHECK(json_object_object_get_ex(result->extra_data, "user_id", &part));
        CHECK(!strcmp(json_object_get_string(part), user_id ? user_id : ""));
    } else {
        CHECK(json_object_object_length(result->secret_parts) == 1);
        CHECK(!json_object_object_get_ex(result->secret_parts, "region", &part));
        CHECK(!result->extra_data);
    }
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 33 && sizeof(other) == 33);
    CHECK(memchr(description, '\'', strlen(description)) == NULL);
    CHECK(strstr(description, "\xe2\x80\x99") != NULL);
    CHECK(br_newrelicuserkey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NewRelicUserKey detector output"));
    free(error);
    error = NULL;
    CHECK(br_newrelicuserkey_init(NULL, NULL) == -1);
    CHECK(br_newrelicuserkey_init(&d, &error) == 0 && d && !error);
    CHECK(br_newrelicuserkey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1066 && d->version == 0 && !strcmp(d->name, "NewRelicUserKey"));
    CHECK(!strcmp(d->custom_name, "") && !strcmp(d->description, description));
    CHECK(d->description[strlen(d->description) - 1] == '.');
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nrak-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    br_results out = test_scan(d, NULL, false, text, len);
    CHECK(!out.len && !setter_calls);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "%s %s", key, key);
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 2 && !setter_calls);
    result_is(&out.items[0], key, NULL, NULL, false, NULL);
    result_is(&out.items[1], key, NULL, NULL, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    CHECK(out.items[0].redacted != out.items[1].redacted);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "%s.", key);
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, NULL, NULL, false, NULL);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "x%s", key);
    expect_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "%sA", key);
    expect_none(d, input, (size_t)n);
    expect_none(d, "NRAK-GDJSS4QZORUYIC1OGTRNGQMT5V", 31);
    expect_none(d, "NRAK-GDJSS4QZORUYIC1OGTRNGQMT5Vh", 32);
    expect_none(d, "nrak-", 5);
}

typedef struct {
    const char *borrowed_key, *body, *bodies[2];
    int status, send_rc;
    const char *send_error, *body_error;
    bool order_us_eu, second_key, status_set[2], send_set[2];
    int statuses[2], send_rcs[2];
    const char *send_errors[2];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *token = s->second_key && http->calls == 2 ? other : key;
    const char *url = s->order_us_eu && http->calls == 2 ? eu_url : us_url;
    const char *body = s->bodies[http->calls - 1] ? s->bodies[http->calls - 1] : s->body;
    CHECK(ctx && http->calls == http->releases + 1 && http->calls <= 2);
    CHECK(request->url && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(!strcmp(request->method, "POST"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1066);
    CHECK(request->body.len == sizeof(query_body) - 1 && request->body.data);
    CHECK(!memcmp(request->body.data, query_body, request->body.len));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Api-Key") && strcmp(request->headers[1].name, "API-Key"));
    CHECK(request->headers[1].value && strlen(request->headers[1].value) == 32);
    CHECK(!memcmp(request->headers[1].value, token, 32));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog user-offline"));
    s->borrowed_key = request->headers[1].value;
    size_t at = http->calls - 1;
    int status = s->status_set[at] ? s->statuses[at] : s->status;
    http->response = (br_http_response){
        .status = status,
        .body = {(const unsigned char *)(body ? body : ""), body ? strlen(body) : 0},
        .body_error = s->body_error,
    };
    http->send_rc = s->send_set[at] ? s->send_rcs[at] : s->send_rc;
    http->send_error = s->send_set[at] ? s->send_errors[at] : s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    if (null_send_cause) {
        CHECK(setter_calls == null_send_setters_before);
        CHECK(seam_key && !memcmp(seam_key, key, 32));
        seam_key = NULL;
    }
    if (null_body_cause) CHECK(setter_calls == null_send_setters_before);
    if (format_before_release)
        CHECK(!fail_format && setter_calls == setters_before_format);
    if (s && s->borrowed_key) {
        const char *token = s->second_key && http->releases == 1 ? other : key;
        CHECK(!memcmp(s->borrowed_key, token, 32));
        s->borrowed_key = NULL;
    }
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static char *join3(const char *a, const char *b, const char *c)
{
    size_t an = strlen(a), bn = strlen(b), cn = c ? strlen(c) : 0;
    char *text = malloc(an + bn + cn + 1);
    CHECK(text);
    memcpy(text, a, an);
    memcpy(text + an, b, bn);
    if (c) memcpy(text + an + bn, c, cn);
    text[an + bn + cn] = '\0';
    return text;
}

static char *region_line(const char *region, const char *inner)
{
    char *head = join3("error verifying region ", region, ": ");
    char *text = join3(head, inner, NULL);
    free(head);
    return text;
}

static void verification(const br_detector *d)
{
    script s = {.status = 200, .order_us_eu = true, .body = user_body};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "user-offline"};
    size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, true, key, 32);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_key);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, "us", "user-1", true, NULL);
    br_results_clear(&out);

    const char *empty_bodies[] = {
        "{}",
        "{\"data\":null}",
        "{\"data\":{\"requestContext\":null}}",
        "{\"data\":{\"requestContext\":{\"userId\":null}}}",
        "null",
        "{\"Data\":{\"RequestContext\":{\"UserID\":\"\"}}}",
    };
    for (size_t i = 0; i < sizeof(empty_bodies) / sizeof(empty_bodies[0]); ++i) {
        s.body = empty_bodies[i];
        http.calls = http.releases = 0;
        before = setter_calls;
        out = test_scan(d, &ctx, true, key, 32);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == before + 1);
        result_is(&out.items[0], key, "us", "", true, NULL);
        br_results_clear(&out);
    }

    s.body = "{\"data\":{\"requestContext\":{\"userId\":\"abc\"}}} trailing";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 32);
    CHECK(out.len == 1 && http.calls == 1);
    result_is(&out.items[0], key, "us", "abc", true, NULL);
    br_results_clear(&out);

    s.body = user_body;
    s.status_set[0] = true;
    s.statuses[0] = 401;
    s.status_set[1] = true;
    s.statuses[1] = 200;
    s.bodies[1] = "{\"data\":{\"requestContext\":{\"userId\":\"eu-user\"}}}";
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 32);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    CHECK(setter_calls == before + 1 && setter_saw_null && !seen_secrets);
    result_is(&out.items[0], key, "eu", "eu-user", true, NULL);
    br_results_clear(&out);

    s.statuses[1] = 403;
    s.bodies[1] = NULL;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 32);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == before + 1 && setter_saw_null);
    result_is(&out.items[0], key, NULL, NULL, false, NULL);
    br_results_clear(&out);

    s.statuses[0] = 500;
    s.statuses[1] = 401;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 32);
    char *one = region_line("us", "unexpected status code for region us: 500");
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    result_is(&out.items[0], key, NULL, NULL, false, one);
    CHECK(!strchr(out.items[0].verification_error, '\n'));
    br_results_clear(&out);
    free(one);

    s.statuses[1] = 400;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 32);
    char *us = region_line("us", "unexpected status code for region us: 500");
    char *eu = region_line("eu", "unexpected status code for region eu: 400");
    char *joined = join3(us, "\n", eu);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
    result_is(&out.items[0], key, NULL, NULL, false, joined);
    CHECK(out.items[0].verification_error[strlen(out.items[0].verification_error) - 1] != '\n');
    br_results_clear(&out);
    free(us);
    free(eu);
    free(joined);

    s.statuses[0] = 500;
    s.statuses[1] = 200;
    s.bodies[1] = user_body;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, key, 32);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && setter_saw_null);
    CHECK(setter_calls == before + 1);
    result_is(&out.items[0], key, "eu", "user-1", true, NULL);
    br_results_clear(&out);

    const char *typed[] = {
        "{\"data\":{\"requestContext\":{\"userId\":1e2}}}",
        "{\"data\":{\"requestContext\":{\"userId\":true}}}",
        "{\"data\":{\"requestContext\":{\"userId\":[1]}}}",
        "{\"data\":{\"requestContext\":{\"userId\":{}}}}",
        "{\"data\":{\"requestContext\":\"x\"}}",
        "{\"data\":1}",
        "\"x\"",
        "[]",
        "",
        "{",
        "{]",
    };
    const char *typed_inner[] = {
        "error decoding response for region us: json: cannot unmarshal number into Go struct field .data.requestContext.userId of type string",
        "error decoding response for region us: json: cannot unmarshal bool into Go struct field .data.requestContext.userId of type string",
        "error decoding response for region us: json: cannot unmarshal array into Go struct field .data.requestContext.userId of type string",
        "error decoding response for region us: json: cannot unmarshal object into Go struct field .data.requestContext.userId of type string",
        "error decoding response for region us: json: cannot unmarshal string into Go struct field .data.requestContext of type struct { UserID string \"json:\\\"userId\\\"\" }",
        "error decoding response for region us: json: cannot unmarshal number into Go struct field graphqlResponse.data of type struct { RequestContext struct { UserID string \"json:\\\"userId\\\"\" } \"json:\\\"requestContext\\\"\" }",
        "error decoding response for region us: json: cannot unmarshal string into Go value of type newrelicuserkey.graphqlResponse",
        "error decoding response for region us: json: cannot unmarshal array into Go value of type newrelicuserkey.graphqlResponse",
        "error decoding response for region us: EOF",
        "error decoding response for region us: unexpected EOF",
        "error decoding response for region us: invalid character ']' looking for beginning of object key string",
    };
    s.statuses[0] = 200;
    s.statuses[1] = 401;
    s.bodies[1] = NULL;
    for (size_t i = 0; i < sizeof(typed) / sizeof(typed[0]); ++i) {
        s.body = typed[i];
        s.body_error = NULL;
        http.calls = http.releases = 0;
        out = test_scan(d, &ctx, true, key, 32);
        char *line = region_line("us", typed_inner[i]);
        CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
        result_is(&out.items[0], key, NULL, NULL, false, line);
        if (i == 0) CHECK(!strstr(out.items[0].verification_error, "1e2"));
        br_results_clear(&out);
        free(line);
    }

    const char *later[] = {
        "{\"data\":{\"requestContext\":{\"userId\":1,\"userId\":\"abc\"}}}",
        "{\"data\":{\"requestContext\":1,\"requestContext\":{\"userId\":\"abc\"}}}",
        "{\"data\":1,\"data\":{\"requestContext\":{\"userId\":\"abc\"}}}",
    };
    const char *later_inner[] = {
        typed_inner[0],
        "error decoding response for region us: json: cannot unmarshal number into Go struct field .data.requestContext of type struct { UserID string \"json:\\\"userId\\\"\" }",
        typed_inner[5],
    };
    const char *kept[] = {
        "{\"data\":{\"requestContext\":{\"userId\":\"abc\",\"userId\":null}}}",
        "{\"data\":{\"requestContext\":{\"userId\":\"abc\"},\"requestContext\":null}}",
        "{\"data\":{\"requestContext\":{\"userId\":\"abc\"}},\"data\":null}",
    };
    for (size_t i = 0; i < sizeof(later) / sizeof(later[0]); ++i) {
        s.body = later[i];
        http.calls = http.releases = 0;
        out = test_scan(d, &ctx, true, key, 32);
        char *line = region_line("us", later_inner[i]);
        CHECK(out.len == 1 && http.calls == 2 && http.releases == 2);
        result_is(&out.items[0], key, NULL, NULL, false, line);
        CHECK(!strstr(out.items[0].verification_error, "abc"));
        CHECK(!strstr(out.items[0].verification_error, "1e2"));
        br_results_clear(&out);
        free(line);
    }
    for (size_t i = 0; i < sizeof(kept) / sizeof(kept[0]); ++i) {
        s.body = kept[i];
        s.statuses[0] = 200;
        http.calls = http.releases = 0;
        out = test_scan(d, &ctx, true, key, 32);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, "us", "abc", true, NULL);
        br_results_clear(&out);
    }
    s.statuses[1] = 401;

    s.body = user_body;
    s.body_error = "copy failed";
    s.statuses[0] = 200;
    s.statuses[1] = 401;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 32);
    char *copied = region_line("us", "error decoding response for region us: copy failed");
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !seen_secrets);
    result_is(&out.items[0], key, NULL, NULL, false, copied);
    br_results_clear(&out);
    free(copied);
    s.body_error = NULL;

    char rejected[80];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s", key) > 0);
    s.send_set[0] = true;
    s.send_rcs[0] = -1;
    s.send_errors[0] = rejected;
    s.statuses[1] = 403;
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, key, 32);
    char detail[96], *sent = NULL;
    CHECK(snprintf(detail, sizeof(detail), "error making request: %s", rejected) > 0);
    sent = region_line("us", detail);
    CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && !seen_secrets && !setter_saw_null);
    result_is(&out.items[0], key, NULL, NULL, false, sent);
    CHECK(strstr(out.items[0].verification_error, key) && !strstr(out.items[0].verification_error, "[REDACTED]"));
    br_results_clear(&out);
    free(sent);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "user-offline", .cancelled = cancelled};
    s.send_set[0] = false;
    http.calls = http.releases = 0;
    out = test_scan(d, &stopped, true, key, 32);
    char *cancel_us = region_line("us", "error making request: context canceled");
    char *cancel_eu = region_line("eu", "error making request: context canceled");
    char *cancelled_cause = join3(cancel_us, "\n", cancel_eu);
    CHECK(out.len == 1 && !http.calls && http.releases == 2 && !seen_secrets);
    result_is(&out.items[0], key, NULL, NULL, false, cancelled_cause);
    br_results_clear(&out);
    free(cancel_us);
    free(cancel_eu);
    free(cancelled_cause);

    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, NULL, true, key, 32);
    char *nil_us = region_line("us", "error constructing request: net/http: nil Context");
    char *nil_eu = region_line("eu", "error constructing request: net/http: nil Context");
    char *nil_cause = join3(nil_us, "\n", nil_eu);
    CHECK(out.len == 1 && !http.calls && !http.releases && setter_calls == before + 1 && !seen_secrets);
    result_is(&out.items[0], key, NULL, NULL, false, nil_cause);
    br_results_clear(&out);
    free(nil_us);
    free(nil_eu);
    free(nil_cause);

    before = setter_calls;
    out = test_scan(d, NULL, false, other, 32);
    CHECK(out.len == 1 && setter_calls == before && !http.calls);
    result_is(&out.items[0], other, NULL, NULL, false, NULL);
    br_results_clear(&out);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(out->items[0].verified && !strcmp(out->items[0].verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char text[80];
    int n = snprintf(text, sizeof(text), "%s %s", key, other);
    br_slice data = {(const unsigned char *)text, (size_t)n};
    script s = {.status = 200, .body = user_body, .second_key = true};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "user-offline"};
    char *error = NULL;
    size_t setters = setter_calls;

    fail_key_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NewRelicUserKey finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicUserKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);

    s.second_key = false;
    fail_region_after = 1;
    http.calls = http.releases = 0;
    setters = setter_calls;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)key, 32}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicUserKey region") && !fail_region_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && setter_calls == setters);
    prior_unchanged(&out, &prior);

    s.second_key = true;
    fail_setter_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicUserKey verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_key);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
}

static int seam_user_id_copy(const void *text, size_t len, char **out)
{
    if (fail_user_copy) {
        fail_user_copy = 0;
        return -1;
    }
    return copy_bytes(text, len, out);
}

static int user_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    seam_key = request && request->nheaders > 1 && request->headers ? request->headers[1].value : NULL;
    if (response) memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    return -1;
}

static int user_first_document(br_slice body, const char *read_error, br_json **out,
                               size_t *end, char **cause)
{
    if (null_body_cause) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return 1;
    }
    return real_first_document(body, read_error, out, end, cause);
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && format && !strcmp(format, "unexpected status code for region %s: %d")) {
        int rc = fail_format;
        fail_format = 0;
        return rc;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, n, format, args);
    va_end(args);
    return rc;
}

static void format_and_null_send(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_user_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_newrelicuserkey_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    script s = {.status = 500, .body = user_body};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "user-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_key = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)key, 32}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format NewRelicUserKey verification status") && !fail_format);
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_key);
        CHECK(setter_calls == setters_before_format);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    format_before_release = false;

    null_send_cause = true;
    null_send_http = &http;
    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results sent = test_scan(observed, &ctx, true, key, 32);
    CHECK(sent.len == 1 && !http.calls && http.releases == 2 && !seam_key);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    result_is(&sent.items[0], key, NULL, NULL, false, NULL);
    br_results_clear(&sent);

    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)key, 32}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record NewRelicUserKey verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 2 && !seam_key);
    CHECK(setter_calls == setters + 1 && setter_saw_null);
    prior_unchanged(&out, &prior);
    free(error);
    error = NULL;
    null_send_cause = false;
    null_send_http = NULL;

    null_body_cause = true;
    s.status = 200;
    s.order_us_eu = true;
    http.calls = http.releases = 0;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    sent = test_scan(observed, &ctx, true, key, 32);
    CHECK(sent.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == setters + 1 && setter_saw_null && !seen_secrets);
    result_is(&sent.items[0], key, NULL, NULL, false, NULL);
    br_results_clear(&sent);
    null_body_cause = false;

    const char *later_copy[] = {
        "{\"data\":{\"requestContext\":{\"userId\":1,\"userId\":\"abc\"}}}",
        "{\"data\":{\"requestContext\":1,\"requestContext\":{\"userId\":\"abc\"}}}",
        "{\"data\":1,\"data\":{\"requestContext\":{\"userId\":\"abc\"}}}",
    };
    s.status = 200;
    s.order_us_eu = true;
    s.body_error = NULL;
    s.send_rc = 0;
    for (size_t i = 0; i < sizeof(later_copy) / sizeof(later_copy[0]); ++i) {
        s.body = later_copy[i];
        http.calls = http.releases = 0;
        s.borrowed_key = NULL;
        setters = setter_calls;
        fail_user_copy = 1;
        CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)key, 32}, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot decode NewRelicUserKey verification response") && !fail_user_copy);
        CHECK(!strstr(error, "cannot unmarshal") && !strstr(error, "abc"));
        CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_key);
        CHECK(setter_calls == setters);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    br_results_clear(&out);
}

int main(void)
{
    char *oversized = NULL;
    CHECK(copy_bytes(NULL, SIZE_MAX, &oversized) == -1 && !oversized);
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    format_and_null_send();
    return test_finish("NewRelicUserKey");
}
