/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"

#include <stdarg.h>
#include <string.h>

/* Test-local seams only. Production regex, findings and HTTP stay linked.
 * br_http_send is renamed only in this include so the detector source still
 * calls it and the NULL regression can return the pointer the native fill
 * would have replaced. */
#define br_results_push klaviyo_real_push
#define br_result_set_verification_error klaviyo_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static int null_send, fail_format, fail_member_after, fail_element_after, fail_setter;
static int setter_null_cause, last_setter_rc;
static size_t member_calls, element_calls, setter_secret_count, setter_secret_len;
static char setter_secret_bytes[64];

static int checked_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    ++member_calls;
    if (fail_member_after && --fail_member_after == 0) return 1;
    return br_json_each_member(object, callback, user);
}

static int checked_each_element(br_slice array, br_json_element_fn callback, void *user)
{
    ++element_calls;
    if (fail_element_after && --fail_element_after == 0) return 1;
    return br_json_each_element(array, callback, user);
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(request && request->url && !strcmp(request->url, "https://a.klaviyo.com/api/profiles"));
    CHECK(request->method && !strcmp(request->method, "GET") && request->nheaders == 2);
    int rc = br_http_send(ctx, request, response, error);
    if (!null_send) return rc;
    null_send = 0;
    CHECK(rc != 0 && error);
    if (*error) {
        CHECK(!strcmp(*error, "HTTP transport failed"));
        free(*error);
        *error = NULL;
    }
    return rc;
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    if (fail_format) {
        CHECK(format && !strcmp(format, "unexpected HTTP response status %d"));
        fail_format = 0;
        return -1;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}

#define br_http_send checked_send
#define br_json_each_member checked_each_member
#define br_json_each_element checked_each_element
#define snprintf checked_snprintf
#define br_klaviyo_init observed_klaviyo_init
#include "../../src/detectors/klaviyo.c"
#undef br_http_send
#undef br_json_each_member
#undef br_json_each_element
#undef snprintf
#undef br_klaviyo_init

static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return klaviyo_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_null_cause = cause == NULL;
    setter_secret_count = count;
    setter_secret_len = 0;
    if (secrets && count == 1 && secrets[0].data && secrets[0].len < sizeof(setter_secret_bytes)) {
        setter_secret_len = secrets[0].len;
        memcpy(setter_secret_bytes, secrets[0].data, setter_secret_len);
    }
    if (fail_setter && --fail_setter == 0) {
        last_setter_rc = 1;
        return 1;
    }
    last_setter_rc = klaviyo_real_setter(result, cause, secrets, count);
    return last_setter_rc;
}

static const char description[] =
    "Klaviyo is a marketing automation platform. Klaviyo API keys can be used to access and modify marketing data and configurations.";

static void legacy_key(char out[38], size_t shift)
{
    static const char hex[] = "0123456789abcdef";
    memcpy(out, "pk_", 3);
    for (size_t i = 0; i < 34; ++i) out[3 + i] = hex[(i + shift) % 16];
    out[37] = '\0';
}

static void newer_key(char out[45], size_t shift)
{
    static const char hex[] = "0123456789abcdef";
    memcpy(out, "pk_Ab12Cd_", 10);
    for (size_t i = 0; i < 34; ++i) out[10 + i] = hex[(i + shift) % 16];
    out[44] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *const *keys = http->user;
    const char *key = keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://a.klaviyo.com/api/profiles"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 935);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Revision"));
    CHECK(!strcmp(request->headers[0].value, "2023-02-22"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char authorization[64];
    snprintf(authorization, sizeof(authorization), "Klaviyo-API-Key %s", key);
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(!strstr(request->headers[1].value, "Bearer "));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog klaviyo-test" : "TruffleHog"));
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(observed_klaviyo_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid Klaviyo detector"));
    free(error);
    CHECK(observed_klaviyo_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(observed_klaviyo_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "Klaviyo") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->type == 935 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pk_"));
    CHECK(detector->max_credential_span == -1 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static void test_regex(const br_detector *detector)
{
    char legacy[38], newer[45], short_hex[37], long_hex[39], upper[38], input[160], glued[40];
    legacy_key(legacy, 1);
    newer_key(newer, 2);
    memcpy(short_hex, legacy, 36);
    short_hex[36] = '\0';
    snprintf(long_hex, sizeof(long_hex), "%sa", legacy);
    memcpy(upper, legacy, sizeof(upper));
    for (size_t i = 3; upper[i]; ++i)
        if (upper[i] >= 'a' && upper[i] <= 'f') upper[i] = (char)(upper[i] - 'a' + 'A');
    snprintf(input, sizeof(input), "before %s after %s tail", legacy, newer);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 935, legacy, "key");
    test_key_result(&out.items[1], 935, newer, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "%s %s", legacy, legacy);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 935, legacy, "key");
    test_key_result(&out.items[1], 935, legacy, "key");
    br_results_clear(&out);

    const char *misses[] = {
        short_hex, long_hex, upper, "pk_",
        "pk_Ab12C_0123456789abcdef0123456789abcdef12", "not-a-key",
    };
    snprintf(glued, sizeof(glued), "x%s", legacy);
    for (size_t i = 0; i < sizeof(misses) / sizeof(misses[0]); ++i) {
        out = test_scan(detector, NULL, false, misses[i], strlen(misses[i]));
        CHECK(!out.len);
        br_results_clear(&out);
    }
    out = test_scan(detector, NULL, false, glued, strlen(glued));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void test_http_and_lifecycle(const br_detector *detector)
{
    char first[38], second[45], input[96];
    legacy_key(first, 3);
    newer_key(second, 4);
    snprintf(input, sizeof(input), "%s %s", first, second);
    const char *keys[] = {first, second};
    const unsigned char unread[] = {'{', 'n', 'o', 't'};
    test_http http = {
        .response = {.status = 200, .body = {unread, sizeof(unread)}, .body_error = "body must not be read"},
        .inspect = inspect_request, .user = keys,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "klaviyo-test"};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    test_key_result(&out.items[0], 935, first, "key");
    test_key_result(&out.items[1], 935, second, "key");
    CHECK(out.items[0].verified && out.items[1].verified);
    CHECK(!out.items[0].verification_error && !out.items[1].verification_error);
    br_results_clear(&out);

    char sensitive[96];
    snprintf(sensitive, sizeof(sensitive), "failed %s again %s", first, first);
    const char *one[] = {first};
    const struct {
        int status, send_rc;
        const char *body_error, *send_error, *error;
        bool verified;
    } cases[] = {
        {.status = 204, .body_error = sensitive, .verified = true},
        {.status = 401, .body_error = sensitive},
        {.status = 300, .error = "unexpected HTTP response status 300"},
        {.status = 402, .error = "unexpected HTTP response status 402"},
        {.status = 500, .error = "unexpected HTTP response status 500"},
        {.status = 200, .send_rc = 1, .send_error = sensitive, .error = "failed [REDACTED] again [REDACTED]"},
        {.status = 200, .send_rc = 1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http one_http = {
            .response = {.status = cases[i].status, .body = {unread, sizeof(unread)},
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = one,
        };
        br_transport one_transport = test_transport(&one_http);
        br_scan_ctx one_ctx = {.transport = &one_transport};
        out = test_scan(detector, &one_ctx, true, first, 37);
        CHECK(out.len == 1 && one_http.calls == 1 && one_http.releases == 1);
        test_key_result(&out.items[0], 935, first, "key");
        CHECK(out.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].error));
            CHECK(!strstr(out.items[0].verification_error, first));
        } else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }

    br_results prior = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 777, "prior", "key") == 0 && br_results_push(&prior, &kept) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == 0 && !error);
    CHECK(prior.len == 1 && prior.items[0].raw.len == 5 && !memcmp(prior.items[0].raw.data, "prior", 5));
    br_results_clear(&prior);
}

static void expect_403(const br_detector *detector, const char *key, const char *body,
                       const char *body_error, bool verified, const char *message)
{
    const char *keys[] = {key};
    test_http http = {
        .response = {.status = 403, .body = {(const unsigned char *)body, body ? strlen(body) : 0},
                     .body_error = body_error},
        .inspect = inspect_request, .user = keys,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, key, 37);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&out.items[0], 935, key, "key");
    CHECK(out.items[0].verified == verified);
    if (message) {
        CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, message));
        CHECK(!strstr(out.items[0].verification_error, key));
        CHECK(!body_error || !strstr(out.items[0].verification_error, body_error));
    } else CHECK(!out.items[0].verification_error);
    br_results_clear(&out);
}

static void test_forbidden_json(const br_detector *detector)
{
    char key[38];
    legacy_key(key, 5);
    const char *verified[] = {
        "{\"errors\":[{\"id\":\"one\"}]}",
        "{\"errors\":[null]}",
        "{\"errors\":[{\"status\":null,\"source\":null}]}",
        "{\"ERRORS\":[{\"STATUS\":403,\"SOURCE\":{\"POINTER\":\"/a\"}}]}",
        "{\"errors\":[{\"status\":1,\"status\":2}]}",
        "{\"errors\":[{\"status\":9223372036854775807}]}",
        "{\"errors\":[{\"status\":-9223372036854775808}]}",
        "{\"errors\":[{\"id\":\"ok\",\"huge\":1234567890123456789012345678901234567890}]}",
        "{\"errors\":[{\"id\":\"first\"}]}{\"errors\":[]}",
        "{\"errors\":[],\"errors\":[{\"id\":\"last\"}]}",
    };
    for (size_t i = 0; i < sizeof(verified) / sizeof(verified[0]); ++i)
        expect_403(detector, key, verified[i], i == 0 ? "later read error" : NULL, true, NULL);

    const char *empty[] = {
        "{\"errors\":[]}", "{}", "null", "{\"errors\":null}",
        "{\"errors\":[{\"id\":\"first\"}],\"errors\":[]}",
    };
    for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); ++i)
        expect_403(detector, key, empty[i], NULL, false, "errors expected");

    const char *bad[] = {
        "{",
        "not-json",
        "{\"errors\":[{\"status\":403.0}]}",
        "{\"errors\":[{\"status\":1,\"status\":2.5}]}",
        "{\"errors\":[{\"status\":9223372036854775808}]}",
        "{\"errors\":[{\"status\":\"403\"}]}",
        "{\"errors\":[{\"id\":1}]}",
        "{\"errors\":[{\"id\":\"ok\"}],\"errors\":\"bad\"}",
        "[{\"errors\":[{\"id\":\"x\"}]}]",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        expect_403(detector, key, bad[i], i == 0 ? "connection reset by peer" : NULL,
                   false, "unexpected API JSON response");
}

static void keep_prior(br_results *results, br_result *sentinel, unsigned char **raw, char **cause)
{
    memset(sentinel, 0, sizeof(*sentinel));
    sentinel->detector_type = 12345;
    sentinel->verified = true;
    sentinel->raw.data = malloc(4);
    CHECK(sentinel->raw.data);
    memcpy(sentinel->raw.data, "keep", 4);
    sentinel->raw.len = 4;
    sentinel->verification_error = strdup("caller-owned");
    CHECK(sentinel->verification_error);
    *raw = sentinel->raw.data;
    *cause = sentinel->verification_error;
    CHECK(br_results_push(results, sentinel) == 0);
}

static void prior_unchanged(const br_results *results, unsigned char *raw, char *cause)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned"));
}

/* These fail an archived verify && !ctx return: that path never captures or
 * creates a finding, so an injected +1 cannot be observed and cannot avoid the setter. */
static void test_nil_context(const br_detector *detector)
{
    char key[38], input[48];
    legacy_key(key, 9);
    snprintf(input, sizeof(input), "%s", key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory iterating regex",
        "out of memory creating Klaviyo result",
    };
    for (int mode = 0; mode < 2; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 500}};
        size_t setters = setter_calls;
        if (mode == 0) {
            /* Two capturing groups, so the iteration buffer is three spans. */
            fail_size = 3 * sizeof(br_span);
            fail_after = 1;
        } else fail_part_after = 1;
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, messages[mode]));
        CHECK(!fail_after && !fail_part_after);
        CHECK(!http.calls && !http.releases && setter_calls == setters);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 500}};
    size_t setters = setter_calls;
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    const char *keys[] = {key};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = keys};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

static int scan_one(const br_detector *detector, test_http *http, const char *key,
                    br_results *results, char **error)
{
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport};
    return detector->scan(detector, &ctx, true,
                          (br_slice){(const unsigned char *)key, strlen(key)}, results, error);
}

static void secret_is_key(const char *key)
{
    CHECK(setter_secret_count == 1 && setter_secret_len == strlen(key));
    CHECK(!memcmp(setter_secret_bytes, key, setter_secret_len));
}

/* These fail an archived walk that returns +1 on a type mismatch: the later
 * each_* never runs, so an injected +1 cannot be observed and the candidate
 * is published as unexpected JSON. */
static void test_policy_failures(const br_detector *detector)
{
    char key[38];
    legacy_key(key, 12);
    const char *keys[] = {key};
    const char *continued =
        "{\"errors\":[{\"id\":1},{\"source\":{\"pointer\":\"x\"}}]}";

    member_calls = element_calls = 0;
    test_http plain = {
        .response = {.status = 403, .body = {(const unsigned char *)continued, strlen(continued)}},
        .inspect = inspect_request, .user = keys,
    };
    br_transport plain_transport = test_transport(&plain);
    br_scan_ctx plain_ctx = {.transport = &plain_transport};
    br_results published = test_scan(detector, &plain_ctx, true, key, 37);
    CHECK(published.len == 1 && plain.calls == 1 && plain.releases == 1);
    CHECK(!published.items[0].verified);
    CHECK(published.items[0].verification_error &&
          !strcmp(published.items[0].verification_error, "unexpected API JSON response"));
    CHECK(member_calls == 4 && element_calls == 1);
    br_results_clear(&published);

    const char *fatal_body = "{\"errors\":[{\"id\":\"ok\"}]}";
    const struct {
        int member_at, element_at;
        const char *body;
        size_t members;
    } walks[] = {
        {.member_at = 1, .body = fatal_body, .members = 1},
        {.element_at = 1, .body = "{\"errors\":[null]}", .members = 1},
        {.member_at = 4, .body = continued, .members = 4},
    };
    for (size_t i = 0; i < sizeof(walks) / sizeof(walks[0]); ++i) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {
            .response = {.status = 403,
                         .body = {(const unsigned char *)walks[i].body, strlen(walks[i].body)}},
            .inspect = inspect_request, .user = keys,
        };
        member_calls = element_calls = 0;
        fail_member_after = walks[i].member_at;
        fail_element_after = walks[i].element_at;
        size_t setters = setter_calls;
        char *error = NULL;
        int rc = scan_one(detector, &http, key, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
        CHECK(!fail_member_after && !fail_element_after);
        CHECK(member_calls == walks[i].members);
        CHECK(http.calls == 1 && http.releases == 1 && setter_calls == setters);
        CHECK(!strstr(error, "unexpected API JSON response"));
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {
        .response = {.status = 200}, .send_rc = 1,
        .inspect = inspect_request, .user = keys,
    };
    size_t setters = setter_calls;
    null_send = 1;
    char *error = NULL;
    CHECK(scan_one(detector, &http, key, &results, &error) == 0 && !error);
    CHECK(http.calls == 1 && http.releases == 1);
    CHECK(setter_calls == setters + 1 && setter_null_cause && last_setter_rc == 0);
    secret_is_key(key);
    CHECK(results.len == 2 && !results.items[1].verified && !results.items[1].verification_error);
    CHECK(results.items[0].verification_error == cause);
    br_results_clear(&results);

    memset(&sentinel, 0, sizeof(sentinel));
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    http = (test_http){
        .response = {.status = 200}, .send_rc = 1,
        .inspect = inspect_request, .user = keys,
    };
    setters = setter_calls;
    null_send = 1;
    fail_setter = 1;
    error = NULL;
    int rc = scan_one(detector, &http, key, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!null_send && !fail_setter);
    CHECK(http.calls == 1 && http.releases == 1);
    CHECK(setter_calls == setters + 1 && setter_null_cause && last_setter_rc == 1);
    secret_is_key(key);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);

    memset(&sentinel, 0, sizeof(sentinel));
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    http = (test_http){
        .response = {.status = 300},
        .inspect = inspect_request, .user = keys,
    };
    setters = setter_calls;
    fail_format = 1;
    error = NULL;
    rc = scan_one(detector, &http, key, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_format && http.calls == 1 && http.releases == 1 && setter_calls == setters);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_regex(detector);
    test_http_and_lifecycle(detector);
    test_forbidden_json(detector);
    test_nil_context(detector);
    test_policy_failures(detector);
    return test_finish("Klaviyo");
}
