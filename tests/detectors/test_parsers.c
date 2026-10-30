/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

extern int br_parsers_init(const br_detector **out, char **error);

#define br_results_push parsers_real_push
#define br_result_set_verification_error parsers_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char fixture[] = "3ui8k045w9b9n6c2fuqbr44p1fg64cjsvn2dv2uvkyxfmjler9ddsls6uqtizt7q";
static const char body[] = "{\"sql\": \"CREATE TABLE t();SELECT 1; SELECT 1 FROM ; SELECT 2\"}";
static const char description[] =
    "Parsers is a service used for parsing SQL queries. Parsers API keys can be used to access and modify this data.";

static size_t fail_size, fail_after, fail_part_after, setter_calls;

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
    return parsers_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return parsers_real_setter(result, cause, secrets, count);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = ((const char *const *)http->user)[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.parsers.dev/api/v1/parse/postgresql/"));
    CHECK(request->body.len == 62 && request->body.data && !memcmp(request->body.data, body, 62));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 765);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && strcmp(request->headers[1].name, "x-api-key"));
    CHECK(strlen(key) == 64 && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(fixture) == 64 && strlen(body) == 62);
    CHECK(br_parsers_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid Parsers detector output"));
    free(error);
    error = NULL;
    CHECK(br_parsers_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 765 && detector->version == 0 && !strcmp(detector->name, "Parsers"));
    CHECK(detector->custom_name && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "parsers"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void add_spaces(char *out, size_t cap, size_t count)
{
    size_t used = strlen(out);
    CHECK(used + count < cap);
    memset(out + used, ' ', count);
    out[used + count] = '\0';
}

static void test_extraction(const br_detector *detector)
{
    char other[65], short_key[64], long_key[66], upper[65], question[65], input[320];
    memcpy(other, fixture, 65);
    other[63] = 'r';
    memcpy(short_key, fixture, 63);
    short_key[63] = '\0';
    memcpy(long_key, fixture, 64);
    long_key[64] = 'a';
    long_key[65] = '\0';
    memcpy(upper, fixture, 65);
    upper[2] = 'I';
    memcpy(question, fixture, 65);
    question[10] = '?';

    snprintf(input, sizeof(input), "parsers token = '%s'", fixture);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 765, fixture, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "parsers token = '%s' | '%s'", fixture, fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 765, fixture, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "parsers %s parsers %s", fixture, fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 765, fixture, "key");
    test_key_result(&out.items[1], 765, fixture, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "PARSERS %s", other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 765, other, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input),
             "parsers keyword is not close to the real key in the data\n = '%s'", fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    input[0] = '\0';
    memcpy(input, "parsers", 8);
    add_spaces(input, sizeof(input), 41);
    strcat(input, fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "parsers %s", short_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "parsers %s", long_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "parsers %s", upper);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "parsers = '%s'", question);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void test_verification(const br_detector *detector)
{
    char other[65], input[180];
    memcpy(other, fixture, 65);
    other[0] = '9';
    snprintf(input, sizeof(input), "parsers %s", fixture);
    const char *only[] = {fixture};
    const unsigned char unread[] = {'n', 'o'};
    const int statuses[] = {200, 299, 199, 401};
    const bool verified[] = {true, true, false, false};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {
            .response = {.status = statuses[i], .body = {unread, sizeof(unread)}, .body_error = "ignored"},
            .inspect = inspect_request, .user = (void *)only,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&out.items[0], 765, fixture, "key");
        CHECK(out.items[0].verified == verified[i] && !out.items[0].verification_error);
        br_results_clear(&out);
    }

    test_http failed = {
        .response = {.status = 200}, .send_rc = 1, .send_error = "transport failed",
        .inspect = inspect_request, .user = (void *)only,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    br_results out = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    test_key_result(&out.items[0], 765, fixture, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    test_http quiet = {.response = {.status = 500}, .send_rc = 1, .send_error = "must not send"};
    br_transport quiet_transport = test_transport(&quiet);
    br_scan_ctx quiet_ctx = {.transport = &quiet_transport};
    out = test_scan(detector, &quiet_ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !quiet.calls && !quiet.releases);
    test_key_result(&out.items[0], 765, fixture, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "parsers %s parsers %s", fixture, other);
    const char *both[] = {fixture, other};
    test_http split = {.inspect = inspect_request, .user = (void *)both, .response = {.status = 204}};
    br_transport split_transport = test_transport(&split);
    br_scan_ctx split_ctx = {.transport = &split_transport};
    out = test_scan(detector, &split_ctx, true, input, strlen(input));
    CHECK(out.len == 2 && split.calls == 2 && split.releases == 2);
    test_key_result(&out.items[0], 765, fixture, "key");
    test_key_result(&out.items[1], 765, other, "key");
    CHECK(out.items[0].verified && out.items[1].verified);
    br_results_clear(&out);
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

static void test_nil_context(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "parsers %s", fixture);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory iterating regex",
        "out of memory creating Parsers result",
    };
    for (int mode = 0; mode < 2; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span);
            fail_after = 1;
        } else fail_part_after = 1;
        char *error = NULL;
        CHECK(detector->scan(detector, NULL, true, slice, &results, &error) != 0);
        CHECK(error && !strcmp(error, messages[mode]));
        CHECK(!http.calls && !http.releases);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 200}};
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    br_results empty = test_scan(detector, NULL, true, "", 0);
    CHECK(!empty.len);
    br_results_clear(&empty);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("Parsers");
}
