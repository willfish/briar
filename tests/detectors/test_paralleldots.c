/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <dlfcn.h>
#include <openssl/rand.h>

extern int br_paralleldots_init(const br_detector **out, char **error);

#define br_results_push paralleldots_real_push
#define br_result_set_verification_error paralleldots_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const unsigned char vector[30] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
};
static const char fixture[] = "Ki82DlwEBI9dqr4k3cZPH6Z5fP39XgEPktFfgZTM4mW";
static const char question[] = "Ki82DlwEBI9dqr4k3cZPH?Z5fP39XgEPktFfgZTM4mW";

static size_t random_calls, fail_size, fail_after, fail_part_after, setter_calls, body_frees;
static int fail_random;
static void *body_block;

int RAND_bytes(unsigned char *out, int count)
{
    CHECK(out && count == 30);
    ++random_calls;
    if (fail_random) {
        fail_random = 0;
        return 0;
    }
    memcpy(out, vector, sizeof(vector));
    return 1;
}

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    void *block = calloc(1, size);
    if (block && size == 349) body_block = block;
    return block;
}

void free(void *block)
{
    if (block && block == body_block) {
        ++body_frees;
        body_block = NULL;
    }
    static void (*real_free)(void *);
    if (!real_free) {
        void *symbol = dlsym(RTLD_NEXT, "free");
        memcpy(&real_free, &symbol, sizeof(real_free));
    }
    real_free(block);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_results_push(br_results *out, br_result *owned)
{
    return paralleldots_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return paralleldots_real_setter(result, cause, secrets, count);
}

static void boundary_of(char out[61])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(vector); ++i) {
        out[2 * i] = hex[vector[i] >> 4];
        out[2 * i + 1] = hex[vector[i] & 15];
    }
    out[60] = '\0';
}

static void expected_body(unsigned char out[349], const char *key, const char *boundary)
{
    size_t n = 0;
    memcpy(out + n, "--", 2); n += 2;
    memcpy(out + n, boundary, 60); n += 60;
    const char *api = "\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n";
    memcpy(out + n, api, strlen(api)); n += strlen(api);
    memcpy(out + n, key, 43); n += 43;
    memcpy(out + n, "\r\n--", 4); n += 4;
    memcpy(out + n, boundary, 60); n += 60;
    const char *text = "\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n";
    memcpy(out + n, text, strlen(text)); n += strlen(text);
    memcpy(out + n, "sample text", 11); n += 11;
    memcpy(out + n, "\r\n--", 4); n += 4;
    memcpy(out + n, boundary, 60); n += 60;
    memcpy(out + n, "--\r\n", 4); n += 4;
    CHECK(n == 349);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = ((const char *const *)http->user)[http->calls - 1];
    char boundary[61], type[91];
    unsigned char expected[349];
    boundary_of(boundary);
    expected_body(expected, key, boundary);
    snprintf(type, sizeof(type), "multipart/form-data; boundary=%s", boundary);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://apis.paralleldots.com/v4/intent"));
    CHECK(request->body.len == 349 && request->body.data && !memcmp(request->body.data, expected, 349));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 479);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, type));
    CHECK(!strchr(request->headers[0].value, '"'));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(strcmp(request->headers[0].name, "Content-Length") && strcmp(request->headers[1].name, "Content-Length"));
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_paralleldots_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid ParallelDots detector output"));
    free(error);
    error = NULL;
    CHECK(strlen(fixture) == 43 && strlen(question) == 43);
    CHECK(br_paralleldots_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 479 && detector->version == 0 && !strcmp(detector->name, "ParallelDots"));
    CHECK(detector->custom_name && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "ParallelDots is an AI service offering various APIs for text analysis. API keys can be used to access these services."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "paralleldots"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(!random_calls);
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
    char key[44], short_key[43], long_key[45], input[320];
    memcpy(key, fixture, 44);
    memcpy(short_key, fixture, 42);
    short_key[42] = '\0';
    memcpy(long_key, fixture, 43);
    long_key[43] = 'Z';
    long_key[44] = '\0';
    size_t draws = random_calls;

    snprintf(input, sizeof(input), "paralleldots token = '%s'", fixture);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && random_calls == draws);
    test_key_result(&out.items[0], 479, fixture, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "paralleldots token = '%s' | '%s'", fixture, fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && random_calls == draws);
    test_key_result(&out.items[0], 479, fixture, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "paralleldots %s paralleldots %s", key, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && random_calls == draws);
    test_key_result(&out.items[0], 479, key, "key");
    test_key_result(&out.items[1], 479, key, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input),
             "paralleldots keyword is not close to the real key in the data\n = '%s'", fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    input[0] = '\0';
    memcpy(input, "paralleldots", 13);
    add_spaces(input, sizeof(input), 41);
    strcat(input, fixture);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "paralleldots = '%s'", question);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "paralleldots %s", short_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "paralleldots %s", long_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    CHECK(random_calls == draws);
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

static void test_verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "paralleldots %s", fixture);
    const char *only[] = {fixture};
    const unsigned char intent[] = {'x', 'i', 'n', 't', 'e', 'n', 't', 'y'};
    const unsigned char wrong_case[] = {'I', 'n', 't', 'e', 'n', 't'};
    const unsigned char plain[] = {'n', 'o'};
    struct {
        int status;
        br_slice body;
        bool verified;
    } cases[] = {
        {200, {intent, sizeof(intent)}, true},
        {299, {(const unsigned char *)"intent", 6}, true},
        {200, {plain, sizeof(plain)}, false},
        {200, {wrong_case, sizeof(wrong_case)}, false},
        {200, {NULL, 0}, false},
        {401, {(const unsigned char *)"intent", 6}, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t frees = body_frees;
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body},
            .inspect = inspect_request, .user = (void *)only,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && body_frees == frees + 1);
        test_key_result(&out.items[0], 479, fixture, "key");
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }

    test_http failed = {
        .response = {.status = 200, .body = {NULL, 1}, .body_error = "read failed"},
        .send_rc = 1, .send_error = "transport failed",
        .inspect = inspect_request, .user = (void *)only,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    br_results out = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    test_key_result(&out.items[0], 479, fixture, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    size_t draws = random_calls;
    test_http quiet = {.response = {.status = 500}, .send_rc = 1};
    br_transport quiet_transport = test_transport(&quiet);
    br_scan_ctx quiet_ctx = {.transport = &quiet_transport};
    out = test_scan(detector, &quiet_ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !quiet.calls && !quiet.releases && random_calls == draws);
    test_key_result(&out.items[0], 479, fixture, "key");
    br_results_clear(&out);
}

static int split_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    test_http *http = user;
    ++http->calls;
    if (http->inspect) http->inspect(http, ctx, request);
    if (http->calls == 1)
        *response = (br_http_response){.status = 200, .body = {(const unsigned char *)"intent", 6}};
    else if (http->send_rc == 7)
        *response = (br_http_response){.status = 200, .body = {NULL, 1}, .body_error = "read failed"};
    else
        *response = (br_http_response){.status = 200, .body = {NULL, 1}};
    *error = NULL;
    return 0;
}

static void release_count(void *user, br_http_response *response)
{
    (void)response;
    ++((test_http *)user)->releases;
}

static void test_body_policy(const br_detector *detector)
{
    char other[44], input[160];
    memcpy(other, fixture, 43);
    other[0] = 'Q';
    other[43] = '\0';
    snprintf(input, sizeof(input), "paralleldots %s paralleldots %s", fixture, other);
    const char *both[] = {fixture, other};
    br_slice slice = {(const unsigned char *)input, strlen(input)};

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http dropped = {.inspect = inspect_request, .user = (void *)both, .send_rc = 7};
    br_transport dropped_transport = {&dropped, split_send, release_count};
    br_scan_ctx dropped_ctx = {.transport = &dropped_transport};
    char *error = NULL;
    /* Reuse send_rc as the response selector without changing inspect's user. */
    dropped.send_rc = 7;
    CHECK(detector->scan(detector, &dropped_ctx, true, slice, &results, &error) == 0 && !error);
    CHECK(dropped.calls == 2 && dropped.releases == 2 && results.len == 2);
    CHECK(results.items[1].verified && !results.items[1].verification_error);
    CHECK(results.items[0].raw.data == raw);
    br_results_clear(&results);

    memset(&sentinel, 0, sizeof(sentinel));
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http invalid = {.inspect = inspect_request, .user = (void *)both};
    br_transport invalid_transport = {&invalid, split_send, release_count};
    br_scan_ctx invalid_ctx = {.transport = &invalid_transport};
    error = NULL;
    CHECK(detector->scan(detector, &invalid_ctx, true, slice, &results, &error) != 0);
    CHECK(error && !strcmp(error, "invalid ParallelDots response body"));
    CHECK(invalid.calls == 2 && invalid.releases == 2);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);
}

static void test_nil_context(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "paralleldots %s", fixture);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory iterating regex",
        "out of memory creating ParallelDots result",
        "ParallelDots random boundary failed",
        "out of memory creating ParallelDots body",
    };
    for (int mode = 0; mode < 4; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        size_t draws = random_calls, frees = body_frees;
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span);
            fail_after = 1;
        } else if (mode == 1) fail_part_after = 1;
        else if (mode == 2) fail_random = 1;
        else {
            fail_size = 349;
            fail_after = 1;
        }
        char *error = NULL;
        CHECK(detector->scan(detector, NULL, true, slice, &results, &error) != 0);
        CHECK(error && !strcmp(error, messages[mode]));
        CHECK(body_frees == frees);
        if (mode < 2) CHECK(random_calls == draws);
        else CHECK(random_calls == draws + 1);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    size_t draws = random_calls, frees = body_frees;
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(random_calls == draws + 1 && body_frees == frees + 1 && !body_block);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    br_results empty = test_scan(detector, NULL, true, "", 0);
    CHECK(!empty.len && random_calls == draws + 1);
    br_results_clear(&empty);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_body_policy(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("ParallelDots");
}
