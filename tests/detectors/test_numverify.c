/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_numverify_init(const br_detector **out, char **error);

#define br_result_set_verification_error num_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_numverify_init observed_init
#include "../../src/detectors/numverify.c"
#undef malloc
#undef free
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_numverify_init

static const char key[] = "0123456789abcdef0123456789abcdef";
static const char other[] = "abcdef0123456789abcdef0123456789";
static const char prefix[] = "https://apilayer.net/api/validate?access_key=";
static const char suffix[] = "&number=14158586273";
static const char restricted[] =
    "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
static const char description[] =
    "Numverify is a service used to validate phone numbers and gather information about them. Numverify API keys can be used to access this service and validate phone numbers.";
static size_t setter_calls, url_n, url_frees, release_n, pushes;
static int fail_url, fail_push;
static bool release_before_push;
static char *urls[8];

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return num_real_setter(result, cause, secrets, count);
}

static size_t url_size(void)
{
    return sizeof(prefix) + sizeof(suffix) - 1 + 32;
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(&detector, &error) == 0 && detector && !error);
    return detector;
}

static void reset_observation(void)
{
    for (size_t i = 0; i < url_n; ++i) CHECK(!urls[i]);
    url_n = url_frees = release_n = pushes = setter_calls = 0;
    fail_url = fail_push = 0;
    release_before_push = false;
}

static void *checked_malloc(size_t size)
{
    if (size != url_size()) return malloc(size);
    CHECK(url_n < 8);
    if (fail_url) {
        fail_url = 0;
        return NULL;
    }
    char *url = malloc(size);
    CHECK(url);
    urls[url_n++] = url;
    return url;
}

static void checked_free(void *value)
{
    if (value) {
        for (size_t i = 0; i < url_n; ++i) {
            if (urls[i] != value) continue;
            urls[i] = NULL;
            ++url_frees;
            break;
        }
    }
    free(value);
}

static void check_url(const char *url, const char *expect_key)
{
    char expected[128];
    snprintf(expected, sizeof(expected), "%s%s%s", prefix, expect_key, suffix);
    CHECK(url && !strcmp(url, expected) && !strstr(url, "%"));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(request && !request->nheaders && !request->headers && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(!request->body.data && !request->dedup_key.data);
    const char *saved = request->url;
    check_url(saved, key);
    int rc = br_http_send(ctx, request, response, error);
    CHECK(request->nheaders == 0 && !request->headers && request->url == saved);
    check_url(saved, key);
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t alive = 0;
    for (size_t i = 0; i < url_n; ++i) {
        if (!urls[i]) continue;
        ++alive;
        check_url(urls[i], key);
    }
    CHECK(alive && alive == url_n - url_frees);
    ++release_n;
    br_http_release(ctx, response);
    (void)response;
}

static int checked_push(br_results *out, br_result *result)
{
    if (release_before_push) CHECK(release_n == url_n && url_frees == url_n);
    else if (url_n) CHECK(!release_n && url_frees < url_n);
    ++pushes;
    if (fail_push) {
        fail_push = 0;
        return 1;
    }
    return br_results_push(out, result);
}

static const char *part(const br_result *result)
{
    br_json *value = NULL;
    CHECK(result->secret_parts && json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void expect_key(const br_result *result, const char *expect, bool verified)
{
    CHECK(result->detector_type == 439 && !result->detector_name && !result->raw_v2.data);
    CHECK(!result->extra_data && !result->redacted && !result->structured_data && !result->verification_error);
    CHECK(result->verified == verified && result->raw.len == 32 && !memcmp(result->raw.data, expect, 32));
    CHECK(!strcmp(part(result), expect));
}

static void keep_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void grammar(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "numverify %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "numverify %s numverify %s", key, other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].raw.data != out.items[1].raw.data);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], other, false);
    br_results_clear(&out);
    char gap[80];
    memset(gap, '.', 40);
    gap[40] = '\0';
    snprintf(input, sizeof(input), "numverify%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    gap[40] = '.';
    gap[41] = '\0';
    snprintf(input, sizeof(input), "numverify%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    const char *rejected[] = {
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdefg",
        "0123456789abcdef0123456789abcdeF",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), "numverify %s", rejected[i]);
        out = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(!out.len);
        br_results_clear(&out);
    }
    out = test_scan(detector, NULL, false, key, 32);
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && request->nheaders == 1 && request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
    check_url(request->url, key);
    CHECK(!request->body.data && !request->dedup_key.data);
}

static void verify_policy(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "numverify %s", key);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; const char *body; const char *read_error; bool verified; } cases[] = {
        {200, "country_code", NULL, true},
        {200, restricted, NULL, true},
        {299, "xx country_code yy", NULL, true},
        {200, "no match", NULL, false},
        {401, "country_code", NULL, false},
        {403, restricted, NULL, false},
        {200, "country_code", "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)},
            .body_error = cases[i].read_error,
        };
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        expect_key(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    http.calls = http.releases = setter_calls = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    br_transport missing = {&http, NULL, test_http_release};
    br_scan_ctx bare = {.transport = &missing};
    http.calls = http.releases = setter_calls = 0;
    http.send_rc = 0;
    out = test_scan(detector, &bare, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    br_scan_ctx zero = {0};
    setter_calls = 0;
    out = test_scan(detector, &zero, true, input, strlen(input));
    CHECK(out.len == 1 && !setter_calls);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !setter_calls);
    br_results_clear(&out);
}

typedef struct {
    br_results *out;
    size_t calls, releases, rows[4];
    int order[4], send_rc;
    const char *body_error;
} num_script;

static int num_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                    br_http_response *response, char **error)
{
    (void)ctx;
    num_script *script = user;
    CHECK(request && request->nheaders == 1 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    check_url(request->url, key);
    ++script->calls;
    if (script->send_rc) {
        *error = strdup("timeout");
        CHECK(*error);
        return script->send_rc;
    }
    *response = (br_http_response){
        .status = 200 + (int)script->calls,
        .body = {(const unsigned char *)"country_code", 12},
        .body_error = script->body_error,
    };
    *error = NULL;
    return 0;
}

static void num_release(void *user, br_http_response *response)
{
    num_script *script = user;
    CHECK(script->releases < 4 && script->out);
    script->rows[script->releases] = script->out->len;
    script->order[script->releases] = response && response->status >= 200 ? response->status - 200 : 0;
    ++script->releases;
}

static void lifo_and_read_error(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "numverify %s numverify %s", key, key);
    br_results out = {0};
    br_result prior = {0};
    keep_caller(&out, &prior);
    num_script script = {.out = &out};
    br_transport transport = {&script, num_send, num_release};
    br_scan_ctx ctx = {.transport = &transport};
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && script.calls == 2 && script.releases == 2 && !setter_calls);
    CHECK(script.order[0] == 2 && script.order[1] == 1 && script.rows[0] == 3 && script.rows[1] == 3);
    expect_key(&out.items[1], key, true);
    expect_key(&out.items[2], key, true);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    snprintf(input, sizeof(input), "numverify %s", key);
    script = (num_script){.out = &out, .send_rc = 1};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && script.calls == 1 && script.releases == 1 && script.rows[0] == 1);
    expect_key(&out.items[1], key, false);
    CHECK(!strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    script = (num_script){.out = &out, .body_error = "read failed"};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && script.calls == 1 && script.releases == 1 && script.rows[0] == 2);
    expect_key(&out.items[1], key, false);
    CHECK(out.items[0].verification_error == prior.verification_error);
    br_results_clear(&out);
}

static void owned_faults(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "numverify %s numverify %s", key, key);
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    reset_observation();
    fail_url = 1;
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot allocate Numverify URL"));
    free(error);
    CHECK(!url_n && !url_frees && !release_n && !setter_calls && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
    keep_caller(&kept, &prior);
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"country_code", 12}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    fail_push = 1;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append Numverify result"));
    free(error);
    CHECK(http.calls == 1 && http.releases == 1 && release_n == 1 && url_frees == 1 && !setter_calls);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&kept);
    reset_observation();
    snprintf(input, sizeof(input), "numverify %s", key);
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && url_n == 1 && url_frees == 1 && !release_n && !setter_calls);
    br_results_clear(&out);
    reset_observation();
}

int main(void)
{
    CHECK(strlen(key) == 32 && strlen(other) == 32 && strlen(restricted) > 20);
    char *error = NULL;
    CHECK(br_numverify_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Numverify detector output"));
    free(error);
    const br_detector *detector = open_detector(br_numverify_init);
    CHECK(open_detector(br_numverify_init) == detector);
    CHECK(detector->type == 439 && detector->version == 0 && !strcmp(detector->name, "Numverify"));
    CHECK(detector->custom_name && !detector->custom_name[0] && !strcmp(detector->description, description));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "numverify"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    grammar(detector);
    verify_policy(detector);
    lifo_and_read_error(detector);
    owned_faults(open_detector(observed_init));
    CHECK(!setter_calls);
    return test_finish("Numverify");
}
