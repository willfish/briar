/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_npmtoken_v1_init(const br_detector **out, char **error);
int br_npmtoken_v2_init(const br_detector **out, char **error);

#define br_result_set_verification_error npm_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static void *checked_malloc(size_t);
static void checked_free(void *);
static br_json *checked_object(void);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define json_object_new_object checked_object
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_npmtoken_v1_init observed_v1_init
#define br_npmtoken_v2_init observed_v2_init
#include "../../src/detectors/npmtoken.c"
#undef malloc
#undef free
#undef json_object_new_object
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_npmtoken_v1_init
#undef br_npmtoken_v2_init

static const char v1_key[] = "3aAcac6c-9847-23d9-ce65-917590b81cf0";
static const char v1_lower[] = "3aacac6c-9847-23d9-ce65-917590b81cf0";
static const char v2_key[] = "npm_hK0FJXBYCkejhEMY4Kp6bOOZn1DlfBOmtbJY";
static const char guide[] = "https://howtorotate.com/docs/tutorials/npm/";
static const char url[] = "https://registry.npmjs.org/-/whoami";
static size_t setter_calls, auth_n, auth_frees, release_n, pushes;
static int fail_meta, fail_push, fail_auth;
static bool release_before_push;
static char *auths[8];

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return npm_real_setter(result, cause, secrets, count);
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
    for (size_t i = 0; i < auth_n; ++i) CHECK(!auths[i]);
    auth_n = auth_frees = release_n = pushes = setter_calls = 0;
    fail_meta = fail_push = fail_auth = 0;
    release_before_push = false;
}

static void *checked_malloc(size_t size)
{
    if ((size == 44 || size == 48) && fail_auth) {
        fail_auth = 0;
        return NULL;
    }
    void *value = malloc(size);
    if (value && (size == 44 || size == 48) && auth_n < 8) auths[auth_n++] = value;
    return value;
}

static void checked_free(void *value)
{
    if (value) {
        for (size_t i = 0; i < auth_n; ++i) {
            if (auths[i] != value) continue;
            auths[i] = NULL;
            ++auth_frees;
            break;
        }
    }
    free(value);
}

static br_json *checked_object(void)
{
    if (fail_meta) {
        fail_meta = 0;
        return NULL;
    }
    return json_object_new_object();
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(request && request->nheaders == 1 && request->headers && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !request->body.data && !request->dedup_key.data);
    CHECK(request->headers[0].value && !strncmp(request->headers[0].value, "Bearer ", 7));
    const br_header *headers = request->headers;
    const char *saved_url = request->url;
    int rc = br_http_send(ctx, request, response, error);
    CHECK(request->nheaders == 1 && request->headers == headers && request->url == saved_url);
    CHECK(saved_url && !strcmp(saved_url, url));
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t alive = 0;
    for (size_t i = 0; i < auth_n; ++i) {
        if (!auths[i]) continue;
        ++alive;
        CHECK(!strncmp(auths[i], "Bearer ", 7));
        CHECK(strlen(auths[i]) == 43 || strlen(auths[i]) == 47);
    }
    CHECK(alive && alive == auth_n - auth_frees);
    ++release_n;
    br_http_release(ctx, response);
}

static int checked_push(br_results *out, br_result *result)
{
    if (release_before_push) CHECK(release_n == auth_n && auth_frees == auth_n);
    else if (auth_n) CHECK(!release_n && auth_frees < auth_n);
    ++pushes;
    if (fail_push) {
        fail_push = 0;
        return 1;
    }
    return br_results_push(out, result);
}

static const char *text_field(br_json *object, const char *name)
{
    br_json *value = NULL;
    CHECK(object && json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static void expect_token(const br_result *result, const char *key, bool verified)
{
    CHECK(result->detector_type == 49 && !result->detector_name && !result->raw_v2.data);
    CHECK(!result->redacted && !result->structured_data && !result->verification_error);
    CHECK(result->verified == verified && result->raw.len == strlen(key));
    CHECK(!memcmp(result->raw.data, key, result->raw.len));
    CHECK(!strcmp(text_field(result->secret_parts, "key"), key));
    CHECK(!strcmp(text_field(result->extra_data, "rotation_guide"), guide));
    CHECK(json_object_object_length(result->extra_data) == 1);
}

static void keep_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void identity(const br_detector *detector, int version, const char *keyword, const char *description)
{
    CHECK(detector->type == 49 && detector->version == version && !strcmp(detector->name, "NpmToken"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], keyword));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state);
}

static void grammar(const br_detector *v1, const br_detector *v2)
{
    char input[160];
    snprintf(input, sizeof(input), "npm %s", v1_key);
    br_results out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_token(&out.items[0], v1_key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "NPM %s", v1_lower);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_token(&out.items[0], v1_lower, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "npm %s npm %s", v1_key, v1_key);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].raw.data != out.items[1].raw.data);
    expect_token(&out.items[0], v1_key, false);
    expect_token(&out.items[1], v1_key, false);
    br_results_clear(&out);
    char gap[96];
    memset(gap, '.', 40);
    gap[40] = '\0';
    snprintf(input, sizeof(input), "npm%s%s", gap, v1_key);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    gap[40] = '.';
    gap[41] = '\0';
    snprintf(input, sizeof(input), "npm%s%s", gap, v1_key);
    out = test_scan(v1, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    const char *rejected[] = {
        "3aBcac6c-9847-23d9-ce65-917590b81cf0",
        "3aAcac6c-984A-23d9-ce65-917590b81cf0",
        "3aAcac6c?9847-23d9-ce65-917590b81cf0",
        "3aAcac6c-9847-23d9-ce65-917590b81cf0a",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), "npm %s", rejected[i]);
        out = test_scan(v1, NULL, false, input, strlen(input));
        CHECK(!out.len);
        br_results_clear(&out);
    }
    out = test_scan(v1, NULL, false, v2_key, strlen(v2_key));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "X%s9", v2_key);
    out = test_scan(v2, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_token(&out.items[0], v2_key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s", v2_key, v2_key);
    out = test_scan(v2, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_token(&out.items[1], v2_key, false);
    br_results_clear(&out);
    char short_v2[40];
    memcpy(short_v2, v2_key, 39);
    short_v2[39] = '\0';
    out = test_scan(v2, NULL, false, short_v2, 39);
    CHECK(!out.len);
    br_results_clear(&out);
    char broken[41];
    memcpy(broken, v2_key, 40);
    broken[8] = '?';
    broken[40] = '\0';
    out = test_scan(v2, NULL, false, broken, 40);
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(v2, NULL, false, v1_key, strlen(v1_key));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && request->nheaders == 2 && request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE);
    CHECK(!strcmp(request->url, url) && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, http->user));
    CHECK(!request->body.data && !request->dedup_key.data);
}

static void verify_policy(const br_detector *detector, const char *key, const char *input)
{
    test_http http = {.user = (void *)key, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {201, true}, {299, true}, {199, false}, {300, false}, {401, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7},
            .body_error = "ignored",
        };
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        expect_token(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    http.calls = http.releases = setter_calls = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    expect_token(&out.items[0], key, false);
    br_results_clear(&out);
    br_transport missing = {&http, NULL, test_http_release};
    br_scan_ctx bare = {.transport = &missing};
    http.calls = http.releases = setter_calls = 0;
    out = test_scan(detector, &bare, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    expect_token(&out.items[0], key, false);
    br_results_clear(&out);
    br_scan_ctx zero = {0};
    setter_calls = 0;
    out = test_scan(detector, &zero, true, input, strlen(input));
    CHECK(out.len == 1 && !setter_calls);
    expect_token(&out.items[0], key, false);
    br_results_clear(&out);
    setter_calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !setter_calls);
    br_results_clear(&out);
}

typedef struct {
    br_results *out;
    const char *key;
    size_t calls, releases, rows[4];
    int order[4], send_rc;
    const char *send_error;
} npm_script;

static int npm_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                    br_http_response *response, char **error)
{
    (void)ctx;
    npm_script *script = user;
    CHECK(request && request->nheaders == 2 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->url, url) && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value + 7, script->key));
    ++script->calls;
    if (script->send_rc) {
        *error = script->send_error ? strdup(script->send_error) : NULL;
        CHECK(!script->send_error || *error);
        return script->send_rc;
    }
    *response = (br_http_response){.status = 200 + (int)script->calls};
    *error = NULL;
    return 0;
}

static void npm_release(void *user, br_http_response *response)
{
    npm_script *script = user;
    CHECK(script->releases < 4 && script->out);
    script->rows[script->releases] = script->out->len;
    script->order[script->releases] = response && response->status >= 200 ? response->status - 200 : 0;
    ++script->releases;
}

static void lifo_and_failed_send(const br_detector *detector, const char *key, const char *input)
{
    br_results out = {0};
    br_result prior = {0};
    keep_caller(&out, &prior);
    npm_script script = {.out = &out, .key = key};
    br_transport transport = {&script, npm_send, npm_release};
    br_scan_ctx ctx = {.transport = &transport};
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && script.calls == 2 && script.releases == 2 && !setter_calls);
    CHECK(script.order[0] == 2 && script.order[1] == 1);
    CHECK(script.rows[0] == 3 && script.rows[1] == 3);
    expect_token(&out.items[1], key, true);
    expect_token(&out.items[2], key, true);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    char one[96];
    if (detector->version == 1) snprintf(one, sizeof(one), "npm %s", key);
    else snprintf(one, sizeof(one), "%s", key);
    script = (npm_script){.out = &out, .key = key, .send_rc = 1, .send_error = "timeout"};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)one, strlen(one)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && script.calls == 1 && script.releases == 1 && script.rows[0] == 1);
    expect_token(&out.items[1], key, false);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
}

static void owned_faults(const br_detector *detector, const char *key)
{
    char input[96];
    if (detector->version == 1) snprintf(input, sizeof(input), "npm %s npm %s", key, key);
    else snprintf(input, sizeof(input), "%s %s", key, key);
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    test_http http = {.response = {.status = 204}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    fail_meta = 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create NpmToken metadata"));
    free(error);
    CHECK(!http.calls && !http.releases && !setter_calls && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
    keep_caller(&kept, &prior);
    reset_observation();
    fail_auth = 1;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot allocate NpmToken authorization"));
    free(error);
    CHECK(!http.calls && !http.releases && !auth_n && !setter_calls && kept.len == 1);
    CHECK(!memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
    keep_caller(&kept, &prior);
    reset_observation();
    fail_push = 1;
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append NpmToken result"));
    free(error);
    CHECK(http.calls == 1 && http.releases == 1 && release_n == 1 && auth_frees == 1 && !setter_calls);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
    reset_observation();
}

int main(void)
{
    CHECK(strlen(v1_key) == 36 && strlen(v1_lower) == 36 && strlen(v2_key) == 40);
    char *error = NULL;
    CHECK(br_npmtoken_v1_init(NULL, &error) != 0 && error && !strcmp(error, "invalid NpmToken detector output"));
    free(error);
    error = NULL;
    CHECK(br_npmtoken_v2_init(NULL, &error) != 0 && error && !strcmp(error, "invalid NpmToken detector output"));
    free(error);
    const br_detector *v1 = open_detector(br_npmtoken_v1_init);
    const br_detector *v2 = open_detector(br_npmtoken_v2_init);
    CHECK(open_detector(br_npmtoken_v1_init) == v1 && open_detector(br_npmtoken_v2_init) == v2);
    identity(v1, 1, "npm", "NPM tokens are used to authenticate and publish packages to the npm registry.");
    identity(v2, 2, "npm_", "NPM tokens are used to authenticate and publish packages to the NPM registry.");
    CHECK(strcmp(v1->description, v2->description));
    grammar(v1, v2);
    char v1_input[80], v2_input[96];
    snprintf(v1_input, sizeof(v1_input), "npm %s", v1_key);
    snprintf(v2_input, sizeof(v2_input), "%s", v2_key);
    verify_policy(v1, v1_key, v1_input);
    verify_policy(v2, v2_key, v2_input);
    char v1_pair[120], v2_pair[120];
    snprintf(v1_pair, sizeof(v1_pair), "npm %s npm %s", v1_key, v1_key);
    snprintf(v2_pair, sizeof(v2_pair), "%s %s", v2_key, v2_key);
    lifo_and_failed_send(v1, v1_key, v1_pair);
    lifo_and_failed_send(v2, v2_key, v2_pair);
    const br_detector *observed_v1 = open_detector(observed_v1_init);
    const br_detector *observed_v2 = open_detector(observed_v2_init);
    owned_faults(observed_v1, v1_key);
    owned_faults(observed_v2, v2_key);
    CHECK(!setter_calls);
    return test_finish("NpmToken");
}
