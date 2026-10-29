/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

extern int br_kontent_init(const br_detector **out, char **error);

static const char env_a[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char env_b[] = "f0e1d2c3-b4a5-9687-0123-456789abcdef";
static const char env_listed[] = "a1b2c3d4-a1b2-c3d4-a1b2-c3d4a1b2c3d4";
static const char env_low[] = "11111111-1111-1111-1111-111111111112";
static const char sentence[] = "The specified API key does not provide the permissions required to access the environment";
static char key_a[500], key_b[500], key_wild[500], key_low[500];
static size_t fail_size, fail_after, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define br_result_set_verification_error kontent_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

#define br_finding_pair_bytes kontent_real_finding_pair
#include "../../src/detectors/findings.c"
#undef br_finding_pair_bytes

#define br_http_send kontent_real_http_send
#define br_http_release kontent_real_http_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release

static br_result *active_result;
static bool sent_this, released_this, null_diag, expect_verified_at_setter;
static size_t setter_calls, null_setter_calls, fail_setter_after;

int br_finding_pair_bytes(br_result *result, int32_t type, br_slice key, const char *key_name,
                          br_slice secondary, const char *secondary_name, br_slice separator)
{
    int rc = kontent_real_finding_pair(result, type, key, key_name, secondary, secondary_name, separator);
    if (rc == 0) {
        active_result = result;
        sent_this = released_this = false;
    }
    return rc;
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                 br_http_response *response, char **error)
{
    sent_this = true;
    if (null_diag) {
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return kontent_real_http_send(ctx, request, response, error);
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    if (active_result) {
        CHECK(!active_result->verified);
        CHECK(!active_result->verification_error);
    }
    released_this = true;
    kontent_real_http_release(ctx, response);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    CHECK(!secrets && !nsecrets);
    if (sent_this) CHECK(released_this);
    if (expect_verified_at_setter) {
        CHECK(result && result->verified);
        expect_verified_at_setter = false;
    }
    if (!cause) ++null_setter_calls;
    sent_this = released_this = false;
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return kontent_real_setter(result, cause, secrets, nsecrets);
}

static void fill_key(char *out, size_t first, size_t mid, size_t tail, char sep, char fill)
{
    char *p = out;
    memcpy(p, "ey", 2); p += 2;
    memset(p, fill, first); p += first;
    *p++ = sep;
    memcpy(p, "ey", 2); p += 2;
    memset(p, fill, mid); p += mid;
    *p++ = sep;
    memset(p, fill, tail);
    p[tail] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    br_slice listed = {(const unsigned char *)env_listed, strlen(env_listed)};
    br_slice low = {(const unsigned char *)env_low, strlen(env_low)};
    br_slice kept = {(const unsigned char *)env_a, strlen(env_a)};
    CHECK(BR_ABI_REVISION == 1 && strlen(env_a) == 36 && strlen(key_a) >= 276);
    CHECK(br_ascii_shannon_entropy(listed) >= 3 && br_ascii_shannon_entropy(low) < 3);
    CHECK(br_ascii_shannon_entropy(kept) >= 3);
    CHECK(br_kontent_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_kontent_init(NULL, NULL) == -1);
    CHECK(br_kontent_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_kontent_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 328 && detector->version == 0 && !strcmp(detector->name, "Kontent"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Kontent is a headless CMS (Content Management System) that allows users to manage and deliver content to any device or application. Kontent API keys can be used to access and manage this content."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "kontent"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, const char *env, const char *api_key, bool verified)
{
    size_t env_len = strlen(env), key_len = strlen(api_key);
    br_json *part = NULL;
    CHECK(result->detector_type == 328 && result->verified == verified);
    CHECK(result->raw.len == env_len && !memcmp(result->raw.data, env, env_len));
    CHECK(result->raw_v2.len == env_len + key_len);
    CHECK(!memcmp(result->raw_v2.data, env, env_len));
    CHECK(!memcmp(result->raw_v2.data + env_len, api_key, key_len));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(json_object_object_get_ex(result->secret_parts, "env_id", &part) && !strcmp(json_object_get_string(part), env));
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), api_key));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_count(const br_detector *detector, const char *input, const char *env, const char *api_key, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&out.items[i], env, api_key, false);
        CHECK(!out.items[i].verification_error);
    }
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == count);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[2200], short_key[500];
    int n = snprintf(input, sizeof(input), "env %s kontent %s", env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_a, 1);
    n = snprintf(input, sizeof(input), "ENV %s KONTENT %s", env_a, key_wild);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_wild, 1);
    n = snprintf(input, sizeof(input), "kontent %s env %s", key_low, env_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_low, 1);
    n = snprintf(input, sizeof(input), "env %s env %s kontent %s", env_a, env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_a, 1);
    n = snprintf(input, sizeof(input), "env %s kontent %s kontent %s", env_a, key_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_a, 1);
    n = snprintf(input, sizeof(input), "env %s env %s", env_a, env_b);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "kontent %s", key_a);
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "env %s kontent %s", env_listed, key_a);
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "env %s kontent %s", env_low, key_a);
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "env %s %s kontent %s", env_a, env_b, key_a);
    expect_count(detector, input, env_a, key_a, 1);
    /* ey, first, separator, ey, mid, separator, tail, and the NUL. */
    size_t short_len = 2 + 29 + 1 + 2 + 200 + 1 + 40 + 1;
    CHECK(short_len <= sizeof(short_key));
    fill_key(short_key, 29, 200, 40, '.', 'A');
    CHECK(strlen(short_key) + 1 == short_len);
    n = snprintf(input, sizeof(input), "env %s kontent %s", env_a, short_key);
    expect_count(detector, input, env_a, short_key, 0);
    n = snprintf(input, sizeof(input), "env%*s%s kontent %s", 41, "", env_a, key_a);
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "env %s kontent%*s%s", env_a, 41, "", key_a);
    expect_count(detector, input, env_a, key_a, 0);
    n = snprintf(input, sizeof(input), "env %s", "3D5F4D88-0511-00B3-37F1-31BB55C25AB4");
    expect_count(detector, input, env_a, key_a, 0);
    expect_count(detector, "", env_a, key_a, 0);
    memset(input, '.', 1100);
    n = snprintf(input + 1100, sizeof(input) - 1100, "kontent %s", key_a);
    CHECK(n > 0 && 1100 + (size_t)n < sizeof(input));
    memcpy(input, "env ", 4);
    memcpy(input + 4, env_a, 36);
    expect_count(detector, input, env_a, key_a, 1);
}

typedef struct { const char *env, *key; int status, send_rc; const char *send_error, *body, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx != steps->ctx && http->releases == at);
    CHECK(!ctx->cancelled && !ctx->cancel_user && !ctx->deadline_monotonic_ms);
    CHECK(ctx->transport == steps->ctx->transport && ctx->user_agent == steps->ctx->user_agent);
    const reply *row = &steps->rows[at];
    char url[80], bearer[520];
    CHECK(snprintf(url, sizeof(url), "https://manage.kontent.ai/v2/projects/%s", row->env) < (int)sizeof(url));
    CHECK(snprintf(bearer, sizeof(bearer), "Bearer %s", row->key) < (int)sizeof(bearer));
    CHECK(request->detector_type == 328 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, bearer));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->suffix ? "TruffleHog kontent-offline" : "TruffleHog"));
    http->response = (br_http_response){.status = row->status,
        .body = {(const unsigned char *)row->body, row->body ? strlen(row->body) : 0},
        .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static bool cancelled(void *user) { (void)user; return true; }

static br_results run(const br_detector *detector, const char *input, script *steps, bool cancel, bool expire)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "kontent-offline" : NULL,
        .cancelled = cancel ? cancelled : NULL, .deadline_monotonic_ms = expire ? 1 : 0};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    char input[800], echoed[800];
    int n = snprintf(input, sizeof(input), "env %s kontent %s", env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const int statuses[] = {199, 200, 401, 300, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.env = env_a, .key = key_a, .status = statuses[i], .body = "ignored"};
        script steps = {.rows = &row, .count = 1, .suffix = true};
        br_results out = run(detector, input, &steps, true, true);
        CHECK(out.len == 1);
        check_pair(&out.items[0], env_a, key_a, statuses[i] == 200);
        if (statuses[i] == 200 || statuses[i] == 401) CHECK(!out.items[0].verification_error);
        else {
            char expected[48];
            snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
            CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, expected));
        }
        br_results_clear(&out);
    }
    char wrapped[160];
    snprintf(wrapped, sizeof(wrapped), "prefix %s suffix", sentence);
    const reply bodies[] = {
        {env_a, key_a, 403, 0, NULL, sentence, NULL},
        {env_a, key_a, 403, 0, NULL, wrapped, NULL},
        {env_a, key_a, 403, 0, NULL, "the specified API key does not provide the permissions required to access the environment", NULL},
        {env_a, key_a, 403, 0, NULL, "The specified API key", NULL},
        {env_a, key_a, 403, 0, NULL, "", "synthetic read failure"},
    };
    const bool verified[] = {true, true, false, false, false};
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        script steps = {.rows = &bodies[i], .count = 1};
        br_results out = run(detector, input, &steps, false, false);
        CHECK(out.len == 1);
        check_pair(&out.items[0], env_a, key_a, verified[i]);
        if (bodies[i].body_error) CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, bodies[i].body_error));
        else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    n = snprintf(echoed, sizeof(echoed), "transport failed %s %s", env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(echoed));
    reply failed = {.env = env_a, .key = key_a, .status = 200, .send_rc = 1, .send_error = echoed, .body_error = "ignored"};
    script fail_steps = {.rows = &failed, .count = 1};
    br_results out = run(detector, input, &fail_steps, true, true);
    CHECK(out.len == 1 && out.items[0].verification_error && !strcmp(out.items[0].verification_error, echoed));
    check_pair(&out.items[0], env_a, key_a, false);
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "env %s env %s kontent %s kontent %s", env_a, env_b, key_a, key_b);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const reply ordered[] = {
        {env_a, key_a, 200, 0, NULL, sentence, NULL},
        {env_a, key_b, 401, 0, NULL, NULL, NULL},
        {env_b, key_a, 403, 0, NULL, sentence, NULL},
        {env_b, key_b, 404, 0, NULL, NULL, NULL},
    };
    script order = {.rows = ordered, .count = 4};
    out = run(detector, input, &order, false, false);
    CHECK(out.len == 4);
    check_pair(&out.items[0], env_a, key_a, true);
    check_pair(&out.items[1], env_a, key_b, false);
    check_pair(&out.items[2], env_b, key_a, true);
    check_pair(&out.items[3], env_b, key_b, false);
    CHECK(out.items[3].verification_error && !strcmp(out.items[3].verification_error, "unexpected status code: 404"));
    br_results_clear(&out);

    n = snprintf(input, sizeof(input), "env %s kontent %s", env_listed, key_a);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .deadline_monotonic_ms = 1};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 0 && !http.calls && !http.releases);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
}

static void nul_wildcard(const br_detector *detector)
{
    char key[300], input[400];
    fill_key(key, 30, 200, 40, '.', 'A');
    size_t key_len = strlen(key);
    CHECK(key_len == 276 && key[32] == '.');
    key[32] = '\0';
    memcpy(input, "env ", 4);
    memcpy(input + 4, env_a, 36);
    memcpy(input + 40, " kontent ", 9);
    memcpy(input + 49, key, key_len);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, 49 + key_len);
    CHECK(out.len == 1 && !out.items[0].verified && !http.calls && !http.releases);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error,
          "net/http: invalid header field value for \"Authorization\""));
    CHECK(out.items[0].raw.len == 36 && !memcmp(out.items[0].raw.data, env_a, 36));
    CHECK(out.items[0].raw_v2.len == 36 + key_len && !memcmp(out.items[0].raw_v2.data + 36, key, key_len));
    br_results_clear(&out);
}

static void nil_context(const br_detector *detector)
{
    char input[800];
    int n = snprintf(input, sizeof(input), "env %s kontent %s", env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results out = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(out.len == 1);
    check_pair(&out.items[0], env_a, key_a, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&out);
}

static void preserve_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(out->items[0].secret_parts == parts);
}

static void owned_failures(const br_detector *detector)
{
    char input[800];
    int n = snprintf(input, sizeof(input), "env %s env %s kontent %s", env_a, env_b, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;

    br_slice bad = {NULL, 4};
    CHECK(detector->scan(detector, NULL, true, bad, &out, &error) == -1 && error);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot create Kontent result") && !fail_part_after && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    reply row = {.env = env_a, .key = key_a, .status = 418};
    script steps = {.rows = &row, .count = 1};
    http.inspect = inspect_request; http.user = &steps; steps.ctx = &ctx;
    fail_size = strlen("unexpected status code: 418") + 1;
    fail_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot verify Kontent candidate"));
    CHECK(http.calls == 1 && http.releases == 1);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    http.calls = http.releases = 0;
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot append Kontent result") && http.calls == 1 && http.releases == 1);
    out.cap = cap;
    free(error);
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);
}

static int mutate_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    test_http *http = user;
    char **borrowed = http->user;
    (void)ctx;
    (void)request;
    ++http->calls;
    memset(response, 0, sizeof(*response));
    if (http->send_rc) {
        *borrowed = malloc(32);
        CHECK(*borrowed);
        memcpy(*borrowed, "borrowed send cause", 20);
        *error = *borrowed;
        return 1;
    }
    *borrowed = malloc(32);
    CHECK(*borrowed);
    memcpy(*borrowed, "borrowed body error", 20);
    response->status = 403;
    response->body = (br_slice){NULL, 7};
    response->body_error = *borrowed;
    *error = NULL;
    return 0;
}

static void mutate_release(void *user, br_http_response *response)
{
    test_http *http = user;
    char **borrowed = http->user;
    ++http->releases;
    if (*borrowed) memset(*borrowed, 'X', 19);
    if (response && response->body_error) memset((char *)response->body_error, 'Y', 19);
}

static int project_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    test_http *http = user;
    (void)ctx;
    (void)request;
    ++http->calls;
    *response = http->response;
    *error = NULL;
    return 0;
}

static void release_policy(const br_detector *detector)
{
    char input[800];
    int n = snprintf(input, sizeof(input), "env %s kontent %s", env_a, key_a);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;

    expect_verified_at_setter = true;
    size_t setters = setter_calls;
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reply row = {.env = env_a, .key = key_a, .status = 200};
    script steps = {.rows = &row, .count = 1, .ctx = &ctx};
    http.inspect = inspect_request;
    http.user = &steps;
    br_results sent = {0};
    CHECK(detector->scan(detector, &ctx, true, data, &sent, &error) == 0 && !error);
    CHECK(sent.len == 1 && sent.items[0].verified && !sent.items[0].verification_error);
    CHECK(!expect_verified_at_setter && setter_calls == setters + 1);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&sent);

    null_diag = true;
    setters = setter_calls;
    size_t nulls = null_setter_calls;
    http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &sent, &error) == 0 && !error);
    null_diag = false;
    CHECK(sent.len == 1 && !sent.items[0].verified && !sent.items[0].verification_error);
    CHECK(setter_calls == setters + 1 && null_setter_calls == nulls + 1);
    CHECK(!http.calls && http.releases == 1);
    br_results_clear(&sent);

    fail_setter_after = 1;
    http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error && !fail_setter_after);
    CHECK(!strcmp(error, "cannot verify Kontent candidate") && http.calls == 1 && http.releases == 1);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    char *borrowed = NULL;
    test_http mutate = {.send_rc = 1, .user = &borrowed};
    br_transport mutate_transport = {&mutate, mutate_send, mutate_release};
    br_scan_ctx mutate_ctx = {.transport = &mutate_transport};
    CHECK(detector->scan(detector, &mutate_ctx, true, data, &sent, &error) == 0 && !error);
    CHECK(sent.len == 1 && !sent.items[0].verified && sent.items[0].verification_error);
    CHECK(!strcmp(sent.items[0].verification_error, "borrowed send cause"));
    CHECK(mutate.calls == 1 && mutate.releases == 1);
    borrowed = NULL;
    br_results_clear(&sent);

    mutate.send_rc = 0;
    mutate.calls = mutate.releases = 0;
    borrowed = NULL;
    CHECK(detector->scan(detector, &mutate_ctx, true, data, &sent, &error) == 0 && !error);
    CHECK(sent.len == 1 && !sent.items[0].verified && sent.items[0].verification_error);
    CHECK(!strcmp(sent.items[0].verification_error, "borrowed body error"));
    CHECK(mutate.calls == 1 && mutate.releases == 1);
    free(borrowed);
    br_results_clear(&sent);

    setters = setter_calls;
    test_http project = {.response = {.status = 403, .body = {NULL, 4}}};
    br_transport project_transport = {&project, project_send, test_http_release};
    br_scan_ctx project_ctx = {.transport = &project_transport};
    CHECK(detector->scan(detector, &project_ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot verify Kontent candidate") && setter_calls == setters);
    CHECK(project.calls == 1 && project.releases == 1);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    project.response.body_error = "synthetic read failure";
    project.calls = project.releases = 0;
    CHECK(detector->scan(detector, &project_ctx, true, data, &sent, &error) == 0 && !error);
    CHECK(sent.len == 1 && !sent.items[0].verified && sent.items[0].verification_error);
    CHECK(!strcmp(sent.items[0].verification_error, "synthetic read failure"));
    CHECK(project.calls == 1 && project.releases == 1 && setter_calls == setters + 1);
    br_results_clear(&sent);
    br_results_clear(&out);
}

int main(void)
{
    fill_key(key_a, 30, 200, 40, '.', 'A');
    fill_key(key_b, 34, 200, 43, '.', 'B');
    fill_key(key_wild, 34, 200, 40, 'X', 'C');
    fill_key(key_low, 30, 200, 40, '.', 'A');
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    nul_wildcard(detector);
    nil_context(detector);
    owned_failures(detector);
    release_policy(detector);
    return test_finish("Kontent");
}
