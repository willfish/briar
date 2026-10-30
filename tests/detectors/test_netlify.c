/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_netlify_v1_init(const br_detector **out, char **error);
int br_netlify_v2_init(const br_detector **out, char **error);

static char v1a[46], v1b[46], v1c[47];
static char v2a[41], v2b[41];
static const char url[] = "https://api.netlify.com/api/v1/sites";
static const char guide[] = "https://howtorotate.com/docs/tutorials/netlify/";
static size_t fail_size, fail_after, fail_part_after;
static bool fail_growth, fail_extra;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#include "../../src/result.c"
#undef realloc

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    if (fail_extra && !strcmp(name, "rotation_guide")) { fail_extra = false; return 1; }
    return json_object_object_add_ex(object, name, value, 0);
}

static void v2_key(char *out, size_t shift)
{
    char suffix[37];
    test_secret(suffix, 36, shift);
    memcpy(out, "nfp_", 4);
    memcpy(out + 4, suffix, 37);
}

static const br_detector *one_descriptor(int (*init)(const br_detector **, char **), int version)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:netlify)(?s:.){0,40}?"); fail_after = 1;
    CHECK(init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 74 && d->version == version && !strcmp(d->name, "Netlify"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Netlify is a cloud platform for web developers that provides hosting and serverless backend services for web applications and static websites. Netlify API keys can be used to manage sites, deploy applications, and access various services offered by the platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "netlify"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    return d;
}

static void check_result(const br_result *r, const char *key, const char *version,
                         bool verified, const char *cause)
{
    CHECK(r->detector_type == 74 && r->raw.len == strlen(key));
    CHECK(!memcmp(r->raw.data, key, r->raw.len) && r->verified == verified);
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL, *guide_value = NULL, *version_value = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), key));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 2);
    CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &guide_value));
    CHECK(json_object_is_type(guide_value, json_type_string));
    CHECK(!strcmp(json_object_get_string(guide_value), guide));
    CHECK(json_object_object_get_ex(r->extra_data, "version", &version_value));
    CHECK(json_object_is_type(version_value, json_type_string));
    CHECK(!strcmp(json_object_get_string(version_value), version));
    if (cause) CHECK(r->verification_error && !strcmp(r->verification_error, cause));
    else CHECK(!r->verification_error);
}

static void expect_n(const br_detector *d, const char *version, const void *text, size_t n,
                     size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, version, false, NULL);
    br_results_clear(&r);
}

static void grammar(const br_detector *v1, const br_detector *v2)
{
    char input[256], changed[48];
    int n = snprintf(input, sizeof(input), "netlify %s", v1a);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 1, v1a);
    n = snprintf(input, sizeof(input), "NeTlIfY=%s", v1b);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 1, v1b);
    n = snprintf(input, sizeof(input), "netlify %s", v1c);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 1, v1c);
    memcpy(changed, v1a, 42); changed[42] = '\0';
    n = snprintf(input, sizeof(input), "netlify %s", changed);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "netlify %sx", v1c);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 0, NULL);
    memcpy(input, "netlify", 7); memcpy(input + 7, v1a, 43);
    expect_n(v1, "1", input, 50, 0, NULL);
    memcpy(changed, v1a, 44); changed[8] = '-'; changed[9] = '_';
    n = snprintf(input, sizeof(input), "netlify %s", changed);
    CHECK(n > 0); expect_n(v1, "1", input, (size_t)n, 1, changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "netlify", 7);
        memset(input + 7, '.', gap);
        memcpy(input + 7 + gap, v1a, 43);
        expect_n(v1, "1", input, 7 + gap + 43, gap == 40 ? 1u : 0u, v1a);
    }
    n = snprintf(input, sizeof(input), "netlify %s\nnetlify %s\nnetlify %s", v1a, v1b, v1a);
    CHECK(n > 0);
    br_results both = test_scan(v1, NULL, false, input, (size_t)n);
    CHECK(both.len == 2);
    check_result(&both.items[0], v1a, "1", false, NULL);
    check_result(&both.items[1], v1b, "1", false, NULL);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    n = snprintf(input, sizeof(input), "netlify %s", v2a);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 1, v2a);
    expect_n(v1, "1", input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "netlify NFP_%s", v2a + 4);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "netlify xnfp_%s", v2a + 4);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 0, NULL);
    memcpy(changed, v2a, 41); changed[8] = '-';
    n = snprintf(input, sizeof(input), "netlify %s", changed);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 0, NULL);
    memcpy(changed, v2a, 41); changed[8] = '_';
    n = snprintf(input, sizeof(input), "netlify %s", changed);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 1, changed);
    n = snprintf(input, sizeof(input), "netlify nfp_%.35s", v2a + 4);
    CHECK(n > 0 && strlen(input + 8) == 39);
    expect_n(v2, "2", input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "netlify %sx", v2a);
    CHECK(n > 0); expect_n(v2, "2", input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "netlify %s netlify %s netlify %s", v2a, v2b, v2a);
    CHECK(n > 0);
    br_results v2both = test_scan(v2, NULL, false, input, (size_t)n);
    CHECK(v2both.len == 2);
    check_result(&v2both.items[0], v2a, "2", false, NULL);
    check_result(&v2both.items[1], v2b, "2", false, NULL);
    br_results_clear(&v2both);
    expect_n(v1, "1", NULL, 0, 0, NULL);
}

typedef struct {
    const char *token;
    const char *const *tokens;
    const br_scan_ctx *ctx;
    const char *live;
} expected;

static const char *token_at(const expected *e, size_t at)
{
    return e->tokens ? e->tokens[at] : e->token;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    char bearer[64];
    int n = snprintf(bearer, sizeof(bearer), "Bearer %s", token_at(e, http->calls - 1));
    CHECK(n > 0 && !e->live && ctx == e->ctx);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 74);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(request->headers[0].value && !strcmp(request->headers[0].value, bearer));
    CHECK(strncmp(request->headers[0].value, "Bearer Bearer ", 14) != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog netlify-offline"));
    e->live = request->headers[0].value;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    char bearer[64];
    if (http->calls) {
        snprintf(bearer, sizeof(bearer), "Bearer %s", token_at(e, http->calls - 1));
        CHECK(e->live && !strcmp(e->live, bearer));
    } else CHECK(!e->live);
    e->live = NULL;
    test_http_release(user, response);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].verified && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static void one_verify(const br_detector *d, const char *version, const char *key,
                       test_http *http, br_scan_ctx *ctx, expected *e,
                       int status, int rc, const char *body_error, const char *send_error,
                       bool verified, const char *cause)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "netlify %s", key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    e->token = key;
    http->calls = http->releases = 0;
    http->response = (br_http_response){.status = status, .body_error = body_error};
    http->send_rc = rc; http->send_error = send_error;
    br_results r = test_scan(d, ctx, true, input, (size_t)n);
    CHECK(r.len == 1 && http->calls == 1 && http->releases == 1 && !e->live);
    check_result(&r.items[0], key, version, verified, cause);
    br_results_clear(&r);
}

static void verification(const br_detector *v1, const br_detector *v2)
{
    expected e = {0};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "netlify-offline"};
    e.ctx = &ctx;
    one_verify(v1, "1", v1a, &http, &ctx, &e, 200, 0, NULL, NULL, true, NULL);
    one_verify(v1, "1", v1a, &http, &ctx, &e, 200, 0, "", NULL, true, NULL);
    one_verify(v1, "1", v1a, &http, &ctx, &e, 200, 0, "synthetic read failure", NULL, true, NULL);
    one_verify(v1, "1", v1a, &http, &ctx, &e, 401, 0, "read", NULL, false, NULL);
    one_verify(v1, "1", v1a, &http, &ctx, &e, 201, 0, "", NULL, false, "unexpected HTTP response status 201");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 299, 0, NULL, NULL, false, "unexpected HTTP response status 299");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 199, 0, NULL, NULL, false, "unexpected HTTP response status 199");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 500, 0, "read", NULL, false, "unexpected HTTP response status 500");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 200, 1, NULL, NULL, false, "HTTP transport failed");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 200, 1, "read", "synthetic send error", false, "synthetic send error");
    char sensitive[160], redacted[160];
    snprintf(sensitive, sizeof(sensitive), "bad %s again %s", v1a, v1a);
    snprintf(redacted, sizeof(redacted), "bad [REDACTED] again [REDACTED]");
    one_verify(v1, "1", v1a, &http, &ctx, &e, 401, 7, NULL, sensitive, false, redacted);
    one_verify(v2, "2", v2a, &http, &ctx, &e, 200, 0, "read", NULL, true, NULL);
    one_verify(v2, "2", v2a, &http, &ctx, &e, 401, 0, "", NULL, false, NULL);
    one_verify(v2, "2", v2a, &http, &ctx, &e, 204, 0, "read", NULL, false, "unexpected HTTP response status 204");
    http.calls = http.releases = 0;
    e.token = v1a;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "netlify-offline"};
    char input[160];
    int n = snprintf(input, sizeof(input), "netlify %s", v1a);
    CHECK(n > 0);
    br_results setup = test_scan(v1, &missing, true, input, (size_t)n);
    CHECK(setup.len == 1 && !http.calls && http.releases == 1 && !e.live);
    check_result(&setup.items[0], v1a, "1", false, "HTTP transport not installed");
    br_results_clear(&setup);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases;
    n = snprintf(input, sizeof(input), "netlify %s netlify %s", v1a, v1b);
    CHECK(n > 0);
    CHECK(v1->scan(v1, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases && kept.len == 3);
    CHECK(kept.items[0].raw.data == prior.raw.data);
    CHECK(kept.items[0].verification_error == prior.verification_error);
    check_result(&kept.items[1], v1a, "1", false, "net/http: nil Context");
    check_result(&kept.items[2], v1b, "1", false, "net/http: nil Context");
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *v1)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "netlify %s netlify %s", v1a, v1b);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expected e = {.token = v1a};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "netlify-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char *error = NULL;

    fail_size = 44; fail_after = 1;
    CHECK(v1->scan(v1, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(v1->scan(v1, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Netlify result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;

    fail_extra = true;
    CHECK(v1->scan(v1, &ctx, true, data, &out, &error) == -1 && error && !fail_extra);
    CHECK(!strcmp(error, "cannot create Netlify metadata"));
    CHECK(!http.calls && !http.releases && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;

    static const char setter_error[] = "synthetic-netlify-setter-failure-without-token-0123456789abcd";
    http.response = (br_http_response){.status = 500};
    http.send_rc = 1; http.send_error = setter_error;
    fail_size = sizeof(setter_error); fail_after = 2;
    CHECK(v1->scan(v1, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot store Netlify verification error"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.send_rc = 0; http.send_error = NULL; http.calls = http.releases = 0;

    fail_size = sizeof("net/http: nil Context"); fail_after = 1;
    CHECK(v1->scan(v1, NULL, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot store Netlify verification error"));
    CHECK(!http.calls && !http.releases);
    check_prior(&out, &prior);
    free(error); error = NULL;

    http.response = (br_http_response){.status = 200};
    const char *tokens[] = {v1a, v1b};
    e.tokens = tokens;
    e.token = NULL;
    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(v1->scan(v1, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Netlify result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    test_secret(v1a, 43, 0);
    test_secret(v1b, 44, 3);
    test_secret(v1c, 45, 5);
    v2_key(v2a, 1);
    v2_key(v2b, 9);
    const br_detector *v1 = one_descriptor(br_netlify_v1_init, 1);
    const br_detector *v2 = one_descriptor(br_netlify_v2_init, 2);
    grammar(v1, v2);
    verification(v1, v2);
    owned_failures(v1);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_extra);
    return test_finish("Netlify");
}
