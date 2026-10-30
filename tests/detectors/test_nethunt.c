/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_nethunt_init(const br_detector **out, char **error);

static char key1[37], key2[37];
static char id1[] = "user.name.id1@example.com";
static char id2[] = "user.name.id2@example.com";
static const char url[] = "https://nethunt.com/api/v1/zapier/triggers/readable-folder";
static size_t fail_size, fail_after, fail_part_after;
static bool fail_growth;

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
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_nethunt_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_nethunt_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:nethunt)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_nethunt_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_nethunt_init(&d, &error) == 0 && d && !error);
    CHECK(br_nethunt_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 268 && d->version == 0 && !strcmp(d->name, "Nethunt"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Nethunt is a CRM tool. Credentials found can be used to access and manage CRM data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nethunt"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 268, key, "key");
    CHECK(r->raw.len == 36 && r->verified == verified && !r->verification_error && !r->extra_data);
    CHECK(!r->raw_v2.data && !r->raw_v2.len);
}

static void extract_n(const br_detector *d, const void *text, size_t n, size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, false);
    br_results_clear(&r);
}

static void place(char *out, size_t *at, const char *text, size_t n)
{
    memcpy(out + *at, text, n);
    *at += n;
}

static void grammar(const br_detector *d)
{
    char input[256], changed[37], id[40];
    size_t at = 0;
    CHECK(strlen(id1) == 25 && strlen(id2) == 25);
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    extract_n(d, input, at, 0, NULL);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, id1, 25);
    extract_n(d, input, at, 0, NULL);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id1, 25);
    extract_n(d, input, at, 1, key1);
    at = 0;
    place(input, &at, "NeThUnT=", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id1, 25);
    extract_n(d, input, at, 1, key1);
    memcpy(input, "nethunt", 7); memcpy(input + 7, key1, 36);
    memcpy(input + 43, " ", 1); memcpy(input + 44, id1, 25);
    extract_n(d, input, 69, 0, NULL);
    memcpy(changed, key1, 36); changed[8] = '\v';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, changed, 36);
    place(input, &at, " ", 1); place(input, &at, id1, 25);
    br_results vt = test_scan(d, NULL, false, input, at);
    CHECK(vt.len == 1 && vt.items[0].raw.len == 36);
    CHECK(!memcmp(vt.items[0].raw.data, changed, 36) && vt.items[0].raw.data[8] == '\v');
    br_results_clear(&vt);
    memcpy(changed, key1, 36); changed[36] = '\0'; changed[8] = 'Z';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, changed, 36);
    place(input, &at, " ", 1); place(input, &at, id1, 25);
    extract_n(d, input, at, 1, changed);
    memcpy(changed, key1, 36); changed[36] = '\0'; changed[8] = '@';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, changed, 36);
    place(input, &at, " ", 1); place(input, &at, id1, 25);
    extract_n(d, input, at, 1, changed);
    for (size_t i = 0; i < 5; ++i) {
        memcpy(changed, key1, 36);
        changed[8] = " \t\n\f\r"[i];
        at = 0;
        place(input, &at, "nethunt ", 8); place(input, &at, changed, 36);
        place(input, &at, id1, 25);
        extract_n(d, input, at, 0, NULL);
    }
    memset(id, 'a', 24);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 24);
    extract_n(d, input, at, 0, NULL);
    memset(id, 'a', 31);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 30);
    extract_n(d, input, at, 1, key1);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 31);
    extract_n(d, input, at, 0, NULL);
    memcpy(id, id1, 26); id[4] = '_';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 25);
    extract_n(d, input, at, 0, NULL);
    memcpy(id, id1, 26); id[4] = '+';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 25);
    extract_n(d, input, at, 0, NULL);
    memcpy(id, id1, 26); id[4] = '-';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 25);
    extract_n(d, input, at, 0, NULL);
    memcpy(id, id1, 26); id[4] = '/';
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " ", 1); place(input, &at, id, 25);
    extract_n(d, input, at, 1, key1);
    char wide[1300];
    memset(wide, ' ', 1100);
    memcpy(wide + 1100, "nethunt ", 8);
    memcpy(wide + 1108, key1, 36);
    wide[1144] = ' ';
    memcpy(wide + 1145, id1, 25);
    extract_n(d, wide, 1170, 1, key1);
    at = 0;
    place(input, &at, "nethunt ", 8); place(input, &at, key1, 36);
    place(input, &at, " nethunt ", 9); place(input, &at, key2, 36);
    place(input, &at, " nethunt ", 9); place(input, &at, id1, 25);
    place(input, &at, " nethunt ", 9); place(input, &at, id2, 25);
    br_results product = test_scan(d, NULL, false, input, at);
    CHECK(product.len == 4);
    check_result(&product.items[0], key1, false);
    check_result(&product.items[1], key1, false);
    check_result(&product.items[2], key2, false);
    check_result(&product.items[3], key2, false);
    CHECK(product.items[0].raw.data != product.items[1].raw.data);
    br_results_clear(&product);
    extract_n(d, NULL, 0, 0, NULL);
}

typedef struct {
    const char *const *auths;
    size_t count;
    const br_scan_ctx *ctx;
    const char *live;
} expected;

static char *auth_of(const char *id, const char *key)
{
    char *out = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                             (br_slice){(const unsigned char *)key, 36}, &out, NULL) == 0 && out);
    CHECK(!strncmp(out, "Basic ", 6) && strncmp(out, "Basic Basic ", 12) != 0);
    return out;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && !e->live);
    CHECK(!strcmp(request->method, "GET") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 268);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(request->headers[0].value && !strcmp(request->headers[0].value, e->auths[at]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog nethunt-offline"));
    e->live = request->headers[0].value;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) CHECK(e->live && !strcmp(e->live, e->auths[http->calls - 1]));
    else CHECK(!e->live);
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

static void pair_text(char *input, size_t n, const char *key, const char *id)
{
    int wrote = snprintf(input, n, "nethunt %s %s", key, id);
    CHECK(wrote > 0 && (size_t)wrote < n);
}

static void one_verify(const br_detector *d, test_http *http, br_scan_ctx *ctx, expected *e,
                       const char *auth, int status, int rc, const char *body_error,
                       const char *send_error, bool verified)
{
    char input[96];
    pair_text(input, sizeof(input), key1, id1);
    const char *auths[] = {auth};
    e->auths = auths; e->count = 1;
    http->calls = http->releases = 0;
    http->response = (br_http_response){.status = status, .body_error = body_error};
    http->send_rc = rc; http->send_error = send_error;
    br_results r = test_scan(d, ctx, true, input, strlen(input));
    CHECK(r.len == 1 && http->calls == 1 && http->releases == 1 && !e->live);
    check_result(&r.items[0], key1, verified);
    br_results_clear(&r);
}

static void verification(const br_detector *d)
{
    char *auth = auth_of(id1, key1);
    expected e = {0};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nethunt-offline"};
    e.ctx = &ctx;
    one_verify(d, &http, &ctx, &e, auth, 200, 0, NULL, NULL, true);
    one_verify(d, &http, &ctx, &e, auth, 201, 0, NULL, NULL, true);
    one_verify(d, &http, &ctx, &e, auth, 299, 0, "", NULL, true);
    one_verify(d, &http, &ctx, &e, auth, 200, 0, "synthetic read failure", NULL, true);
    one_verify(d, &http, &ctx, &e, auth, 199, 0, NULL, NULL, false);
    one_verify(d, &http, &ctx, &e, auth, 300, 0, "read", NULL, false);
    one_verify(d, &http, &ctx, &e, auth, 401, 0, NULL, NULL, false);
    one_verify(d, &http, &ctx, &e, auth, 200, 1, NULL, "synthetic send error", false);
    one_verify(d, &http, &ctx, &e, auth, 204, 7, "read", key1, false);
    http.calls = http.releases = 0;
    const char *auths[] = {auth};
    e.auths = auths; e.count = 1;
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "nethunt-offline"};
    char input[96];
    pair_text(input, sizeof(input), key1, id1);
    br_results dropped = test_scan(d, &missing, true, input, strlen(input));
    CHECK(dropped.len == 1 && !http.calls && http.releases == 1 && !e.live);
    check_result(&dropped.items[0], key1, false);
    br_results_clear(&dropped);
    free(auth);
}

static void product_and_nil(const br_detector *d)
{
    char input[180];
    int n = snprintf(input, sizeof(input), "nethunt %s nethunt %s nethunt %s nethunt %s",
                     key1, key2, id1, id2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char *a0 = auth_of(id1, key1), *a1 = auth_of(id2, key1);
    char *a2 = auth_of(id1, key2), *a3 = auth_of(id2, key2);
    const char *auths[] = {a0, a1, a2, a3};
    expected e = {.auths = auths, .count = 4};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200, .body_error = ""}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nethunt-offline"};
    e.ctx = &ctx;
    br_results r = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(r.len == 4 && http.calls == 4 && http.releases == 4 && !e.live);
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key1, true);
    check_result(&r.items[2], key2, true);
    check_result(&r.items[3], key2, true);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);
    free(a0); free(a1); free(a2); free(a3);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == calls);
    check_prior(&kept, &prior);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "nethunt %s nethunt %s nethunt %s", key1, key2, id1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    char *a0 = auth_of(id1, key1), *a1 = auth_of(id1, key2);
    const char *auths[] = {a0, a1};
    expected e = {.auths = auths, .count = 2};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nethunt-offline"};
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

    fail_size = 37; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Nethunt result"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;

    fail_size = 91; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
    CHECK(!http.calls && !http.releases && !e.live);
    check_prior(&out, &prior);
    free(error); error = NULL;

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append Nethunt result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error);
    br_results_clear(&out);
    free(a0); free(a1);
}

int main(void)
{
    test_secret(key1, 36, 0);
    test_secret(key2, 36, 3);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    product_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth);
    return test_finish("Nethunt");
}
