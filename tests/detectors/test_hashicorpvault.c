/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/endpoints.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_json.h"
#include "../../src/detectors/json.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

#include <pthread.h>
#include <stdarg.h>
#include <time.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

typedef enum {
    NONE, CAPTURE, ENDPOINTS, FINDING, ALLOCATION, POLICY_GROWTH, DOCUMENT,
    MEMBER, ELEMENT, RETAIN, TYPE_CAUSE, MAP, METADATA, SETTER, PUSH, CAUSE, STATUS_FORMAT
} fault_kind;
static fault_kind fault;
static size_t fail_nth, fail_size;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE;
    return true;
}
static void *checked_malloc(size_t n) { return n == fail_size && hit(ALLOCATION) ? NULL : malloc(n); }
static void *checked_realloc(void *p, size_t n) { return hit(POLICY_GROWTH) ? NULL : realloc(p, n); }
static char *checked_strdup(const char *s) { return hit(CAUSE) ? NULL : strdup(s); }
static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    if (!strcmp(format, "unexpected HTTP response status %d") && hit(STATUS_FORMAT)) return -1;
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}
static int checked_captures(const br_regex *r, br_slice s, br_captures *c, bool unique, char **error)
{
    if (hit(CAPTURE)) return 1;
    return br_captures_find(r, s, c, unique, error);
}
static int checked_endpoints(const br_endpoints *e, const char *cloud, const br_captures *c, br_byte_endpoints *out, char **error)
{
    return hit(ENDPOINTS) ? 1 : br_endpoints_collect_bytes(e, cloud, c, out, error);
}
static int checked_finding(br_result *r, int32_t t, br_slice k, const char *kn, br_slice u, const char *un, br_slice sep)
{
    return hit(FINDING) ? 1 : br_finding_pair_bytes(r, t, k, kn, u, un, sep);
}
static int checked_document(br_slice s, const char *read, br_json **out, size_t *end, char **cause)
{
    return hit(DOCUMENT) ? -1 : br_json_first_document(s, read, out, end, cause);
}
static int checked_member(br_slice s, br_json_member_fn fn, void *u) { return hit(MEMBER) ? 1 : br_json_each_member(s, fn, u); }
static int checked_element(br_slice s, br_json_element_fn fn, void *u) { return hit(ELEMENT) ? 1 : br_json_each_element(s, fn, u); }
static int checked_retain(br_json *v, br_slice *s, br_bytes *b, char **error)
{
    return hit(RETAIN) ? 1 : br_gcp_json_text(v, s, b, error);
}
static int checked_type_cause(br_json *v, const char *f, const char *t, char **cause)
{
    return hit(TYPE_CAUSE) ? 1 : br_json_type_cause(v, f, t, cause);
}
static br_json *checked_map(void) { return hit(MAP) ? NULL : json_object_new_object(); }
static int checked_metadata(br_json *m, const char *k, br_json *v) { return hit(METADATA) ? 1 : json_object_object_add(m, k, v); }

/* Observe the ordinary send/release contract without stripping keys or
 * auto-wrapping an injection. Only this module's calls are instrumented. */
typedef struct { const char *token, *base, *url; int32_t type; } expected_request;
static expected_request expected;
static const br_http_request *provider_request;
static size_t sends, releases, setters;
static char *saved_url;
static unsigned char *saved_key;
static size_t saved_keylen;
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(r->profile == BR_HTTP_DETECTOR_PUBLIC && r->detector_type == expected.type);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, expected.url));
    CHECK(!r->body.data && !r->body.len && r->nheaders == (effective ? 2u : 1u));
    CHECK(effective ? r->timeout_ms > 0 && r->timeout_ms <= 10000 : r->timeout_ms == 10000);
    CHECK(!strcmp(r->headers[0].name, "X-Vault-Token") && !strcmp(r->headers[0].value, expected.token));
    char prefix[32]; int n = snprintf(prefix, sizeof(prefix), "%d:", (int)expected.type);
    size_t base = strlen(expected.base), token = strlen(expected.token);
    CHECK(n > 0 && r->dedup_key.len == (size_t)n + base + 1 + token);
    CHECK(!memcmp(r->dedup_key.data, prefix, (size_t)n));
    CHECK(!memcmp(r->dedup_key.data + n, expected.base, base) && r->dedup_key.data[n + base] == ':');
    CHECK(!memcmp(r->dedup_key.data + n + base + 1, expected.token, token));
    if (effective) CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, "TruffleHog vault-offline"));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(!provider_request);
    request_values(r, false);
    provider_request = r;
    saved_url = strdup(r->url); saved_key = malloc(r->dedup_key.len); saved_keylen = r->dedup_key.len;
    CHECK(saved_url && saved_key); memcpy(saved_key, r->dedup_key.data, saved_keylen);
    ++sends;
    return br_http_send(ctx, r, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && !strcmp(provider_request->url, saved_url));
    CHECK(provider_request->dedup_key.len == saved_keylen && !memcmp(provider_request->dedup_key.data, saved_key, saved_keylen));
    request_values(provider_request, false);
    br_http_release(ctx, response);
    provider_request = NULL; free(saved_url); free(saved_key); saved_url = NULL; saved_key = NULL;
    ++releases;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(!provider_request && sends == releases && !r->verified && !r->extra_data);
    CHECK(count == 1 && secrets && secrets[0].len == r->raw.len && !memcmp(secrets[0].data, r->raw.data, r->raw.len));
    ++setters;
    return hit(SETTER) ? 1 : br_result_set_verification_error(r, cause, secrets, count);
}
static int checked_push(br_results *r, br_result *v) { return hit(PUSH) ? 1 : br_results_push(r, v); }

/* Compile the exact module with narrow local failure hooks; no production
 * seams, linker flags, global allocator overrides or shared files are needed. */
#define malloc checked_malloc
#define realloc checked_realloc
#define strdup checked_strdup
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_endpoints_collect_bytes checked_endpoints
#define br_finding_pair_bytes checked_finding
#define br_json_first_document checked_document
#define br_json_each_member checked_member
#define br_json_each_element checked_element
#define br_gcp_json_text checked_retain
#define br_json_type_cause checked_type_cause
#define json_object_new_object checked_map
#define json_object_object_add checked_metadata
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#include "../../src/detectors/hashicorpvault.c"
#undef malloc
#undef realloc
#undef strdup
#undef snprintf
#undef br_captures_find
#undef br_endpoints_collect_bytes
#undef br_finding_pair_bytes
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_each_element
#undef br_gcp_json_text
#undef br_json_type_cause
#undef json_object_new_object
#undef json_object_object_add
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push

static const char origin[] = "https://synthetic.invalid";
static const char lookup[] = "https://synthetic.invalid/v1/auth/token/lookup-self";
static char batch1[305], batch2[305], service1[125], legacy[43];
static void token(char *out, const char *prefix, size_t n, size_t shift)
{
    size_t len = strlen(prefix); memcpy(out, prefix, len); test_secret(out + len, n, shift);
}
static void field(br_json *map, const char *name, br_slice value)
{
    br_json *v = NULL;
    CHECK(map && json_object_object_get_ex(map, name, &v) && json_object_is_type(v, json_type_string));
    CHECK((size_t)json_object_get_string_len(v) == value.len && (!value.len || !memcmp(json_object_get_string(v), value.data, value.len)));
}
static void finding(const br_result *r, const br_detector *d, const char *key, br_slice endpoint,
                    bool verified, const char *cause)
{
    size_t n = strlen(key);
    CHECK(r->detector_type == d->type && !r->detector_name && r->verified == verified);
    CHECK(r->raw.len == n && !memcmp(r->raw.data, key, n));
    CHECK(r->raw_v2.len == n + 1 + endpoint.len && !memcmp(r->raw_v2.data, key, n));
    CHECK(r->raw_v2.data[n] == ':' && (!endpoint.len || !memcmp(r->raw_v2.data + n + 1, endpoint.data, endpoint.len)));
    CHECK(r->redacted && strlen(r->redacted) == 11 && !memcmp(r->redacted, key, 8) && !strcmp(r->redacted + 8, "..."));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    field(r->secret_parts, "key", text(key)); field(r->secret_parts, "url", endpoint);
    CHECK(!r->verification_from_cache && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->chunk_offset && !r->chunk_offset_set);
    CHECK((r->verification_error != NULL) == (cause != NULL));
    if (cause) CHECK(!strcmp(r->verification_error, cause));
}
static void metadata(const br_result *r, br_slice policies, const char *orphan,
                     const char *renewable, br_slice type, br_slice entity)
{
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 5);
    field(r->extra_data, "policies", policies); field(r->extra_data, "orphan", text(orphan));
    field(r->extra_data, "renewable", text(renewable)); field(r->extra_data, "type", type); field(r->extra_data, "entity_id", entity);
}
static const br_detector *descriptor(bool batch)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    int (*init)(const br_detector **, char **) = batch ? br_hashicorpvaultbatchtoken_init : br_hashicorpvaulttoken_init;
    CHECK(BR_ABI_REVISION == 1 && init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(!init(&d, &error) && d && !error && !init(&again, NULL) && again == d);
    CHECK(d->type == (batch ? 1061 : 1062) && !d->version && !strcmp(d->name, batch ? "HashiCorpVaultBatchToken" : "HashiCorpVaultToken"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, batch ? "This detector detects and verifies HashiCorp Vault batch tokens" :
        "HashiCorp Vault is a secrets management service. Vault tokens (periodic, service, and admin) can be used to access and manage stored secrets and resources."));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && d->validate_endpoints);
    CHECK(d->cloud_endpoint && !*d->cloud_endpoint && d->nkeywords == (batch ? 1u : 2u));
    CHECK(!strcmp(d->keywords[0], batch ? "hvb." : "hvs."));
    if (!batch) CHECK(!strcmp(d->keywords[1], "vault")); /* s. alone is NOT a dispatch keyword. */
    br_endpoints zero = {0}; CHECK(d->validate_endpoints(&zero, &error) != 0 && error); free(error); error = NULL;
    const char *empty[] = {""}; zero.configured = empty; zero.nconfigured = 1;
    CHECK(!d->validate_endpoints(&zero, &error) && !error);
    return d;
}
static br_results nov(const br_detector *d, const void *input, size_t n, const br_endpoints *e)
{
    br_scan_ctx ctx = {.endpoints = e};
    size_t calls = sends;
    br_results r = test_scan(d, &ctx, false, input, n);
    CHECK(sends == calls && !provider_request);
    return r;
}
static void extraction_case(const br_detector *d, const char *input, const char *key)
{
    const char *configured[] = {origin}; br_endpoints e = {.configured = configured, .nconfigured = 1};
    br_results r = nov(d, input, strlen(input), &e); CHECK(r.len == (key ? 1u : 0u));
    if (key) { finding(&r.items[0], d, key, text(origin), false, NULL); CHECK(!r.items[0].extra_data); }
    br_results_clear(&r);
}
static void grammar(const br_detector *d)
{
    bool batch = d->type == 1061;
    const char *prefixes[] = {batch ? "hvb." : "hvs.", "s."};
    size_t minimum[] = {batch ? 50u : 90u, 18}, maximum[] = {batch ? 300u : 120u, 40};
    char key[306], input[1000];
    for (size_t p = 0; p < (batch ? 1u : 2u); ++p) {
        size_t lengths[] = {minimum[p] - 1, minimum[p], maximum[p], maximum[p] + 1};
        for (size_t i = 0; i < 4; ++i) {
            token(key, prefixes[p], lengths[i], 3); snprintf(input, sizeof(input), "%s", key);
            extraction_case(d, input, i == 1 || i == 2 ? key : NULL);
        }
        token(key, prefixes[p], minimum[p], 2);
        const char *good[] = {"%s", "(%s)", ".%s\r\n", "vault='%s'", "\xc3\xa9%s"};
        for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, key); }
        snprintf(input, sizeof(input), "_%s", key); extraction_case(d, input, NULL);
        snprintf(input, sizeof(input), "x%s", key); extraction_case(d, input, NULL);
        key[0] = (char)(key[0] - 'a' + 'A'); extraction_case(d, key, NULL);
        token(key, prefixes[p], minimum[p], 0); key[strlen(key) - 1] = '-'; extraction_case(d, key, key);
        key[strlen(key) - 1] = '_'; extraction_case(d, key, key);
        if (batch) { key[strlen(key) - 1] = '.'; extraction_case(d, key, key); }
        else { snprintf(input, sizeof(input), "%s.tail", key); extraction_case(d, input, key); }
    }
    extraction_case(d, "", NULL);
    /* Source patterns consume the final delimiter and preserve whole originals. */
    const char *a = batch ? batch1 : service1, *b = batch ? batch2 : legacy;
    snprintf(input, sizeof(input), "%s\n%s\r%s", a, b, a);
    const char *configured[] = {origin}; br_endpoints e = {.configured = configured, .nconfigured = 1};
    br_results r = nov(d, input, strlen(input), &e); CHECK(r.len == 2);
    finding(&r.items[0], d, a, text(origin), false, NULL); finding(&r.items[1], d, b, text(origin), false, NULL);
    br_results_clear(&r);
}
static void endpoints(const br_detector *d)
{
    const char *a = d->type == 1061 ? batch1 : service1, *b = d->type == 1061 ? batch2 : legacy;
    const char *one = "https://one.hashicorp.cloud", *two = "http://two.hashicorp.cloud:8200";
    char input[1200];
    snprintf(input, sizeof(input), "%s %s %s %s/path %s/other %s/sub/path", a, b, a, one, one, two);
    const char *configured[] = {one, one, ""};
    br_endpoints e = {.configured = configured, .nconfigured = 3, .cloud = one, .use_cloud = true, .use_found = true};
    const char *selected[] = {one, "", one, one, two};
    br_results r = nov(d, input, strlen(input), &e); CHECK(r.len == 10);
    for (size_t i = 0; i < r.len; ++i) {
        size_t t = d->type == 1061 ? i % 2 : i / 5, u = d->type == 1061 ? i / 2 : i % 5;
        finding(&r.items[i], d, t ? b : a, text(selected[u]), false, NULL); CHECK(!r.items[i].extra_data);
    }
    br_results_clear(&r);
    r = nov(d, input, strlen(input), NULL); CHECK(r.len == 4); br_results_clear(&r);
    br_endpoints zero = {0}; r = nov(d, input, strlen(input), &zero); CHECK(!r.len); br_results_clear(&r);
    br_scan_ctx ctx = {.endpoints = &zero}; r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!r.len); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s HTTPS://no.hashicorp.cloud https://no.HASHICORP.cloud https://no.hashicorpxcloud", a);
    r = nov(d, input, strlen(input), NULL); CHECK(!r.len); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s https://one.hashicorp.cloud.evil/path", a);
    r = nov(d, input, strlen(input), NULL); CHECK(r.len == 1); finding(&r.items[0], d, a, text(one), false, NULL); br_results_clear(&r);
    static const unsigned char binary[] = "https://x\0y\v\xc2\xa0.hashicorp.cloud:999999/path";
    br_slice base = {binary, sizeof(binary) - 1 - strlen("/path")};
    size_t len = strlen(a); memcpy(input, a, len); input[len++] = ' '; memcpy(input + len, binary, sizeof(binary) - 1); len += sizeof(binary) - 1;
    r = nov(d, input, len, NULL); CHECK(r.len == 1); finding(&r.items[0], d, a, base, false, NULL); br_results_clear(&r);
    /* The 1024 multipart span is an engine hint, not a cap in FromData. */
    size_t n = strlen(a) + 1600 + strlen(one); char *far = malloc(n + 1); CHECK(far);
    memcpy(far, a, strlen(a)); memset(far + strlen(a), ' ', 1600); memcpy(far + strlen(a) + 1600, one, strlen(one) + 1);
    r = nov(d, far, n, NULL); CHECK(r.len == 1); finding(&r.items[0], d, a, text(one), false, NULL); br_results_clear(&r); free(far);
}

/* The backend is explicitly owned, nonblocking, thread-safe and deadline-aware.
 * Assertions stay on the scan thread; worker checks have mutex-protected counts. */
typedef struct {
    pthread_mutex_t mutex;
    expected_request request;
    int status, rc;
    br_slice body;
    const char *read_error, *send_error;
    size_t calls, releases, checks;
    bool destroyed;
    const br_http_request *raw_request;
} fake;
#define BACKEND_CHECK(f, expr) do { ++(f)->checks; if (!(expr)) { fprintf(stderr, "FAIL fake: %s\n", #expr); exit(1); } } while (0)
static int64_t monotonic_ms(void)
{
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void backend_values(fake *f, const br_http_request *r)
{
    const expected_request *e = &f->request;
    BACKEND_CHECK(f, r && r->profile == BR_HTTP_DETECTOR_PUBLIC && r->timeout_ms > 0 && r->timeout_ms <= 10000);
    BACKEND_CHECK(f, r->detector_type == e->type && !strcmp(r->method, "GET") && !strcmp(r->url, e->url));
    BACKEND_CHECK(f, !r->body.data && !r->body.len && r->nheaders == 2);
    BACKEND_CHECK(f, !strcmp(r->headers[0].name, "X-Vault-Token") && !strcmp(r->headers[0].value, e->token));
    BACKEND_CHECK(f, !strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, "TruffleHog vault-offline"));
    char prefix[32]; int n = snprintf(prefix, sizeof(prefix), "%d:", (int)e->type); size_t b = strlen(e->base), t = strlen(e->token);
    BACKEND_CHECK(f, n > 0 && r->dedup_key.len == (size_t)n + b + 1 + t && !memcmp(r->dedup_key.data, prefix, (size_t)n));
    BACKEND_CHECK(f, !memcmp(r->dedup_key.data + n, e->base, b) && r->dedup_key.data[n + b] == ':' && !memcmp(r->dedup_key.data + n + b + 1, e->token, t));
}
static int fake_send(void *opaque, const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    fake *f = opaque; pthread_mutex_lock(&f->mutex);
    BACKEND_CHECK(f, ctx && !ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > monotonic_ms());
    BACKEND_CHECK(f, !f->raw_request && !f->destroyed); backend_values(f, r);
    f->raw_request = r; ++f->calls;
    unsigned char *body = f->body.len ? malloc(f->body.len) : NULL;
    BACKEND_CHECK(f, !f->body.len || body); if (f->body.len) memcpy(body, f->body.data, f->body.len);
    char *read = f->read_error ? strdup(f->read_error) : NULL;
    BACKEND_CHECK(f, !f->read_error || read);
    *response = (br_http_response){.status = f->status, .body = {body, f->body.len}, .body_error = read};
    *error = f->send_error ? strdup(f->send_error) : NULL;
    BACKEND_CHECK(f, !f->send_error || *error);
    int rc = f->rc; pthread_mutex_unlock(&f->mutex); return rc;
}
static void fake_release(void *opaque, br_http_response *r)
{
    fake *f = opaque; pthread_mutex_lock(&f->mutex);
    BACKEND_CHECK(f, f->raw_request && r); backend_values(f, f->raw_request);
    if (r->body.len) memset((void *)r->body.data, '!', r->body.len);
    free((void *)r->body.data); free((void *)r->body_error); f->raw_request = NULL; ++f->releases;
    pthread_mutex_unlock(&f->mutex);
}
static void fake_destroy(void *opaque)
{
    fake *f = opaque; pthread_mutex_lock(&f->mutex);
    CHECK(!f->raw_request && f->calls == f->releases && !f->destroyed);
    f->destroyed = true; test_assertions += f->checks;
    pthread_mutex_unlock(&f->mutex); CHECK(!pthread_mutex_destroy(&f->mutex));
}
static br_http_client *client_init(fake *f)
{
    CHECK(!pthread_mutex_init(&f->mutex, NULL));
    br_http_owned_backend backend = {.transport = {f, fake_send, fake_release}, .destroy = fake_destroy};
    br_http_client *c = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&c, backend, BR_HTTP_DETECTOR_PUBLIC, &error) && c && !error);
    return c;
}
static void client_destroy(br_http_client *c, fake *f)
{
    char *error = NULL; CHECK(!br_http_client_drain(c, &error) && !error);
    br_http_client_destroy(c); CHECK(f->destroyed);
}
static int invoke(const br_detector *d, br_http_client *client, fake *f, const char *base,
                  const char *url, const char *key, br_results *out, char **error)
{
    expected = (expected_request){key, base, url, d->type};
    pthread_mutex_lock(&f->mutex); f->request = expected; pthread_mutex_unlock(&f->mutex);
    const char *configured[] = {base}; br_endpoints e = {.configured = configured, .nconfigured = 1};
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .endpoints = &e, .user_agent = "vault-offline"};
    size_t calls = sends, closes = releases;
    int rc = d->scan(d, &ctx, true, text(key), out, error);
    CHECK(!provider_request && sends - calls == releases - closes);
    pthread_mutex_lock(&f->mutex); CHECK(f->calls == f->releases && !f->raw_request); pthread_mutex_unlock(&f->mutex);
    return rc;
}
static br_results response(const br_detector *d, br_http_client *client, fake *f, const char *key,
                           int status, br_slice body, const char *read, int rc, const char *cause)
{
    pthread_mutex_lock(&f->mutex); f->status = status; f->body = body; f->read_error = read; f->rc = rc; f->send_error = cause; pthread_mutex_unlock(&f->mutex);
    br_results r = {0}; char *error = NULL; size_t calls = sends, set = setters;
    int result = invoke(d, client, f, origin, lookup, key, &r, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(!result && !error && r.len == 1 && sends == calls + 1 && setters == set + 1);
    return r;
}
static void verification(const br_detector *d, br_http_client *client, fake *f)
{
    const char *key = d->type == 1061 ? batch1 : service1;
    const int statuses[] = {200, 401, 403, 199, 201, 204, 299, 302, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char cause[80]; const char *error = NULL;
        if (i > 2) { snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]); error = cause; }
        br_results r = response(d, client, f, key, statuses[i], TEXT("{}"), NULL, 0, NULL);
        finding(&r.items[0], d, key, text(origin), i == 0, error);
        if (!i) metadata(&r.items[0], TEXT(""), "false", "false", TEXT(""), TEXT("")); else CHECK(!r.items[0].extra_data);
        br_results_clear(&r);
    }
    char whole[700], sanitized[300];
    snprintf(whole, sizeof(whole), "whole Do failure %s at %s repeats %s", key, origin, key);
    snprintf(sanitized, sizeof(sanitized), "whole Do failure [REDACTED] at %s repeats [REDACTED]", origin);
    br_results r = response(d, client, f, key, 200, TEXT("{}"), NULL, 1, whole);
    finding(&r.items[0], d, key, text(origin), false, sanitized); CHECK(!r.items[0].extra_data); br_results_clear(&r);
    /* Owned ReadAll errors win over status, complete JSON and an empty cause. */
    for (size_t i = 0; i < 3; ++i) {
        const char *read = i == 2 ? "" : whole;
        r = response(d, client, f, key, i == 1 ? 401 : 200, TEXT("{} trailing"), read, 0, NULL);
        finding(&r.items[0], d, key, text(origin), false, i == 2 ? "" : sanitized); CHECK(!r.items[0].extra_data); br_results_clear(&r);
    }
    r = response(d, client, f, key, 200, TEXT("{}"), NULL, 1, "unexpected HTTP response status 403");
    finding(&r.items[0], d, key, text(origin), false, "unexpected HTTP response status 403"); br_results_clear(&r);
}
static void typed_json(const br_detector *d, br_http_client *client, fake *f)
{
    const char *key = d->type == 1061 ? batch1 : service1;
    const char *zeros[] = {"null", "{}", "{\"data\":null}", "{\"data\":{}}", "{} trailing invalid", "{} {}"};
    for (size_t i = 0; i < sizeof(zeros) / sizeof(zeros[0]); ++i) {
        br_results r = response(d, client, f, key, 200, text(zeros[i]), NULL, 0, NULL);
        finding(&r.items[0], d, key, text(origin), true, NULL); metadata(&r.items[0], TEXT(""), "false", "false", TEXT(""), TEXT("")); br_results_clear(&r);
    }
    const struct { const char *json, *policies, *orphan, *renewable, *type, *entity; } good[] = {
        {"{\"data\":{\"display_name\":\"name\",\"expire_time\":\"expiry\",\"entity_id\":\"entity\",\"type\":\"service\",\"orphan\":true,\"renewable\":false,\"policies\":[\"default\",\"synthetic\"]}}", "default, synthetic", "true", "false", "service", "entity"},
        {"{\"data\":{\"entity_id\":\"first\",\"type\":\"old\",\"orphan\":true,\"policies\":[\"old0\",\"old1\",\"old2\"]},\"data\":null,\"DATA\":{\"entity_id\":null,\"type\":\"new\",\"orphan\":null,\"renewable\":true,\"policies\":[null],\"policies\":[null,null,null]}}", "old0, old1, old2", "true", "true", "new", "first"},
        {"{\"data\":{\"policies\":[\"a\",\"b\",\"c\",\"d\"],\"policies\":[\"x\"],\"policies\":[null,null,null,null,null]}}", "x, b, c, d, ", "false", "false", "", ""},
        {"{\"data\":{\"policies\":[\"a\",\"b\"],\"policies\":[],\"policies\":[null,null]}}", ", ", "false", "false", "", ""},
        {"{\"data\":{\"policies\":[\"a\",\"b\"],\"policies\":null,\"policies\":[null,null]}}", ", ", "false", "false", "", ""},
        {"{\"unknown\":1e999999,\"data\":{\"unknown\":99999999999999999999999999999999999999999999,\"TYPE\":\"batch\",\"policie\\u017f\":[\"p\"]}}", "p", "false", "false", "batch", ""},
    };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        br_results r = response(d, client, f, key, 200, text(good[i].json), NULL, 0, NULL);
        finding(&r.items[0], d, key, text(origin), true, NULL);
        metadata(&r.items[0], text(good[i].policies), good[i].orphan, good[i].renewable, text(good[i].type), text(good[i].entity)); br_results_clear(&r);
    }
    br_results r = response(d, client, f, key, 200, TEXT("{\"data\":{\"entity_id\":\"a\\u0000b\",\"type\":\"\xff\",\"policies\":[\"a\\u0000b\",null]}}"), NULL, 0, NULL);
    finding(&r.items[0], d, key, text(origin), true, NULL);
    metadata(&r.items[0], TEXT("a\0b, "), "false", "false", TEXT("\xef\xbf\xbd"), TEXT("a\0b")); br_results_clear(&r);
    const struct { const char *json, *cause; } bad[] = {
        {"", "EOF"}, {"{", "unexpected EOF"}, {"[]", "json: cannot unmarshal array into Go value of type hashicorpvault.LookupResponse"},
        {"{\"data\":{\"display_name\":1,\"display_name\":\"later\"}}", "json: cannot unmarshal number into Go struct field .Data.display_name of type string"},
        {"{\"data\":{\"entity_id\":false}}", "json: cannot unmarshal bool into Go struct field .Data.entity_id of type string"},
        {"{\"data\":{\"expire_time\":[]}}", "json: cannot unmarshal array into Go struct field .Data.expire_time of type string"},
        {"{\"data\":{\"type\":{}}}", "json: cannot unmarshal object into Go struct field .Data.type of type string"},
        {"{\"data\":{\"orphan\":\"true\"}}", "json: cannot unmarshal string into Go struct field .Data.orphan of type bool"},
        {"{\"data\":{\"renewable\":0}}", "json: cannot unmarshal number into Go struct field .Data.renewable of type bool"},
        {"{\"data\":{\"policies\":\"default\"}}", "json: cannot unmarshal string into Go struct field .Data.policies of type []string"},
        {"{\"data\":{\"policies\":[\"a\",false,null]}}", "json: cannot unmarshal bool into Go struct field .Data.policies of type string"},
        {"{\"data\":[]}", "json: cannot unmarshal array into Go struct field LookupResponse.Data of type struct { DisplayName string \"json:\\\"display_name\\\"\"; EntityId string \"json:\\\"entity_id\\\"\"; ExpireTime string \"json:\\\"expire_time\\\"\"; Orphan bool \"json:\\\"orphan\\\"\"; Policies []string \"json:\\\"policies\\\"\"; Renewable bool \"json:\\\"renewable\\\"\"; Type string \"json:\\\"type\\\"\" }"},
        {"{\"data\":{\"expire_time\":false},\"data\":null,\"data\":{\"expire_time\":\"fixed\",\"orphan\":2}}", "json: cannot unmarshal bool into Go struct field .Data.expire_time of type string"},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        r = response(d, client, f, key, 200, text(bad[i].json), NULL, 0, NULL);
        finding(&r.items[0], d, key, text(origin), false, bad[i].cause); CHECK(!r.items[0].extra_data); br_results_clear(&r);
    }
}
static void url_paths(const br_detector *d, br_http_client *client, fake *f)
{
    const char *key = d->type == 1061 ? batch1 : service1;
    const struct { const char *base, *url; } paths[] = {
        {"https://synthetic.invalid/team//./x/../", "https://synthetic.invalid/team/v1/auth/token/lookup-self"},
        {"http://UPPER.invalid:999999999999/../../root/../_~/", "http://UPPER.invalid:999999999999/_~/v1/auth/token/lookup-self"},
        {"https://../a/../../b/./c//", "https://../b/c/v1/auth/token/lookup-self"},
        {"https://synthetic.invalid/v1/auth/token/lookup-self", "https://synthetic.invalid/v1/auth/token/lookup-self/v1/auth/token/lookup-self"},
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        pthread_mutex_lock(&f->mutex); f->status = 401; f->body = TEXT("ignored"); f->rc = 0; f->read_error = f->send_error = NULL; pthread_mutex_unlock(&f->mutex);
        br_results r = {0}; char *error = NULL;
        CHECK(!invoke(d, client, f, paths[i].base, paths[i].url, key, &r, &error) && !error && r.len == 1);
        finding(&r.items[0], d, key, text(paths[i].base), false, NULL); br_results_clear(&r);
    }
    /* No arbitrary URL cap; no DNS or numeric-port-range validation. */
    size_t n = strlen(origin), capacity = n + 2250;
    char *base = malloc(n + 2200), *url = malloc(capacity); CHECK(base && url);
    memcpy(base, origin, n); base[n++] = '/'; memset(base + n, 'a', 2100); base[n + 2100] = 0;
    snprintf(url, capacity, "%s/v1/auth/token/lookup-self", base);
    br_results r = {0}; char *error = NULL; CHECK(!invoke(d, client, f, base, url, key, &r, &error) && !error && r.len == 1);
    finding(&r.items[0], d, key, text(base), false, NULL); br_results_clear(&r); free(base); free(url);
}
static void unsupported_and_guard(const br_detector *d)
{
    const char *key = d->type == 1061 ? batch1 : service1;
    const char *configured[] = {origin}; br_endpoints e = {.configured = configured, .nconfigured = 1};
    test_http http = {0}; br_transport borrowed = test_transport(&http);
    br_scan_ctx ctx = {.endpoints = &e, .transport = &borrowed};
    expected = (expected_request){key, origin, lookup, d->type};
    br_results r = test_scan(d, &ctx, true, key, strlen(key)); CHECK(r.len == 1 && !http.calls && http.releases == 1);
    finding(&r.items[0], d, key, text(origin), false, "unsupported HTTP request coalescing"); br_results_clear(&r);
    ctx.transport = NULL; r = test_scan(d, &ctx, true, key, strlen(key)); CHECK(r.len == 1);
    finding(&r.items[0], d, key, text(origin), false, "HTTP transport not installed"); br_results_clear(&r);
    char input[600]; const char *found = "https://one.hashicorp.cloud";
    snprintf(input, sizeof(input), "%s %s/path", key, found);
    size_t calls = sends; r = test_scan(d, NULL, true, input, strlen(input)); CHECK(r.len == 1 && sends == calls);
    finding(&r.items[0], d, key, text(found), false, "net/http: nil Context"); CHECK(!r.items[0].extra_data); br_results_clear(&r);
    const char *bad[] = {"", "https://synthetic.invalid?query", "https://synthetic.invalid/%2e", "https://u@synthetic.invalid", "https://synthetic.invalid:", "https://synthetic.invalid/\v"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        configured[0] = bad[i];
        r = nov(d, key, strlen(key), &e); CHECK(r.len == 1); finding(&r.items[0], d, key, text(bad[i]), false, NULL); br_results_clear(&r);
        char *error = NULL; CHECK(d->scan(d, &ctx, true, text(key), &r, &error) == -1 && error && !r.len && sends == calls);
        CHECK(!strcmp(error, "unsupported Vault endpoint URL form at JoinPath")); free(error); br_results_clear(&r);
    }
    /* Unsupported transformation wins before nil context, not a mock-text URL error. */
    snprintf(input, sizeof(input), "%s https://x\vy.hashicorp.cloud/path", key);
    char *error = NULL; CHECK(d->scan(d, NULL, true, text(input), &r, &error) == -1 && error && !r.len && sends == calls); free(error);
}
static void resource_failures(const br_detector *d, br_http_client *client, fake *f)
{
    const char *key = d->type == 1061 ? batch1 : service1;
    br_results out = {0}; br_result sentinel = {.detector_type = 777, .verified = true};
    sentinel.raw.data = (unsigned char *)strdup("prior"); sentinel.raw.len = 5; sentinel.verification_error = strdup("caller-owned");
    CHECK(sentinel.raw.data && sentinel.verification_error && !br_results_push(&out, &sentinel)); sentinel = out.items[0];
    const fault_kind cases[] = {CAPTURE, ENDPOINTS, FINDING, ALLOCATION, DOCUMENT, MEMBER, ELEMENT, POLICY_GROWTH, RETAIN, MAP, METADATA, SETTER, PUSH, CAUSE, TYPE_CAUSE};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        pthread_mutex_lock(&f->mutex); f->status = cases[i] == CAUSE ? 500 : 200; f->rc = 0; f->read_error = f->send_error = NULL;
        f->body = cases[i] == TYPE_CAUSE ? TEXT("{\"data\":{\"orphan\":1}}") : TEXT("{\"data\":{\"policies\":[\"a\",\"b\"],\"entity_id\":\"entity\"}}"); pthread_mutex_unlock(&f->mutex);
        fault = cases[i]; fail_nth = 1; fail_size = 12;
        char *error = NULL; int rc = invoke(d, client, f, origin, lookup, key, &out, &error);
        CHECK(rc == -1 && fault == NONE); /* Includes positive helper/setter failures. */
        CHECK(out.len == 1 && out.items[0].raw.data == sentinel.raw.data && out.items[0].verification_error == sentinel.verification_error && out.items[0].verified && out.items[0].detector_type == 777);
        CHECK(!memcmp(out.items[0].raw.data, "prior", 5) && !strcmp(out.items[0].verification_error, "caller-owned")); free(error);
    }
    /* Distinct provider-owned URL, complete-key and policy-assembly allocations. */
    const struct { size_t size; const char *message; } allocations[] = {
        {strlen(origin) + sizeof("/v1/auth/token/lookup-self") + 1, "cannot allocate Vault lookup URL"},
        {5 + strlen(origin) + 1 + strlen(key), "cannot allocate Vault request key"},
        {sizeof("a, b"), "cannot project Vault metadata"},
    };
    pthread_mutex_lock(&f->mutex); f->status = 200; f->body = TEXT("{\"data\":{\"policies\":[\"a\",\"b\"]}}"); pthread_mutex_unlock(&f->mutex);
    for (size_t i = 0; i < sizeof(allocations) / sizeof(allocations[0]); ++i) {
        fault = ALLOCATION; fail_nth = 1; fail_size = allocations[i].size;
        char *error = NULL;
        CHECK(invoke(d, client, f, origin, lookup, key, &out, &error) == -1 && error && fault == NONE && !strcmp(error, allocations[i].message));
        CHECK(out.len == 1 && out.items[0].raw.data == sentinel.raw.data); free(error);
    }
    /* Fatal retention still wins AFTER an ordinary typed error, proving that
     * source visitation is not short-circuited when the first cause is saved. */
    pthread_mutex_lock(&f->mutex); f->status = 200; f->body = TEXT("{\"data\":{\"display_name\":1,\"entity_id\":\"late\"}}"); pthread_mutex_unlock(&f->mutex);
    fault = RETAIN; fail_nth = 1; char *error = NULL; size_t set = setters;
    CHECK(invoke(d, client, f, origin, lookup, key, &out, &error) == -1 && error && fault == NONE && setters == set && out.len == 1); free(error);
    /* Roll back an already-published invocation finding, not the caller's. */
    const char *configured[] = {origin, "https://synthetic.invalid?unsupported"}; br_endpoints e = {.configured = configured, .nconfigured = 2};
    br_scan_ctx ctx = {.endpoints = &e}; error = NULL;
    CHECK(d->scan(d, &ctx, true, text(key), &out, &error) == -1 && error && out.len == 1 && out.items[0].raw.data == sentinel.raw.data); free(error);
    /* A later push failure rolls back only this invocation's first finding. */
    fault = PUSH; fail_nth = 2; error = NULL;
    CHECK(d->scan(d, &ctx, false, text(key), &out, &error) == -1 && error && fault == NONE && out.len == 1 && out.items[0].raw.data == sentinel.raw.data); free(error);
    /* URL allocation must be attempted before nil-context's ordinary outcome. */
    char input[600]; snprintf(input, sizeof(input), "%s https://one.hashicorp.cloud", key);
    fault = ALLOCATION; fail_nth = 1; fail_size = strlen("https://one.hashicorp.cloud") + sizeof("/v1/auth/token/lookup-self") + 1; error = NULL;
    CHECK(d->scan(d, NULL, true, text(input), &out, &error) == -1 && error && fault == NONE && out.len == 1); free(error);
    br_results_clear(&out);
}
static void status_format_failure(const br_detector *d, br_http_client *client, fake *f)
{
    br_results out = {0}; br_result sentinel = {.detector_type = 777, .verified = true};
    sentinel.raw.data = (unsigned char *)strdup("prior"); sentinel.raw.len = 5; sentinel.verification_error = strdup("caller-owned");
    CHECK(sentinel.raw.data && sentinel.verification_error && !br_results_push(&out, &sentinel)); sentinel = out.items[0];
    pthread_mutex_lock(&f->mutex);
    f->status = 500; f->body = TEXT("{}"); f->rc = 0; f->read_error = f->send_error = NULL;
    size_t backend_calls = f->calls, backend_releases = f->releases;
    pthread_mutex_unlock(&f->mutex);
    size_t calls = sends, closes = releases, set = setters;
    fault = STATUS_FORMAT; fail_nth = 1; char *error = NULL;
    CHECK(invoke(d, client, f, origin, lookup, batch1, &out, &error) == -1 && error && fault == NONE);
    CHECK(!strcmp(error, "cannot format Vault HTTP status") && sends == calls + 1 && releases == closes + 1 && setters == set);
    CHECK(out.len == 1 && out.items[0].raw.data == sentinel.raw.data && out.items[0].verification_error == sentinel.verification_error);
    CHECK(out.items[0].detector_type == 777 && out.items[0].verified && out.items[0].raw.len == 5 && !memcmp(out.items[0].raw.data, "prior", 5) && !strcmp(out.items[0].verification_error, "caller-owned"));
    pthread_mutex_lock(&f->mutex); CHECK(f->calls == backend_calls + 1 && f->releases == backend_releases + 1); pthread_mutex_unlock(&f->mutex);
    free(error); br_results_clear(&out);
}
int main(void)
{
    token(batch1, "hvb.", 50, 0); token(batch2, "hvb.", 70, 7);
    token(service1, "hvs.", 90, 0); token(legacy, "s.", 18, 9);
    const br_detector *batch = descriptor(true), *service = descriptor(false);
    grammar(batch); grammar(service); endpoints(batch); endpoints(service);
    fake backends[2] = {0}; br_http_client *clients[2] = {client_init(&backends[0]), client_init(&backends[1])};
    CHECK(clients[0] != clients[1] && br_http_client_transport(clients[0]) != br_http_client_transport(clients[1]));
    const br_detector *detectors[] = {batch, service};
    for (size_t i = 0; i < 2; ++i) {
        verification(detectors[i], clients[i], &backends[i]); typed_json(detectors[i], clients[i], &backends[i]);
        url_paths(detectors[i], clients[i], &backends[i]); unsupported_and_guard(detectors[i]); resource_failures(detectors[i], clients[i], &backends[i]);
    }
    status_format_failure(batch, clients[0], &backends[0]);
    client_destroy(clients[0], &backends[0]); client_destroy(clients[1], &backends[1]);
    CHECK(!provider_request && sends == releases && fault == NONE);
    return test_finish("HashiCorp Vault batch/service TOKEN extraction/endpoints/owned PUBLIC10/typed JSON/resources");
}
