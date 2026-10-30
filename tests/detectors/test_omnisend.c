/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>

int br_omnisend_init(const br_detector **out, char **error);

/* Established named-test seams observe original provider frames, never retain
 * synthesized ordinary request/header-array/UA storage after send returns. */
#define br_http_send omnisend_real_send
#define br_http_release omnisend_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#define br_results_push omnisend_real_push
#define br_result_set_verification_error omnisend_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[76], other[76];
static const char endpoint[] = "https://api.omnisend.com/v3/contacts?limit=100&offset=0";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_request_after, fail_push_after, setter_calls;
static bool fail_next_malloc;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false; ++failed_allocations; return NULL;
    }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t n = strlen(value) + 1; char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key") && fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
    return rc;
}
int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return omnisend_real_push(out, owned);
}
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; return omnisend_real_setter(result, cause, secrets, count);
}
static const br_detector *descriptor(void)
{
    test_secret(key, 75, 0); key[5] = 'Q'; key[19] = 'Y';
    test_secret(other, 75, 7); other[10] = 'Z'; other[38] = '-';
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 75 && strlen(other) == 75);
    CHECK(br_omnisend_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Omnisend detector output")); free(error); error = NULL;
    CHECK(br_omnisend_init(NULL, NULL) == -1);
    /* No opaque regex-owner size, current or historical. */
    fail_next_malloc = true;
    CHECK(br_omnisend_init(&d, &error) == -1 && !d && error && !fail_next_malloc); free(error); error = NULL;
    CHECK(br_omnisend_init(&d, &error) == 0 && d && !error);
    CHECK(br_omnisend_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 205 && d->version == 0 && !strcmp(d->name, "Omnisend") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Omnisend is a marketing automation platform focused on e-commerce. Omnisend API keys can be used to access and manage marketing campaigns, contacts, and other resources within the Omnisend platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "omnisend"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}
static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 205, expected, "key"); CHECK(r->raw.len == 75 && r->verified == verified && !r->verification_error);
}
static void extraction_case(const br_detector *d, const void *input, size_t length, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, false, input, length);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[350], changed[77];
    snprintf(input, sizeof(input), "omnisend '%s'", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preOmNiSeNdSuffix:\r\n%s", other); extraction_case(d, input, strlen(input), other);
    extraction_case(d, key, strlen(key), NULL); extraction_case(d, NULL, 0, NULL);
    memcpy(changed, key, sizeof(key)); changed[74] = '\0'; snprintf(input, sizeof(input), "omnisend %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 75); changed[75] = 'A'; changed[76] = '\0'; snprintf(input, sizeof(input), "omnisend %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[20] = '_'; snprintf(input, sizeof(input), "omnisend %s", changed); extraction_case(d, input, strlen(input), NULL);
    changed[20] = '-'; snprintf(input, sizeof(input), "omnisend %s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "omnisend _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "omnisend %s_", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "omnisend \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    /* Full source boundaries, NOT forced alphanumeric capture endpoints. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-'; snprintf(input, sizeof(input), "omnisend X%s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "omnisend '%s'", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[74] = '-'; snprintf(input, sizeof(input), "omnisend '%sZ", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "omnisend '%s'", changed); extraction_case(d, input, strlen(input), NULL);
    memset(changed, '-', 75); changed[75] = '\0'; snprintf(input, sizeof(input), "omnisend X%sZ", changed); extraction_case(d, input, strlen(input), changed);
    memset(changed, '0', 75); snprintf(input, sizeof(input), "omnisend %s", changed); extraction_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "omnisend", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key, sizeof(key));
        extraction_case(d, input, 8 + gap + 75, gap == 40 ? key : NULL);
        size_t at = 8; for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, sizeof(key)); extraction_case(d, input, at + 75, gap == 40 ? key : NULL);
    }
    memcpy(input, "omnisend", 8); input[8] = '\0'; input[9] = '\r'; input[10] = '\n'; memcpy(input + 11, key, sizeof(key)); extraction_case(d, input, 86, key);
    snprintf(input, sizeof(input), "omnisend %s %s", key, key); extraction_case(d, input, strlen(input), key); /* Nonoverlap, not dedup. */
    char repeated[1300]; size_t at = 0;
    for (size_t i = 0; i < 12; ++i) at += (size_t)snprintf(repeated + at, sizeof(repeated) - at, "omnisend %s\n", i % 2 ? other : key);
    br_results out = test_scan(d, NULL, false, repeated, at); CHECK(out.len == 12);
    for (size_t i = 0; i < out.len; ++i) finding(&out.items[i], i % 2 ? other : key, false);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, repeated, at); CHECK(!out.len); br_results_clear(&out);
    fail_request_after = 1; snprintf(input, sizeof(input), "omnisend %s", key);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len && !fail_request_after && fail_next_malloc);
    fail_next_malloc = false; br_results_clear(&out); /* Header/request allocation is unreached after nil. */
}

static struct {
    bool active, closing; const br_scan_ctx *ctx; br_results *out; const char *const *keys;
    size_t count, base, release_len, sends, releases, next_deferred;
    const br_http_request *requests[3]; br_http_response *responses[3]; bool ok[3], released[3];
} observed;
static void request_is(const br_http_request *r, const char *expected, bool prepared, const br_scan_ctx *ctx)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, endpoint) && r->detector_type == 205 && r->profile == BR_HTTP_SANE);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (prepared ? 2u : 1u) && !strcmp(r->headers[0].name, "X-Api-Key") && !strcmp(r->headers[0].value, expected));
    CHECK(strlen(r->headers[0].value) == 75 && r->timeout_ms == (prepared ? 5000u : 0u));
    if (prepared) CHECK(ctx && !strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, ctx->user_agent ? "TruffleHog omnisend-test" : "TruffleHog"));
}
static void originals_live(void)
{
    for (size_t i = 0; i < observed.sends; ++i) if (!observed.released[i]) request_is(observed.requests[i], observed.keys[i], false, observed.ctx);
}
static void observe(const br_scan_ctx *ctx, br_results *out, const char *const *keys, size_t count, size_t release_len)
{
    memset(&observed, 0, sizeof(observed)); observed.active = true; observed.ctx = ctx; observed.out = out; observed.keys = keys;
    observed.count = count; observed.base = out->len; observed.release_len = release_len;
}
int br_http_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    size_t i = observed.sends; CHECK(observed.active && ctx == observed.ctx && i < observed.count && observed.count <= 3 && !observed.closing);
    CHECK(observed.out->len == observed.base + i); originals_live(); request_is(request, observed.keys[i], false, ctx);
    observed.requests[i] = request; observed.responses[i] = response; ++observed.sends;
    int rc = omnisend_real_send(ctx, request, response, error); observed.ok[i] = rc == 0;
    originals_live(); return rc;
}
void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t i = 0; while (i < observed.sends && (observed.responses[i] != response || observed.released[i])) ++i;
    CHECK(observed.active && ctx == observed.ctx && i < observed.sends); originals_live();
    if (observed.ok[i]) {
        if (!observed.closing) { observed.closing = true; observed.next_deferred = observed.sends; }
        while (observed.next_deferred && !observed.ok[observed.next_deferred - 1]) --observed.next_deferred;
        CHECK(observed.next_deferred && --observed.next_deferred == i && observed.out->len == observed.release_len);
    } else CHECK(!observed.closing && i + 1 == observed.sends && observed.out->len == observed.base + i);
    omnisend_real_release(ctx, response); originals_live(); observed.released[i] = true; ++observed.releases;
}
typedef struct { test_http http; const int *codes; } wire;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire *w = http->user; size_t i = http->calls - 1;
    CHECK(ctx == observed.ctx && i < observed.count); request_is(request, observed.keys[i], true, ctx);
    if (w->codes) http->send_rc = w->codes[i];
}
static void release_reply(void *user, br_http_response *response) { test_http_release(user, response); }
static int scan_into(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *input, br_results *out, char **error)
{
    int rc = d->scan(d, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, error);
    CHECK(observed.sends == observed.releases); observed.active = false; return rc;
}
static void verification(const br_detector *d)
{
    const char *keys[] = {key}; char input[100]; snprintf(input, sizeof(input), "omnisend %s", key);
    const int statuses[] = {INT_MIN,-1,0,199,200,201,204,206,250,299,300,301,401,403,500,INT_MAX};
    static const unsigned char body[] = "\0\xff not JSON";
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        wire w = {.http = {.response = {.status = statuses[i], .body = {body, sizeof(body) - 1}, .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored read error"}}};
        w.http.inspect = inspect; w.http.user = &w; br_transport transport = {&w.http, test_http_send, release_reply}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "omnisend-test"};
        br_results out = {0}; char *error = NULL; observe(&ctx, &out, keys, 1, 1); CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error);
        CHECK(out.len == 1 && observed.sends == 1 && w.http.calls == 1 && w.http.releases == 1); finding(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *causes[] = {"synthetic Do failure", "out of memory constructing HTTP headers", "cannot create Omnisend request", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        wire w = {.http = {.send_rc = i % 2 ? 1 : -7, .send_error = causes[i], .response = {.status = 200, .body_error = "ignored"}}};
        w.http.inspect = inspect; w.http.user = &w; br_transport transport = {&w.http, test_http_send, release_reply}; br_scan_ctx ctx = {.transport = &transport};
        br_results out = {0}; char *error = NULL; observe(&ctx, &out, keys, 1, 1); CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error);
        CHECK(out.len == 1 && w.http.calls == 1 && w.http.releases == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *many[] = {key, other, key}; const int mixed[] = {0,1,0}; char repeated[300];
    snprintf(repeated, sizeof(repeated), "omnisend %s\nomnisend %s\nomnisend %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        wire w = {.codes = mode == 2 ? mixed : NULL, .http = {.send_rc = mode == 1 ? 1 : 0, .send_error = "synthetic mixed Do", .response = {.status = mode == 0 ? 401 : 204, .body_error = ""}}};
        w.http.inspect = inspect; w.http.user = &w; br_transport transport = {&w.http, test_http_send, release_reply}; br_scan_ctx ctx = {.transport = &transport};
        br_results out = {0}; char *error = NULL; observe(&ctx, &out, many, 3, 3); CHECK(!scan_into(d, &ctx, true, repeated, &out, &error) && !error);
        CHECK(out.len == 3 && w.http.calls == 3 && w.http.releases == 3);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], many[i], mode == 2 && !mixed[i]);
        br_results_clear(&out);
    }
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_next_malloc = true; return false; }
static void preparation(const br_detector *d)
{
    const char *keys[] = {key}; char input[100]; snprintf(input, sizeof(input), "omnisend %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = {&http, test_http_send, test_http_release};
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "bad\r\nagent" : NULL};
        br_results out = {0}; char *error = NULL; size_t failures = failed_allocations; observe(&ctx, &out, keys, 1, 1);
        CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error && out.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u));
        CHECK(!fail_next_malloc && failed_allocations == failures + (mode == 4)); finding(&out.items[0], key, false); br_results_clear(&out);
    }
}
static br_results caller_owned(void)
{
    br_results out = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 17, "keep", "key")); prior.verified = true;
    prior.verification_error = strdup("caller diagnostic"); CHECK(prior.verification_error && !br_results_push(&out, &prior)); return out;
}
static void preserved(br_results *out, unsigned char *raw, br_json *parts, char *cause, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "keep", "key");
    CHECK(out->items[0].verified && out->items[0].raw.data == raw && out->items[0].secret_parts == parts && out->items[0].verification_error == cause && !strcmp(cause, "caller diagnostic"));
    free(error); br_results_clear(out);
}
static void owned_failures(const br_detector *d)
{
    const char *keys[] = {key, other}; char input[200]; snprintf(input, sizeof(input), "omnisend %s\nomnisend %s", key, other);
    for (int mode = 0; mode < 8; ++mode) {
        wire w = {.http = {.response = {.status = 200}}}; w.http.inspect = inspect; w.http.user = &w;
        br_transport transport = {&w.http, test_http_send, release_reply}; br_scan_ctx ctx = {.transport = &transport};
        br_results out = caller_owned(); unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts; char *cause = out.items[0].verification_error, *error = NULL;
        if (mode == 0) fail_next_malloc = true;
        else if (mode == 1) { fail_size = 75; fail_after = 1; }
        else if (mode >= 2 && mode <= 4) fail_part_after = 2;
        else if (mode == 5 || mode == 6) fail_request_after = mode == 5 ? 1u : 2u;
        else fail_push_after = 2;
        const br_scan_ctx *scan_ctx = mode == 3 || mode == 4 ? NULL : &ctx;
        observe(scan_ctx, &out, keys, 2, 2);
        int rc = scan_into(d, scan_ctx, mode != 3, input, &out, &error);
        CHECK(!fail_next_malloc && !fail_after && !fail_part_after && !fail_request_after && !fail_push_after);
        CHECK(observed.sends == (mode == 2 || mode == 6 ? 1u : mode == 7 ? 2u : 0u));
        preserved(&out, raw, parts, cause, rc, error);
    }
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); verification(d); preparation(d); owned_failures(d);
    CHECK(!setter_calls && !observed.active && !fail_after && !fail_part_after && !fail_request_after && !fail_push_after && !fail_next_malloc);
    return test_finish("Omnisend full hyphen boundaries, SANE body-ignore, scan-LIFO frames and owned rollback");
}
