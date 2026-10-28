/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[47], b[47], c[47]; /* Synthetic, byte-distinct tokens. */
static const char guide[] = "https://howtorotate.com/docs/tutorials/flexport/";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_guide_after, guides_added;
static const char *fail_duplicate, *watch_duplicate;
static size_t fail_duplicate_after, watched_copies;

/* Actual allocation/JSON APIs only, never a Bearer formatting-failure seam. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(value, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) { memcpy(copy, value, size); if (watch_duplicate && !strcmp(value, watch_duplicate)) ++watched_copies; }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    bool rotation = !strcmp(name, "rotation_guide");
    if (rotation && fail_guide_after && --fail_guide_after == 0) return 1;
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && rotation) ++guides_added;
    return rc;
}
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 46 && strlen(b) == 46 && strlen(c) == 46);
    CHECK(br_flexport_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_flexport_init(&d, &error) == 0 && d && !error);
    CHECK(br_flexport_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 1009 && d->version == 0 && !strcmp(d->name, "Flexport") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Flexport is a global logistics company that provides shipping, freight forwarding, and supply chain management services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "shltm_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified, const char *cause)
{
    br_result base = *r; base.extra_data = NULL; /* Check the shared key-only fields separately from the required guide. */
    test_key_result(&base, 1009, expected, "key"); CHECK(r->raw.len == 46 && r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
    br_json *value = NULL;
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
    CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &value) && json_object_is_type(value, json_type_string));
    CHECK(!strcmp(json_object_get_string(value), guide));
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    size_t before = guides_added; br_results out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && guides_added == before + out.len);
    if (expected) result(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[192], changed[47]; extract_case(d, a, a); /* Neither a provider-name prefix nor an end boundary is required. */
    const char *good[] = {"'%s'", "flexport %s", "-%s", "%sLONGER_payload-0123", "%s_", "%s!"};
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        snprintf(input, sizeof(input), good[i], a); extract_case(d, input, a);
    }
    const char *bad[] = {"x%s", "_%s", "flexport %.45s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], a); extract_case(d, input, NULL);
    }
    memcpy(changed, a, sizeof(a)); memcpy(changed, "SHLTM_", 6); extract_case(d, changed, NULL);
    memcpy(changed, a, sizeof(a)); changed[0] = 'S'; extract_case(d, changed, NULL);
    const char invalid[] = {'.', '+', '/', '[', '^'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[20] = invalid[i]; extract_case(d, changed, NULL);
    }
    memcpy(changed, "shltm_", 6); memset(changed + 6, '0', 40); changed[46] = '\0'; extract_case(d, changed, changed);
    extract_case(d, "flexport", NULL);
    /* a ends in '-' (nonword): adjacent tokens need NO consumed delimiter. */
    snprintf(input, sizeof(input), "%s%s", a, b); br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    result(&out.items[0], a, false, NULL); result(&out.items[1], b, false, NULL);
    CHECK(out.items[0].extra_data != out.items[1].extra_data); br_results_clear(&out);
}

typedef struct {
    const char *key; int status, rc; const char *send_error, *read_error, *cause;
    bool verified, copy_fails, fail_redaction;
} reply;
typedef struct {
    const reply *rows; size_t count, guide_start; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; char expected_auth[54]; char *transport_storage;
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(guides_added == s->guide_start + http->calls); /* Guide exists BEFORE verification. */
    CHECK(request->detector_type == 1009 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://logistics-api.flexport.com/logistics/api/2024-04/webhooks"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[1].name, "User-Agent"));
    memcpy(s->expected_auth, "Bearer ", 7); memcpy(s->expected_auth + 7, row->key, 47);
    CHECK(strlen(request->headers[0].value) == 53 && !memcmp(request->headers[0].value, s->expected_auth, 54));
    CHECK(!strcmp(request->headers[1].value, s->suffix ? "TruffleHog flexport-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[0].value;
    static const unsigned char ignored_body[] = "\0\xffmalformed \"error\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
    if (row->fail_redaction) { fail_size = sizeof("[REDACTED]"); fail_after = 1; }
}
static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    test_http *http = user; script *s = http->user;
    int rc = test_http_send(user, ctx, request, response, error);
    const reply *row = &s->rows[http->calls - 1]; s->transport_storage = *error;
    /* Observe the REAL setter's cause copy, excluding mock error allocation. */
    watch_duplicate = row->send_error ? row->send_error : row->cause; watched_copies = 0;
    return rc;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; const reply *row = &s->rows[http->calls - 1];
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, s->expected_auth, 54));
    size_t expected = row->cause && !row->copy_fails ? 1u : 0u;
    if (row->rc && !row->send_error) ++expected; /* Shared fallback cause allocation. */
    CHECK(watched_copies == expected);
    watch_duplicate = NULL;
    /* Mutate the borrowed original cause before its provider-owned free. Any
     * later setter/copy would retain this poison instead of the expected text. */
    if (s->transport_storage) memset(s->transport_storage, '!', strlen(s->transport_storage));
    s->transport_storage = NULL; s->borrowed_auth = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "flexport-offline" : NULL}; s->ctx = &ctx; s->guide_start = guides_added;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth && !watch_duplicate); return out;
}
static void verify_one(const br_detector *d, reply row)
{
    row.key = a; script s = {.rows = &row, .count = 1}; br_results out = run(d, text(a), true, &s);
    CHECK(out.len == 1); result(&out.items[0], a, row.verified, row.cause); br_results_clear(&out);
}
static void unique_and_retained_guide(const br_detector *d)
{
    char input[320]; snprintf(input, sizeof(input), "%sTAIL_A\n%sTAIL_B\n%s\n%s\n%s", a, a, b, c, b); br_slice data = text(input);
    const char *keys[] = {a, b, c}; script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false, NULL);
    CHECK(out.items[0].extra_data != out.items[1].extra_data && out.items[0].raw.data != out.items[1].raw.data); br_results_clear(&out);
    const reply rows[] = {{.key = a, .status = 200, .verified = true, .read_error = a},
        {.key = b, .status = 403, .verified = true, .read_error = ""}, {.key = c, .status = 401}};
    script s = {.rows = rows, .count = 3, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], rows[i].verified, NULL);
    br_results_clear(&out);
    size_t before = guides_added; out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 3 && guides_added == before + 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false, "net/http: nil Context");
    br_results_clear(&out);
}
static void verification_and_redaction(const br_detector *d)
{
    const reply rows[] = {{.status = 200, .verified = true}, {.status = 403, .verified = true, .read_error = "ignored"}, {.status = 401},
        {.status = 201, .cause = "unexpected HTTP response status 201", .read_error = a},
        {.status = 500, .cause = "unexpected HTTP response status 500", .read_error = ""},
        {.status = 200, .rc = 1, .send_error = "cannot create Flexport result", .cause = "cannot create Flexport result"},
        {.status = 403, .rc = -7, .send_error = "out of memory constructing HTTP headers", .cause = "out of memory constructing HTTP headers"},
        {.status = 401, .rc = 1, .send_error = "", .cause = ""}, {.rc = 1, .cause = "HTTP transport failed"}};
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); ++i) verify_one(d, rows[i]);
    char sensitive[320], redacted[240];
    snprintf(sensitive, sizeof(sensitive), "key=%s Bearer %s other=%s url=https://logistics-api.flexport.com/logistics/api/2024-04/webhooks", a, a, b);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] Bearer [REDACTED] other=%s url=https://logistics-api.flexport.com/logistics/api/2024-04/webhooks", b);
    verify_one(d, (reply){.status = 200, .rc = -1, .send_error = sensitive, .cause = redacted, .read_error = sensitive});
}
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_causes(const br_detector *d)
{
    const char *causes[] = {"HTTP transport not installed", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode ? fail_headers : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, a, strlen(a));
        CHECK(out.len == 1 && !http.calls && http.releases == (size_t)mode);
        CHECK(!fail_after && failed_allocations == before + (size_t)mode);
        result(&out.items[0], a, false, causes[mode]); br_results_clear(&out);
    }
}
static void prior_result(br_results *out)
{
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].secret_parts == prior->secret_parts && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}
static void resource_failures(const br_detector *d)
{
    char input[112]; snprintf(input, sizeof(input), "%s\n%s", a, b); br_slice data = text(input);
    reply rows[] = {{.key = a, .status = 200}, {.key = b, .status = 403}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    for (int failure = 0; failure < 5; ++failure) {
        s.guide_start = guides_added;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 regex scratch failure. */
        if (failure == 1) { fail_size = 47; fail_after = 2; }
        if (failure == 2) { fail_size = 46; fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        if (failure == 4) fail_guide_after = 2; /* Positive guide insertion failure before ordinary 403. */
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : failure == 4 ? "cannot create Flexport rotation metadata" : "cannot create Flexport result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after && !fail_guide_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    fail_guide_after = 2; /* Guide resources precede nil-context cause handling. */
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Flexport rotation metadata") && !fail_guide_after);
    check_prior(&out, &saved); free(error); error = NULL;
    rows[1] = (reply){.key = b, .status = 503, .cause = "unexpected HTTP response status 503", .copy_fails = true};
    fail_duplicate = rows[1].cause; fail_duplicate_after = 1; s.guide_start = guides_added;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Flexport verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    rows[1] = (reply){.key = b, .status = 200, .rc = 1, .send_error = b, .cause = "[REDACTED]", .fail_redaction = true};
    s.guide_start = guides_added;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Flexport verification error") && !fail_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Flexport verification error") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; s.guide_start = guides_added; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Flexport result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    memcpy(a, "shltm_", 6); memcpy(b, "shltm_", 6); test_secret(a + 6, 40, 0); test_secret(b + 6, 40, 13);
    a[6] = 'A'; a[16] = '_'; a[30] = '-'; a[45] = '-'; b[6] = 'Z'; b[23] = '-'; b[45] = '_';
    memcpy(c, a, sizeof(a)); c[6] = 'a';
    const br_detector *d = descriptor();
    extraction(d); unique_and_retained_guide(d); verification_and_redaction(d); shared_send_causes(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_guide_after && !fail_duplicate_after && !watch_duplicate);
    return test_finish("Flexport");
}
