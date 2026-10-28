/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char *const ids[] = {"470123450678901", "4701234506789012", "47012345067890123", "470123450678901234"};
static char a[33], b[33]; /* Synthetic, case-distinct alphanumeric fixtures. */
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate;
static bool fail_raw_on_release;

/* Existing resource APIs only; no URL formatter/cap failure seam. */
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
    if (copy) memcpy(copy, value, size);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(a) == 32 && strlen(b) == 32);
    CHECK(br_facebookoauth_init(NULL, &error) == -1 && error); free(error); error = NULL;
    /* Both independent pattern initializations fail closed and permit retry. */
    for (size_t at = 1; at <= 2; ++at) {
        fail_size = sizeof("(?i:facebook)(?s:.){0,40}?"); fail_after = at;
        CHECK(br_facebookoauth_init(&d, &error) == -1 && !d && error && !fail_after);
        CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    }
    CHECK(br_facebookoauth_init(&d, &error) == 0 && d && !error);
    CHECK(br_facebookoauth_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 40 && d->version == 0 && !strcmp(d->name, "FacebookOAuth") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Facebook OAuth tokens are used to authenticate users and provide access to Facebook's API services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "facebook"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void part(br_json *parts, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(parts, name, &value) && json_object_is_type(value, json_type_string));
    CHECK(json_object_get_string_len(value) == (int)strlen(expected) && !strcmp(json_object_get_string(value), expected));
}
static void result(const br_result *r, const char *id, const char *secret, bool verified)
{
    size_t idlen = strlen(id);
    CHECK(r->detector_type == 40 && r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(r->raw.len == 32 && !memcmp(r->raw.data, secret, 32)); /* Raw is NEVER ID. */
    CHECK(r->redacted && !strcmp(r->redacted, id));
    CHECK(r->raw_v2.len == idlen + 32 && !memcmp(r->raw_v2.data, id, idlen) && !memcmp(r->raw_v2.data + idlen, secret, 32));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    part(r->secret_parts, "id", id); part(r->secret_parts, "secret", secret);
    br_json *wrong = NULL; CHECK(!json_object_object_get_ex(r->secret_parts, "key", &wrong));
    CHECK(!r->detector_name && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->chunk_offset && !r->chunk_offset_set);
}
static void extract_case(const br_detector *d, const char *input, const char *id, const char *secret)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (id ? 1u : 0u) && !http.calls && !http.releases);
    if (id) result(&out.items[0], id, secret, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[256], changed[34];
    const char *formats[] = {"facebook %s\nFACEBOOK %s", "FaCeBoOk='%s' faCeBoOk='%s'", "preFACEBOOKsuffix:%s\nprefacebooksuffix:%s", "facebook\r\n%s\nfacebook\r%s", "facebook id='%s' secret='%s'"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], ids[0], a); extract_case(d, input, ids[0], a);
    }
    for (size_t i = 0; i < 4; ++i) {
        snprintf(input, sizeof(input), "facebook %s\nfacebook %s", ids[i], b); extract_case(d, input, ids[i], b);
    }
    const char *bad[] = {"%s\n%s", "%s\nfacebook %s", "facebook%s\nfacebook %s", "facebook _%s\nfacebook %s", "facebook %s_\nfacebook %s", "facebook %s\nfacebook_%s", "facebook %s\nfacebook %s_", "facebook %s\nfacebook x%s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], ids[0], a); extract_case(d, input, NULL, NULL);
    }
    const char *wrong_ids[] = {"47012345067890", "4701234506789012345", "47012345067890x"};
    for (size_t i = 0; i < sizeof(wrong_ids) / sizeof(wrong_ids[0]); ++i) {
        snprintf(input, sizeof(input), "facebook %s\nfacebook %s", wrong_ids[i], a); extract_case(d, input, NULL, NULL);
    }
    for (int role = 0; role < 2; ++role) {
        for (int gap = 40; gap <= 41; ++gap) {
            if (role == 0) snprintf(input, sizeof(input), "facebook%*s%s\nfacebook %s", gap, "", ids[0], a);
            else snprintf(input, sizeof(input), "facebook %s\nfacebook%*s%s", ids[0], gap, "", a);
            extract_case(d, input, gap == 40 ? ids[0] : NULL, a);
        }
    }
    memcpy(changed, a, sizeof(a)); changed[31] = '\0';
    snprintf(input, sizeof(input), "facebook %s\nfacebook %s", ids[0], changed); extract_case(d, input, NULL, NULL);
    memcpy(changed, a, sizeof(a)); changed[32] = 'Z'; changed[33] = '\0';
    snprintf(input, sizeof(input), "facebook %s\nfacebook %s", ids[0], changed); extract_case(d, input, NULL, NULL);
    const char invalid[] = {'-', '_', '+'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, a, sizeof(a)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "facebook %s\nfacebook %s", ids[0], changed); extract_case(d, input, NULL, NULL);
    }
    extract_case(d, "facebook 000000000000000\nfacebook aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "000000000000000", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); /* No local entropy/FP filter. */
    extract_case(d, "facebook 470123450678901\nfacebook 12345678901234567890123456789012", ids[0], "12345678901234567890123456789012");
}

typedef struct { const char *id, *secret; int status, rc; const char *send_error, *read_error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url; char expected_url[95]; size_t url_length;
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 40 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    int n = snprintf(s->expected_url, sizeof(s->expected_url), "https://graph.facebook.com/me?access_token=%s|%s", row->id, row->secret);
    CHECK(n == (int)(43 + strlen(row->id) + 1 + 32) && n >= 91 && n <= 94); s->url_length = (size_t)n;
    CHECK(strlen(request->url) == s->url_length && !memcmp(request->url, s->expected_url, s->url_length + 1));
    CHECK(strchr(request->url, '|') && !strstr(request->url, "%7C") && !strstr(request->url, "%7c"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, s->suffix ? "TruffleHog facebook-offline" : "TruffleHog"));
    s->borrowed_url = request->url;
    static const unsigned char ignored_body[] = "\0\xffmalformed \"error\" body";
    http->response = (br_http_response){.status = row->status, .body = {ignored_body, sizeof(ignored_body) - 1}, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_url && !memcmp(s->borrowed_url, s->expected_url, s->url_length + 1));
    s->borrowed_url = NULL; test_http_release(user, response);
    /* Arm an actual next-finding Raw allocation, AFTER both regex scratch
     * allocations and the first kept product, not an artificial URL stage. */
    if (fail_raw_on_release) { fail_raw_on_release = false; fail_size = 32; fail_after = 1; }
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "facebook-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url); return out;
}
static void verify_one(const br_detector *d, reply row, bool verified)
{
    char input[128]; if (!row.id) row.id = ids[0]; if (!row.secret) row.secret = a;
    snprintf(input, sizeof(input), "facebook %s\nfacebook %s", row.id, row.secret);
    script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == 1); result(&out.items[0], row.id, row.secret, verified); br_results_clear(&out);
}
static void products_and_no_span_cap(const br_detector *d)
{
    char input[2600]; int n = snprintf(input, sizeof(input), "facebook %s\nFACEBOOK %s\nfacebook %s\n", ids[0], ids[3], ids[0]); CHECK(n > 0);
    size_t at = (size_t)n; memset(input + at, ' ', 2048); at += 2048;
    CHECK(snprintf(input + at, sizeof(input) - at, "facebook %s\nfacebook %s\nFaCeBoOk %s", a, b, a) > 0);
    br_slice data = text(input); const char *id_order[] = {ids[0], ids[3], ids[0]}, *secret_order[] = {a, b, a};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i) result(&out.items[i], id_order[i / 3], secret_order[i % 3], false);
    br_results_clear(&out);
    reply rows[9] = {0};
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.id = id_order[i / 3], .secret = secret_order[i % 3], .status = 200, .read_error = "ignored"};
    rows[1].status = 403; rows[3].rc = 1; rows[3].send_error = "out of memory constructing HTTP headers"; rows[5].status = 299; rows[8].status = 300;
    script s = {.rows = rows, .count = 9, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i) result(&out.items[i], id_order[i / 3], secret_order[i % 3], i != 1 && i != 3 && i != 8);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, data.data, data.len); CHECK(out.len == 0); br_results_clear(&out); /* Constructor SKIPs all products. */
    out = test_scan(d, NULL, false, data.data, data.len); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i) result(&out.items[i], id_order[i / 3], secret_order[i % 3], false);
    br_results_clear(&out);
}
static void verification(const br_detector *d)
{
    for (size_t i = 0; i < 4; ++i) verify_one(d, (reply){.id = ids[i], .secret = b, .status = 200, .read_error = ""}, true);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verify_one(d, (reply){.status = statuses[i], .read_error = i % 2 ? "" : a}, statuses[i] >= 200 && statuses[i] < 300);
    char sensitive[192]; snprintf(sensitive, sizeof(sensitive), "https://graph.facebook.com/me?access_token=%s|%s repeated=%s", ids[0], a, a);
    const char *causes[] = {"net/http: nil Context", "cannot create FacebookOAuth result", "out of memory constructing HTTP headers", sensitive, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 200, .rc = i % 2 ? -7 : 1, .send_error = causes[i], .read_error = ""}, false);
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "facebook %s\nfacebook %s", ids[0], a);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], ids[0], a, false); br_results_clear(&out);
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
    char input[160]; snprintf(input, sizeof(input), "facebook %s\nfacebook %s\nfacebook %s", ids[0], a, b); br_slice data = text(input);
    reply rows[] = {{.id = ids[0], .secret = a, .status = 200}, {.id = ids[0], .secret = b, .status = 200, .rc = 1, .send_error = "out of memory in Do"}};
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    for (int failure = 0; failure < 6; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 2; } /* Actual +1 scratch failure in SECRET's independent search. */
        if (failure == 1) { fail_size = 33; fail_after = 2; }
        if (failure == 2) fail_raw_on_release = true;
        if (failure == 3) { fail_size = 47; fail_after = 2; }
        if (failure == 4) fail_part_after = 4; /* Positive JSON failure adding second product's ID. */
        if (failure == 5) { fail_duplicate = ids[0]; fail_duplicate_after = 2; }
        CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create FacebookOAuth result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after && !fail_duplicate_after && !fail_raw_on_release);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_url);
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Redacted must exist BEFORE constructor SKIP; V2 must exist with verify off. */
    fail_duplicate = ids[0]; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FacebookOAuth result") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    fail_size = 47; fail_after = 2;
    CHECK(d->scan(d, &ctx, false, data, &out, &error) == -1 && error && !strcmp(error, "cannot create FacebookOAuth result") && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &saved); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard after successful verification. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append FacebookOAuth result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved); br_results_clear(&out);
}

int main(void)
{
    test_secret(a, 32, 0); test_secret(b, 32, 11); a[0] = 'A'; a[9] = 'Z'; a[31] = 'X'; b[20] = 'Q'; b[31] = 'Y';
    const br_detector *d = descriptor();
    extraction(d); products_and_no_span_cap(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after && !fail_raw_on_release);
    return test_finish("FacebookOAuth");
}
