/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char k1[21], k2[21], id1[21], id2[21], id3[21];
static size_t fail_size, fail_after, failed_allocations, fail_part_after, basic_allocations;
static const char *fail_duplicate;
static size_t fail_duplicate_after;

/* Target existing allocation/JSON APIs, not production failure switches. */
void *malloc(size_t size)
{
    if (size == 63) ++basic_allocations;
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
    CHECK(BR_ABI_REVISION == 1 && strlen(k1) == 20 && strlen(k2) == 20 && strlen(id1) == 20);
    CHECK(br_easyinsight_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:easyinsight|easy-insight|key)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_easyinsight_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_easyinsight_init(&d, &error) == 0 && d && !error);
    CHECK(br_easyinsight_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 282 && d->version == 0 && !strcmp(d->name, "EasyInsight") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "EasyInsight is a business intelligence tool that provides data visualization and reporting. EasyInsight API keys can be used to access and manage data within the platform."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "easyinsight") && !strcmp(d->keywords[1], "easy-insight"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void json_part(br_json *parts, const char *name, const char *expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, name, &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), expected, 20));
}
static void pair_result(const br_result *r, const char *key, const char *id, bool verified, const char *error)
{
    CHECK(r->detector_type == 282 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == 20 && !memcmp(r->raw.data, key, 20));
    CHECK(r->raw_v2.len == 40 && !memcmp(r->raw_v2.data, key, 20) && !memcmp(r->raw_v2.data + 20, id, 20));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    json_part(r->secret_parts, "key", key); json_part(r->secret_parts, "id", id);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
}
static void extract_one(const br_detector *d, const char *input, const char *key, const char *id, bool found)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = basic_allocations; br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (found ? 1u : 0u) && !http.calls && !http.releases && basic_allocations == before);
    if (found) pair_result(&out.items[0], key, id, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[1700], changed[22];
    /* Generic role prefixes are extraction-only. The dispatch hint follows
     * credentials, so its common prefix cannot change the role memberships. */
    snprintf(input, sizeof(input), "KEY %s\nid %s\neasyinsight", k1, id1); extract_one(d, input, k1, id1, true);
    snprintf(input, sizeof(input), "ID %s\nkey %s\nEASY-INSIGHT", id1, k1); extract_one(d, input, k1, id1, true);
    snprintf(input, sizeof(input), "key %s\nid %s", k1, id1); extract_one(d, input, k1, id1, true); /* Direct scan needs no dispatch hint. */
    snprintf(input, sizeof(input), "key %s\nkey %s\neasyinsight", k1, k2); extract_one(d, input, k1, id1, false);
    snprintf(input, sizeof(input), "id %s\nid %s\neasy-insight", id1, id2); extract_one(d, input, k1, id1, false);
    snprintf(input, sizeof(input), "key %s\nkey %s\nid %s\neasyinsight", k1, k1, k1); extract_one(d, input, k1, k1, false);
    const char *bad[] = {"%s\nid %s\neasyinsight", "key%s\nid %s\neasyinsight", "key _%s\nid %s\neasyinsight", "key %s_\nid %s\neasyinsight"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], k1, id1); extract_one(d, input, k1, id1, false);
    }
    const char invalid[] = {'_', '-', '.'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, k1, sizeof(k1)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "key %s\nid %s\neasyinsight", changed, id1); extract_one(d, input, k1, id1, false);
    }
    memcpy(changed, k1, sizeof(k1)); changed[19] = '\0';
    snprintf(input, sizeof(input), "key %s\nid %s\neasyinsight", changed, id1); extract_one(d, input, k1, id1, false);
    memcpy(changed, k1, sizeof(k1)); changed[20] = 'a'; changed[21] = '\0';
    snprintf(input, sizeof(input), "key %s\nid %s\neasyinsight", changed, id1); extract_one(d, input, k1, id1, false);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "KEY%*s%s\nID %s\neasyinsight", gap, "", k1, id1); extract_one(d, input, k1, id1, gap == 40);
    }
    snprintf(input, sizeof(input), "preKEYsuffix:\r\n%s\nID\r\n%s\neasyinsight", k1, id1); extract_one(d, input, k1, id1, true);
    int n = snprintf(input, sizeof(input), "key %s", k1); CHECK(n == 24);
    memset(input + n, ' ', 1300); snprintf(input + n + 1300, sizeof(input) - (size_t)n - 1300, "\nid %s\neasy-insight", id1);
    extract_one(d, input, k1, id1, true); /* Span hint is not detector-local pairing policy. */
    /* Common provider prefixes populate BOTH sets; unequal directed pairs stay. */
    snprintf(input, sizeof(input), "EaSyInSiGhT %s\nEASY-INSIGHT %s", k1, id1);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    pair_result(&out.items[0], k1, id1, false, NULL); pair_result(&out.items[1], id1, k1, false, NULL); br_results_clear(&out);
}

typedef struct { const char *key, *id; int status, rc; const char *error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth, *borrowed_key, *borrowed_id; char *returned_error;
} script;
static void check_basic(const char *auth, const char *key, const char *id)
{
    CHECK(auth && strlen(auth) == 62 && !memcmp(auth, "Basic ", 6));
    CHECK(auth[61] == '=' && auth[60] != '=');
    unsigned char decoded[44]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 56) == 42);
    CHECK(!memcmp(decoded, id, 20) && decoded[20] == ':' && !memcmp(decoded + 21, key, 20));
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 282 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.easy-insight.com/app/api/users.json"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization")); check_basic(request->headers[2].value, row->key, row->id);
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, s->suffix ? "TruffleHog easyinsight-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[2].value; s->borrowed_key = row->key; s->borrowed_id = row->id;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)}, .body_error = "ignored read/drain error"};
    http->send_rc = row->rc; http->send_error = row->error;
}
static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *s = http->user; s->returned_error = *error;
    return rc;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    check_basic(s->borrowed_auth, s->borrowed_key, s->borrowed_id); s->borrowed_auth = NULL;
    /* Ordinary causes must already have been copied, without redaction. */
    if (s->returned_error) memset(s->returned_error, '!', strlen(s->returned_error));
    s->returned_error = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, send_request, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "easyinsight-offline" : NULL}; s->ctx = &ctx;
    size_t before = basic_allocations; br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth && basic_allocations == before + s->count);
    return out;
}

static void products_and_inner_break(const br_detector *d)
{
    char input[320]; int n = snprintf(input, sizeof(input), "key %s\nKEY %s\nkey %s\nid %s\nID %s\nid %s\nid %s\neasy-insight", k1, k2, k1, id1, id2, id3, id1);
    CHECK(n > 0 && (size_t)n < sizeof(input)); br_slice data = text(input);
    const char *keys[] = {k1, k2}, *ids[] = {id1, id2, id3};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 6);
    for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < 3; ++i) pair_result(&out.items[k * 3 + i], keys[k], ids[i], false, NULL);
    CHECK(out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
    char echo[128]; CHECK(snprintf(echo, sizeof(echo), "outer: %s / %s / %s", k1, id1, k1) > 0);
    const reply rows[] = {{k1, id1, 200, 1, echo}, {k1, id2, 200, 0, NULL}, {k2, id1, 401, 0, NULL}, {k2, id2, 201, 0, NULL}, {k2, id3, 200, 0, NULL}};
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 5);
    const char *errors[] = {echo, NULL, NULL, "unexpected status code: 201", NULL};
    for (size_t i = 0; i < 5; ++i) pair_result(&out.items[i], rows[i].key, rows[i].id, i == 1 || i == 4, errors[i]);
    br_results_clear(&out);
    size_t before = basic_allocations; out = test_scan(d, NULL, true, data.data, data.len);
    CHECK(out.len == 6 && basic_allocations == before);
    for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < 3; ++i) pair_result(&out.items[k * 3 + i], keys[k], ids[i], false, "net/http: nil Context");
    br_results_clear(&out);
}

static void verification(const br_detector *d)
{
    char input[96]; CHECK(snprintf(input, sizeof(input), "key %s\nid %s\neasyinsight", k1, id1) > 0); br_slice data = text(input);
    const int statuses[] = {200, 401, 201, 204, 299, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {k1, id1, statuses[i], 0, NULL}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1);
        char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]) > 0);
        pair_result(&out.items[0], k1, id1, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : error); br_results_clear(&out);
    }
    char echo[128]; CHECK(snprintf(echo, sizeof(echo), "%s %s %s %s", k1, id1, k1, id1) > 0);
    const char *causes[] = {echo, "outer: inner: literal", "net/http: nil Context", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {k1, id1, 200, i % 2 ? -7 : 1, causes[i]}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1);
        pair_result(&out.items[0], k1, id1, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 4 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[96]; CHECK(snprintf(input, sizeof(input), "key %s\nid %s\neasyinsight", k1, id1) > 0);
    const char *errors[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        pair_result(&out.items[0], k1, id1, false, errors[mode]); br_results_clear(&out);
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
    char input[128]; CHECK(snprintf(input, sizeof(input), "key %s\nkey %s\nid %s\neasyinsight", k1, k2, id1) > 0); br_slice data = text(input);
    reply rows[] = {{k1, id1, 200, 0, NULL}, {k2, id1, 200, 0, NULL}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create EasyInsight result", "cannot create EasyInsight result", "cannot create EasyInsight result"};
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 2; } /* Actual +1 during independent ID iteration. */
            if (failure == 1) { fail_size = 21; fail_after = 3; }
            if (failure == 2) { fail_size = 20; fail_after = 2; }
            if (failure == 3) { fail_size = 40; fail_after = 2; } /* RawV2, no separator. */
            if (failure == 4) fail_part_after = 4; /* +1 adding the second finding's ID. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        br_results_clear(&out);
    }
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, send_request, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    fail_size = 63; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    /* Nil context retains findings BEFORE Basic encoding, unlike Dwolla. */
    fail_size = 63; fail_after = 1; br_results nil = test_scan(d, NULL, true, data.data, data.len);
    CHECK(nil.len == 2 && fail_after == 1); fail_after = 0; br_results_clear(&nil);
    rows[1].status = 503; http.calls = http.releases = 0; fail_duplicate = "unexpected status code: 503"; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set EasyInsight verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set EasyInsight verification error") && !fail_duplicate_after);
    check_prior(&out, &saved); free(error); error = NULL;
    http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append EasyInsight result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    test_secret(k1, 20, 0); test_secret(k2, 20, 11); test_secret(id1, 20, 7); test_secret(id2, 20, 19); test_secret(id3, 20, 29);
    k1[0] = 'K'; k1[9] = 'Q'; k2[8] = 'Z'; id1[0] = 'A'; id2[7] = 'B'; id3[12] = 'C';
    const br_detector *d = descriptor();
    extraction(d); products_and_inner_break(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("EasyInsight");
}
