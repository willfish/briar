/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[44], other[44], short_id[19], long_id[31];
/* Never send this source payload outside the injected offline transport. */
static const unsigned char sms_body[] = "{\"source\":\"abcde\",\"destination\":\"+6512345678\",\"text\":\"Hello World!\",\"encoding\":\"AUTO\"}";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;

/* Exercise existing allocation/JSON boundaries, not URL-format failure seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other) == 43 && strlen(short_id) == 18 && strlen(long_id) == 30);
    CHECK(sizeof(sms_body) - 1 == 86);
    CHECK(br_eightxeight_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:8x8)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_eightxeight_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_eightxeight_init(&d, &error) == 0 && d && !error);
    CHECK(br_eightxeight_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 727 && d->version == 0 && !strcmp(d->name, "EightxEight") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "8x8 is a provider of cloud-based communication services including voice, video, chat, and contact center solutions."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "8x8"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void json_part(br_json *parts, const char *name, const char *expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, name, &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)strlen(expected) && !memcmp(json_object_get_string(part), expected, strlen(expected)));
}
static void pair_result(const br_result *r, const char *expected_key, const char *id, bool verified)
{
    CHECK(r->detector_type == 727 && r->verified == verified && !r->verification_from_cache && !r->verification_error);
    CHECK(r->raw.len == 43 && !memcmp(r->raw.data, expected_key, 43));
    CHECK(r->raw_v2.len == 43 + strlen(id) && !memcmp(r->raw_v2.data, expected_key, 43) && !memcmp(r->raw_v2.data + 43, id, strlen(id)));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    json_part(r->secret_parts, "key", expected_key); json_part(r->secret_parts, "id", id);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
}
static void extract_case(const br_detector *d, const char *input, const char *expected_key, const char *id, bool found)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (found ? 1u : 0u) && !http.calls && !http.releases);
    if (found) pair_result(&out.items[0], expected_key, id, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[1700], changed_key[45], changed_id[32];
    const char *formats[] = {"8x8 '%s'\n8x8 %s", "8X8\r\n%s\n8x8 %s", "pre8X8suffix:%s\n8x8\r%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key, short_id); extract_case(d, input, key, short_id, true);
    }
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, long_id); extract_case(d, input, key, long_id, true);
    const char *bad[] = {"%s\n8x8 %s", "8x8%s\n8x8 %s", "8x8 _%s\n8x8 %s", "8x8 %s_\n8x8 %s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key, short_id); extract_case(d, input, key, short_id, false);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "8x8%*s%s\n8x8 %s", gap, "", key, short_id); extract_case(d, input, key, short_id, gap == 40);
        snprintf(input, sizeof(input), "8x8 %s\n8x8%*s%s", key, gap, "", short_id); extract_case(d, input, key, short_id, gap == 40);
    }
    memcpy(changed_key, key, sizeof(key)); changed_key[42] = '\0';
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", changed_key, short_id); extract_case(d, input, key, short_id, false);
    memcpy(changed_key, key, sizeof(key)); changed_key[43] = 'A'; changed_key[44] = '\0';
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", changed_key, short_id); extract_case(d, input, key, short_id, false);
    const char invalid[] = {'_', '-'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed_key, key, sizeof(key)); changed_key[10] = invalid[i];
        snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", changed_key, short_id); extract_case(d, input, key, short_id, false);
    }
    memcpy(changed_id, short_id, sizeof(short_id)); changed_id[17] = '\0';
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, changed_id); extract_case(d, input, key, short_id, false);
    memcpy(changed_id, long_id, sizeof(long_id)); changed_id[30] = 'A'; changed_id[31] = '\0';
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, changed_id); extract_case(d, input, key, long_id, false);
    memcpy(changed_id, short_id, sizeof(short_id)); changed_id[10] = '-';
    snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, changed_id); extract_case(d, input, key, short_id, false);
    snprintf(input, sizeof(input), "8x8 %s", key); extract_case(d, input, key, short_id, false);
    snprintf(input, sizeof(input), "8x8 %s", short_id); extract_case(d, input, key, short_id, false);
    int n = snprintf(input, sizeof(input), "8x8 %s", key); CHECK(n == 47);
    memset(input + n, ' ', 1300); snprintf(input + n + 1300, sizeof(input) - (size_t)n - 1300, "\n8x8 %s", long_id);
    extract_case(d, input, key, long_id, true); /* No detector-local 1024-byte span cap. */
}

typedef struct { const char *key, *id; int status, rc; const char *error; int body_kind; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url, *borrowed_auth, *borrowed_key; br_slice borrowed_body;
    char expected_url[79];
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 727 && request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "POST"));
    int n = snprintf(s->expected_url, sizeof(s->expected_url), "https://sms.8x8.com/api/v1/subaccounts/%s/messages", row->id);
    CHECK(n == 48 + (int)strlen(row->id) && n >= 66 && n <= 78);
    CHECK(strlen(request->url) == (size_t)n && !memcmp(request->url, s->expected_url, (size_t)n + 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization")); const char *auth = request->headers[1].value;
    CHECK(auth && strlen(auth) == 50 && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, row->key, 44));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, s->suffix ? "TruffleHog eightxeight-offline" : "TruffleHog"));
    CHECK(request->body.data && request->body.len == sizeof(sms_body) - 1 && !memcmp(request->body.data, sms_body, sizeof(sms_body) - 1));
    /* Fixed recipient, source, Hello World!, AUTO and field order are checked as
     * exact bytes. No socket, DNS lookup or actual SMS is performed by this fake. */
    s->borrowed_url = request->url; s->borrowed_auth = auth; s->borrowed_key = row->key; s->borrowed_body = request->body;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->body_kind ? (br_slice){junk, sizeof(junk)} : (br_slice){0},
        .body_error = row->body_kind == 0 ? NULL : row->body_kind == 1 ? "" : "ignored read error"};
    http->send_rc = row->rc; http->send_error = row->error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_url && !strcmp(s->borrowed_url, s->expected_url));
    CHECK(s->borrowed_auth && !memcmp(s->borrowed_auth, "Bearer ", 7) && !memcmp(s->borrowed_auth + 7, s->borrowed_key, 44));
    CHECK(s->borrowed_body.len == sizeof(sms_body) - 1 && !memcmp(s->borrowed_body.data, sms_body, sizeof(sms_body) - 1));
    s->borrowed_url = s->borrowed_auth = NULL; s->borrowed_body = (br_slice){0}; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "eightxeight-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url && !s->borrowed_auth && !s->borrowed_body.data);
    return out;
}

static void occurrences_and_nil_skip(const br_detector *d)
{
    char input[320]; int n = snprintf(input, sizeof(input), "8x8 %s\n8X8 %s\n8x8 %s\n8x8 %s\n8x8 %s\n8x8 %s", key, other, key, short_id, long_id, short_id);
    CHECK(n > 0 && (size_t)n < sizeof(input)); br_slice data = text(input);
    const char *keys[] = {key, other, key}, *ids[] = {short_id, long_id, short_id};
    const int statuses[] = {200, 204, 299, 199, 300, 401, 429, 500, 201}; reply rows[9];
    for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 3; ++i) {
        size_t at = k * 3 + i; rows[at] = (reply){keys[k], ids[i], statuses[at], 0, NULL, (int)(at % 3)};
    }
    for (int verify = 0; verify < 2; ++verify) {
        script s = {.rows = rows, .count = verify ? 9u : 0u, .suffix = true}; br_results out = run(d, data, verify, &s); CHECK(out.len == 9);
        for (size_t i = 0; i < 9; ++i) pair_result(&out.items[i], rows[i].key, rows[i].id, verify && statuses[i] >= 200 && statuses[i] < 300);
        CHECK(out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
        out = test_scan(d, NULL, verify, data.data, data.len); CHECK(out.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < out.len; ++i) pair_result(&out.items[i], rows[i].key, rows[i].id, false);
        br_results_clear(&out);
    }
}

static void suppressed_send_errors(const br_detector *d)
{
    char input[96]; CHECK(snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, short_id) == 70); br_slice data = text(input);
    const char *causes[] = {"net/http: nil Context", "cannot create EightxEight result", "synthetic timeout",
        "out of memory constructing HTTP headers", "unsupported: redirects for native HTTP POST", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {key, short_id, 200, i % 2 ? -7 : 1, causes[i], 2}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1); pair_result(&out.items[0], key, short_id, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[96]; CHECK(snprintf(input, sizeof(input), "8x8 %s\n8x8 %s", key, short_id) == 70);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        pair_result(&out.items[0], key, short_id, false); br_results_clear(&out);
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
    char input[128]; CHECK(snprintf(input, sizeof(input), "8x8 %s\n8x8 %s\n8x8 %s", key, short_id, long_id) == 105); br_slice data = text(input);
    const reply rows[] = {{key, short_id, 200, 0, NULL, 2}, {key, long_id, 200, 0, NULL, 1}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create EightxEight result", "cannot create EightxEight result", "cannot create EightxEight result"};
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 2; } /* Actual +1 in independent ID iteration. */
            if (failure == 1) { fail_size = 31; fail_after = 1; }
            if (failure == 2) { fail_size = 43; fail_after = 2; }
            if (failure == 3) { fail_size = 73; fail_after = 1; } /* Second pair's RawV2=43+30. */
            if (failure == 4) fail_part_after = 4; /* +1 adding the second finding's ID. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_url && !s.borrowed_auth);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        size_t cap = out.cap; out.cap = 0; /* Actual +1 push failure after a verified response. */
        CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append EightxEight result"));
        out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
        /* Normal constructor SKIPs also preserve preexisting caller findings. */
        CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved);
        br_results_clear(&out);
    }
}

int main(void)
{
    test_secret(key, 43, 0); test_secret(other, 43, 11); test_secret(short_id, 18, 7); test_secret(long_id, 30, 19);
    key[0] = 'K'; key[20] = 'Q'; other[12] = 'Z'; short_id[0] = short_id[17] = '_'; short_id[8] = 'A'; long_id[4] = '_'; long_id[19] = 'B';
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_nil_skip(d); suppressed_send_errors(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after);
    return test_finish("EightxEight");
}
