/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define BYTES(s) (br_slice){(const unsigned char *)(s), sizeof(s) - 1}
static unsigned char keys[2][1140];
static char ids[2][26];
static size_t fail_size, fail_after, fail_part_after, allocation_failures;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice token(unsigned char *out, br_slice first, br_slice second, size_t shift)
{
    memcpy(out, "ey", 2); test_secret((char *)out + 2, 73, shift); out[7] = 'Q';
    memcpy(out + 75, first.data, first.len);
    size_t at = 75 + first.len;
    memcpy(out + at, "ey", 2); test_secret((char *)out + at + 2, 365, shift + 3); out[at + 17] = 'Z';
    at += 367; memcpy(out + at, second.data, second.len); at += second.len;
    test_secret((char *)out + at, 683, shift + 7); out[at + 29] = '_'; out[at + 71] = '-';
    return (br_slice){out, at + 683};
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_graphcms_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:graph)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_graphcms_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_graphcms_init(&d, &error) == 0 && d && !error && br_graphcms_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 223 && d->version == 0 && !strcmp(d->name, "GraphCMS") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "GraphCMS, now known as Hygraph, is a CSM software. The GraphCSM API token can enable someone to interact with CMS content."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "graphcms") && d->max_credential_span == 1024 && d->max_secret_size == -1 && d->start_offset == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, br_slice key, bool verified)
{
    CHECK(r->detector_type == 223 && r->raw.len == key.len && !memcmp(r->raw.data, key.data, key.len));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *part = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == key.len && !memcmp(json_object_get_string(part), key.data, key.len));
}

static br_slice input_for(unsigned char *input, br_slice key, const char *id_text)
{
    memcpy(input, key.data, key.len); input[key.len] = ';';
    size_t len = strlen(id_text); memcpy(input + key.len + 1, id_text, len);
    return (br_slice){input, key.len + 1 + len};
}
static br_results scan_value(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice key)
{
    unsigned char input[1300]; char id_text[40]; snprintf(id_text, sizeof(id_text), "GrApH %s", ids[0]);
    br_slice data = input_for(input, key, id_text); return test_scan(d, ctx, verify, data.data, data.len);
}
static void grammar_case(const br_detector *d, br_slice key, const br_slice *expected)
{
    br_results r = scan_value(d, NULL, false, key); CHECK(r.len == (expected ? 1u : 0u));
    if (expected) check_result(&r.items[0], *expected, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    br_slice key = {keys[0], 1127}; unsigned char value[1200], input[1500];
    grammar_case(d, key, &key);
    const br_slice separators[] = {BYTES("!"), BYTES("Q"), BYTES("\0"), BYTES("\v"), BYTES("\r"), BYTES("\t"), BYTES("\xf0\x9f\x9a\x80")};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        br_slice k = token(value, separators[i], separators[i], 2); grammar_case(d, k, &k);
        if (i == 6) CHECK(k.len == 1133);
    }
    br_slice k = token(value, BYTES("\n"), BYTES("."), 0); grammar_case(d, k, NULL);
    k = token(value, BYTES("."), BYTES("\n"), 0); grammar_case(d, k, NULL);
    memcpy(value, key.data, key.len); value[0] = 'E'; grammar_case(d, (br_slice){value, key.len}, NULL);
    memcpy(value, key.data, key.len); value[77] = 'Y'; grammar_case(d, (br_slice){value, key.len}, NULL);
    memcpy(value, key.data, key.len); value[40] = '_'; grammar_case(d, (br_slice){value, key.len}, NULL);
    memcpy(value, key.data, key.len); value[100] = '-'; grammar_case(d, (br_slice){value, key.len}, NULL);
    memcpy(value, key.data, 40); memcpy(value + 40, key.data + 41, key.len - 41); grammar_case(d, (br_slice){value, key.len - 1}, NULL);
    memcpy(value, key.data, 100); value[100] = 'Q'; memcpy(value + 101, key.data + 100, key.len - 100); grammar_case(d, (br_slice){value, key.len + 1}, NULL);
    memcpy(value, key.data, key.len); value[key.len] = 'q'; grammar_case(d, (br_slice){value, key.len + 1}, NULL);
    memcpy(value, key.data, key.len); value[key.len - 1] = '-'; grammar_case(d, (br_slice){value, key.len}, NULL);
    value[key.len] = 'q'; k = (br_slice){value, key.len}; grammar_case(d, (br_slice){value, key.len + 1}, &k); /* Ending nonword followed by word: source boundary, not token validation. */
    value[0] = '_'; memcpy(value + 1, key.data, key.len); grammar_case(d, (br_slice){value, key.len + 1}, NULL);
    value[0] = '-'; k = (br_slice){value + 1, key.len}; grammar_case(d, (br_slice){value, key.len + 1}, &k);
    const char *formats[] = {"GrApH %s", "myGRAPHsuffix:%s", "graph\r\n%s", "%s", "graph %sX", "graph _%s", "graph %s_"};
    for (size_t i = 0; i < 7; ++i) {
        char text[100]; snprintf(text, sizeof(text), formats[i], ids[0]); br_slice data = input_for(input, key, text);
        br_results r = test_scan(d, NULL, false, data.data, data.len); CHECK(r.len == (i < 3 ? 1u : 0u)); br_results_clear(&r);
    }
    char text[200]; snprintf(text, sizeof(text), "graph %s", ids[0]); text[10] = 'Z';
    br_slice data = input_for(input, key, text); br_results r = test_scan(d, NULL, false, data.data, data.len); CHECK(!r.len); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(text, "graph", 5); memset(text + 5, ' ', gap); memcpy(text + 5 + gap, ids[0], 26);
        data = input_for(input, key, text); r = test_scan(d, NULL, false, data.data, data.len); CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(text, "graph", 5);
        for (size_t i = 0; i < gap; ++i) memcpy(text + 5 + 4 * i, "\xf0\x9f\x9a\x80", 4);
        memcpy(text + 5 + 4 * gap, ids[0], 26); data = input_for(input, key, text);
        r = test_scan(d, NULL, false, data.data, data.len); CHECK(r.len == (gap == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    /* Direct extraction ignores dispatch keyword and engine span; ID may be
     * far away and the ordinary key already exceeds the inherited 1024 hint. */
    memcpy(input, "graph", 5); memset(input + 5, ' ', 39); input[44] = '\n'; memcpy(input + 45, ids[0], 25); input[70] = ';';
    memcpy(input + 71, key.data, key.len); r = test_scan(d, NULL, false, input, 71 + key.len); CHECK(r.len == 1); br_results_clear(&r);
    r = test_scan(d, NULL, false, key.data, key.len); CHECK(!r.len); br_results_clear(&r);
    r = test_scan(d, NULL, false, "graph b7c9d2e5f6g8h3j4k1m0n2p4q", 31); CHECK(!r.len); br_results_clear(&r);
}

typedef struct {
    const br_slice *keys;
    const char *const *ids;
    size_t count;
    const char *auth, *url;
    br_slice body;
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1; CHECK(ctx && at < s->count && http->releases == at && !s->auth);
    br_slice key = s->keys[at]; char expected[100]; snprintf(expected, sizeof(expected), "https://api-ap-northeast-1.graphcms.com/v2/%s/master", s->ids[at]);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, expected));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 223);
    CHECK(request->body.len == sizeof("{users {id name}}") - 1 && !memcmp(request->body.data, "{users {id name}}", sizeof("{users {id name}}") - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/graphql"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 7 + key.len && !memcmp(request->headers[1].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[1].value + 7, key.data, key.len) && !request->headers[1].value[7 + key.len]);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog graphcms-offline"));
    s->auth = request->headers[1].value; s->url = request->url; s->body = request->body;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s && s->auth) {
        size_t at = http->calls - 1; CHECK(!memcmp(s->auth + 7, s->keys[at].data, s->keys[at].len) && !s->auth[7 + s->keys[at].len]);
        char expected[100]; snprintf(expected, sizeof(expected), "https://api-ap-northeast-1.graphcms.com/v2/%s/master", s->ids[at]); CHECK(!strcmp(s->url, expected));
        CHECK(s->body.len == sizeof("{users {id name}}") - 1 && !memcmp(s->body.data, "{users {id name}}", sizeof("{users {id name}}") - 1)); s->auth = s->url = NULL; s->body = (br_slice){0};
    } else CHECK(!response->status && !response->body.data && !response->body_error);
    test_http_release(user, response);
}

static void verification(const br_detector *d)
{
    br_slice key = {keys[0], 1127}; const char *id = ids[0]; script s = {.keys = &key, .ids = &id, .count = 1};
    test_http http = {.user = &s, .inspect = inspect}; br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "graphcms-offline"};
    const int statuses[] = {199, 200, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = BYTES("\0\xff not JSON"), .body_error = i % 2 ? "" : "ignored read error"};
        br_results r = scan_value(d, &ctx, true, key); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !s.auth); check_result(&r.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&r);
    }
    const char *causes[] = {"cannot create GraphCMS result", "context deadline exceeded", "", NULL};
    for (size_t i = 0; i < 4; ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? -7 : 1; http.send_error = causes[i];
        br_results r = scan_value(d, &ctx, true, key); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); check_result(&r.items[0], key, false); br_results_clear(&r);
    }
    http.send_rc = 0; http.send_error = NULL; http.response = (br_http_response){.status = 200};
    unsigned char value[1140]; const br_slice allowed[] = {BYTES("\t"), BYTES("\xf0\x9f\x9a\x80")};
    for (size_t i = 0; i < 2; ++i) {
        key = token(value, allowed[i], allowed[i], 1); http.calls = http.releases = 0;
        br_results r = scan_value(d, &ctx, true, key); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1); check_result(&r.items[0], key, true); br_results_clear(&r);
    }
    key = token(value, BYTES("."), BYTES("\0"), 1); http.calls = http.releases = 0;
    br_results second_nul = scan_value(d, &ctx, true, key); CHECK(second_nul.len == 1 && !http.calls && !http.releases); check_result(&second_nul.items[0], key, false); br_results_clear(&second_nul);
    const br_slice blocked[] = {BYTES("\0"), BYTES("\v"), BYTES("\r")};
    for (size_t i = 0; i < 3; ++i) {
        key = token(value, blocked[i], blocked[i], 1); http.calls = http.releases = 0;
        br_results r = scan_value(d, &ctx, true, key); CHECK(r.len == 1 && !http.calls && http.releases == (i == 0 ? 0u : 1u)); check_result(&r.items[0], key, false); br_results_clear(&r);
        r = scan_value(d, NULL, true, key); CHECK(!r.len); br_results_clear(&r);
        r = scan_value(d, &ctx, false, key); CHECK(r.len == 1 && !http.calls); check_result(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void products(const br_detector *d)
{
    unsigned char input[7000]; size_t at = 0; br_slice expected_keys[9]; const char *expected_ids[9];
    for (size_t i = 0; i < 3; ++i) { memcpy(input + at, keys[i % 2], 1127); at += 1127; input[at++] = ';'; }
    memset(input + at, ' ', 1500); at += 1500;
    for (size_t i = 0; i < 3; ++i) { memcpy(input + at, "graph ", 6); at += 6; memcpy(input + at, ids[i % 2], 25); at += 25; input[at++] = ';'; }
    for (size_t i = 0; i < 9; ++i) { expected_keys[i] = (br_slice){keys[(i / 3) % 2], 1127}; expected_ids[i] = ids[(i % 3) % 2]; }
    script s = {.keys = expected_keys, .ids = expected_ids, .count = 9}; test_http http = {.user = &s, .inspect = inspect, .response = {.status = 201}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "graphcms-offline"};
    for (int verify = 0; verify < 2; ++verify) {
        br_results r = test_scan(d, &ctx, verify, input, at); CHECK(r.len == 9 && http.calls == (verify ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) check_result(&r.items[i], expected_keys[i], verify);
        CHECK(r.items[0].raw.data != r.items[1].raw.data); br_results_clear(&r);
    }
    br_results r = test_scan(d, NULL, true, input, at); CHECK(!r.len); br_results_clear(&r);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static void resources(const br_detector *d)
{
    br_slice key = {keys[0], 1127};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL, .user_agent = mode == 3 ? "bad\r\nagent" : NULL, .deadline_monotonic_ms = mode == 4 ? 1 : 0};
        size_t before = allocation_failures; br_results r = scan_value(d, &ctx, true, key);
        CHECK(r.len == 1 && !http.calls && http.releases == (mode ? 1u : 0u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u)); check_result(&r.items[0], key, false); br_results_clear(&r);
    }
    br_result seed = {0}; br_results out = {0}; CHECK(br_finding_key(&seed, 777, "caller", "key") == 0); seed.verified = true; CHECK(br_results_push(&out, &seed) == 0);
    unsigned char *raw = out.items[0].raw.data; br_json *parts = out.items[0].secret_parts;
    unsigned char input[1300]; char id_text[80]; snprintf(id_text, sizeof(id_text), "graph %s;graph %s", ids[0], ids[1]); br_slice data = input_for(input, key, id_text);
    for (int mode = 0; mode < 8; ++mode) {
        char *error = NULL; size_t cap = out.cap; test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        if (mode == 0) { fail_size = 1128; fail_after = 1; }
        if (mode == 1) { fail_size = 26; fail_after = 1; }
        if (mode == 2) fail_part_after = 2; /* Earlier appended finding must roll back. */
        if (mode == 3) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (mode == 4) out.cap = 0; /* Real push capacity guard, not a stub. */
        unsigned char nul[1140];
        if (mode == 5 || mode == 6) { br_slice k = token(nul, BYTES("\0"), BYTES("."), 0); data = input_for(input, k, id_text); fail_part_after = 1; }
        if (mode == 7) { data = input_for(input, key, id_text); fail_size = 1127; fail_after = 1; }
        CHECK(d->scan(d, mode == 6 ? NULL : &ctx, true, data, &out, &error) == -1 && error && !fail_after && !fail_part_after);
        out.cap = cap;
        const char *expected = mode < 2 ? "out of memory copying detector capture" : mode == 3 ? "out of memory iterating regex" : mode == 4 ? "cannot append GraphCMS result" : "cannot create GraphCMS result";
        CHECK(!strcmp(error, expected) && out.len == 1 && out.items[0].raw.data == raw && out.items[0].secret_parts == parts && out.items[0].verified && !memcmp(raw, "caller", 6));
        CHECK(http.calls == http.releases && http.calls == (mode == 2 || mode == 4 ? 1u : 0u)); free(error);
    }
    br_results_clear(&out);
}

int main(void)
{
    CHECK(token(keys[0], BYTES("!"), BYTES("?"), 0).len == 1127);
    CHECK(token(keys[1], BYTES("."), BYTES("Q"), 13).len == 1127);
    test_secret(ids[0], 25, 0); test_secret(ids[1], 25, 7);
    const br_detector *d = descriptor(); extraction(d); verification(d); products(d); resources(d);
    return test_finish("GraphCMS");
}
