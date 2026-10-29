/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error intercom_real_setter
#define br_results_push intercom_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

/* Synthetic encodings of tok: followed by bytes 0..39, 255..216, or 0..36. */
static const char key[] = "dG9rOgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJic=";
static const char other[] = "dG9rOv/+/fz7+vn49/b19PPy8fDv7u3s6+rp6Ofm5eTj4uHg397d3Nva2dg=";
static const char short_key[] = "dG9rOgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQ=";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls;
static size_t failed_allocations;
static bool fail_agent;

/* Reuse the existing named-test allocation and positive-return seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return intercom_real_setter(result, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 7;
    return intercom_real_push(out, owned);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 60 && strlen(other) == 60 && strlen(short_key) == 56);
    CHECK(br_intercom_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Intercom detector output")); free(error); error = NULL;
    CHECK(br_intercom_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:intercom)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_intercom_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_intercom_init(&d, &error) == 0 && d && !error);
    CHECK(br_intercom_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 156 && d->version == 0 && !strcmp(d->name, "Intercom") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Intercom is a customer messaging platform that allows businesses to communicate with customers. Intercom tokens can be used to access and manage customer data and communication."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "intercom"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 156, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK((size_t)json_object_get_string_len(part) == strlen(expected));
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "invalid\r\nagent"};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static size_t fixture(unsigned char *out, const char *prefix, const void *token, size_t len)
{
    size_t n = strlen(prefix);
    memcpy(out, prefix, n); memcpy(out + n, token, len);
    return n + len;
}

static void extraction(const br_detector *d)
{
    char input[512], changed[61];
    const char *good[] = {"intercom '%s'", "InTeRcOm\r\n%s", "myINTERCOMsuffix:%s", "intercom-%s", "intercom %sword", "intercom %s="};
    const char *bad[] = {"%s", "%s intercom", "inter-com %s", "intercom%s", "intercom X%s", "intercom _%s", "intercom %.59s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], key); extract(d, input, strlen(input), key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract(d, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "intercom", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key, 60);
        extract(d, input, 68 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 8 + 4 * gap, key, 60);
        extract(d, input, 68 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "intercom\0", 9); memcpy(input + 9, key, 60); extract(d, input, 69, key);
    snprintf(input, sizeof(input), "intercom %s %s", key, other); extract(d, input, strlen(input), key);
    memcpy(changed, key, sizeof(key)); changed[58] = 'f'; /* Non-strict unused pad bits. */
    snprintf(input, sizeof(input), "intercom %s", changed); extract(d, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); memcpy(changed, "VE9L", 4); /* TOK:, not tok:. */
    snprintf(input, sizeof(input), "intercom %s", changed); extract(d, input, strlen(input), NULL);
    memset(changed, 'A', 59); changed[59] = '='; changed[60] = '\0';
    snprintf(input, sizeof(input), "intercom %s", changed); extract(d, input, strlen(input), NULL);
    extract(d, NULL, 0, NULL);
}

static void captured_then_rejected(const br_detector *d, const void *token, size_t len)
{
    unsigned char input[512]; size_t n = fixture(input, "intercom ", token, len);
    br_captures captures = {0}; char *error = NULL;
    CHECK(br_captures_find(d->state, (br_slice){input, n}, &captures, false, &error) == 0 && !error);
    CHECK(captures.len == 1 && captures.lengths[0] == len && !memcmp(captures.items[0], token, len));
    br_captures_clear(&captures);
    extract(d, input, n, NULL);
    br_results out = test_scan(d, NULL, true, input, n);
    CHECK(!out.len); br_results_clear(&out);
}

static void decoding_and_trim(const br_detector *d)
{
    unsigned char input[512], token[256];
    const unsigned char corrupt[] = {'@', '=', ' ', '\t', '\v', '\f', 0};
    for (size_t i = 0; i < sizeof(corrupt); ++i) {
        memcpy(token, key, 60); token[20] = corrupt[i];
        /* Every corrupt case has an already-decodable tok: prefix. */
        captured_then_rejected(d, token, 60);
    }
    memcpy(token, key, 20); memcpy(token + 20, "\xf0\x9f\x92\xa1", 4); memcpy(token + 24, key + 21, 39);
    captured_then_rejected(d, token, 63); /* 60 RUNES, not 60 bytes. */
    const char *spaces[] = {" ", "\t", "\r", "\n", "\v", "\f", "\xc2\x85", "\xc2\xa0", "\xe3\x80\x80"};
    for (size_t i = 0; i < sizeof(spaces) / sizeof(*spaces); ++i) {
        size_t width = strlen(spaces[i]);
        for (size_t j = 0; j < 4; ++j) memcpy(token + j * width, spaces[i], width);
        memcpy(token + 4 * width, short_key, 56);
        /* Boundary after keyword's final word rune admits leading whitespace. */
        size_t n = fixture(input, "intercom", token, 4 * width + 56);
        extract(d, input, n, short_key);
        br_results out = test_scan(d, NULL, false, input, n);
        CHECK(out.len == 1); result_is(&out.items[0], short_key, false); br_results_clear(&out);
    }
    memset(token, ' ', 52); memcpy(token + 52, "dG9rOg==", 8);
    size_t n = fixture(input, "intercom", token, 60);
    extract(d, input, n, "dG9rOg=="); /* Exactly tok:, with no decoded remainder. */
    token[52 + 5] = 'v'; /* Non-strict two-pad-bit quantum remains tok:. */
    n = fixture(input, "intercom", token, 60); extract(d, input, n, "dG9rOv==");
    memset(token, ' ', 56); memcpy(token + 56, "Zg==", 4);
    n = fixture(input, "intercom", token, 60); extract(d, input, n, NULL); /* Decoded len < 4. */
}

typedef struct {
    const char *keys[3], *agent;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth, *borrowed_url;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && at < 3 && ctx == s->ctx && http->releases == at && !s->borrowed_auth);
    CHECK(request->detector_type == 156 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.intercom.io/contacts?per_page=5"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, s->keys[at]));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, s->agent));
    /* Only provider originals, never effective request/header-array/UA storage. */
    s->borrowed_auth = request->headers[0].value; s->borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(http->calls == http->releases + 1);
        CHECK(!strncmp(s->borrowed_auth, "Bearer ", 7) && !strcmp(s->borrowed_auth + 7, s->keys[http->calls - 1]));
        CHECK(!strcmp(s->borrowed_url, "https://api.intercom.io/contacts?per_page=5"));
        s->borrowed_auth = s->borrowed_url = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void occurrences_and_construction(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "intercom %s\nintercom %s\nintercom %s", key, other, key);
    script s = {.keys = {key, other, key}, .agent = "TruffleHog intercom-offline", .count = 3};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "intercom-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], s.keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    fail_size = sizeof("Bearer ") + 60; fail_after = 1;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && fail_after == 1); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && fail_after == 1); br_results_clear(&out); fail_after = 0;
    memset(input, '\v', 52); memcpy(input + 52, "dG9rOg==", 8);
    unsigned char short_input[128]; size_t n = fixture(short_input, "intercom", input, 60);
    s.keys[0] = "dG9rOg=="; s.count = 1; http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, short_input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], s.keys[0], true); br_results_clear(&out);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void verification(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "intercom %s", key);
    script s = {.keys = {key}, .agent = "TruffleHog", .count = 1};
    test_http http = {.user = &s, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored partial read"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {7, "cannot allocate Intercom authorization"}, {-1, "cannot decode Intercom Base64"},
        {1, "out of memory constructing HTTP headers"}, {-1, key}, {1, ""}, {1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_transport missing_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i >= 5 ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    /* A valid 56-byte encoding plus four interior CR/LF runes fits the capture.
     * Preserve those bytes in Raw/auth: ordinary header validation rejects it. */
    char crlf[61]; memcpy(crlf, short_key, 8); memcpy(crlf + 8, "\r\n\r\n", 4); memcpy(crlf + 12, short_key + 8, 49);
    size_t n = fixture((unsigned char *)input, "intercom ", crlf, 60);
    extract(d, input, n, crlf);
    http.calls = http.releases = 0;
    br_results out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && !http.calls && http.releases == 1); result_is(&out.items[0], crlf, false); br_results_clear(&out);
    CHECK(cancellations == 1 && !setter_calls && !s.borrowed_auth && !s.borrowed_url);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "intercom %s\nintercom %s", key, other);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    script s = {.keys = {key, other}, .agent = "TruffleHog", .count = 2};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    char *error = NULL;
    const struct { const char *cause; size_t calls; } cases[] = {
        {"out of memory copying detector capture", 0}, {"out of memory iterating regex", 0},
        {"cannot decode Intercom Base64", 0}, {"cannot create Intercom finding", 0},
        {"cannot decode Intercom Base64", 1}, {"cannot create Intercom finding", 1},
        {"cannot allocate Intercom authorization", 1}, {"cannot append Intercom finding", 2},
        {"cannot create Intercom finding", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        http.calls = http.releases = 0;
        if (i == 0) { fail_size = 61; fail_after = 2; }
        if (i == 1) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (i == 2) { fail_size = 45; fail_after = 1; }
        if (i == 3) fail_part_after = 1;
        if (i == 4) { fail_size = 45; fail_after = 2; }
        if (i == 5) fail_part_after = 2;
        if (i == 6) { fail_size = sizeof("Bearer ") + 60; fail_after = 2; }
        if (i == 7) fail_push_after = 2;
        if (i == 8) { fail_size = 60; fail_after = 2; }
        const br_scan_ctx *scan_ctx = i <= 3 ? NULL : &ctx;
        CHECK(d->scan(d, scan_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].cause)); free(error); error = NULL;
        CHECK(!fail_after && !fail_part_after && !fail_push_after);
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !s.borrowed_auth && !s.borrowed_url);
        prior_unchanged(&out, &prior);
    }
    /* Decoder resources fail even in NoV and before ordinary corruption drops. */
    input[9 + 20] = '@'; fail_size = 45; fail_after = 1;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode Intercom Base64") && !fail_after); free(error); error = NULL;
    prior_unchanged(&out, &prior); input[9 + 20] = key[20];
    /* A later owned failure beats an earlier suppressed mixed Do failure. */
    http.calls = http.releases = 0; http.send_rc = 1; http.send_error = "cannot decode Intercom Base64";
    fail_size = 45; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode Intercom Base64") && !fail_after); free(error); error = NULL;
    CHECK(http.calls == 1 && http.releases == 1); prior_unchanged(&out, &prior);
    fail_push_after = 2;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Intercom finding") && !fail_push_after); free(error);
    prior_unchanged(&out, &prior);
    fail_size = sizeof("Bearer ") + 60; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && !fail_after);
    prior_unchanged(&out, &prior);
    br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    decoding_and_trim(d);
    occurrences_and_construction(d);
    verification(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_agent && !setter_calls);
    return test_finish("Intercom rune capture/trim/Base64/metadata/auth/status/errors/release/rollback");
}
