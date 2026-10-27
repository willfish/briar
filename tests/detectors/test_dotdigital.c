/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char email[] = "apiuser-a1b2c3d4e5f6@apiconnector.com";
static const char other[] = "apiuser-z9y8x7w6v5u4@apiconnector.com";
static const char pass[] = "Abcd1234", second[] = "Zyxw9876", third[] = "LastKey9";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, basic_allocations;
static const char *fail_duplicate;
static size_t fail_duplicate_after;

/* Target existing resource APIs, not production-only failure switches. */
void *malloc(size_t size)
{
    if (size == 71) ++basic_allocations; /* Basic(EMAIL37:PASSWORD8) plus NUL. */
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(text, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(text) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(email) == 37 && strlen(other) == 37);
    CHECK(br_dotdigital_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_dotdigital_init(&d, &error) == 0 && d && !error);
    CHECK(br_dotdigital_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 325 && d->version == 0 && !strcmp(d->name, "Dotdigital") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Dotdigital is an email marketing automation platform. API keys can be used to access and manage email campaigns and related data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "@apiconnector.com"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void json_part(br_json *parts, const char *name, br_slice expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, name, &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)expected.len && !memcmp(json_object_get_string(part), expected.data, expected.len));
}

static void pair_result(const br_result *r, br_slice e, br_slice p, bool verified, const char *error)
{
    CHECK(r->detector_type == 325 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == e.len && !memcmp(r->raw.data, e.data, e.len));
    CHECK(r->raw_v2.len == e.len + p.len && !memcmp(r->raw_v2.data, e.data, e.len));
    CHECK(!memcmp(r->raw_v2.data + e.len, p.data, p.len));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    json_part(r->secret_parts, "email", e); json_part(r->secret_parts, "password", p);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
}

static br_slice fixture(unsigned char *out, br_slice e, const char *prefix, br_slice p)
{
    size_t at = 0, n = strlen(prefix);
    memcpy(out + at, e.data, e.len); at += e.len; out[at++] = '\n';
    memcpy(out + at, prefix, n); at += n;
    memcpy(out + at, p.data, p.len); at += p.len; out[at++] = '\n';
    return (br_slice){out, at};
}

static void extract_case(const br_detector *d, br_slice data, br_slice e, br_slice p, bool found)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, data.data, data.len);
    CHECK(out.len == (found ? 1u : 0u) && !http.calls && !http.releases);
    if (found) pair_result(&out.items[0], e, p, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    unsigned char input[1800]; br_slice e = TEXT(email), p = TEXT(pass), data;
    const char *prefixes[] = {"pass ", "pW ", "PaSs\r\n", "prePASSsuffix "};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
        extract_case(d, fixture(input, e, prefixes[i], p), e, p, true);
    extract_case(d, fixture(input, e, "secret ", p), e, p, false);
    char changed[39]; const size_t positions[] = {0, 8, 21};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        memcpy(changed, email, sizeof(email)); changed[positions[i]] = 'A';
        extract_case(d, fixture(input, text(changed), "pw ", p), text(changed), p, false);
    }
    snprintf(changed, sizeof(changed), "_%s", email);
    extract_case(d, fixture(input, text(changed), "pw ", p), e, p, false);
    snprintf(changed, sizeof(changed), "%s_", email);
    extract_case(d, fixture(input, text(changed), "pw ", p), e, p, false);
    memcpy(changed, email, sizeof(email)); changed[33] = 'X'; /* Pinned unescaped '.' is a wildcard. */
    extract_case(d, fixture(input, text(changed), "pw ", p), text(changed), p, true);
    char wrong[] = "apiuser-a1b2c3d4e5f@apiconnector.com";
    extract_case(d, fixture(input, text(wrong), "pw ", p), e, p, false);
    char long_uid[] = "apiuser-a1b2c3d4e5f67@apiconnector.com";
    extract_case(d, fixture(input, text(long_uid), "pw ", p), e, p, false);
    char password[26]; memset(password, 'A', 25); password[25] = '\0';
    for (size_t n = 7; n <= 25; n += n == 7 ? 1 : n == 8 ? 16 : 1)
        extract_case(d, fixture(input, e, "pw ", (br_slice){(const unsigned char *)password, n}), e,
                     (br_slice){(const unsigned char *)password, n}, n == 8 || n == 24);
    for (int gap = 40; gap <= 41; ++gap) {
        char prefix[48]; CHECK(snprintf(prefix, sizeof(prefix), "pw%*s", gap, "") == gap + 2);
        extract_case(d, fixture(input, e, prefix, p), e, p, gap == 40);
    }
    const unsigned char excluded[] = {'\t', '\n', '\f', '\r', ' '};
    unsigned char split[] = "AbcdX1234";
    for (size_t i = 0; i < sizeof(excluded); ++i) {
        split[4] = excluded[i];
        extract_case(d, fixture(input, e, "pass ", (br_slice){split, 9}), e, p, false);
    }
    const char vt[] = "Abcd\v1234", nul[] = "Abcd\0" "1234", unicode[] = "Abcd\xc2\xa0" "1234";
    const br_slice special[] = {TEXT(vt), TEXT(nul), TEXT(unicode), TEXT("Abc:!234")};
    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); ++i)
        extract_case(d, fixture(input, e, "pass ", special[i]), e, special[i], true);
    extract_case(d, fixture(input, e, "pass", TEXT("=Abcd1234")), e, TEXT("=Abcd1234"), true);
    extract_case(d, fixture(input, e, "pass", TEXT("\xc2\xa0" "Abcd1234")), e, TEXT("\xc2\xa0" "Abcd1234"), true); /* No TrimSpace. */
    unsigned char wide[46]; wide[0] = 'A';
    for (size_t i = 0; i < 22; ++i) { wide[1 + 2 * i] = 0xc2; wide[2 + 2 * i] = 0xa0; } wide[45] = 'Z';
    extract_case(d, fixture(input, e, "pw ", (br_slice){wide, sizeof(wide)}), e, (br_slice){wide, sizeof(wide)}, true); /* 24 runes, 46 bytes. */
    memcpy(input, email, 37); memset(input + 37, ' ', 1300);
    int n = snprintf((char *)input + 1337, sizeof(input) - 1337, "\npass %s", pass); CHECK(n == 14);
    extract_case(d, (br_slice){input, 1337 + (size_t)n}, e, p, true); /* No detector-local 1024-byte cap. */
    data = fixture(input, TEXT("not-an-email"), "pw ", p); extract_case(d, data, e, p, false);
}

typedef struct { br_slice email, password; int status, rc; const char *error; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx;
    const char *borrowed_auth; br_slice borrowed_email, borrowed_password;
    bool suffix;
} script;

static void check_basic(const char *auth, br_slice e, br_slice p)
{
    CHECK(auth && !strncmp(auth, "Basic ", 6));
    size_t n = strlen(auth + 6); CHECK(n && n % 4 == 0 && n < 256);
    unsigned char decoded[256]; int size = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, (int)n);
    CHECK(size >= 0); size -= auth[6 + n - 1] == '='; size -= auth[6 + n - 2] == '=';
    CHECK((size_t)size == e.len + 1 + p.len && !memcmp(decoded, e.data, e.len) && decoded[e.len] == ':');
    CHECK(!memcmp(decoded + e.len + 1, p.data, p.len));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 325 && request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://r1-api.dotdigital.com/v2/account-info"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    check_basic(request->headers[0].value, row->email, row->password);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, s->suffix ? "TruffleHog dotdigital-offline" : "TruffleHog"));
    s->borrowed_auth = request->headers[0].value; s->borrowed_email = row->email; s->borrowed_password = row->password;
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)}, .body_error = "ignored read/drain error"};
    http->send_rc = row->rc; http->send_error = row->error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    check_basic(s->borrowed_auth, s->borrowed_email, s->borrowed_password); s->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "dotdigital-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_auth);
    return out;
}

static void products_and_breaks(const br_detector *d)
{
    char input[320]; int n = snprintf(input, sizeof(input), "%s\n%s\n%s\npw %s\npass %s\npw %s\npass %s", email, other, email, pass, second, pass, third);
    CHECK(n > 0 && (size_t)n < sizeof(input)); br_slice data = {(const unsigned char *)input, (size_t)n};
    const br_slice emails[] = {TEXT(email), TEXT(other)}, passwords[] = {TEXT(pass), TEXT(second), TEXT(third)};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 6);
    for (size_t e = 0; e < 2; ++e) for (size_t p = 0; p < 3; ++p)
        pair_result(&out.items[e * 3 + p], emails[e], passwords[p], false, NULL);
    CHECK(out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
    const reply rows[] = {
        {TEXT(email), TEXT(pass), 200, 1, "outer: Abcd1234 apiuser-a1b2c3d4e5f6@apiconnector.com"},
        {TEXT(email), TEXT(second), 200, 0, NULL}, {TEXT(other), TEXT(pass), 401, 0, NULL},
        {TEXT(other), TEXT(second), 204, 0, NULL}, {TEXT(other), TEXT(third), 200, 0, NULL},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 5);
    const char *errors[] = {rows[0].error, NULL, NULL, "unexpected status code: 204", NULL};
    for (size_t i = 0; i < 5; ++i) pair_result(&out.items[i], rows[i].email, rows[i].password, i == 1 || i == 4, errors[i]);
    br_results_clear(&out);
    size_t before = basic_allocations; out = test_scan(d, NULL, true, data.data, data.len);
    CHECK(out.len == 6 && basic_allocations == before);
    for (size_t e = 0; e < 2; ++e) for (size_t p = 0; p < 3; ++p)
        pair_result(&out.items[e * 3 + p], emails[e], passwords[p], false, "net/http: nil Context");
    br_results_clear(&out);
    /* Bytewise sets must not conflate passwords which differ after NUL. */
    unsigned char binary[160]; br_slice first = TEXT("Abcd\0" "1234"), last = TEXT("Abcd\0" "5678");
    br_slice b = fixture(binary, TEXT(email), "pw ", first); size_t at = b.len;
    memcpy(binary + at, "pass ", 5); at += 5; memcpy(binary + at, last.data, last.len); at += last.len; binary[at++] = '\n';
    out = test_scan(d, NULL, false, binary, at); CHECK(out.len == 2);
    pair_result(&out.items[0], TEXT(email), first, false, NULL); pair_result(&out.items[1], TEXT(email), last, false, NULL); br_results_clear(&out);
}

static void verification(const br_detector *d)
{
    unsigned char input[256]; br_slice data = fixture(input, TEXT(email), "pass ", TEXT(pass));
    const int statuses[] = {200, 401, 201, 204, 299, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {TEXT(email), TEXT(pass), statuses[i], 0, NULL}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1);
        char error[64]; CHECK(snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]) > 0);
        pair_result(&out.items[0], row.email, row.password, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : error); br_results_clear(&out);
    }
    const char *causes[] = {"net/http: nil Context", "outer: inner: Abcd1234", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {TEXT(email), TEXT(pass), 200, i % 2 ? -7 : 1, causes[i]}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1);
        pair_result(&out.items[0], row.email, row.password, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    unsigned char wide[46]; wide[0] = 'A';
    for (size_t i = 0; i < 22; ++i) { wide[1 + 2 * i] = 0xc2; wide[2 + 2 * i] = 0xa0; } wide[45] = 'Z';
    const br_slice passwords[] = {TEXT("Abcd\0" "1234"), TEXT("Abcd\xc2\xa0" "1234"), TEXT("Abcd\v1234"),
        {wide, sizeof(wide)}, TEXT("Abc:!234")};
    for (size_t i = 0; i < sizeof(passwords) / sizeof(passwords[0]); ++i) {
        data = fixture(input, TEXT(email), "pass ", passwords[i]);
        reply row = {TEXT(email), passwords[i], 200, 0, NULL}; script s = {.rows = &row, .count = 1};
        br_results out = run(d, data, true, &s); CHECK(out.len == 1); pair_result(&out.items[0], row.email, row.password, true, NULL); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }

static void shared_send_domain(const br_detector *d)
{
    unsigned char input[96]; br_slice data = fixture(input, TEXT(email), "pass ", TEXT(pass));
    const char *errors[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, data.data, data.len);
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        pair_result(&out.items[0], TEXT(email), TEXT(pass), false, errors[mode]); br_results_clear(&out);
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
    char input[160]; CHECK(snprintf(input, sizeof(input), "%s\n%s\npass %s", email, other, pass) > 0); br_slice data = text(input);
    const reply rows[] = {{TEXT(email), TEXT(pass), 200, 0, NULL}, {TEXT(other), TEXT(pass), 200, 0, NULL}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "cannot create Dotdigital result", "cannot create Dotdigital result", "cannot create Dotdigital result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 2; } /* Genuine +1 from password capture iteration. */
            if (failure == 1) { fail_size = 37; fail_after = 2; }
            if (failure == 2) { fail_size = 45; fail_after = 2; } /* RawV2. */
            if (failure == 3) fail_part_after = 4; /* +1 adding the second pair's password. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure ? 1u : 0u) && http.releases == http.calls && !s.borrowed_auth);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        br_results_clear(&out);
    }
    /* Basic's actual +1 allocation failure must roll back a prior verified pair. */
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
    script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    fail_size = 71; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
    /* A real +1 setter failure after the second response is fatal, not a break. */
    const reply status_rows[] = {rows[0], {TEXT(other), TEXT(pass), 503, 0, NULL}};
    s.rows = status_rows; http.calls = http.releases = 0; fail_duplicate = "unexpected status code: 503"; fail_duplicate_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dotdigital verification error") && !fail_duplicate_after);
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&out, &saved); free(error); error = NULL;
    fail_duplicate = "net/http: nil Context"; fail_duplicate_after = 2; size_t before = basic_allocations;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot set Dotdigital verification error") && !fail_duplicate_after);
    CHECK(basic_allocations == before); check_prior(&out, &saved); free(error); error = NULL;
    /* Genuine +1 push failure AFTER a verified response, before its private break. */
    s.rows = rows; http.calls = http.releases = 0; size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Dotdigital result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); products_and_breaks(d); verification(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after);
    return test_finish("Dotdigital");
}
