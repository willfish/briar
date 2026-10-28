/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"
#include <curl/curl.h>
#include <limits.h>
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static char key[45], other_key[45];
static const char email[] = "User+tag@Example.test";
static const char quoted[] = "\"A\\ B+\x01Z\"@Example.test";
static size_t fail_form_after, form_allocations, fail_finding_after;
static bool track_form;
enum { int_text_length = 8193 };
static bool fail_int_text;
static size_t int_text_allocations;

void *malloc(size_t size)
{
    if (track_form && size == 34) {
        ++form_allocations;
        if (fail_form_after && --fail_form_after == 0) return NULL;
    }
    /* decode_int copies exactly the raw text length, unlike libxml's
     * NUL-terminated text storage. Arm only during the targeted scan. */
    if (fail_int_text && size == int_text_length) { ++int_text_allocations; return NULL; }
    return calloc(1, size);
}

struct json_object *json_object_new_string_len(const char *value, int len)
{
    CHECK(len == 44 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char text[45]; memcpy(text, value, (size_t)len); text[len] = 0;
    return json_object_new_string(text);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gocanvas_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(!br_gocanvas_init(&d, &error) && d && !error);
    CHECK(!br_gocanvas_init(&again, &error) && again == d && !error);
    CHECK(d->type == 714 && d->version == 0 && !strcmp(d->name, "GoCanvas") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "GoCanvas is a platform for automating business processes using mobile forms. GoCanvas API keys can be used to access and modify data within the GoCanvas platform."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gocanvas"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 714, expected, "key"); CHECK(r->verified == verified && !r->verification_error);
}

static char *input_for(const char *const *emails, size_t ne, const char *const *keys, size_t nk)
{
    size_t len = 1 + nk * 54;
    for (size_t i = 0; i < ne; ++i) len += strlen(emails[i]) + 10;
    char *input = malloc(len); CHECK(input); size_t at = 0;
    for (size_t i = 0; i < ne; ++i) {
        memcpy(input + at, "gocanvas", 8); at += 8;
        input[at++] = emails[i][0] == '"' ? 'X' : ' ';
        size_t n = strlen(emails[i]); memcpy(input + at, emails[i], n); at += n; input[at++] = '\n';
    }
    for (size_t i = 0; i < nk; ++i) {
        memcpy(input + at, "gocanvas ", 9); at += 9;
        memcpy(input + at, keys[i], 44); at += 44; input[at++] = '\n';
    }
    CHECK(at + 1 == len); input[at] = 0; return input;
}

static char *one_input(const char *address)
{
    const char *emails[] = {address}, *keys[] = {key}; return input_for(emails, 1, keys, 1);
}

static void expect(const br_detector *d, const char *input, size_t count)
{
    br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == count);
    for (size_t i = 0; i < r.len; ++i) check_result(&r.items[i], key, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[4096];
    snprintf(input, sizeof(input), "GoCaNvAs %s\n%s\n", email, key); expect(d, input, 1);
    snprintf(input, sizeof(input), "gocanvas %s", key); expect(d, input, 0); /* No EOF delimiter or email. */
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas %s", email, key); expect(d, input, 0);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas %s\t", email, key); expect(d, input, 0);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas %s \t", email, key); expect(d, input, 1);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas %s\r", email, key); expect(d, input, 1);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas _%s\n", email, key); expect(d, input, 0);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas A%s\n", email, key); expect(d, input, 0);
    snprintf(input, sizeof(input), "gocanvas %s\ngocanvas %s \n", email, key + 1); expect(d, input, 0);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "gocanvas %s\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\ngocanvas%*s%s\n", email, gap, "", key); expect(d, input, gap == 40);
    }
    /* No local 1024 cap: multipart span is only an engine hint. */
    char *far = malloc(2200); CHECK(far);
    size_t at = (size_t)sprintf(far, "gocanvas %s\n", email); memset(far + at, '!', 1800); at += 1800;
    sprintf(far + at, "\ngocanvas %s\n", key); expect(d, far, 1); free(far);
}

typedef struct {
    int status, send_rc; br_slice body; const char *body_error, *send_error, *encoded;
    size_t calls, releases; const unsigned char *borrowed_body; size_t borrowed_len;
    const char *borrowed_auth, *borrowed_url;
} script;

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    script *s = user; CHECK(ctx && s->calls == s->releases); ++s->calls;
    CHECK(request->detector_type == 714 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.gocanvas.com/apiv2/forms.xml"));
    CHECK(request->body.len && request->body.data && !request->dedup_key.len && request->nheaders == 3);
    bool type = false, auth = false, ua = false;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *h = &request->headers[i];
        if (!strcmp(h->name, "Content-Type")) { CHECK(!strcmp(h->value, "application/x-www-form-urlencoded")); type = true; }
        else if (!strcmp(h->name, "Authorization")) {
            CHECK(strlen(h->value) == 51 && !memcmp(h->value, "Bearer ", 7));
            CHECK(!memcmp(h->value + 7, key, 44) || !memcmp(h->value + 7, other_key, 44));
            s->borrowed_auth = h->value; auth = true;
        } else { CHECK(!strcmp(h->name, "User-Agent") && !strcmp(h->value, "TruffleHog")); ua = true; }
    }
    CHECK(type && auth && ua && request->body.len >= 9 && !memcmp(request->body.data, "username=", 9));
    if (s->encoded) CHECK(request->body.len == strlen(s->encoded) && !memcmp(request->body.data, s->encoded, request->body.len));
    s->borrowed_body = request->body.data; s->borrowed_len = request->body.len; s->borrowed_url = request->url;
    *response = (br_http_response){.status = s->status, .body = s->body, .body_error = s->body_error};
    *error = s->send_error ? strdup(s->send_error) : NULL;
    CHECK(!s->send_error || *error); return s->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    script *s = user; CHECK(response && s->calls == s->releases + 1);
    CHECK(s->borrowed_body && s->borrowed_len >= 9 && !memcmp(s->borrowed_body, "username=", 9));
    CHECK(s->borrowed_auth && strlen(s->borrowed_auth) == 51 && !memcmp(s->borrowed_auth, "Bearer ", 7));
    CHECK(!strcmp(s->borrowed_url, "https://www.gocanvas.com/apiv2/forms.xml"));
    ++s->releases;
}

static br_results run(const br_detector *d, const char *input, bool verify, script *s)
{
    br_transport transport = {s, send_response, release_response}; br_scan_ctx ctx = {.transport = &transport};
    br_results r = {0}; char *error = NULL;
    int rc = d->scan(d, &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
    if (rc || error) fprintf(stderr, "synthetic response status=%d body=%.*s error=%s\n", s->status, (int)s->body.len, s->body.data ? (const char *)s->body.data : "", error ? error : "(none)");
    CHECK(!rc && !error && s->calls == s->releases); return r;
}

static void xml_case(const br_detector *d, br_slice body, int status, const char *read_error,
                     size_t count, bool verified)
{
    char *input = one_input(email); script s = {.status = status, .body = body, .body_error = read_error, .encoded = "username=User%2Btag%40Example.test"};
    br_results r = run(d, input, true, &s); CHECK(s.calls == 1 && r.len == count);
    if (count) check_result(&r.items[0], key, verified);
    br_results_clear(&r); free(input);
}

static void products(const br_detector *d)
{
    const char *emails[] = {email, "user+tag@example.test", email}, *keys[] = {key, other_key, key};
    char *input = input_for(emails, 3, keys, 3);
    for (int v = 0; v < 2; ++v) {
        script s = {.status = 200, .body = TEXT("<anything/>")}; br_results r = run(d, input, v, &s);
        CHECK(r.len == 6 && s.calls == (v ? 6u : 0u));
        for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 3; ++k) check_result(&r.items[e * 3 + k], keys[k], v);
        br_results_clear(&r);
    }
    track_form = true; form_allocations = 0;
    br_results r = test_scan(d, NULL, true, input, strlen(input)); track_form = false;
    CHECK(!r.len && form_allocations == 6); /* Case changes do not change encoded length. */
    br_results_clear(&r); free(input);
    input = one_input(quoted); script s = {.status = 200, .body = TEXT("<r/>"), .encoded = "username=%22A%5C+B%2B%01Z%22%40Example.test"};
    r = run(d, input, true, &s); CHECK(r.len == 1); br_results_clear(&r); free(input);
    input = one_input("a@[127.0.0.1]Z"); s = (script){.status = 200, .body = TEXT("<r/>"), .encoded = "username=a%40%5B127.0.0.1%5D"};
    r = run(d, input, true, &s); CHECK(r.len == 1); br_results_clear(&r); free(input);
    char *large = malloc(8200); CHECK(large); memset(large, 'A', 8100); strcpy(large + 8100, "@Example.test");
    input = one_input(large); s = (script){.status = 200, .body = TEXT("<r/>")}; r = run(d, input, true, &s);
    CHECK(r.len == 1 && s.borrowed_len == 8124); br_results_clear(&r); free(input); free(large);
}

static void xml_contract(const br_detector *d)
{
    const int statuses[] = {199, 200, 204, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        int code = statuses[i]; xml_case(d, TEXT("<root/>"), code, NULL, 1, code >= 200 && code < 300);
        xml_case(d, TEXT("<root><Error/></root>"), code, NULL, 1, false);
        xml_case(d, TEXT("<root><Error><ErrorCode>bad</ErrorCode></Error></root>"), code, NULL, 0, false);
        xml_case(d, TEXT("<root><broken></root>"), code, NULL, 0, false);
    }
    const char *valid[] = {
        "<Error><ErrorCode>nonnumeric ignored root field</ErrorCode></Error>",
        "<root><error/><Wrapper><Error><ErrorCode>invalid ignored</ErrorCode></Error></Wrapper></root>",
        "<?xml version='1.0' encoding='UTF-8'?><arbitrary><!-- <!DOCTYPE harmless> --></arbitrary>"
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) xml_case(d, (br_slice){(const unsigned char *)valid[i], strlen(valid[i])}, 200, NULL, 1, true);
    const char *errors[] = {
        "<r xmlns:e='urn:test'><e:Error/></r>",
        "<r><Error><ErrorCode/></Error></r>",
        "<r><Error><ErrorCode><nested>invalid</nested></ErrorCode></Error></r>",
        "<r><Error><ErrorCode> +<![CDATA[12]]><!-- ignored --><nested>nonnumeric</nested>3 </ErrorCode></Error></r>",
        "<r><Error><ErrorCode>-9223372036854775808</ErrorCode><ErrorCode>9223372036854775807</ErrorCode></Error></r>",
        "<r><Error><ErrorCode>\xc2\xa0+42\xe3\x80\x80</ErrorCode></Error></r>"
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) xml_case(d, (br_slice){(const unsigned char *)errors[i], strlen(errors[i])}, 200, NULL, 1, false);
    const char *drops[] = {
        "", " \r\n\t", "<r><Error><ErrorCode> </ErrorCode></Error></r>",
        "<r><Error><ErrorCode>9223372036854775808</ErrorCode></Error></r>",
        "<r><Error><ErrorCode>-9223372036854775809</ErrorCode></Error></r>",
        "<r><Error><ErrorCode>1e3</ErrorCode></Error></r>",
        "<r><Error><ErrorCode>bad</ErrorCode><ErrorCode>0</ErrorCode></Error></r>",
        "<r><Error><ErrorCode>0</ErrorCode><ErrorCode>bad</ErrorCode></Error></r>",
        "<?xml version='1.1'?><r/>", "<?xml version='1.0' encoding='ISO-8859-1'?><r/>"
    };
    for (size_t i = 0; i < sizeof(drops) / sizeof(drops[0]); ++i) xml_case(d, (br_slice){(const unsigned char *)drops[i], strlen(drops[i])}, 200, NULL, 0, false);
    xml_case(d, TEXT("<r/>"), 200, "", 1, false);
    xml_case(d, TEXT(""), 200, "read failure", 1, false);
    xml_case(d, TEXT("<r><broken></r>"), 200, "read failure", 1, false);
    char *input = one_input(email);
    const char *causes[] = {"synthetic Do failure", "out of memory", "net/http: nil Context", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script s = {.status = 200, .body = TEXT("<r/>"), .send_rc = 1, .send_error = causes[i]};
        br_results r = run(d, input, true, &s); CHECK(r.len == 1); check_result(&r.items[0], key, false); br_results_clear(&r);
    }
    free(input);
}

static void first_int_failure(const br_detector *d)
{
    static const char prefix[] = "<r><Error><ErrorCode>bad</ErrorCode><ErrorCode>";
    static const char between[] = "</ErrorCode></Error><Error><ErrorCode>";
    static const char suffix[] = "</ErrorCode></Error></r>";
    size_t len = sizeof(prefix) - 1 + int_text_length + sizeof(between) - 1 + int_text_length + sizeof(suffix) - 1;
    char *body = malloc(len); CHECK(body); size_t at = 0;
    memcpy(body + at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memset(body + at, '0', int_text_length); at += int_text_length;
    memcpy(body + at, between, sizeof(between) - 1); at += sizeof(between) - 1;
    memset(body + at, '0', int_text_length); at += int_text_length;
    memcpy(body + at, suffix, sizeof(suffix) - 1); at += sizeof(suffix) - 1; CHECK(at == len);
    char *input = one_input(email);
    script s = {.status = 200, .body = {(const unsigned char *)body, len}};
    br_transport t = {&s, send_response, release_response}; br_scan_ctx ctx = {.transport = &t};
    br_results r = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key"));
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&r, &prior));
    unsigned char *saved = r.items[0].raw.data; char *saved_error = r.items[0].verification_error;
    br_json *saved_parts = r.items[0].secret_parts; char *error = NULL;
    /* Both later fields are unreachable: a duplicate ErrorCode in this Error,
     * then an ErrorCode in its sibling Error. Neither may allocate after bad. */
    int_text_allocations = 0; fail_int_text = true;
    int rc = d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
    fail_int_text = false;
    CHECK(int_text_allocations == 0);
    CHECK(rc == 0 && error == NULL && r.len == 1 && s.calls == 1 && s.releases == 1);
    CHECK(r.items[0].detector_type == 777 && r.items[0].raw.data == saved && r.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    CHECK(r.items[0].verified && r.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned") && r.items[0].secret_parts == saved_parts);
    free(error); br_results_clear(&r); free(input); free(body);
}

static void fatal_cases(const br_detector *d)
{
    const char *bodies[] = {
        "<!DOCTYPE r SYSTEM 'file:///definitely-not-readable-gocanvas'><r/>",
        "<!DOCTYPE r SYSTEM 'https://invalid.test/no-network'><r/>",
        "<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///not-readable'>]><r>&x;</r>",
        "<r/>trailing", "<r/><second/>", "preceding<r/>", "<r><undefined:Error/></r>"
    };
    char *input = one_input(email);
    for (size_t i = 0; i <= sizeof(bodies) / sizeof(bodies[0]); ++i) {
        script s = {.status = 200};
        if (i < sizeof(bodies) / sizeof(bodies[0])) s.body = (br_slice){(const unsigned char *)bodies[i], strlen(bodies[i])};
        else s.body = (br_slice){(const unsigned char *)"x", (size_t)INT_MAX + 1};
        br_transport t = {&s, send_response, release_response}; br_scan_ctx ctx = {.transport = &t};
        br_results r = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); CHECK(!br_results_push(&r, &prior));
        unsigned char *saved = r.items[0].raw.data; char *error = NULL;
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) == -1);
        CHECK(error && strstr(error, i == sizeof(bodies) / sizeof(bodies[0]) ? "resource failure" : "unsupported:"));
        CHECK(r.len == 1 && r.items[0].raw.data == saved && !memcmp(saved, "prior", 5) && s.calls == 1 && s.releases == 1);
        free(error); br_results_clear(&r);
    }
    free(input);
    const char *emails[] = {email}, *keys[] = {key, other_key}; input = input_for(emails, 1, keys, 2);
    for (int mode = 0; mode < 3; ++mode) {
        script s = {.status = 200, .body = TEXT("<r/>")}; br_transport t = {&s, send_response, release_response}; br_scan_ctx ctx = {.transport = &t};
        br_results r = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); CHECK(!br_results_push(&r, &prior));
        unsigned char *saved = r.items[0].raw.data; char *error = NULL;
        if (mode == 2) fail_finding_after = 2; else fail_form_after = 2;
        track_form = true; form_allocations = 0;
        int rc = d->scan(d, mode == 1 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        track_form = false;
        CHECK(rc == -1 && error && !fail_form_after && !fail_finding_after);
        CHECK(r.len == 1 && r.items[0].raw.data == saved && !memcmp(saved, "prior", 5));
        CHECK(s.calls == (mode == 1 ? 0u : 1u) && s.releases == s.calls && form_allocations == (mode == 2 ? 1u : 2u));
        free(error); br_results_clear(&r);
    }
    free(input);
}

static void native_guard(const br_detector *d)
{
    char *error = NULL; const br_transport *native = br_curl_transport_init(&error); CHECK(native && !error);
    br_scan_ctx ctx = {.transport = native};
    br_http_request req = {.method = "GET", .url = "https://invalid.test/no-network", .profile = BR_HTTP_SANE, .body = TEXT("username=synthetic")};
    br_http_response response = {0};
    CHECK(br_http_send(&ctx, &req, &response, &error) != 0 && error && !strcmp(error, "unsupported: curl adapter supports bodyless GET or POST"));
    br_http_release(&ctx, &response); free(error);
    char *input = one_input(email); br_results r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1); check_result(&r.items[0], key, false); br_results_clear(&r); free(input); curl_global_cleanup();
}

int main(void)
{
    test_secret(key, 43, 1); key[4] = 'Z'; key[9] = '/'; key[17] = '+'; key[42] = 'z'; key[43] = '='; key[44] = 0;
    memcpy(other_key, key, sizeof(key)); other_key[2] = 'T';
    const br_detector *d = descriptor(); extraction(d); products(d); xml_contract(d); first_int_failure(d); fatal_cases(d); native_guard(d);
    return test_finish("GoCanvas required-hidden email products, GET form, ReadAll/XML boundaries and rollback");
}
