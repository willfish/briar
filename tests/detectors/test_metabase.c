/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../../src/go_url.h"
#include "../support/detector_test.h"

int br_metabase_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[37], other[37];
typedef enum { NONE, COMPILE, CAPTURE, PARSE, DECODE, FINDING, DOCUMENT, PUSH, BIG_HOST } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, freed_patterns, captures, parses, decodes, findings, documents, projections, sends, releases;
static int document_failure;
static const br_regex *key_pattern, *url_pattern;
static br_result *active_result;
static br_go_url_parts *active_parts;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static const char *expected_url = "http://Host.test/api/user/current", *expected_agent = "TruffleHog";
static char events[256];
static size_t nevents;
static bool watch, projecting, product_requests;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
/* Existing per-module seams exercise explicit ownership failures, not a new
 * transport/verdict framework or production injection/configuration surface. */
static int checked_compile(const char *const *words, size_t n, const char *capture, br_regex **out, char **error)
{
    CHECK(n == 1 && !strcmp(words[0], "metabase"));
    CHECK(!strcmp(capture, "\\b([a-zA-Z0-9-]{36})\\b") || !strcmp(capture, "\\b(https?:\\/\\/[-a-zA-Z0-9@:%._\\+~#=]{7,256})\\b"));
    int rc = br_regex_compile_prefixed(words, n, capture, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *r, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && (r == key_pattern || r == url_pattern)); ++captures; event(r == key_pattern ? 'K' : 'U');
    int rc = br_captures_find(r, input, out, unique, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_parse(br_slice original, br_go_url_parts *out, br_go_url_error *ordinary, char **error)
{
    CHECK(!active_result && !active_parts && !provider_request); ++parses; event('A'); projecting = false; active_parts = out;
    int rc = br_go_url_parse(original, out, ordinary, error);
    if (rc == 0 && hit(PARSE)) { ordinary->kind = BR_GO_URL_ESCAPE; return 1; }
    if (rc == 0 && hit(BIG_HOST)) {
        /* Artificial helper projection overflow proves private bounded-builder
         * failure beats nil-context skip. This is not an accepted URL fixture. */
        static unsigned char oversized[1024]; memset(oversized, 'x', sizeof(oversized));
        out->host = (br_slice){oversized, sizeof(oversized)};
    }
    return rc;
}
static int checked_decode(br_slice raw, bool query, br_bytes *out, bool *valid, char **error)
{
    CHECK(!query && active_parts && !active_result); ++decodes; event('D');
    int rc = br_go_url_decode(raw, query, out, valid, error);
    if (rc == 0 && hit(DECODE)) { *valid = false; return 1; }
    return rc;
}
static void checked_url_clear(br_go_url_parts *parts)
{
    CHECK(parts == active_parts && !provider_request); br_go_url_clear(parts); active_parts = NULL;
}
static bool checked_allowed(unsigned char c, br_go_url_encoding mode)
{
    CHECK(active_result && active_parts);
    if (!projecting) { ++projections; event('T'); projecting = true; }
    return br_go_url_byte_allowed(c, mode);
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part,
                            br_slice url, const char *url_part, br_slice separator)
{
    CHECK(active_parts && !active_result && !separator.len && !separator.data);
    ++findings; event('F'); active_result = r;
    int rc = br_finding_pair_bytes(r, type, token, part, url, url_part, separator);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r)
{
    if (active_result == r) active_result = NULL;
    br_result_clear(r);
}
static int checked_document(br_slice body, br_json **out, char **cause)
{
    CHECK(active_result && provider_request); ++documents; event('J');
    int rc = br_json_document(body, out, cause);
    return hit(DOCUMENT) ? document_failure : rc;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_parts && active_result->raw.len == 36);
    CHECK(r->detector_type == 950 && r->profile == BR_HTTP_DETECTOR_LOCAL && !strcmp(r->method, "GET"));
    const char *wanted = expected_url;
    if (product_requests) {
        br_json *original = NULL; CHECK(json_object_object_get_ex(active_result->secret_parts, "url", &original));
        wanted = !strcmp(json_object_get_string(original), "https://other.test") ? "https://other.test/api/user/current" : "http://Host.test/api/user/current";
    }
    CHECK(!strcmp(r->url, wanted) && r->timeout_ms == (effective ? 10000u : 0u));
    CHECK(!r->dedup_key.data && !r->dedup_key.len && !r->body.data && !r->body.len);
    CHECK(r->nheaders == (effective ? 2u : 1u) && !strcmp(r->headers[0].name, "X-Metabase-Session"));
    CHECK(strlen(r->headers[0].value) == 36 && !memcmp(r->headers[0].value, active_result->raw.data, 36));
    CHECK(!active_result->verification_error);
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request); request_values(request, false);
    provider_request = request; provider_ctx = ctx; ++sends; event('S');
    return br_http_send(ctx, request, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_ctx); request_values(provider_request, false);
    /* Only ORIGINAL projected URL/header/key/parsed structures survive here;
     * the borrowed transport's synthesized headers/UA ended at send return. */
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_ctx = NULL;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(r == active_result && active_parts && !provider_request && sends == releases); event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_go_url_parse checked_parse
#define br_go_url_decode checked_decode
#define br_go_url_clear checked_url_clear
#define br_go_url_byte_allowed checked_allowed
#define br_finding_pair_bytes checked_finding
#define br_result_clear checked_clear
#define br_json_document checked_document
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#include "../../src/detectors/metabase.c"
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_go_url_parse
#undef br_go_url_decode
#undef br_go_url_clear
#undef br_go_url_byte_allowed
#undef br_finding_pair_bytes
#undef br_result_clear
#undef br_json_document
#undef br_http_send
#undef br_http_release
#undef br_results_push

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_metabase_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_metabase_init(NULL, NULL) == -1);
    for (size_t n = 1; n <= 2; ++n) {
        size_t freed = freed_patterns; fault = COMPILE; fail_nth = n;
        CHECK(br_metabase_init(&d, &error) == -1 && !d && error && fault == NONE);
        CHECK(freed_patterns == freed + n && !metabase_compiled.key && !metabase_compiled.url); free(error); error = NULL;
    }
    CHECK(!br_metabase_init(&d, &error) && d && !error && !br_metabase_init(&again, NULL) && again == d);
    key_pattern = metabase_compiled.key; url_pattern = metabase_compiled.url;
    CHECK(d->type == 950 && !d->version && !strcmp(d->name, "Metabase") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Metabase is an open-source business intelligence tool. Metabase session tokens can be used to access and interact with the Metabase API."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "metabase"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *token, const char *original, bool verified)
{
    size_t n = strlen(token), u = strlen(original);
    CHECK(r->detector_type == 950 && r->verified == verified && !r->verification_error);
    CHECK(r->raw.len == n && !memcmp(r->raw.data, token, n) && !r->detector_name);
    CHECK(r->raw_v2.len == n + u && !memcmp(r->raw_v2.data, token, n) && !memcmp(r->raw_v2.data + n, original, u));
    CHECK(!r->redacted && !r->extra_data && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == n && !memcmp(json_object_get_string(part), token, n));
    CHECK(json_object_object_get_ex(r->secret_parts, "url", &part));
    CHECK(json_object_is_type(part, json_type_string) && (size_t)json_object_get_string_len(part) == u && !memcmp(json_object_get_string(part), original, u));
    size_t at = 0;
    json_object_object_foreach(r->secret_parts, name, value) { (void)value; CHECK(!strcmp(name, at++ ? "url" : "key")); }
    CHECK(at == 2);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(provider_request && ctx == provider_ctx); request_values(r, true);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static void extract(const br_detector *d, const void *input, size_t len, const char *token, const char *original)
{
    size_t sent = sends, projected = projections, cap = captures;
    br_results out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == (token ? 1u : 0u) && sends == sent && projections == projected && captures == cap + 2);
    if (token) result_is(&out.items[0], token, original, false);
    CHECK(!active_result && !active_parts); br_results_clear(&out);
}
static void key_grammar(const br_detector *d)
{
    char input[600], changed[38];
    const char *good[] = {"metabase '%s'", "MeTaBaSe=-%s-", "myMETABASEsuffix\r\n%s", "metabase\r%s", "metabase\n%s", "metabase é%sé"};
    const char *bad[] = {"%s", "meta base %s", "%s metabase", "metabase%s", "metabase _%s", "metabase %s_", "metabase %sZ", "metabase %.35s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        size_t n = (size_t)snprintf(input, sizeof(input), good[i], key); snprintf(input + n, sizeof(input) - n, "\nmetabase http://Host.test");
        extract(d, input, strlen(input), key, "http://Host.test");
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        size_t n = (size_t)snprintf(input, sizeof(input), bad[i], key); snprintf(input + n, sizeof(input) - n, "\nmetabase http://Host.test");
        extract(d, input, strlen(input), NULL, NULL);
    }
    const char invalid[] = "_+/ ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", changed); extract(d, input, strlen(input), NULL, NULL);
    }
    memset(changed, 'A', 36); changed[36] = 0;
    snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", changed); extract(d, input, strlen(input), changed, "http://Host.test");
    changed[0] = '-'; snprintf(input, sizeof(input), "metabase x%s\nmetabase http://Host.test", changed); extract(d, input, strlen(input), changed, "http://Host.test");
    snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", changed); extract(d, input, strlen(input), NULL, NULL);
    changed[0] = 'A'; changed[35] = '-'; snprintf(input, sizeof(input), "metabase %sX\nmetabase http://Host.test", changed); extract(d, input, strlen(input), changed, "http://Host.test");
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "metabase", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, key, 36);
        snprintf(input + 44 + gap, sizeof(input) - 44 - gap, "\nmetabase http://Host.test"); extract(d, input, strlen(input), gap == 40 ? key : NULL, "http://Host.test");
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "💡", 4);
        memcpy(input + 8 + 4 * gap, key, 36); snprintf(input + 44 + 4 * gap, sizeof(input) - 44 - 4 * gap, "\nmetabase http://Host.test");
        extract(d, input, strlen(input), gap == 40 ? key : NULL, "http://Host.test");
    }
    memcpy(input, "metabase\0", 9); memcpy(input + 9, key, 36); memcpy(input + 45, "\nmetabase http://Host.test", 26);
    extract(d, input, 71, key, "http://Host.test");
    snprintf(input, sizeof(input), "metabase %s", key); extract(d, input, strlen(input), NULL, NULL);
    extract(d, NULL, 0, NULL, NULL);
}
static void url_case(const br_detector *d, const char *url, const char *original, const char *projected)
{
    char input[600]; snprintf(input, sizeof(input), "metabase %s\nmetabase %s", key, url);
    extract(d, input, strlen(input), original ? key : NULL, original);
    test_http http = {.inspect = inspect, .response = {.status = 200, .body = TEXT("null")}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; expected_url = projected;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == (original ? 1u : 0u) && http.calls == (original ? 1u : 0u) && http.releases == http.calls);
    if (original) result_is(&out.items[0], key, original, true);
    br_results_clear(&out);
}
static void urls(const br_detector *d)
{
    const struct { const char *input, *original, *projected; } cases[] = {
        {"http://Host.test", "http://Host.test", "http://Host.test/api/user/current"},
        {"https://MiXeD.test:999999", "https://MiXeD.test:999999", "https://MiXeD.test:999999/api/user/current"},
        {"http://host.test:9:99999", "http://host.test:9:99999", "http://host.test:9:99999/api/user/current"},
        {"http://host.test:#fragment", "http://host.test:#fragment", "http://host.test:/api/user/current#fragment"},
        {"http://a+b.test", "http://a+b.test", "http://a+b.test/api/user/current"},
        {"http://user:p%2f+@Host.test", "http://user:p%2f+@Host.test", "http://user:p%2F+@Host.test/api/user/current"},
        {"http://a+b:p%2b@Host.test#x+%2b", "http://a+b:p%2b@Host.test#x+%2b", "http://a+b:p+@Host.test/api/user/current#x+%2b"},
        {"http://ab%00cd:p%00@Host.test#%00", "http://ab%00cd:p%00@Host.test#%00", "http://ab%00cd:p%00@Host.test/api/user/current#%00"},
        {"http://a%3ab:c%3ad@Host.test", "http://a%3ab:c%3ad@Host.test", "http://a%3Ab:c%3Ad@Host.test/api/user/current"},
        {"http://a@b@Host.test", "http://a@b@Host.test", "http://a%40b@Host.test/api/user/current"},
        {"http://:@Host.test", "http://:@Host.test", "http://:@Host.test/api/user/current"},
        {"http://@Host.test", "http://@Host.test", "http://@Host.test/api/user/current"},
        {"http://Host%25name.test", "http://Host%25name.test", "http://Host%25name.test/api/user/current"},
        {"http://H%c3%b6st.test", "http://H%c3%b6st.test", "http://H%C3%B6st.test/api/user/current"},
        {"http://Host%ff.test", "http://Host%ff.test", "http://Host%FF.test/api/user/current"},
        {"http://Host.test#%7e%2f%aa", "http://Host.test#%7e%2f%aa", "http://Host.test/api/user/current#%7e%2f%aa"},
        {"http://Host.test#%7e%2f%aa#x", "http://Host.test#%7e%2f%aa#x", "http://Host.test/api/user/current#~/%AA%23x"},
        {"http://#abcdef", "http://#abcdef", "http:///api/user/current#abcdef"},
        {"http://user@#fragment", "http://user@#fragment", "http://user@/api/user/current#fragment"},
        {"http://#ab%2f##c", "http://#ab%2f##c", "http:///api/user/current#ab/%23%23c"},
        {"http://Host.test/path?query#fragment", "http://Host.test", "http://Host.test/api/user/current"},
        {"http://Host.test?query", "http://Host.test", "http://Host.test/api/user/current"},
        {"http://Host.test.", "http://Host.test", "http://Host.test/api/user/current"},
        {"http://host7ab", "http://host7ab", "http://host7ab/api/user/current"},
        {"http://short6", NULL, NULL}, {"HTTPS://Host.test", NULL, NULL}, {"http://[::1]", NULL, NULL},
        {"http://Host.test:bad", NULL, NULL}, {"http://Host.test:%zz", NULL, NULL},
        {"http://Host%61.test", NULL, NULL}, {"http://Host%00.test", NULL, NULL},
        {"http://Host%zz.test", NULL, NULL}, {"http://u%zz@Host.test", NULL, NULL},
        {"http://Host.test#frag%z1", NULL, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) url_case(d, cases[i].input, cases[i].original, cases[i].projected);
    char url[270], projected[300];
    memcpy(url, "http://", 7); memset(url + 7, 'h', 256); url[263] = 0;
    snprintf(projected, sizeof(projected), "%s/api/user/current", url); url_case(d, url, url, projected);
    url[263] = 'h'; url[264] = 0; url_case(d, url, NULL, NULL);
    char input[600];
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "metabase %s\nmetabase", key);
        memset(input + at, ':', gap); strcpy(input + at + gap, "http://Host.test");
        extract(d, input, strlen(input), gap == 40 ? key : NULL, "http://Host.test");
    }
    expected_url = "http://Host.test/api/user/current";
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read, const char *send_error, int send_rc)
{
    char input[120]; snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", key);
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_error = send_error, .send_rc = send_rc};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t sent = sends, released = releases, doc = documents;
    nevents = 0; events[0] = 0; watch = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input)); watch = false;
    CHECK(sends == sent + 1 && releases == released + 1 && http.calls == 1 && http.releases == 1);
    CHECK(documents == doc + (send_rc == 0 && !read && status == 200 ? 1u : 0u));
    CHECK(!active_result && !active_parts && !provider_request);
    CHECK(!strcmp(events, send_rc ? "KUAFTSRP" : read ? "KUAFTSR" : status == 200 ? "KUAFTSJRP" : "KUAFTSRP"));
    return out;
}
static void bodies(const br_detector *d)
{
    const struct { const char *body; bool valid; } values[] = {
        {"null", true}, {"true", true}, {"false", true}, {"7", true}, {"-0.0", true}, {"\"scalar\"", true},
        {"[]", true}, {"{}", true}, {" \r\n[1,null,{}]\t ", true}, {"1e999999", true}, {"-1e-999999", true},
        {"99999999999999999999999999999999999999999999999", true}, {"{\"a\":1e999999,\"a\":null}", true},
        {"", false}, {" \r\n", false}, {"{", false}, {"{bad", false}, {"null null", false}, {"{} trailing", false},
        {"{}{}", false}, {"01", false}, {"NaN", false}, {"Infinity", false}, {"[1,]", false}, {"{\"a\":1,}", false},
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); ++i) {
        br_results out = response(d, 200, text(values[i].body), NULL, NULL, 0);
        CHECK(out.len == 1); result_is(&out.items[0], key, "http://Host.test", values[i].valid); br_results_clear(&out);
    }
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        br_results out = response(d, statuses[i], TEXT("null"), NULL, NULL, 0);
        CHECK(out.len == 1); result_is(&out.items[0], key, "http://Host.test", statuses[i] == 200); br_results_clear(&out);
        out = response(d, statuses[i], TEXT("{}"), "read failure AFTER completed JSON", NULL, 0); CHECK(!out.len); br_results_clear(&out);
        out = response(d, statuses[i], TEXT("{bad"), "", NULL, 0); CHECK(!out.len); br_results_clear(&out);
    }
    const unsigned char nul[] = {'{', '}', 0};
    br_results out = response(d, 200, (br_slice){nul, sizeof(nul)}, NULL, NULL, 0);
    CHECK(out.len == 1); result_is(&out.items[0], key, "http://Host.test", false); br_results_clear(&out);
    const char *errors[] = {"timeout", "out of memory constructing HTTP headers", "cannot validate Metabase JSON body", key, "", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        out = response(d, 200, TEXT("null"), "ignored read error", errors[i], i % 2 ? -7 : 1);
        CHECK(out.len == 1); result_is(&out.items[0], key, "http://Host.test", false); br_results_clear(&out);
    }
}
static void inspect_products(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    size_t at = http->calls - 1; CHECK(at < 9);
    CHECK(!strcmp(r->url, at % 3 == 1 ? "https://other.test/api/user/current" : "http://Host.test/api/user/current"));
    inspect(http, ctx, r);
    const char *token = at / 3 == 1 ? other : key;
    CHECK(!memcmp(active_result->raw.data, token, 36));
}
static void products_and_nil(const br_detector *d)
{
    char input[2600]; size_t at = (size_t)snprintf(input, sizeof(input), "metabase %s\nmetabase %s\nmetabase %s\n", key, other, key);
    memset(input + at, '!', 1600); at += 1600;
    strcpy(input + at, "\nmetabase http://Host.test\nmetabase https://other.test\nmetabase http://Host.test");
    test_http http = {.inspect = inspect_products, .response = {.status = 200, .body = TEXT("null")}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"http://ignored.test"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "http://also-ignored.test", .use_cloud = true};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "metabase-offline"};
    size_t p = parses, cap = captures, projected = projections, sent = sends; expected_agent = "TruffleHog metabase-offline";
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 9 && parses == p + 9 && captures == cap + 2 && projections == projected && sends == sent && !http.calls);
    for (size_t i = 0; i < 9; ++i) result_is(&out.items[i], i / 3 == 1 ? other : key, i % 3 == 1 ? "https://other.test" : "http://Host.test", false);
    br_results_clear(&out); product_requests = true; out = test_scan(d, &ctx, true, input, strlen(input)); product_requests = false;
    CHECK(out.len == 9 && http.calls == 9 && http.releases == 9 && parses == p + 18 && projections == projected + 9);
    for (size_t i = 0; i < 9; ++i) result_is(&out.items[i], i / 3 == 1 ? other : key, i % 3 == 1 ? "https://other.test" : "http://Host.test", true);
    br_results_clear(&out); p = parses; projected = projections; sent = sends;
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && parses == p + 9 && projections == projected + 9 && sends == sent); br_results_clear(&out);
    expected_agent = "TruffleHog"; expected_url = "http://Host.test/api/user/current";
    snprintf(input, sizeof(input), "metabase %s\nmetabase http://u%%00:p%%2f@Host.test#%%7e", key);
    size_t decode = decodes; projected = projections;
    nevents = 0; events[0] = 0; watch = true; out = test_scan(d, NULL, false, input, strlen(input)); watch = false;
    CHECK(out.len == 1 && decodes == decode + 3 && projections == projected && !strcmp(events, "KUADDDFP"));
    result_is(&out.items[0], key, "http://u%00:p%2f@Host.test#%7e", false); br_results_clear(&out);
    snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test:bad\nmetabase http://Host.test", key);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 1); result_is(&out.items[0], key, "http://Host.test", false); br_results_clear(&out);
}
static bool cancelled(void *u) { ++*(size_t *)u; return true; }
static void preparation(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    char input[120]; snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", key);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t sent = sends, released = releases, projected = projections, doc = documents; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && projections == projected + 1 && documents == doc);
        CHECK(!http.calls && http.releases == (i ? 1u : 0u)); result_is(&out.items[0], key, "http://Host.test", false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void owned_failures(const br_detector *d)
{
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; bool nil, nov, empty_keys, invalid_url; int json_status; } cases[] = {
        {CAPTURE, 1, true, true, false, false, 0}, {CAPTURE, 2, true, true, true, false, 0},
        {PARSE, 1, true, true, false, true, 0}, {PARSE, 2, false, false, false, false, 0},
        {DECODE, 1, true, false, false, false, 0}, {DECODE, 2, true, true, false, false, 0},
        {DECODE, 3, false, false, false, false, 0}, {DECODE, 4, true, true, false, false, 0},
        {FINDING, 1, true, false, false, false, 0}, {FINDING, 2, false, false, false, false, 0},
        {FINDING, 2, true, true, false, false, 0}, {DOCUMENT, 1, false, false, false, false, -1},
        {DOCUMENT, 2, false, false, false, false, 2}, {PUSH, 2, false, false, false, false, 0},
        {PUSH, 2, true, true, false, false, 0}, {BIG_HOST, 1, true, false, false, false, 0},
        {BIG_HOST, 2, false, false, false, false, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        const char *url = cases[i].invalid_url ? "http://Host.test:%zz" : cases[i].kind == DECODE ? "http://u%00:p%2f@Host.test#%7e" : "http://Host.test";
        char input[240];
        if (cases[i].empty_keys) snprintf(input, sizeof(input), "metabase %s", url);
        else snprintf(input, sizeof(input), "metabase %s\nmetabase %s\nmetabase %s", key, other, url);
        expected_url = cases[i].kind == DECODE ? "http://u%00:p%2F@Host.test/api/user/current#%7e" : "http://Host.test/api/user/current";
        test_http http = {.inspect = inspect, .response = {.status = 200, .body = TEXT("null")}};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        fault = cases[i].kind; fail_nth = cases[i].nth; document_failure = cases[i].json_status;
        size_t failed = failures, sent = sends, released = releases; char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, !cases[i].nov, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && failures == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request && !active_result && !active_parts);
        if (cases[i].nil || cases[i].nov) CHECK(sends == sent);
        free(error);
    }
    expected_url = "http://Host.test/api/user/current";
    fault = DOCUMENT; fail_nth = 1; document_failure = -1;
    br_results kept = response(d, 401, TEXT("null"), NULL, NULL, 0); CHECK(kept.len == 1 && fault == DOCUMENT); br_results_clear(&kept);
    kept = response(d, 200, TEXT("null"), "read error", NULL, 0); CHECK(!kept.len && fault == DOCUMENT); br_results_clear(&kept);
    kept = response(d, 200, TEXT("null"), NULL, "suppressed", 1); CHECK(kept.len == 1 && fault == DOCUMENT); br_results_clear(&kept); fault = NONE;
    char input[120]; snprintf(input, sizeof(input), "metabase %s\nmetabase http://Host.test", key);
    fault = PARSE; fail_nth = 1; CHECK(d->scan(d, NULL, false, text(input), &out, NULL) == -1 && fault == NONE);
    char *error = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error); error = NULL;
    br_detector invalid = *d; invalid.state = NULL;
    CHECK(d->scan(&invalid, NULL, false, text(input), &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    test_secret(key, 36, 0); key[0] = 'Z'; key[5] = key[6] = '-'; key[12] = 'G'; key[35] = '9';
    test_secret(other, 36, 7); other[0] = 'Q';
    const br_detector *d = descriptor(); key_grammar(d); urls(d); bodies(d); products_and_nil(d); preparation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !active_result && !active_parts && !provider_request && !watch);
    return test_finish("Metabase");
}
