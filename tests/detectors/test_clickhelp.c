/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char portal[] = "docs.clickhelp.co", other_portal[] = "guide.try.clickhelp.co";
static const char email[] = "Reader@Example.test", other_email[] = "reader@example.test";
static const char quoted[] = "\"A\\ B+\x01Z\"@Example.test";
static const char key[] = "AbCd0123EfGh4567IjKl8901", other_key[] = "ZyXw9876VuTs5432RqPo1098";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static const char status_503[] = "unexpected status code: 503";
static bool track_allocations, fail_status_copy;
static size_t basic_allocations, primary_allocations, fail_basic_after, fail_primary_after;

/* Existing focused malloc seam: these fixtures need 67 bytes for Basic(19:24)
 * and 24 bytes for the OWNED primary secret. Zeroed forwarding is valid malloc. */
void *malloc(size_t size)
{
    if (track_allocations && size == 67) {
        ++basic_allocations;
        if (fail_basic_after && --fail_basic_after == 0) return NULL;
    }
    if (track_allocations && size == 24) {
        ++primary_allocations;
        if (fail_primary_after && --fail_primary_after == 0) return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 24 && strlen(other_key) == 24 && strlen(email) == 19);
    CHECK(br_clickhelp_init(NULL, &error) == -1 && error && !strcmp(error, "invalid ClickHelp detector output")); free(error); error = NULL;
    CHECK(!br_clickhelp_init(&detector, &error) && detector && !error);
    CHECK(!br_clickhelp_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 456 && detector->version == 0 && !strcmp(detector->name, "ClickHelp") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "ClickHelp is a documentation tool that allows users to create and manage online documentation. ClickHelp API keys can be used to access and modify documentation data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clickhelp.co"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void text_part(br_json *object, const char *name, br_slice expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len && !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void check_result(const br_result *result, const char *expected_portal, br_slice expected_email,
                          const char *primary, bool verified, const char *error)
{
    size_t plen = strlen(expected_portal);
    CHECK(result->detector_type == 456 && !result->detector_name && result->verified == verified);
    CHECK(result->raw.len == plen && !memcmp(result->raw.data, expected_portal, plen));
    CHECK(result->raw_v2.len == plen + expected_email.len && !memcmp(result->raw_v2.data, expected_portal, plen));
    CHECK(!memcmp(result->raw_v2.data + plen, expected_email.data, expected_email.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    text_part(result->secret_parts, "url", (br_slice){(const unsigned char *)expected_portal, plen}); text_part(result->secret_parts, "email", expected_email);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    if (primary) CHECK(result->primary_secret.len == 24 && result->primary_secret.data != result->raw.data && result->primary_secret.data != result->raw_v2.data && !memcmp(result->primary_secret.data, primary, 24));
    else CHECK(!result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static char *input_for(const char *const *portals, size_t np, const br_slice *emails, size_t ne, const char *const *keys, size_t nk)
{
    size_t size = 1 + nk * 32;
    for (size_t i = 0; i < np; ++i) size += strlen(portals[i]) + 1;
    for (size_t i = 0; i < ne; ++i) size += emails[i].len + 1 + (emails[i].data[0] == '"');
    char *out = malloc(size); CHECK(out); size_t at = 0;
    /* Keys first: no accidental dependence on the later portal's dispatch text
     * as a key prefix. Portals/emails below are DIRECT, without prefixes. */
    for (size_t i = 0; i < nk; ++i) { memcpy(out + at, "secret ", 7); at += 7; memcpy(out + at, keys[i], 24); at += 24; out[at++] = '\n'; }
    for (size_t i = 0; i < np; ++i) { size_t n = strlen(portals[i]); memcpy(out + at, portals[i], n); at += n; out[at++] = '\n'; }
    for (size_t i = 0; i < ne; ++i) {
        if (emails[i].data[0] == '"') out[at++] = 'X'; /* Outside capture 1; source boundary before quote. */
        memcpy(out + at, emails[i].data, emails[i].len); at += emails[i].len; out[at++] = '\n';
    }
    CHECK(at + 1 == size); out[at] = '\0'; return out;
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, TEXT(email), NULL, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[26]; const char *prefixes[] = {"clickhelp", "KEY", "ToKeN", "API", "SECRET"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s\n%s\n%s\n%s", prefixes[i], key, isolation, portal, email); expect_one(detector, input, portal);
    }
    snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", key, isolation, portal, email); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "secret %s\n%s", key, email); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "secret %s\n%s", key, portal); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%s\n%s", portal, email); expect_one(detector, input, NULL);
    const struct { const char *input, *expected; } hosts[] = {
        {"DoCs.clickhelp.co", "DoCs.clickhelp.co"}, {"docs.try.clickhelp.co", "docs.try.clickhelp.co"},
        {"docs.CLICKHELP.CO", NULL}, {"ab.clickhelp.co", NULL}, {"abcdefghijklmnopqrstu.clickhelp.co", NULL},
        {"_-ab.clickhelp.co", "-ab.clickhelp.co"}, {"ab-.clickhelp.co", "ab-.clickhelp.co"},
        {"docs.clickhelp.co.uk", "docs.clickhelp.co"}, {"docs.clickhelp.com", NULL},
        {"docs.Try.clickhelp.co", "Try.clickhelp.co"},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "secret %s\n%s\n%s\n%s", key, isolation, hosts[i].input, email); expect_one(detector, input, hosts[i].expected);
    }
    memcpy(changed, key, sizeof(key)); changed[23] = 0; snprintf(input, sizeof(input), "secret %s\n%s\n%s\n%s", changed, isolation, portal, email); expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sZ", key); snprintf(input, sizeof(input), "secret %s\n%s\n%s\n%s", changed, isolation, portal, email); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '-'; snprintf(input, sizeof(input), "secret %s\n%s\n%s\n%s", changed, isolation, portal, email); expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "secret%*s%s\n%s\n%s\n%s", gap, "", key, isolation, portal, email); expect_one(detector, input, gap == 40 ? portal : NULL);
    }
}

typedef struct { const char *portal, *key, *send_error; br_slice email; int status, send_rc; bool echo; } reply;
typedef struct {
    reply rows[8]; size_t count; bool track, mutate_error, mutated; char echo[512]; char *returned_error;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 8 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 456 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    char url[96]; CHECK(snprintf(url, sizeof(url), "https://%s/api/v1/projects", step->portal) > 0); CHECK(!strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 3);
    CHECK(header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/json"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); size_t plain_len = step->email.len + 25, encoded = 4 * ((plain_len + 2) / 3);
    CHECK(auth && strlen(auth) == 6 + encoded && !memcmp(auth, "Basic ", 6));
    unsigned char *plain = malloc(encoded / 4 * 3); CHECK(plain); int n = EVP_DecodeBlock(plain, (const unsigned char *)auth + 6, (int)encoded); CHECK(n >= 0);
    size_t padding = (auth[5 + encoded] == '=') + (auth[4 + encoded] == '='); CHECK((size_t)n == plain_len + padding);
    CHECK(!memcmp(plain, step->email.data, step->email.len) && plain[step->email.len] == ':' && !memcmp(plain + step->email.len + 1, step->key, 24)); free(plain);
    static const unsigned char body[] = "\xff\0ignored body";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
    if (step->echo) {
        CHECK(step->email.len == 19);
        int used = snprintf(steps->echo, sizeof(steps->echo), "portal=%s email=%.*s key=%s auth=%s", step->portal, 19, (const char *)step->email.data, step->key, auth); CHECK(used > 0 && (size_t)used < sizeof(steps->echo));
        http->send_error = steps->echo; http->send_rc = -1;
    }
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; script *steps = http->user;
    int rc = test_http_send(user, ctx, request, response, error); steps->returned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->mutate_error && steps->returned_error) { memset(steps->returned_error, '!', strlen(steps->returned_error)); steps->mutated = true; }
    steps->returned_error = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    basic_allocations = primary_allocations = 0; track_allocations = steps->track; br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); track_allocations = false;
    CHECK(http.calls == steps->count && http.releases == steps->count);
    if (steps->track) CHECK(basic_allocations == (verify ? steps->count : 0) && primary_allocations == (verify ? steps->count : 0));
    return results;
}

static br_results single(const br_detector *detector, reply step)
{
    if (!step.portal) step.portal = portal;
    if (!step.key) step.key = key;
    if (!step.email.data) step.email = TEXT(email);
    const char *portals[] = {step.portal}, *keys[] = {step.key}; char *input = input_for(portals, 1, &step.email, 1, keys, 1); script steps = {.count = 1}; steps.rows[0] = step;
    br_results results = run(detector, input, true, &steps); free(input); CHECK(results.len == 1); return results;
}

static void products_and_primary(const br_detector *detector)
{
    const char *portals[] = {portal, other_portal, portal}, *keys[] = {key, other_key, key}; const br_slice emails[] = {TEXT(email), TEXT(other_email), TEXT(email)};
    char *input = input_for(portals, 3, emails, 3, keys, 3); script steps = {.count = 8, .track = true};
    for (size_t p = 0; p < 2; ++p) for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 2; ++k) steps.rows[p * 4 + e * 2 + k] = (reply){.portal = portals[p], .email = emails[e], .key = keys[k], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {.track = true}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 8);
        for (size_t p = 0; p < 2; ++p) for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 2; ++k) check_result(&results.items[p * 4 + e * 2 + k], portals[p], emails[e], verify ? keys[k] : NULL, verify, NULL);
        CHECK(results.items[0].raw.len == results.items[1].raw.len && !memcmp(results.items[0].raw.data, results.items[1].raw.data, results.items[0].raw.len));
        CHECK(results.items[0].raw_v2.len == results.items[1].raw_v2.len && !memcmp(results.items[0].raw_v2.data, results.items[1].raw_v2.data, results.items[0].raw_v2.len)); br_results_clear(&results);
    }
    basic_allocations = primary_allocations = 0; track_allocations = true; br_results results = test_scan(detector, NULL, true, input, strlen(input)); track_allocations = false;
    CHECK(results.len == 8 && !basic_allocations && primary_allocations == 8);
    for (size_t p = 0; p < 2; ++p) for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 2; ++k) check_result(&results.items[p * 4 + e * 2 + k], portals[p], emails[e], keys[k], false, "net/http: nil Context");
    br_results_clear(&results); free(input);
}

static void verification(const br_detector *detector)
{
    const int codes[] = {200, 401, 201, 204, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.status = codes[i]}); char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]);
        check_result(&results.items[0], portal, TEXT(email), key, codes[i] == 200, codes[i] == 200 || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    const char *causes[] = {"synthetic Do failure", NULL};
    for (size_t i = 0; i < 2; ++i) { br_results results = single(detector, (reply){.status = 200, .send_rc = 1, .send_error = causes[i]}); check_result(&results.items[0], portal, TEXT(email), key, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&results); }
    const char *portals[] = {portal}, *keys[] = {key}; const br_slice emails[] = {TEXT(email)}; char *input = input_for(portals, 1, emails, 1, keys, 1);
    script steps = {.count = 1, .mutate_error = true}; steps.rows[0] = (reply){.portal = portal, .email = TEXT(email), .key = key, .status = 200, .echo = true};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 1 && steps.mutated); check_result(&results.items[0], portal, TEXT(email), key, false, steps.echo); br_results_clear(&results); free(input);
    results = single(detector, (reply){.status = 200, .email = TEXT(quoted)}); check_result(&results.items[0], portal, TEXT(quoted), key, true, NULL); br_results_clear(&results);
    size_t local_len = 8193; char *large = malloc(local_len + sizeof("@Example.test")); CHECK(large); memset(large, 'A', local_len); memcpy(large + local_len, "@Example.test", sizeof("@Example.test")); br_slice long_email = {(const unsigned char *)large, local_len + sizeof("@Example.test") - 1};
    results = single(detector, (reply){.status = 200, .email = long_email}); check_result(&results.items[0], portal, long_email, key, true, NULL); br_results_clear(&results); free(large);
}

static void resource_boundaries(const br_detector *detector)
{
    const char *portals[] = {portal}, *keys[] = {key, other_key}; const br_slice emails[] = {TEXT(email)}; char *input = input_for(portals, 1, emails, 1, keys, 2);
    br_result probe = {0}; fail_status_copy = true; CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2}; for (size_t k = 0; k < 2; ++k) steps.rows[k] = (reply){.portal = portal, .email = TEXT(email), .key = keys[k], .status = mode == 2 && k == 1 ? 503 : 200};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        basic_allocations = primary_allocations = 0; track_allocations = true;
        if (mode == 0) fail_basic_after = 2;
        if (mode == 1) fail_primary_after = 2;
        if (mode == 2) fail_status_copy = true;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_allocations = false;
        CHECK(rc == -1 && error && !strcmp(error, mode == 1 ? "cannot copy ClickHelp primary secret" : "cannot verify ClickHelp candidate"));
        CHECK(!fail_basic_after && !fail_primary_after && !fail_status_copy && basic_allocations == 2 && primary_allocations == (mode == 1 ? 2u : 1u));
        CHECK(http.calls == (mode == 0 ? 1u : 2u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); text_part(results.items[0].secret_parts, "key", TEXT("prior")); free(error); br_results_clear(&results);
        br_results recovered = run(detector, input, true, &steps); CHECK(recovered.len == 2);
        for (size_t k = 0; k < 2; ++k) check_result(&recovered.items[k], portal, TEXT(email), keys[k], mode != 2 || k == 0, mode == 2 && k == 1 ? status_503 : NULL);
        br_results_clear(&recovered);
    }
    free(input);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products_and_primary(detector); verification(detector); resource_boundaries(detector);
    return test_finish("ClickHelp unique triples + hidden API keys + owned verify-only primary + unredacted causes");
}
