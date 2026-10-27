/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char key[] = "0123456789abcdef0123456789abcdef", other_key[] = "fedcba9876543210fedcba9876543210";
static const char email[] = "User+tag@Example.test", other_email[] = "user+tag@example.test";
static const char quoted[] = "\"A\\ B+\x01Z\"@Example.test";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static bool track_url;
static size_t url_allocations, fail_url_after, fail_finding_after;

/* Existing narrow allocation check: fixed URL/query prefix=79, encoded simple
 * email=25, NUL=1. Count/fail the one 105-byte URL, not shared HTTP setup. */
void *malloc(size_t size)
{
    if (track_url && size == 105) { ++url_allocations; if (fail_url_after && --fail_url_after == 0) return NULL; }
    return calloc(1, size);
}

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 5); /* Only API key, or caller-owned sentinel. */
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[33]; memcpy(copy, value, (size_t)len); copy[len] = 0; return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other_key) == 32);
    CHECK(br_cloze_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Cloze detector output")); free(error); error = NULL;
    CHECK(!br_cloze_init(&detector, &error) && detector && !error);
    CHECK(!br_cloze_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 711 && detector->version == 0 && !strcmp(detector->name, "Cloze") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Cloze is a relationship management tool that helps users manage their connections and interactions. Cloze API keys can be used to access and manage user data and interactions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloze"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 711, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static char *input_for(const br_slice *emails, size_t ne, const char *const *keys, size_t nk)
{
    size_t size = 1 + nk * 39; for (size_t i = 0; i < ne; ++i) size += emails[i].len + 7;
    char *out = malloc(size); CHECK(out); size_t at = 0;
    for (size_t i = 0; i < ne; ++i) {
        memcpy(out + at, "cloze", 5); at += 5;
        /* X is outside capture 1; the leading boundary before quote needs it. */
        out[at++] = emails[i].data[0] == '"' ? 'X' : ' ';
        memcpy(out + at, emails[i].data, emails[i].len); at += emails[i].len; out[at++] = '\n';
    }
    for (size_t i = 0; i < nk; ++i) { memcpy(out + at, "cloze ", 6); at += 6; memcpy(out + at, keys[i], 32); at += 32; out[at++] = '\n'; }
    CHECK(at + 1 == size); out[at] = '\0'; return out;
}

static void expect_one(const br_detector *detector, const char *input, bool expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[34];
    snprintf(input, sizeof(input), "CLOZE %s\n%s\nClOzE %s", email, isolation, key); expect_one(detector, input, true);
    snprintf(input, sizeof(input), "cloze %s", key); expect_one(detector, input, false); /* Emails required, never a standalone-key fallback. */
    snprintf(input, sizeof(input), "cloze %s", email); expect_one(detector, input, false);
    snprintf(input, sizeof(input), "%s\n%s\ncloze %s", email, isolation, key); expect_one(detector, input, false);
    snprintf(input, sizeof(input), "cloze %s\n%s\n%s", email, isolation, key); expect_one(detector, input, false);
    memcpy(changed, key, sizeof(key)); changed[10] = 'A'; snprintf(input, sizeof(input), "cloze %s\n%s\ncloze %s", email, isolation, changed); expect_one(detector, input, false);
    memcpy(changed, key, sizeof(key)); changed[10] = 'g'; snprintf(input, sizeof(input), "cloze %s\n%s\ncloze %s", email, isolation, changed); expect_one(detector, input, false);
    memcpy(changed, key, sizeof(key)); changed[31] = 0; snprintf(input, sizeof(input), "cloze %s\n%s\ncloze %s", email, isolation, changed); expect_one(detector, input, false);
    snprintf(changed, sizeof(changed), "%sf", key); snprintf(input, sizeof(input), "cloze %s\n%s\ncloze %s", email, isolation, changed); expect_one(detector, input, false);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "cloze%*s%s\n%s\ncloze %s", gap, "", email, isolation, key); expect_one(detector, input, gap == 40);
        snprintf(input, sizeof(input), "cloze %s\n%s\ncloze%*s%s", email, isolation, gap, "", key); expect_one(detector, input, gap == 40);
    }
    snprintf(input, sizeof(input), "clozeX%s\n%s\ncloze %s", quoted, isolation, key); expect_one(detector, input, true); /* Full quoted capture; no last-space projection. */
}

typedef struct { const char *key, *encoded, *send_error; br_slice email; int status, send_rc; } reply;
typedef struct {
    reply rows[6]; size_t count; bool track; const br_scan_ctx *expected_ctx;
    const char *borrowed_url; size_t borrowed_len;
} script;

static int hex_value(unsigned char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 6 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 711 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog")); /* No auth/Type/Accept/logical CL. */
    char prefix[80]; CHECK(snprintf(prefix, sizeof(prefix), "https://api.cloze.com/v1/profile?api_key=%s&user=", step->key) == 79);
    size_t len = strlen(request->url); CHECK(len > 79 && !memcmp(request->url, prefix, 79));
    if (step->encoded) CHECK(len == 79 + strlen(step->encoded) && !memcmp(request->url + 79, step->encoded, strlen(step->encoded)));
    /* Decode every byte independently, preserving case/quoted controls. Only
     * canonical uppercase percent bytes, '+' spaces and unreserved literals. */
    size_t decoded = 0;
    for (size_t i = 79; i < len;) {
        unsigned char c = (unsigned char)request->url[i++];
        if (c == '%') {
            CHECK(len - i >= 2); int hi = hex_value((unsigned char)request->url[i]), lo = hex_value((unsigned char)request->url[i + 1]); CHECK(hi >= 0 && lo >= 0); c = (unsigned char)(hi * 16 + lo); i += 2;
        } else if (c == '+') c = ' ';
        else CHECK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~');
        CHECK(decoded < step->email.len && c == step->email.data[decoded++]);
    }
    CHECK(decoded == step->email.len); steps->borrowed_url = request->url; steps->borrowed_len = len;
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == steps->borrowed_len && !memcmp(steps->borrowed_url, "https://api.cloze.com/v1/profile?", 33));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    url_allocations = 0; track_url = steps->track; br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); track_url = false;
    CHECK(http.calls == steps->count && http.releases == steps->count);
    if (steps->track) CHECK(url_allocations == (verify ? steps->count : 0));
    return results;
}

static br_results single(const br_detector *detector, reply step)
{
    if (!step.key) step.key = key;
    if (!step.email.data) step.email = TEXT(email);
    const char *keys[] = {step.key}; char *input = input_for(&step.email, 1, keys, 1); script steps = {.count = 1}; steps.rows[0] = step;
    br_results results = run(detector, input, true, &steps); free(input); CHECK(results.len == 1); check_result(&results.items[0], step.key, !step.send_error && !step.send_rc && step.status >= 200 && step.status < 300); return results;
}

static void products_and_nil(const br_detector *detector)
{
    const br_slice emails[] = {TEXT(email), TEXT(other_email), TEXT(email)}; const char *keys[] = {key, other_key, key}; char *input = input_for(emails, 3, keys, 3);
    script steps = {.count = 6, .track = true}; for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 3; ++k) steps.rows[e * 3 + k] = (reply){.key = keys[k], .email = emails[e], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {.track = true}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 6);
        for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 3; ++k) check_result(&results.items[e * 3 + k], keys[k], verify);
        CHECK(!memcmp(results.items[0].raw.data, results.items[3].raw.data, 32)); br_results_clear(&results); /* Detector retains identical hidden-email projections, not a CLI dedup assertion. */
    }
    url_allocations = 0; track_url = true; br_results results = test_scan(detector, NULL, true, input, strlen(input)); track_url = false; CHECK(!results.len && url_allocations == 6); br_results_clear(&results); free(input);
    const br_slice overlap[] = {TEXT("0123456789abcdef0123456789abcdef@Example.test"), TEXT("0123456789abcdef0123456789abcdef@Example.test")}; input = input_for(overlap, 2, NULL, 0);
    steps = (script){.count = 2}; for (size_t i = 0; i < 2; ++i) steps.rows[i] = (reply){.key = key, .email = overlap[0], .status = 200};
    results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); br_results_clear(&results); free(input);
}

static void query_and_status(const br_detector *detector)
{
    br_results results = single(detector, (reply){.status = 200, .encoded = "User%2Btag%40Example.test"}); br_results_clear(&results);
    results = single(detector, (reply){.status = 200, .email = TEXT(quoted), .encoded = "%22A%5C+B%2B%01Z%22%40Example.test"}); br_results_clear(&results);
    results = single(detector, (reply){.status = 200, .email = TEXT("a-_.~+%=&?@Example.test"), .encoded = "a-_.~%2B%25%3D%26%3F%40Example.test"}); br_results_clear(&results);
    size_t local_len = 8193; char *large = malloc(local_len + sizeof("@Example.test")); CHECK(large); memset(large, 'A', local_len); memcpy(large + local_len, "@Example.test", sizeof("@Example.test"));
    results = single(detector, (reply){.status = 299, .email = {(const unsigned char *)large, local_len + sizeof("@Example.test") - 1}}); br_results_clear(&results); free(large);
    const int codes[] = {199, 200, 201, 204, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) { results = single(detector, (reply){.status = codes[i]}); br_results_clear(&results); }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "synthetic Do failure", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) { results = single(detector, (reply){.status = 200, .send_error = causes[i], .send_rc = 1}); br_results_clear(&results); }
}

static void resource_boundary(const br_detector *detector)
{
    const br_slice emails[] = {TEXT(email)}; const char *keys[] = {key, other_key}; char *input = input_for(emails, 1, keys, 2);
    script steps = {.count = 2, .track = true}; for (size_t k = 0; k < 2; ++k) steps.rows[k] = (reply){.key = keys[k], .email = emails[0], .status = 200};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        url_allocations = 0; track_url = true;
        if (mode == 2) fail_finding_after = 2; else fail_url_after = 2;
        int rc = detector->scan(detector, mode == 1 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_url = false;
        CHECK(rc == -1 && !fail_url_after && !fail_finding_after && error && !strcmp(error, mode == 2 ? "cannot create Cloze result" : "cannot construct Cloze request URL"));
        CHECK(url_allocations == (mode == 2 ? 1u : 2u) && http.calls == (mode == 1 ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        br_json *part = NULL; CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior")); free(error); br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true); br_results_clear(&results); free(input);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products_and_nil(detector); query_and_status(detector); resource_boundary(detector);
    return test_finish("Cloze unique required-hidden emails x key occurrences + complete sorted query + allocation-before-skip");
}
