/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[35], other[35];
static const char url_prefix[] = "https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey=";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;

/* Target existing resource APIs only; no URL/Reader preparation failure seam. */
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
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 34 && strlen(other) == 34);
    CHECK(br_etherscan_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:etherscan)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_etherscan_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_etherscan_init(&d, &error) == 0 && d && !error);
    CHECK(br_etherscan_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 905 && d->version == 0 && !strcmp(d->name, "Etherscan") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Etherscan is a Block Explorer and Analytics Platform for Ethereum, a decentralized smart contracts platform. Etherscan API keys can be used to access various functionalities provided by Etherscan."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "etherscan"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 905, expected, "key");
    CHECK(r->raw.len == 34 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 34);
}
static void extract_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[192], changed[36];
    const char *formats[] = {"etherscan '%s'", "EtHeRsCaN=%s", "preETHERSCANsuffix:%s", "etherscan\r\n%s", "etherscan\r%s", "etherscan\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); extract_case(d, input, key);
    }
    const char *bad[] = {"%s", "%s etherscan", "ether scan %s", "etherscan%s", "etherscan _%s", "etherscan %s_", "etherscan x%s", "etherscan %s9"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); extract_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "etherscan%*s%s", gap, "", key); extract_case(d, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[33] = '\0';
    snprintf(input, sizeof(input), "etherscan %s", changed); extract_case(d, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[34] = 'A'; changed[35] = '\0';
    snprintf(input, sizeof(input), "etherscan %s", changed); extract_case(d, input, NULL);
    const char invalid[] = {'a', 'z', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = invalid[i];
        snprintf(input, sizeof(input), "ETHERSCAN %s", changed); extract_case(d, input, NULL);
    }
    memset(changed, '0', 34); changed[34] = '\0';
    snprintf(input, sizeof(input), "etherscan %s", changed); extract_case(d, input, changed); /* No local FP/entropy/token validation. */
    snprintf(input, sizeof(input), "etherscan %s %s", key, other); extract_case(d, input, key); /* One prefix is consumed per match. */
}

typedef struct { const char *key; int status; br_slice body; const char *read_error, *send_error; int rc; } reply;
typedef struct {
    const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url; char expected_url[sizeof(url_prefix) + 34];
} script;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->detector_type == 905 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(snprintf(s->expected_url, sizeof(s->expected_url), "%s%s", url_prefix, row->key) == (int)(sizeof(url_prefix) - 1 + 34));
    CHECK(strlen(request->url) == sizeof(s->expected_url) - 1 && !memcmp(request->url, s->expected_url, sizeof(s->expected_url)));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, s->suffix ? "TruffleHog etherscan-offline" : "TruffleHog"));
    /* Exact query order/fixed address/latest/apikey-last and header count exclude
     * encoding, Auth, Type, Accept or invented logical Content-Length. */
    s->borrowed_url = request->url;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->borrowed_url && !memcmp(s->borrowed_url, s->expected_url, sizeof(s->expected_url)));
    s->borrowed_url = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, br_slice data, bool verify, script *s)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "etherscan-offline" : NULL}; s->ctx = &ctx;
    br_results out = test_scan(d, &ctx, verify, data.data, data.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url); return out;
}
static void verify_one(const br_detector *d, reply row, bool keep, bool verified)
{
    char input[64]; CHECK(snprintf(input, sizeof(input), "etherscan %s", key) == 44);
    row.key = key; script s = {.rows = &row, .count = 1}; br_results out = run(d, text(input), true, &s);
    CHECK(out.len == (keep ? 1u : 0u)); if (keep) result(&out.items[0], key, verified); br_results_clear(&out);
}

static void occurrences_and_drop_vs_keep(const br_detector *d)
{
    char input[256]; CHECK(snprintf(input, sizeof(input), "etherscan %s\nETHERSCAN %s\netherscan %s\netherscan %s\netherscan %s", key, other, key, other, key) == 224);
    br_slice data = text(input); const char *keys[] = {key, other, key, other, key};
    script none = {0}; br_results out = run(d, data, false, &none); CHECK(out.len == 5);
    for (size_t i = 0; i < 5; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
    const reply rows[] = {
        {.key = key, .status = 401, .body = TEXT("\0\xff\"OK\"")},
        {.key = other, .status = 200, .body = TEXT("partial \"OK\""), .read_error = "synthetic read failure"},
        {.key = key, .status = 500, .body = TEXT("no marker")},
        {.key = other, .status = 200, .body = TEXT("\"OK\""), .read_error = "", .send_error = "synthetic Do failure", .rc = 1},
        {.key = key, .status = 500, .body = TEXT("\"OK\"")},
    };
    script s = {.rows = rows, .count = 5, .suffix = true}; out = run(d, data, true, &s); CHECK(out.len == 4);
    result(&out.items[0], key, true); result(&out.items[1], key, false); result(&out.items[2], other, false); result(&out.items[3], key, true);
    br_results_clear(&out);
    for (int verify = 0; verify < 2; ++verify) {
        out = test_scan(d, NULL, verify, data.data, data.len); CHECK(out.len == (verify ? 0u : 5u));
        for (size_t i = 0; i < out.len; ++i) result(&out.items[i], keys[i], false);
        br_results_clear(&out);
    }
}

static void binary_markers_and_read_drops(const br_detector *d)
{
    const int statuses[] = {199, 200, 302, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        verify_one(d, (reply){.status = statuses[i], .body = TEXT("not JSON \0\xff\"OK\" anywhere")}, true, true);
        verify_one(d, (reply){.status = statuses[i], .body = TEXT("\"OK\""), .read_error = ""}, false, false);
    }
    const br_slice good[] = {TEXT("\"OK\""), TEXT("malformed { \"OK\" suffix"), TEXT("\xff\0junk\"OK\"\0after")};
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); ++i)
        verify_one(d, (reply){.status = 500, .body = good[i]}, true, true);
    const br_slice bad[] = {TEXT("OK"), TEXT("\"ok\""), TEXT("\"Ok\""), TEXT("\" OK \""), TEXT("\"O K\""), {0}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        verify_one(d, (reply){.status = 200, .body = bad[i]}, true, false);
    const int errors_at[] = {200, 401, 500};
    for (size_t i = 0; i < sizeof(errors_at) / sizeof(errors_at[0]); ++i)
        verify_one(d, (reply){.status = errors_at[i], .body = TEXT("\0\xff\"OK\""), .read_error = "partial body failure"}, false, false);
    const char *causes[] = {"net/http: nil Context", "cannot create Etherscan result", "out of memory constructing HTTP headers", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i)
        verify_one(d, (reply){.status = 401, .body = TEXT("\"OK\""), .read_error = "", .send_error = causes[i], .rc = i % 2 ? -7 : 1}, true, false);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    char input[64]; CHECK(snprintf(input, sizeof(input), "etherscan %s", key) == 44);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = failed_allocations; br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && failed_allocations == before + (mode == 4 ? 1u : 0u));
        result(&out.items[0], key, false); br_results_clear(&out);
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
    char input[160]; CHECK(snprintf(input, sizeof(input), "etherscan %s\netherscan %s\netherscan %s", key, other, key) == 134); br_slice data = text(input);
    const reply rows[] = {{.key = key, .status = 500, .body = TEXT("\"OK\"")},
        {.key = other, .status = 200, .body = TEXT("\"OK\""), .read_error = "DROP this read"}};
    for (int mode = 0; mode < 3; ++mode) {
        br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL;
        script s = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &s};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
        const char *messages[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create Etherscan result", "cannot create Etherscan result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Actual +1 capture failure. */
            if (failure == 1) { fail_size = 35; fail_after = 2; }
            if (failure == 2) { fail_size = 34; fail_after = 2; }
            if (failure == 3) fail_part_after = 2; /* +1 finding insertion BEFORE its read DROP/nil SKIP. */
            CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1);
            CHECK(error && !strcmp(error, messages[failure]) && !fail_after && !fail_part_after);
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_url);
            check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
        }
        /* A later own failure must roll back an earlier kept result even after
         * an intervening ordinary read-error DROP (or constructor SKIPs). */
        fail_size = 34; fail_after = 3;
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Etherscan result") && !fail_after);
        CHECK(http.calls == (mode == 1 ? 2u : 0u) && http.releases == http.calls); check_prior(&out, &saved);
        free(error); error = NULL; http.calls = http.releases = 0;
        size_t cap = out.cap; out.cap = 0; /* Actual +1 append guard failure. */
        CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Etherscan result"));
        out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &saved); free(error); error = NULL;
        CHECK(d->scan(d, NULL, true, data, &out, &error) == 0 && !error); check_prior(&out, &saved); br_results_clear(&out);
    }
}

int main(void)
{
    test_secret(key, 34, 0); test_secret(other, 34, 11);
    for (size_t i = 0; i < 34; ++i) {
        if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        if (other[i] >= 'a' && other[i] <= 'z') other[i] -= 'a' - 'A';
    }
    const br_detector *d = descriptor();
    extraction(d); occurrences_and_drop_vs_keep(d); binary_markers_and_read_drops(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after);
    return test_finish("Etherscan");
}
