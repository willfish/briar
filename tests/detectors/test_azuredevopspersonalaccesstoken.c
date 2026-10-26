/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

typedef struct { const char *key, *organization; } expected_pair;
typedef struct {
    const expected_pair *pairs;
    size_t len;
    const br_http_response *responses;
} expected_requests;
typedef enum { FOUND, REJECTED, STATUS_ERROR, READ_SHAPE } outcome;
static const char read_shape_error[] = "unsupported: Azure DevOps PAT Scanner read shape for a 65536-byte final marker line";
static char lower_key[53], second_key[53], upper_key[53];
static const unsigned char marker[] = "lastUpdateTime";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(!br_azuredevopspersonalaccesstoken_init(&detector, &error) && detector && !error);
    CHECK(!br_azuredevopspersonalaccesstoken_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 972 && detector->version == 0 && !strcmp(detector->name, "AzureDevopsPersonalAccessToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) "
        "are used to authenticate and authorize access to Azure DevOps services and resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "azure"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_azuredevopspersonalaccesstoken_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void check_pair(const br_result *result, const expected_pair *pair)
{
    size_t org_len = strlen(pair->organization);
    CHECK(result->detector_type == 972 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 52 && !memcmp(result->raw.data, pair->key, 52));
    CHECK(result->raw_v2.data && result->raw_v2.len == 52 + org_len);
    CHECK(!memcmp(result->raw_v2.data, pair->key, 52));
    CHECK(!memcmp(result->raw_v2.data + 52, pair->organization, org_len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *org = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, "organization", &org));
    CHECK(json_object_is_type(key, json_type_string) && !strcmp(json_object_get_string(key), pair->key));
    CHECK(json_object_is_type(org, json_type_string) && !strcmp(json_object_get_string(org), pair->organization));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    char url[128];
    snprintf(url, sizeof(url), "https://dev.azure.com/%s/_apis/projects", pair->organization);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 972);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    /* Independent Base64 implementation checks the leading ':' for EMPTY
     * username and preserves the original key spelling as the password. */
    unsigned char credential[53], encoded[73];
    credential[0] = ':'; memcpy(credential + 1, pair->key, 52);
    CHECK(EVP_EncodeBlock(encoded, credential, sizeof(credential)) == 72);
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 78 && !memcmp(auth, "Basic ", 6) && !strcmp(auth + 6, (const char *)encoded));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog devops-pat-test" : "TruffleHog"));
    if (expected->responses) http->response = expected->responses[http->calls - 1];
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_pair *pair, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pair);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    expected_pair pair = {lower_key, "CaseOrg7"};
    const struct { const char *format; size_t count; } cases[] = {
        {"azure '%s'\nazure '%s'", 1},
        {"AZURE %s\nAzure %s", 1},
        {"prefixazuresuffix %s\nazure %s", 1},
        {"azure\r\n%s\nazure\r\n%s", 1},
        {"%s\n%s", 0},
        {"azure _%s\nazure %s", 0},
        {"azure %s_\nazure %s", 0},
        {"azure %sx\nazure %s", 0},
        {"azure %.51s\nazure %s", 0},
        {"azure %s\nazure _%s", 0},
        {"azure %s\nazure %s_", 0},
        {"azure %s\nazure '-%s-'", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, pair.key, pair.organization);
        expect_extraction(detector, input, strlen(input), &pair, cases[i].count);
    }
    pair.key = upper_key;
    snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.organization);
    expect_extraction(detector, input, strlen(input), &pair, 0);
    char mixed_key[53]; memcpy(mixed_key, lower_key, sizeof(mixed_key)); mixed_key[0] = 'B';
    snprintf(input, sizeof(input), "azure %s\nazure %s", mixed_key, pair.organization);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    pair.key = lower_key;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "azure", 5); memset(input + 5, '-', gap);
        snprintf(input + 5 + gap, sizeof(input) - 5 - gap, "%s\nazure %s", pair.key, pair.organization);
        expect_extraction(detector, input, strlen(input), &pair, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "azure %s\nazure", pair.key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", pair.organization);
        expect_extraction(detector, input, strlen(input), &pair, gap == 40 ? 1 : 0);
    }
    char org50[51], org51[52]; memset(org50, 'B', 50); org50[50] = 0;
    memset(org51, 'C', 51); org51[51] = 0;
    const struct { const char *org; size_t count; } organizations[] = {
        {"Abcd123", 1}, {org50, 1}, {"Abcd12", 0}, {org51, 0}, {"Case_Org7", 0},
    };
    for (size_t i = 0; i < sizeof(organizations) / sizeof(organizations[0]); ++i) {
        pair.organization = organizations[i].org;
        snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.organization);
        expect_extraction(detector, input, strlen(input), &pair, organizations[i].count);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "azure %s", lower_key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "azure %s", "CaseOrg7");
    expect_extraction(detector, input, strlen(input), NULL, 0);
}

static void occurrences(const br_detector *detector)
{
    char input[320];
    snprintf(input, sizeof(input), "azure OtherOrg8\nazure %s\nazure %s\nazure CaseOrg7\nazure %s\nazure OtherOrg8",
             lower_key, second_key, lower_key);
    const expected_pair pairs[] = {
        {lower_key, "OtherOrg8"}, {lower_key, "CaseOrg7"}, {lower_key, "OtherOrg8"},
        {second_key, "OtherOrg8"}, {second_key, "CaseOrg7"}, {second_key, "OtherOrg8"},
        {lower_key, "OtherOrg8"}, {lower_key, "CaseOrg7"}, {lower_key, "OtherOrg8"},
    };
    expected_requests expected = {pairs, sizeof(pairs) / sizeof(pairs[0]), NULL};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {.response = {.status = 201, .body = {marker, sizeof(marker) - 1}},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == expected.len);
        CHECK(http.calls == (verify ? expected.len : 0) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            check_pair(&results.items[i], &pairs[i]);
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void expect_response(const br_detector *detector, int status, br_slice body,
                             const char *read_error, outcome expected_outcome)
{
    expected_pair pair = {second_key, "Case-Org7"};
    expected_requests expected = {&pair, 1, NULL};
    char input[128], status_error[80];
    snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.organization);
    test_http http = {.response = {.status = status, .body = body, .body_error = read_error},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "devops-pat-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    const br_result *result = &results.items[0]; check_pair(result, &pair);
    CHECK(result->verified == (expected_outcome == FOUND));
    if (expected_outcome == STATUS_ERROR) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", status);
        CHECK(result->verification_error && !strcmp(result->verification_error, status_error));
    } else if (expected_outcome == READ_SHAPE)
        CHECK(result->verification_error && !strcmp(result->verification_error, read_shape_error));
    else CHECK(!result->verification_error);
    br_results_clear(&results);
}

static void status_and_binary_bodies(const br_detector *detector)
{
    static const unsigned char binary[] = "not JSON\0lastUpdateTime\r\n";
    static const unsigned char split[] = "lastUpdate\nTime";
    static const unsigned char wrong_case[] = "lastupdatetime";
    static const unsigned char bare_cr[] = "noise\rlastUpdateTime\r";
    const struct { int status; br_slice body; const char *error; outcome expected; } cases[] = {
        {200, {marker, sizeof(marker) - 1}, NULL, FOUND},
        {204, {binary, sizeof(binary) - 1}, "ignored body error", FOUND},
        {206, {bare_cr, sizeof(bare_cr) - 1}, "ignored body error", FOUND},
        {200, {split, sizeof(split) - 1}, NULL, STATUS_ERROR},
        {202, {wrong_case, sizeof(wrong_case) - 1}, NULL, STATUS_ERROR},
        {200, {NULL, 0}, "ignored body error", STATUS_ERROR},
        {401, {binary, sizeof(binary) - 1}, "ignored body error", REJECTED},
        {401, {NULL, 0}, "ignored body error", REJECTED},
        {300, {marker, sizeof(marker) - 1}, NULL, STATUS_ERROR},
        {403, {marker, sizeof(marker) - 1}, NULL, STATUS_ERROR},
        {500, {marker, sizeof(marker) - 1}, "ignored body error", STATUS_ERROR},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        expect_response(detector, cases[i].status, cases[i].body, cases[i].error, cases[i].expected);
}

static br_bytes line_body(size_t payload, const char *ending, bool include_marker)
{
    size_t tail = strlen(ending);
    br_bytes out = {malloc(payload + tail), payload + tail}; CHECK(out.data);
    memset(out.data, 'x', payload);
    if (include_marker) { CHECK(payload >= sizeof(marker) - 1); memcpy(out.data, marker, sizeof(marker) - 1); }
    memcpy(out.data + payload, ending, tail);
    return out;
}

static void scanner_boundaries(const br_detector *detector)
{
    br_bytes lf_ok = line_body(65535, "\n", true), crlf_ok = line_body(65534, "\r\n", true);
    br_bytes lf_long = line_body(65536, "\n", true), crlf_long = line_body(65535, "\r\n", true);
    br_bytes final_ok = line_body(65535, "", true), final_boundary = line_body(65536, "", true);
    br_bytes boundary_without_marker = line_body(65536, "", false), final_cr = line_body(65535, "\r", true);
    br_bytes final_long = line_body(65537, "", true);
    br_bytes early = {malloc(70015), 70015}, late = {malloc(70016), 70016};
    CHECK(early.data && late.data);
    memcpy(early.data, marker, 14); early.data[14] = '\n'; memset(early.data + 15, 'x', 70000);
    memset(late.data, 'x', 70000); late.data[70000] = '\n';
    memcpy(late.data + 70001, marker, 14); late.data[70015] = '\n';
    const struct { br_bytes body; int status; const char *error; outcome expected; } cases[] = {
        {lf_ok, 206, NULL, FOUND},
        {crlf_ok, 200, NULL, FOUND},
        {lf_long, 200, NULL, STATUS_ERROR},
        {crlf_long, 200, NULL, STATUS_ERROR},
        {final_ok, 299, "ignored terminal read error", FOUND},
        {final_boundary, 200, NULL, READ_SHAPE},
        {final_boundary, 201, "terminal read shape still unknown", READ_SHAPE},
        {boundary_without_marker, 200, NULL, STATUS_ERROR},
        {final_cr, 200, NULL, READ_SHAPE},
        {final_long, 200, "ignored terminal read error", STATUS_ERROR},
        {early, 200, "ignored later error", FOUND},
        {late, 200, "ignored later error", STATUS_ERROR},
        {final_boundary, 401, "ignored terminal read error", REJECTED},
        {final_boundary, 500, "ignored terminal read error", STATUS_ERROR},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        expect_response(detector, cases[i].status, (br_slice){cases[i].body.data, cases[i].body.len}, cases[i].error, cases[i].expected);
    free(lf_ok.data); free(crlf_ok.data); free(lf_long.data); free(crlf_long.data);
    free(final_ok.data); free(final_boundary.data); free(boundary_without_marker.data); free(final_cr.data);
    free(final_long.data); free(early.data); free(late.data);
}

static void boundary_does_not_stop_pairs(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "azure %s\nazure FirstOrg7\nazure SecondOrg8", second_key);
    const expected_pair pairs[] = {{second_key, "FirstOrg7"}, {second_key, "SecondOrg8"}};
    br_bytes boundary = line_body(65536, "", true);
    const br_http_response responses[] = {
        {.status = 200, .body = {boundary.data, boundary.len}},
        {.status = 200, .body = {marker, sizeof(marker) - 1}},
    };
    expected_requests expected = {pairs, 2, responses};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) check_pair(&results.items[i], &pairs[i]);
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, read_shape_error));
    CHECK(results.items[1].verified && !results.items[1].verification_error);
    br_results_clear(&results); free(boundary.data);
}

static bool cancelled(void *user) { return *(bool *)user; }

static void creation_transport_and_context(const br_detector *detector)
{
    expected_pair pair = {lower_key, "CaseOrg7"}; expected_requests expected = {&pair, 1, NULL};
    char input[128], sensitive[256], redacted[160];
    snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.organization);
    snprintf(sensitive, sizeof(sensitive), "org=%s key=%s again=%s", pair.organization, pair.key, pair.key);
    snprintf(redacted, sizeof(redacted), "org=%s key=[REDACTED] again=[REDACTED]", pair.organization);
    test_http http = {.response = {.status = 200, .body = {marker, sizeof(marker) - 1}},
                      .send_rc = 1, .send_error = sensitive, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_pair(&results.items[0], &pair);
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, redacted));
    CHECK(!strstr(results.items[0].verification_error, pair.key) && strstr(results.items[0].verification_error, pair.organization));
    br_results_clear(&results);
    /* Request construction fails before transport when context is nil. */
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 1 && http.releases == 1); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_pair(&results.items[0], &pair); br_results_clear(&results);
    bool stop = true;
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http = (test_http){.inspect = inspect_request, .user = &expected};
        ctx = (br_scan_ctx){.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .cancel_user = &stop, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        check_pair(&results.items[0], &pair);
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(lower_key, 52, 0);
    test_secret(second_key, 52, 7);
    for (size_t i = 0; i < sizeof(upper_key); ++i)
        upper_key[i] = lower_key[i] >= 'a' && lower_key[i] <= 'z' ? lower_key[i] - 'a' + 'A' : lower_key[i];
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); status_and_binary_bodies(detector);
    scanner_boundaries(detector); boundary_does_not_stop_pairs(detector); creation_transport_and_context(detector);
    return test_finish("AzureDevopsPersonalAccessToken bounded ScanLines policy");
}
