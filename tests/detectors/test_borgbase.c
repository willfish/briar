/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char first_key[151], second_key[151];
static const unsigned char exact_marker[] = "\"sshList\":[]";
typedef struct { const char *const *keys; size_t len; } expected_requests;

/* Exercise the real setter's positive +1 resource return, targeting only its
 * copy of this provider's 503 status error. Other allocations remain normal. */
static bool fail_status_copy;
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, "unexpected status code: 503")) {
        fail_status_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_borgbase_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_borgbase_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 723 && detector->version == 0 && !strcmp(detector->name, "Borgbase"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Borgbase is a service for hosting Borg repositories. Borgbase API keys can be used to manage and access these repositories."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "borgbase"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_borgbase_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 723, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], word[154];
    const struct { const char *format; size_t count; } cases[] = {
        {"borgbase '%s'", 1}, {"BORGBASE: %s", 1}, {"prefixborgbasesuffix %s", 1},
        {"borgbase\r\n%s\t", 1}, {"%s", 0}, {"borg base %s", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t len = 147; len <= 153; ++len) {
        test_secret(word, len, 3);
        snprintf(input, sizeof(input), "borgbase %s", word);
        expect_extraction(detector, input, strlen(input), word, len >= 148 && len <= 152 ? 1 : 0);
    }
    test_secret(word, 150, 3);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "borgbase", 8); memset(input + 8, ':', gap);
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s", word);
        expect_extraction(detector, input, strlen(input), word, gap == 40 ? 1 : 0);
    }
    test_secret(word, 152, 3);
    snprintf(input, sizeof(input), "borgbase _%s", word);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* 153 word bytes cannot truncate at a boundary. */
    snprintf(input, sizeof(input), "borgbase %s_", word);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    word[0] = '/';
    snprintf(input, sizeof(input), "borgbase %s", word);
    expect_extraction(detector, input, strlen(input), word + 1, 1); /* Boundary starts after slash. */
    snprintf(input, sizeof(input), "borgbase W%s", word);
    expect_extraction(detector, input, strlen(input), word, 1); /* Word BEFORE slash allows a slash-leading capture. */
    test_secret(word, 148, 3); word[0] = '/';
    snprintf(input, sizeof(input), "borgbase %s", word);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* Dropping slash leaves only 147 bytes. */
    test_secret(word, 148, 3); word[147] = '/';
    snprintf(input, sizeof(input), "borgbase %s", word);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    test_secret(word, 152, 3); word[151] = '/';
    snprintf(input, sizeof(input), "borgbase %sZ", word);
    expect_extraction(detector, input, strlen(input), word, 1); /* Ending slash has a boundary before Z. */
    memcpy(word, first_key, sizeof(first_key)); word[70] = '+';
    snprintf(input, sizeof(input), "borgbase %s", word);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(word, 'Z', 150); word[150] = 0;
    snprintf(input, sizeof(input), "borgbase %s", word);
    expect_extraction(detector, input, strlen(input), word, 1); /* No JWT/Base64 validation or entropy/FP filter. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.borgbase.com/graphql"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 723);
    static const char body[] = "{\"query\":\"{ sshList {id, name}}\"}";
    CHECK(request->body.data && request->body.len == sizeof(body) - 1 && !memcmp(request->body.data, body, sizeof(body) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char authorization[192];
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog borgbase-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* No explicit Accept or Content-Length header. */
}

static void occurrences(const br_detector *detector)
{
    char input[640];
    snprintf(input, sizeof(input), "borgbase %s\nBORGBASE %s\nborgbase %s", first_key, second_key, first_key);
    const char *keys[] = {first_key, second_key, first_key};
    expected_requests expected = {keys, sizeof(keys) / sizeof(keys[0])};
    for (int mode = 0; mode < 3; ++mode) {
        bool verify = mode != 0;
        const char *dns_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200, .body = {exact_marker, sizeof(exact_marker) - 1}},
                          .send_rc = mode == 2 ? 1 : 0, .send_error = dns_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 723, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1));
            if (dns_error) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, dns_error));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 723, keys[i], "key");
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 723, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[192], unredacted[512];
    snprintf(input, sizeof(input), "borgbase %s", second_key);
    snprintf(unredacted, sizeof(unredacted), "synthetic transport/read key=%s again=%s", second_key, second_key);
    const char *keys[] = {second_key}; expected_requests expected = {keys, 1};
    static const unsigned char json[] = "{\"data\":{\"sshList\":[]}}";
    static const unsigned char spaced[] = "{\"sshList\": []}";
    static const unsigned char wrong_case[] = "{\"sshlist\":[]}";
    static const unsigned char nonempty[] = "{\"sshList\":[{\"id\":\"synthetic\"}]}";
    static const unsigned char binary[] = {'x', 0, 0xff, '"', 's', 's', 'h', 'L', 'i', 's', 't', '"', ':', '[', ']', '!'};
    const br_slice marker_body = {exact_marker, sizeof(exact_marker) - 1}, binary_body = {binary, sizeof(binary)};
    const struct {
        int status;
        br_slice body;
        const char *body_error;
        int send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, {json, sizeof(json) - 1}, NULL, 0, NULL, true, NULL},
        {200, marker_body, NULL, 0, NULL, true, NULL}, /* Not valid JSON: substring alone verifies. */
        {200, binary_body, NULL, 0, NULL, true, NULL}, /* Marker after NUL and invalid UTF-8. */
        {200, {spaced, sizeof(spaced) - 1}, NULL, 0, NULL, false, NULL},
        {200, {wrong_case, sizeof(wrong_case) - 1}, NULL, 0, NULL, false, NULL},
        {200, {nonempty, sizeof(nonempty) - 1}, NULL, 0, NULL, false, NULL},
        {200, {NULL, 0}, NULL, 0, NULL, false, NULL},
        {200, binary_body, unredacted, 0, NULL, false, unredacted}, /* Read error beats a present marker. */
        {401, binary_body, unredacted, 0, NULL, false, NULL},
        {403, binary_body, unredacted, 0, NULL, false, "unexpected status code: 403"},
        {201, binary_body, unredacted, 0, NULL, false, "unexpected status code: 201"},
        {500, binary_body, unredacted, 0, NULL, false, "unexpected status code: 500"},
        {200, binary_body, NULL, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, binary_body, NULL, -1, "context canceled", false, "context canceled"},
        {200, binary_body, NULL, 1, unredacted, false, unredacted},
        {200, binary_body, NULL, 1, NULL, false, "HTTP transport failed"},
        {200, binary_body, NULL, 0, NULL, true, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].body_error},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "borgbase-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; test_key_result(result, 723, second_key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
        else CHECK(!result->verification_error);
        if (cases[i].error == unredacted) {
            CHECK(strstr(result->verification_error, second_key));
            CHECK(!strstr(result->verification_error, "[REDACTED]"));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_errors(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "borgbase %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 723, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

static void resource_returns(const br_detector *detector)
{
    br_result probe = {0};
    fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected status code: 503", NULL, 0) == 1);
    CHECK(!fail_status_copy && !probe.verification_error);
    br_result_clear(&probe);
    char input[192]; snprintf(input, sizeof(input), "borgbase %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    test_http http = {.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; char *error = NULL;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_status_copy && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 723, first_key, "key");
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected status code: 503"));
    br_results_clear(&results);
}

int main(void)
{
    test_secret(first_key, 150, 0); test_secret(second_key, 150, 9);
    first_key[20] = '/'; first_key[50] = '_'; first_key[80] = '.'; first_key[110] = '-'; first_key[130] = 'Z';
    second_key[30] = '/'; second_key[60] = '_'; second_key[90] = '.'; second_key[120] = '-'; second_key[140] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); context_errors(detector); resource_returns(detector);
    return test_finish("Borgbase");
}
