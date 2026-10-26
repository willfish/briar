/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic old-format PAT intentionally belongs to both detector identities. */
static const char old_pat[] = "7/1234567890123456:abcdefghijklmnopqrstuvwxyz012345";
static const char new_pat[] = "7/1234567890123456/6543210987654321:AbCdEfGhIjKlMnOpQrStUvWxYz012345";

static void check_metadata(const br_detector *detector, int32_t type,
                            const char *name, const char *description)
{
    CHECK(detector && detector->type == type && detector->version == 0);
    CHECK(!strcmp(detector->name, name) && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "asana"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *tokens, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], detector->type, tokens[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_prefix(const br_detector *detector, const char *token)
{
    char input[192];
    const char *one[] = {token};
    const struct { const char *format; bool matches; } cases[] = {
        {"asana %s", true}, {"preASANAsuffix:%s", true},
        {"asana\r\n '%s'", true}, {"asana \xc3\xa9%s\xc3\xa9", true},
        {"%s", false}, {"asana _%s", false}, {"asana %s_", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, token);
        expect_extraction(detector, input, one, cases[i].matches ? 1 : 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "asana", 5);
        memset(input + 5, '!', gap);
        memcpy(input + 5 + gap, token, strlen(token) + 1);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    expect_extraction(detector, "", NULL, 0);
}

static void test_oauth(const br_detector *detector, const char *token)
{
    test_prefix(detector, token);
    char input[96], changed[52];
    const char *one[] = {changed};
    memset(changed, 'a', 51); changed[51] = '\0';
    snprintf(input, sizeof(input), "asana %s", changed);
    expect_extraction(detector, input, one, 1); /* No PAT grammar or entropy restriction. */
    memcpy(changed, token, sizeof(changed));
    changed[30] = 'Q';
    snprintf(input, sizeof(input), "asana %s", changed);
    expect_extraction(detector, input, NULL, 0); /* Folding applies only to the prefix. */
    snprintf(input, sizeof(input), "asana %.50s", token);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "asana %s9", token);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, token, sizeof(changed));
    changed[50] = ':';
    snprintf(input, sizeof(input), "asana %s", changed);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "asana %sX", changed);
    expect_extraction(detector, input, one, 1); /* A colon-to-word transition is an ASCII boundary. */
}

static void test_pat(const br_detector *detector)
{
    test_prefix(detector, old_pat);
    char input[128];
    const char *one[] = {new_pat};
    snprintf(input, sizeof(input), "asana %s", new_pat);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "asana 7/123456789012345:abcdefghijklmnopqrstuvwxyz012345");
    expect_extraction(detector, input, NULL, 0); /* At least 16 digits after the slash. */
    snprintf(input, sizeof(input), "asana %.50s", old_pat);
    expect_extraction(detector, input, NULL, 0); /* At least 32 suffix characters. */
}

typedef struct {
    const char *const *tokens;
    size_t count;
    int32_t type;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const char *token = expected->tokens[http->calls - 1];
    size_t len = strlen(token);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.asana.com/api/1.0/users/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == expected->type);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == len + 7);
    CHECK(!memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[0].value + 7, token, len + 1));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog asana-test"));
}

static void test_occurrences(const br_detector *detector, const char *first, const char *second)
{
    char input[256];
    snprintf(input, sizeof(input), "asana %s\nasana %s\nasana %s", first, second, first);
    const char *tokens[] = {first, second, first};
    expect_extraction(detector, input, tokens, 3);
    expected_requests expected = {tokens, 3, detector->type};
    test_http http = {
        .response = {.status = 200, .body_error = "ignored body/drain failure"},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "asana-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], detector->type, tokens[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

typedef struct {
    int status, send_rc;
    const char *send_error, *error;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, const char *token, verification_case fixture)
{
    size_t size = strlen(token) + sizeof("asana ");
    char *input = malloc(size);
    CHECK(input);
    snprintf(input, size, "asana %s", token);
    const char *tokens[] = {token};
    expected_requests expected = {tokens, 1, detector->type};
    static const unsigned char body[] = {0, 0xff, '{'};
    test_http http = {
        .response = {.status = fixture.status, .body = {body, sizeof(body)}, .body_error = "ignored body/drain failure"},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "asana-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], detector->type, token, "key");
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, token));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
}

static void test_verification(const br_detector *detector, const char *token)
{
    const verification_case cases[] = {
        {.status = 200, .verified = true}, {.status = 401},
        {.status = 201, .error = "unexpected status code 201"},
        {.status = 400, .error = "unexpected status code 400"},
        {.status = 403, .error = "unexpected status code 403"},
        {.status = 500, .error = "unexpected status code 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, token, cases[i]);
    char cause[256];
    snprintf(cause, sizeof(cause), "candidate=%s other=leave-this-alone candidate-again=%s", token, token);
    verify_case(detector, token, (verification_case){.status = 200, .send_rc = -1,
        .send_error = cause, .error = "candidate=[REDACTED] other=leave-this-alone candidate-again=[REDACTED]"});

    char input[96];
    snprintf(input, sizeof(input), "asana %s", token);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    test_key_result(&results.items[0], detector->type, token, "key");
    br_results_clear(&results);
}

static char *long_pat(void)
{
    /* Exercise every unbounded component; the 4097-byte alphanumeric suffix is
     * not a valid Base64 length, but the upstream regex accepts it unchanged. */
    const size_t first = 72, second = 96, third = 80, suffix = 4097;
    size_t len = first + second + third + suffix + 3;
    char *token = malloc(len + 1);
    CHECK(token);
    size_t at = 0;
    memset(token + at, '7', first); at += first; token[at++] = '/';
    memset(token + at, '2', second); at += second; token[at++] = '/';
    memset(token + at, '8', third); at += third; token[at++] = ':';
    test_secret(token + at, suffix, 3);
    token[at + 2] = 'Q';
    CHECK(strlen(token) == len && len == 4348);
    return token;
}

int main(void)
{
    const br_detector *oauth = NULL, *pat = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_asanaoauth_init(&oauth, &error) == 0 && !error && oauth);
    CHECK(br_asanapersonalaccesstoken_init(&pat, &error) == 0 && !error && pat);
    check_metadata(oauth, 98, "AsanaOauth",
                   "Asana is a work management platform that helps teams organize, track, and manage their work. "
                   "Asana OAuth tokens can be used to access and interact with Asana's API on behalf of a user.");
    check_metadata(pat, 41, "AsanaPersonalAccessToken",
                   "Asana is a web and mobile application designed to help teams organize, track, and manage their work. "
                   "Asana Personal Access Tokens can be used to access and modify data within Asana.");
    CHECK(oauth != pat && oauth->state != pat->state && oauth->scan == pat->scan);
    const void *oauth_state = oauth->state, *pat_state = pat->state;
    CHECK(br_asanaoauth_init(&again, &error) == 0 && !error && again == oauth && again->state == oauth_state);
    CHECK(br_asanapersonalaccesstoken_init(&again, &error) == 0 && !error && again == pat && again->state == pat_state);
    CHECK(br_asanaoauth_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Asana OAuth detector output"));
    free(error); error = NULL;
    CHECK(br_asanapersonalaccesstoken_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Asana PAT detector output"));
    free(error);
    CHECK(br_asanaoauth_init(NULL, NULL) != 0);
    CHECK(br_asanapersonalaccesstoken_init(NULL, NULL) != 0);
    CHECK(strlen(old_pat) == 51 && strlen(new_pat) == 68);
    char oauth_key[52], other_oauth[52], overlap[64];
    test_secret(oauth_key, 51, 0); oauth_key[9] = ':'; oauth_key[22] = '/';
    test_secret(other_oauth, 51, 9);
    test_oauth(oauth, oauth_key);
    test_pat(pat);
    snprintf(overlap, sizeof(overlap), "asana %s", old_pat);
    const char *old[] = {old_pat};
    expect_extraction(oauth, overlap, old, 1);
    expect_extraction(pat, overlap, old, 1);
    verify_case(oauth, old_pat, (verification_case){.status = 200, .verified = true});
    test_occurrences(oauth, oauth_key, other_oauth);
    test_occurrences(pat, old_pat, new_pat);
    test_verification(oauth, oauth_key);
    test_verification(pat, old_pat);
    char *large = long_pat();
    verify_case(pat, large, (verification_case){.status = 200, .verified = true});
    free(large);
    CHECK(br_asanaoauth_init(&again, NULL) == 0 && again == oauth && again->state == oauth_state);
    CHECK(br_asanapersonalaccesstoken_init(&again, NULL) == 0 && again == pat && again->state == pat_state);
    return test_finish("Asana OAuth and PAT");
}
