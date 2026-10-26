/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other[33];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_audd_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_audd_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_audd_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 376 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Audd") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Audd is a music recognition service. Audd API tokens can be used to access the Audd API services for recognizing music and obtaining metadata."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "audd"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 376, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[33];
    const char *const one[] = {key}, *const hyphenated[] = {other};
    const char *const ordered[] = {key, other, key};
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "audd %s", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "preAUDDsuffix:%s\naudd\r\n%s\naudd %s", key, other, key);
    expect_extraction(detector, input, ordered, 3);
    snprintf(input, sizeof(input), "audd %s", other);
    expect_extraction(detector, input, hyphenated, 1); /* Not UUID-shaped or restricted to hex. */
    snprintf(input, sizeof(input), "audd \xc3\xa9%s\xc3\xa9", key);
    expect_extraction(detector, input, one, 1); /* ASCII word boundaries. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "audd");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *const wrappers[] = {"audd _%s", "audd %s_", "audd %sq"};
    for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        snprintf(input, sizeof(input), wrappers[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "audd %.31s", key);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[7] = 'Q';
    snprintf(input, sizeof(input), "audd %s", changed);
    expect_extraction(detector, input, NULL, 0);
    changed[7] = '%';
    snprintf(input, sizeof(input), "audd %s", changed);
    expect_extraction(detector, input, NULL, 0);
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *const low[] = {changed};
    snprintf(input, sizeof(input), "audd %s", changed);
    expect_extraction(detector, input, low, 1); /* No local placeholder filtering. */

    /* A boundary can enclose a captured hyphen when its outside neighbor is a
     * word character. Do not impose extra first/last-alphanumeric restrictions. */
    memcpy(changed, key, sizeof(changed));
    changed[0] = '-';
    snprintf(input, sizeof(input), "audd Q%s", changed);
    expect_extraction(detector, input, low, 1);
    snprintf(input, sizeof(input), "audd %s", changed);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[31] = '-';
    snprintf(input, sizeof(input), "audd %sQ", changed);
    expect_extraction(detector, input, low, 1);
    snprintf(input, sizeof(input), "audd %s", changed);
    expect_extraction(detector, input, NULL, 0);
    memset(changed, '-', 32);
    snprintf(input, sizeof(input), "audd Q%sQ", changed);
    expect_extraction(detector, input, low, 1);

    unsigned char bytes[37];
    memcpy(bytes, "audd\0", 5);
    memcpy(bytes + 5, key, 32);
    br_results results = test_scan(detector, NULL, false, bytes, sizeof(bytes));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 376, key, "key");
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

typedef struct { const char *const *keys; size_t count; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    char url[192];
    snprintf(url, sizeof(url),
             "https://api.audd.io/setCallbackUrl/?api_token=%s&url=https://yourwebsite.com/callbacks_handler/", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 376);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* Only the shared User-Agent, no provider headers. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog audd-test"));
}

static void verification(const br_detector *detector)
{
    static const char binary[] = "\0\xff not-json \"status\":\"success\"\0tail";
    const struct {
        int status;
        const char *body, *body_error;
        bool verified;
        int send_rc;
        const char *send_error;
        size_t body_len;
    } cases[] = {
        {200, "{\"status\":\"success\"}", NULL, true, 0, NULL, 0},
        {201, "not JSON: \"status\":\"success\" trailing", NULL, true, 0, NULL, 0},
        {204, "\"status\":\"success\"", NULL, true, 0, NULL, 0},
        {299, "\"status\":\"success\"", NULL, true, 0, NULL, 0},
        {199, "\"status\":\"success\"", NULL, false, 0, NULL, 0},
        {300, "\"status\":\"success\"", NULL, false, 0, NULL, 0},
        {401, "\"status\":\"success\"", NULL, false, 0, NULL, 0},
        {403, "\"status\":\"success\"", "suppressed read failure", false, 0, NULL, 0},
        {500, "\"status\":\"success\"", NULL, false, 0, NULL, 0},
        {200, binary, NULL, true, 0, NULL, sizeof(binary) - 1},
        {200, "{\"status\": \"success\"}", NULL, false, 0, NULL, 0},
        {200, "{\"status\" :\"success\"}", NULL, false, 0, NULL, 0},
        {200, "{\"STATUS\":\"success\"}", NULL, false, 0, NULL, 0},
        {200, "{\"status\":\"SUCCESS\"}", NULL, false, 0, NULL, 0},
        {200, "{\"status\":\"successfully\"}", NULL, false, 0, NULL, 0},
        {200, NULL, NULL, false, 0, NULL, 0},
        {200, "\"status\":\"success\"", "suppressed read failure", false, 0, NULL, 0},
        {200, "\"status\":\"success\"", "", false, 0, NULL, 0},
        {200, "\"status\":\"success\"", NULL, false, -1, "context deadline exceeded", 0},
        {200, "\"status\":\"success\"", NULL, false, -1, "context canceled", 0},
        {200, "\"status\":\"success\"", NULL, false, -1, NULL, 0},
    };
    char input[64];
    snprintf(input, sizeof(input), "audd %s", key);
    const char *const keys[] = {key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {keys, 1};
        test_http http = {
            .response = {.status = cases[i].status,
                .body = {(const unsigned char *)cases[i].body, cases[i].body_len ? cases[i].body_len : cases[i].body ? strlen(cases[i].body) : 0},
                .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "audd-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 376, key, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_scan_ctx offline = {0};
    const br_scan_ctx *contexts[] = {&offline, NULL};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        /* Safe C ABI behavior, not an emulation of Go's nil-context skip. */
        br_results results = test_scan(detector, contexts[i], true, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], 376, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void duplicate_verification(const br_detector *detector)
{
    char input[192], suppressed[192];
    snprintf(input, sizeof(input), "audd %s\naudd %s\naudd %s", key, other, key);
    snprintf(suppressed, sizeof(suppressed), "suppressed cause key=%s repeated=%s other=%s", key, key, other);
    const char *const keys[] = {key, other, key};
    static const unsigned char body[] = "\"status\":\"success\"";
    for (int mode = 0; mode < 3; ++mode) {
        requests expected = {keys, 3};
        test_http http = {
            .response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = mode == 2 ? suppressed : NULL},
            .send_rc = mode == 1 ? -1 : 0, .send_error = mode == 1 ? suppressed : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "audd-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t r = 0; r < results.len; ++r) {
            test_key_result(&results.items[r], 376, keys[r], "key");
            CHECK(results.items[r].verified == (mode == 0) && !results.items[r].verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, "audd too-short", strlen("audd too-short"));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    other[7] = '-';
    other[13] = '-';
    other[24] = '-';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    duplicate_verification(detector);
    return test_finish("Audd");
}
