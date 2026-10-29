/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_jumpcloud_init(const br_detector **out, char **error);

static char key[41], other[41];
static size_t fail_size, fail_after;
static int fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

void *realloc(void *old, size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    if (!size) { free(old); return NULL; }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) {
        if (old) memcpy(copy, old, previous < size ? previous : size);
        free(old);
    }
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#include "../../src/detectors/jumpcloud.c"

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_jumpcloud_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Jumpcloud detector output"));
    free(error);
    error = NULL;
    CHECK(!br_jumpcloud_init(&detector, &error) && detector && !error);
    CHECK(!br_jumpcloud_init(&again, NULL) && again == detector);
    CHECK(detector->type == 131 && detector->version == 0 && !strcmp(detector->name, "Jumpcloud"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Jumpcloud is a cloud-based directory service platform that offers user and device management, "
                  "single sign-on, and other identity and access management (IAM) features. "
                  "Jumpcloud API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "jumpcloud"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_raw(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) {
        test_key_result(&results.items[0], 131, expected, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320];
    const char *formats[] = {"jumpcloud %s", "JUMPCLOUD '%s'", "prefixjumpcloudsuffix=%s", "jumpcloud\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        expect_raw(detector, input, strlen(input), key);
    }
    snprintf(input, sizeof(input), "jumpcloud token = '%s'", key);
    expect_raw(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "jumpcloud token = '%s' | '%s'", key, key);
    expect_raw(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "jumpcloud keyword is not close to the real key in the data\n = '%s'", key);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "jumpcloud = '%s'", "ugys2uNNSDMylExbF0n4ttJrxL4ghI4YWK1nr0H");
    expect_raw(detector, input, strlen(input), NULL);
    expect_raw(detector, key, 40, NULL);
    expect_raw(detector, "", 0, NULL);

    char upper[41];
    memset(upper, 'A', 40);
    upper[40] = '\0';
    snprintf(input, sizeof(input), "JumpCloud %s", upper);
    expect_raw(detector, input, strlen(input), upper);
    char changed[41];
    memcpy(changed, key, sizeof(changed));
    changed[10] = '-';
    snprintf(input, sizeof(input), "jumpcloud %s", changed);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "jumpcloud %sx", key);
    expect_raw(detector, input, strlen(input), NULL);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "jumpcloud", 9);
        memset(input + 9, '.', gap);
        memcpy(input + 9 + gap, key, 40);
        input[9 + gap + 40] = '\0';
        expect_raw(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    unsigned char binary[56];
    memcpy(binary, "\xffjumpcloud ", 12);
    memcpy(binary + 12, key, 40);
    expect_raw(detector, binary, 52, key);
    unsigned char vt[52];
    memcpy(vt, "jumpcloud", 9);
    vt[9] = 0x0b;
    memcpy(vt + 10, key, 40);
    expect_raw(detector, vt, 50, key);

    snprintf(input, sizeof(input), "jumpcloud %s jumpcloud %s", key, other);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && !http.calls && !http.releases);
    test_key_result(&results.items[0], 131, key, "key");
    test_key_result(&results.items[1], 131, other, "key");
    br_results_clear(&results);
}

typedef struct { const char *keys[2]; size_t len; } expected_requests;

static const int *scripted_status;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    const char *secret = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://console.jumpcloud.com/api/v2/systemgroups"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 131);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key") && !strcmp(request->headers[0].value, secret));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog jumpcloud-test"));
    if (scripted_status) http->response.status = scripted_status[http->calls - 1];
}

static void expect_one(const br_detector *detector, test_http *http, const char *input,
                       bool verified, size_t calls)
{
    expected_requests expected = {{key, other}, calls};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "jumpcloud-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == calls && http->releases == calls);
    test_key_result(&results.items[0], 131, key, "key");
    CHECK(results.items[0].verified == verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "jumpcloud %s", key);
    const int verified_status[] = {200, 201, 204, 299};
    const int unverified_status[] = {199, 300, 401, 404, 500};
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(verified_status) / sizeof(verified_status[0]); ++i) {
        test_http http = {.response = {.status = verified_status[i], .body = {body, sizeof(body)}, .body_error = "ignored read"}};
        expect_one(detector, &http, input, true, 1);
    }
    for (size_t i = 0; i < sizeof(unverified_status) / sizeof(unverified_status[0]); ++i) {
        test_http http = {.response = {.status = unverified_status[i], .body = {body, sizeof(body)}, .body_error = "ignored read"}};
        expect_one(detector, &http, input, false, 1);
    }
    const char *errors[] = {"dial synthetic: no such host", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        expect_one(detector, &http, input, false, 1);
    }

    snprintf(input, sizeof(input), "jumpcloud %s\njumpcloud %s", key, other);
    const int statuses[] = {200, 401};
    scripted_status = statuses;
    expected_requests expected = {{key, other}, 2};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "jumpcloud-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        test_key_result(&results.items[i], 131, expected.keys[i], "key");
        CHECK(results.items[i].verified == (statuses[i] == 200) && !results.items[i].verification_error);
    }
    scripted_status = NULL;
    br_results_clear(&results);
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void seed(br_results *results)
{
    br_result prior = {0};
    CHECK(!br_finding_key_bytes(&prior, 7, (br_slice){(const unsigned char *)"kept", 4}, "kept"));
    CHECK(!br_results_push(results, &prior));
}

static void context_and_resource(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "jumpcloud %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0, .user_agent = "jumpcloud-test"};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1 && !results.items[0].verified);
        CHECK(!results.items[0].verification_error);
        test_key_result(&results.items[0], 131, key, "key");
        br_results_clear(&results);
    }
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    seed(&results);
    char *error = NULL;
    int rc = detector->scan(detector, NULL, true, (br_slice){NULL, 1}, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "invalid or uninitialized Jumpcloud scan"));
    CHECK(results.len == 1 && results.items[0].detector_type == 7);
    free(error);
    br_results_clear(&results);

    seed(&results);
    http.calls = http.releases = 0;
    fail_part_after = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && !fail_part_after && error && !strcmp(error, "cannot create Jumpcloud finding"));
    CHECK(results.len == 1 && results.items[0].detector_type == 7 && !http.calls && !http.releases);
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jumpcloud %s jumpcloud %s", key, other);
    seed(&results);
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request,
                       .user = &(expected_requests){{key, other}, 2}};
    transport = test_transport(&http);
    fail_part_after = 2;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport, .user_agent = "jumpcloud-test"}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && !fail_part_after && error && !strcmp(error, "cannot create Jumpcloud finding"));
    CHECK(results.len == 1 && results.items[0].detector_type == 7);
    CHECK(http.calls == 1 && http.releases == 1);
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jumpcloud %s", key);
    seed(&results);
    results.cap = results.len; /* Next publication must grow, so the failure is this invocation. */
    http = (test_http){.response = {.status = 200}};
    transport = test_transport(&http);
    fail_size = 2 * sizeof(br_result);
    fail_after = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && !fail_after && error && !strcmp(error, "cannot append Jumpcloud finding"));
    CHECK(results.len == 1 && results.items[0].detector_type == 7 && http.calls == 1 && http.releases == 1);
    free(error);
    br_results_clear(&results);

    http = (test_http){.response = {.status = 204}};
    expect_one(detector, &http, input, true, 1);
}

int main(void)
{
    test_secret(key, 40, 0);
    test_secret(other, 40, 5);
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("Jumpcloud");
}
