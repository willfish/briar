/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>
#include <openssl/evp.h>
#include <stdarg.h>

int br_jupiterone_init(const br_detector **out, char **error);

static char key[77], other[77], third[77];
static bool fail_status_copy;
static int fail_finding_after;
static size_t fail_realloc_size;
static int fail_realloc;
static const char status_500[] = "unexpected HTTP response status 500";

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_500)) {
        fail_status_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && len == 76 && --fail_finding_after == 0) return NULL;
    if (len < 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    if (!copy) return NULL;
    if (len && value) memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    struct json_object *object = json_object_new_string(copy);
    free(copy);
    return object;
}

void *realloc(void *old, size_t size)
{
    if (fail_realloc && size == fail_realloc_size) {
        fail_realloc = 0;
        return NULL;
    }
    if (!size) {
        free(old);
        return NULL;
    }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) {
        if (old) memcpy(copy, old, previous < size ? previous : size);
        free(old);
    }
    return copy;
}

static int (*jupiterone_http_send)(const br_scan_ctx *, const br_http_request *,
                                    br_http_response *, char **) = br_http_send;
static void (*jupiterone_http_release)(const br_scan_ctx *, br_http_response *) = br_http_release;
static int (*jupiterone_set_error)(br_result *, const char *, const br_slice *, size_t) =
    br_result_set_verification_error;

static int force_null_send_cause;
static int force_format_fail;
static int setter_force_rc;
static int setter_calls;
static int setter_was_null;
static char setter_text[160];
static unsigned char setter_secret_bytes[80];
static br_slice setter_secret;
static size_t setter_nsecrets;
enum { EV_SETTER = 1, EV_RELEASE = 2 };
static int event_log[8];
static int event_len;

static void reset_observe(void)
{
    setter_calls = setter_was_null = setter_force_rc = force_format_fail = 0;
    setter_text[0] = '\0';
    setter_secret = (br_slice){0};
    setter_nsecrets = 0;
    memset(setter_secret_bytes, 0, sizeof(setter_secret_bytes));
    event_len = 0;
}

static int inject_send(const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    int rc = jupiterone_http_send(ctx, request, response, error);
    if (force_null_send_cause && rc && error) {
        free(*error);
        *error = NULL;
        force_null_send_cause = 0;
    }
    return rc;
}

static void observe_release(const br_scan_ctx *ctx, br_http_response *response)
{
    if (event_len < 8) event_log[event_len++] = EV_RELEASE;
    jupiterone_http_release(ctx, response);
}

static int observe_setter(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    if (event_len < 8) event_log[event_len++] = EV_SETTER;
    ++setter_calls;
    setter_was_null = cause == NULL;
    setter_text[0] = '\0';
    if (cause) {
        size_t n = strlen(cause);
        if (n >= sizeof(setter_text)) n = sizeof(setter_text) - 1;
        memcpy(setter_text, cause, n);
        setter_text[n] = '\0';
    }
    setter_nsecrets = nsecrets;
    setter_secret = (br_slice){0};
    if (nsecrets && secrets && secrets[0].len <= sizeof(setter_secret_bytes)) {
        if (secrets[0].len && secrets[0].data)
            memcpy(setter_secret_bytes, secrets[0].data, secrets[0].len);
        setter_secret = (br_slice){setter_secret_bytes, secrets[0].len};
    }
    if (setter_force_rc) {
        int forced = setter_force_rc;
        setter_force_rc = 0;
        return forced;
    }
    return jupiterone_set_error(result, cause, secrets, nsecrets);
}

static int inject_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    if (force_format_fail) {
        force_format_fail = 0;
        return -1;
    }
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return n;
}

#define snprintf inject_snprintf
#define br_http_send inject_send
#define br_http_release observe_release
#define br_result_set_verification_error observe_setter
#include "../../src/detectors/jupiterone.c"
#undef br_result_set_verification_error
#undef br_http_release
#undef br_http_send
#undef snprintf

static void check_body(void)
{
    unsigned char digest[32], want[32];
    unsigned int len = 0;
    static const char hex[] = "734f86752e5aac1c9742860477ceeb4d418e5d4d1a1178406727e24a1e9dbb95";
    CHECK(sizeof(jupiterone_query) - 1 == 293);
    CHECK(EVP_Digest(jupiterone_query, sizeof(jupiterone_query) - 1, digest, &len, EVP_sha256(), NULL) == 1);
    CHECK(len == 32);
    for (size_t i = 0; i < 32; ++i) {
        unsigned value = 0;
        CHECK(sscanf(hex + 2 * i, "%2x", &value) == 1);
        want[i] = (unsigned char)value;
    }
    CHECK(!memcmp(digest, want, 32));
    CHECK(strstr(jupiterone_query, "\\\"find jupiterone_account\\\""));
    CHECK(memchr(jupiterone_query, '\t', sizeof(jupiterone_query)));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 76);
    CHECK(br_jupiterone_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid JupiterOne detector output"));
    free(error);
    error = NULL;
    CHECK(!br_jupiterone_init(&detector, &error) && detector && !error);
    CHECK(!br_jupiterone_init(&again, NULL) && again == detector);
    CHECK(detector->type == 982 && detector->version == 0 && !strcmp(detector->name, "JupiterOne"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "JupiterOne is a cloud security management platform. "
                  "JupiterOne API keys can be used to access and manage security data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "jupiterone"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    check_body();
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
        test_key_result(&results.items[0], 982, expected, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], upper[77], short_key[76];
    const char *formats[] = {"jupiterone %s", "JUPITERONE '%s'", "prefixjupiteronesuffix=%s", "jupiterone\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        expect_raw(detector, input, strlen(input), key);
    }
    snprintf(input, sizeof(input), "jupiterone token = '%s'", key);
    expect_raw(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "jupiterone token = '%s' | '%s'", key, key);
    expect_raw(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "jupiterone keyword is not close to the real key in the data\n = '%s'", key);
    expect_raw(detector, input, strlen(input), NULL);
    memcpy(short_key, key, 75);
    short_key[75] = '\0';
    snprintf(input, sizeof(input), "jupiterone = '%s'", short_key);
    expect_raw(detector, input, strlen(input), NULL);
    expect_raw(detector, key, 76, NULL);
    expect_raw(detector, "", 0, NULL);

    memset(upper, 'A', 76);
    upper[76] = '\0';
    snprintf(input, sizeof(input), "JupiterOne %s", upper);
    expect_raw(detector, input, strlen(input), upper);
    char changed[77];
    memcpy(changed, key, sizeof(changed));
    changed[10] = '_';
    snprintf(input, sizeof(input), "jupiterone %s", changed);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "jupiterone %sx", key);
    expect_raw(detector, input, strlen(input), NULL);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "jupiterone", 10);
        memset(input + 10, '.', gap);
        memcpy(input + 10 + gap, key, 76);
        input[10 + gap + 76] = '\0';
        expect_raw(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    unsigned char binary[96];
    memcpy(binary, "\xffjupiterone ", 12);
    memcpy(binary + 12, key, 76);
    expect_raw(detector, binary, 88, key);
    unsigned char vt[88];
    memcpy(vt, "jupiterone", 10);
    vt[10] = 0x0b;
    memcpy(vt + 11, key, 76);
    expect_raw(detector, vt, 87, key);

    snprintf(input, sizeof(input), "jupiterone %s jupiterone %s", key, other);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && !http.calls && !http.releases);
    test_key_result(&results.items[0], 982, key, "key");
    test_key_result(&results.items[1], 982, other, "key");
    br_results_clear(&results);
}

typedef struct {
    const char *keys[3];
    size_t len;
} expected_requests;

static const int *scripted_status;

static bool contains(const void *haystack, size_t hay_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len > hay_len) return false;
    for (size_t i = 0; i + needle_len <= hay_len; ++i)
        if (!memcmp((const unsigned char *)haystack + i, needle, needle_len)) return true;
    return false;
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    const char *secret = expected->keys[http->calls - 1];
    char bearer[84];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://graphql.us.jupiterone.io/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 982);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == 293 && request->body.data);
    CHECK(!memcmp(request->body.data, jupiterone_query, 293));
    CHECK(!contains(request->url, strlen(request->url), secret));
    CHECK(!contains(request->body.data, request->body.len, secret));
    CHECK(request->nheaders == 4);
    snprintf(bearer, sizeof(bearer), "Bearer %s", secret);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, bearer));
    CHECK(!strcmp(request->headers[1].name, "Jupiterone-Account"));
    CHECK(!strcmp(request->headers[1].value, "12345678-1234-1234-1234-123412341234"));
    CHECK(!strcmp(request->headers[2].name, "Content-Type") && !strcmp(request->headers[2].value, "application/json"));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog jupiterone-test"));
    if (scripted_status) http->response.status = scripted_status[http->calls - 1];
}

static void expect_secret(void)
{
    CHECK(setter_nsecrets == 1 && setter_secret.len == 76 && setter_secret.data);
    CHECK(!memcmp(setter_secret.data, key, 76));
}

static void expect_one(const br_detector *detector, test_http *http, const char *input,
                       bool verified, const char *cause)
{
    expected_requests expected = {{key, other, third}, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    reset_observe();
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "jupiterone-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 982, key, "key");
    CHECK(results.items[0].verified == verified);
    if (cause) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cause));
    else CHECK(!results.items[0].verification_error);
    if (verified || !cause) {
        CHECK(setter_calls == 0 && event_len == 1 && event_log[0] == EV_RELEASE);
    } else {
        CHECK(setter_calls == 1 && !setter_was_null);
        CHECK(event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
        expect_secret();
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[512], cause[160], redacted[96];
    snprintf(input, sizeof(input), "jupiterone %s", key);
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    const int verified_status[] = {200};
    const int silent_status[] = {401};
    const int other_status[] = {0, 199, 201, 204, 299, 300, 404, 500};
    for (size_t i = 0; i < sizeof(verified_status) / sizeof(verified_status[0]); ++i) {
        test_http http = {.response = {.status = verified_status[i], .body = {body, sizeof(body)}, .body_error = "ignored read"}};
        expect_one(detector, &http, input, true, NULL);
    }
    for (size_t i = 0; i < sizeof(silent_status) / sizeof(silent_status[0]); ++i) {
        test_http http = {.response = {.status = silent_status[i], .body = {body, sizeof(body)}, .body_error = "ignored read"}};
        expect_one(detector, &http, input, false, NULL);
    }
    for (size_t i = 0; i < sizeof(other_status) / sizeof(other_status[0]); ++i) {
        char status_cause[64];
        snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", other_status[i]);
        test_http http = {.response = {.status = other_status[i], .body = {body, sizeof(body)}, .body_error = "ignored read"}};
        expect_one(detector, &http, input, false, status_cause);
    }
    test_http closed = {.response = {.status = 200}, .send_rc = 1, .send_error = "synthetic transport closed"};
    expect_one(detector, &closed, input, false, "synthetic transport closed");
    snprintf(cause, sizeof(cause), "dial %s refused", key);
    snprintf(redacted, sizeof(redacted), "dial [REDACTED] refused");
    test_http leaked = {.response = {.status = 200}, .send_rc = 1, .send_error = cause};
    expect_one(detector, &leaked, input, false, redacted);
    CHECK(!strcmp(setter_text, cause));

    force_null_send_cause = 1;
    reset_observe();
    test_http absent = {.response = {.status = 200}, .send_rc = 1};
    expected_requests absent_expected = {{key, other, third}, 1};
    absent.inspect = inspect_request;
    absent.user = &absent_expected;
    br_transport absent_transport = test_transport(&absent);
    br_scan_ctx absent_ctx = {.transport = &absent_transport, .user_agent = "jupiterone-test"};
    br_results absent_results = test_scan(detector, &absent_ctx, true, input, strlen(input));
    CHECK(!force_null_send_cause);
    CHECK(absent_results.len == 1 && absent.calls == 1 && absent.releases == 1);
    CHECK(!absent_results.items[0].verified && !absent_results.items[0].verification_error);
    CHECK(setter_calls == 1 && setter_was_null && !setter_text[0]);
    CHECK(event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
    expect_secret();
    test_key_result(&absent_results.items[0], 982, key, "key");
    br_results_clear(&absent_results);

    snprintf(input, sizeof(input), "jupiterone %s\njupiterone %s\njupiterone %s", key, other, third);
    const int statuses[] = {200, 401, 404};
    scripted_status = statuses;
    expected_requests expected = {{key, other, third}, 3};
    reset_observe();
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "jupiterone-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    const char *want[] = {NULL, NULL, "unexpected HTTP response status 404"};
    const char *secrets[] = {key, other, third};
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 982, secrets[i], "key");
        CHECK(results.items[i].verified == (statuses[i] == 200));
        if (want[i]) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, want[i]));
        else CHECK(!results.items[i].verification_error);
    }
    CHECK(setter_calls == 1 && !setter_was_null);
    CHECK(!strcmp(setter_text, "unexpected HTTP response status 404"));
    CHECK(event_len == 4 && event_log[0] == EV_RELEASE && event_log[1] == EV_RELEASE);
    CHECK(event_log[2] == EV_SETTER && event_log[3] == EV_RELEASE);
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

static void preserved(const br_results *results, int rc, const char *error, const char *message)
{
    CHECK(rc != 0 && error && !strcmp(error, message));
    CHECK(results->len == 1 && results->items[0].detector_type == 7);
}

static void context_and_resource(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "jupiterone %s", key);
    reset_observe();
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && setter_calls == 0 && event_len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "jupiterone %s jupiterone %s", key, other);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jupiterone %s", key);
    test_http http = {.response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    const char *prep[] = {"context canceled", "context deadline exceeded"};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        reset_observe();
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0, .user_agent = "jupiterone-test"};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, prep[deadline]));
        CHECK(setter_calls == 1 && !setter_was_null && !strcmp(setter_text, prep[deadline]));
        CHECK(event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
        expect_secret();
        test_key_result(&results.items[0], 982, key, "key");
        br_results_clear(&results);
    }
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);

    seed(&results);
    char *error = NULL;
    int rc = detector->scan(detector, NULL, true, (br_slice){NULL, 1}, &results, &error);
    preserved(&results, rc, error, "invalid or uninitialized JupiterOne scan");
    free(error);
    br_results_clear(&results);

    seed(&results);
    http.calls = http.releases = 0;
    fail_finding_after = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_finding_after && !http.calls && !http.releases);
    preserved(&results, rc, error, "cannot create JupiterOne finding");
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jupiterone %s jupiterone %s", key, other);
    seed(&results);
    expected_requests expected = {{key, other, third}, 2};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    transport = test_transport(&http);
    fail_finding_after = 2;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport, .user_agent = "jupiterone-test"}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_finding_after && http.calls == 1 && http.releases == 1);
    preserved(&results, rc, error, "cannot create JupiterOne finding");
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jupiterone %s", key);
    seed(&results);
    http = (test_http){.response = {.status = 500}};
    transport = test_transport(&http);
    reset_observe();
    fail_status_copy = true;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && http.calls == 1 && http.releases == 1);
    CHECK(setter_calls == 1 && event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
    expect_secret();
    preserved(&results, rc, error, "cannot set JupiterOne verification error");
    free(error);
    br_results_clear(&results);

    seed(&results);
    http = (test_http){.response = {.status = 404}};
    transport = test_transport(&http);
    reset_observe();
    setter_force_rc = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!setter_force_rc && http.calls == 1 && http.releases == 1);
    CHECK(setter_calls == 1 && !setter_was_null && !strcmp(setter_text, "unexpected HTTP response status 404"));
    CHECK(event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
    expect_secret();
    preserved(&results, rc, error, "cannot set JupiterOne verification error");
    free(error);
    br_results_clear(&results);

    seed(&results);
    http = (test_http){.send_rc = 1};
    transport = test_transport(&http);
    reset_observe();
    force_null_send_cause = 1;
    setter_force_rc = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!force_null_send_cause && !setter_force_rc && http.calls == 1 && http.releases == 1);
    CHECK(setter_calls == 1 && setter_was_null && !setter_text[0]);
    CHECK(event_len == 2 && event_log[0] == EV_SETTER && event_log[1] == EV_RELEASE);
    expect_secret();
    preserved(&results, rc, error, "cannot set JupiterOne verification error");
    free(error);
    br_results_clear(&results);

    seed(&results);
    http = (test_http){.response = {.status = 500}};
    transport = test_transport(&http);
    reset_observe();
    force_format_fail = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!force_format_fail && setter_calls == 0 && http.calls == 1 && http.releases == 1);
    CHECK(event_len == 1 && event_log[0] == EV_RELEASE);
    preserved(&results, rc, error, "cannot format JupiterOne verification status");
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jupiterone %s jupiterone %s", key, other);
    const int statuses[] = {200, 500};
    scripted_status = statuses;
    seed(&results);
    http = (test_http){.inspect = inspect_request, .user = &expected};
    transport = test_transport(&http);
    reset_observe();
    fail_status_copy = true;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport, .user_agent = "jupiterone-test"}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && http.calls == 2 && http.releases == 2);
    CHECK(setter_calls == 1 && event_len == 3 && event_log[0] == EV_RELEASE);
    CHECK(event_log[1] == EV_SETTER && event_log[2] == EV_RELEASE);
    preserved(&results, rc, error, "cannot set JupiterOne verification error");
    scripted_status = NULL;
    free(error);
    br_results_clear(&results);

    scripted_status = statuses;
    seed(&results);
    http = (test_http){.inspect = inspect_request, .user = &expected};
    transport = test_transport(&http);
    reset_observe();
    force_format_fail = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport, .user_agent = "jupiterone-test"}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!force_format_fail && setter_calls == 0 && http.calls == 2 && http.releases == 2);
    CHECK(event_len == 2 && event_log[0] == EV_RELEASE && event_log[1] == EV_RELEASE);
    preserved(&results, rc, error, "cannot format JupiterOne verification status");
    scripted_status = NULL;
    free(error);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "jupiterone %s", key);
    seed(&results);
    results.cap = results.len;
    http = (test_http){.response = {.status = 200}};
    transport = test_transport(&http);
    fail_realloc_size = 2 * sizeof(br_result);
    fail_realloc = 1;
    error = NULL;
    rc = detector->scan(detector, &((br_scan_ctx){.transport = &transport}), true,
                        (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_realloc && http.calls == 1 && http.releases == 1);
    preserved(&results, rc, error, "cannot append JupiterOne finding");
    free(error);
    br_results_clear(&results);

    http = (test_http){.response = {.status = 200}};
    expect_one(detector, &http, input, true, NULL);
}

int main(void)
{
    test_secret(key, 76, 0);
    test_secret(other, 76, 5);
    test_secret(third, 76, 11);
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("JupiterOne");
}
