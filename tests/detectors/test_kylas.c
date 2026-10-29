/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_kylas_init(const br_detector **out, char **error);

static char key[37], other[37];
static size_t fail_part_after;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 36 && strlen(other) == 36 && key[8] != '-' && other[8] != '-');
    CHECK(br_kylas_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Kylas detector output"));
    free(error);
    error = NULL;
    CHECK(br_kylas_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_kylas_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 272 && detector->version == 0 && !strcmp(detector->name, "Kylas"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Kylas is a sales CRM platform. Kylas API keys can be used to access and manage sales data."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "kylas"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_nov(const br_detector *detector, const void *data, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, data, len);
    CHECK(http.calls == 0 && http.releases == 0);
    if (!expected) CHECK(out.len == 0);
    else {
        CHECK(out.len == 1);
        test_key_result(&out.items[0], 272, expected, "key");
        CHECK(!out.items[0].verified && !out.items[0].verification_error);
        CHECK(out.items[0].raw.len == 36);
    }
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[96], changed[38];
    const char *accepted[] = {"kylas %s", "KYLAS %s", "KyLaS=%s", "kylas\t%s", "kylas\n%s", "kylas '%s'."};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        CHECK(snprintf(input, sizeof(input), accepted[i], key) > 0);
        expect_nov(detector, input, strlen(input), key);
    }
    char gap[83];
    memcpy(gap, "kylas", 5);
    memset(gap + 5, ' ', 40);
    memcpy(gap + 45, key, 36);
    gap[81] = '\0';
    expect_nov(detector, gap, 81, key); /* 40-byte prefix window, ASCII boundary. */
    memset(gap + 5, ' ', 41);
    memcpy(gap + 46, key, 36);
    gap[82] = '\0';
    expect_nov(detector, gap, 82, NULL); /* 41st byte is outside PrefixRegex. */
    char vt[43];
    memcpy(vt, "kylas", 5);
    vt[5] = '\v';
    memcpy(vt + 6, key, 36);
    vt[42] = '\0';
    expect_nov(detector, vt, 42, key); /* Shared prefix helper includes VT. */

    memcpy(changed, key, 37);
    changed[8] = '-';
    CHECK(snprintf(input, sizeof(input), "kylas %s", changed) == 42);
    expect_nov(detector, input, 42, changed);
    changed[8] = '_';
    CHECK(snprintf(input, sizeof(input), "kylas %s", changed) == 42);
    expect_nov(detector, input, 42, NULL);
    memcpy(changed, key, 37);
    changed[3] = 'A';
    CHECK(snprintf(input, sizeof(input), "kylas %s", changed) == 42);
    expect_nov(detector, input, 42, NULL);

    memcpy(changed, key, 35);
    changed[35] = '\0';
    CHECK(snprintf(input, sizeof(input), "kylas %s", changed) == 41);
    expect_nov(detector, input, 41, NULL);
    memcpy(changed, key, 36);
    changed[36] = 'z';
    changed[37] = '\0';
    CHECK(snprintf(input, sizeof(input), "kylas %s", changed) == 43);
    expect_nov(detector, input, 43, NULL);

    CHECK(snprintf(input, sizeof(input), "kylas%s", key) == 41);
    expect_nov(detector, input, 41, NULL);
    CHECK(snprintf(input, sizeof(input), "%s kylas", key) == 42);
    expect_nov(detector, input, 42, NULL);
    expect_nov(detector, key, 36, NULL);
    expect_nov(detector, "kylas", 5, NULL);
    expect_nov(detector, "", 0, NULL);
}

typedef struct {
    const char *key;
    int status, send_rc;
    const char *send_error, *body_error;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    const char *saved[4];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == 0);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 272 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.kylas.io/v1/contacts"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Api-Key"));
    CHECK(request->headers[1].value && strlen(request->headers[1].value) == 36);
    CHECK(!memcmp(request->headers[1].value, row->key, 36));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    CHECK(at < sizeof(steps->saved) / sizeof(steps->saved[0]));
    steps->saved[at] = request->headers[1].value;
    static const unsigned char junk[] = {0xff, '{', 'n', 'o', 't', '-', 'j', 's', 'o', 'n'};
    http->response = (br_http_response){
        .status = row->status,
        .body = {junk, sizeof(junk)},
        .body_error = row->body_error,
    };
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *steps = http->user;
    CHECK(http->calls > http->releases);
    size_t from_end = http->calls - 1 - http->releases;
    CHECK(steps->saved[from_end] && !memcmp(steps->saved[from_end], steps->rows[from_end].key, 36));
    test_http_release(user, response);
}

static br_results verify_scan(const br_detector *detector, const void *data, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, data, len);
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void duplicates(const br_detector *detector)
{
    char input[128];
    CHECK(snprintf(input, sizeof(input), "kylas %s kylas %s", key, other) == 85);
    br_results out = test_scan(detector, NULL, false, input, 85);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 272, key, "key");
    test_key_result(&out.items[1], 272, other, "key");
    CHECK(!out.items[0].verified && !out.items[1].verified);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "kylas %s kylas %s", key, key) == 85);
    out = test_scan(detector, NULL, false, input, 85);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 272, key, "key");
    test_key_result(&out.items[1], 272, key, "key");
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "kylas %s kylas %s", key, other) == 85);
    const reply rows[] = {{key, 200, 0, NULL, NULL}, {other, 204, 0, NULL, NULL}};
    script steps = {.rows = rows, .count = 2};
    out = verify_scan(detector, input, 85, &steps);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 272, key, "key");
    test_key_result(&out.items[1], 272, other, "key");
    CHECK(out.items[0].verified && out.items[1].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    /* Upstream "ignore duplicate" is prefix consumption, not a uniqueness map. */
    int consumed = snprintf(input, sizeof(input), "kylas token = '%s' | '%s'", key, key);
    CHECK(consumed == (int)strlen(input) && consumed > 36 * 2);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, input, (size_t)consumed);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&out.items[0], 272, key, "key");
    br_results_clear(&out);
}

static void nov_and_nil(const br_detector *detector)
{
    char input[96];
    CHECK(snprintf(input, sizeof(input), "kylas %s\nkylas %s", key, other) == 85);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;

    br_results added = test_scan(detector, NULL, false, input, 85);
    CHECK(added.len == 2 && !added.items[0].verified && !added.items[1].verified);
    br_results_clear(&added);

    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, 85}, &out, &error) == 0);
    CHECK(!error && out.len == 1 && out.items[0].raw.data == raw && out.items[0].secret_parts == parts);
    CHECK(out.items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    br_results_clear(&out);
}

static void statuses(const br_detector *detector)
{
    char input[48];
    CHECK(snprintf(input, sizeof(input), "kylas %s", key) == 42);
    const int codes[] = {199, 200, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        reply row = {.key = key, .status = codes[i]};
        script steps = {.rows = &row, .count = 1};
        br_results out = verify_scan(detector, input, 42, &steps);
        CHECK(out.len == 1);
        test_key_result(&out.items[0], 272, key, "key");
        CHECK(out.items[0].verified == (codes[i] >= 200 && codes[i] < 300));
        CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    const char *errors[] = {"synthetic read failure", ""};
    for (size_t i = 0; i < 2; ++i) {
        reply row = {.key = key, .status = i ? 299 : 200, .body_error = errors[i]};
        script steps = {.rows = &row, .count = 1};
        br_results out = verify_scan(detector, input, 42, &steps);
        CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
        test_key_result(&out.items[0], 272, key, "key");
        br_results_clear(&out);
    }
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void send_failures(const br_detector *detector)
{
    char input[48];
    CHECK(snprintf(input, sizeof(input), "kylas %s", key) == 42);
    const char *causes[] = {"net/http: nil Context", key, NULL};
    const int codes[] = {1, -7, 1};
    for (size_t i = 0; i < 3; ++i) {
        reply row = {.key = key, .status = 200, .send_rc = codes[i], .send_error = causes[i],
                     .body_error = i == 1 ? "ignored when send fails" : NULL};
        script steps = {.rows = &row, .count = 1};
        br_results out = verify_scan(detector, input, 42, &steps);
        CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
        test_key_result(&out.items[0], 272, key, "key");
        br_results_clear(&out);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    br_results out = test_scan(detector, &ctx, true, input, 42);
    CHECK(out.len == 1 && http.calls == 0 && http.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    test_key_result(&out.items[0], 272, key, "key");
    br_results_clear(&out);
}

static void check_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(out->items[0].secret_parts == parts);
}

static void allocation_rollback(const br_detector *detector)
{
    char input[96];
    CHECK(snprintf(input, sizeof(input), "kylas %s kylas %s", key, other) == 85);
    br_slice data = {(const unsigned char *)input, 85};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    size_t capacity = out.cap;

    const reply rows[] = {{key, 200, 0, NULL, NULL}, {other, 200, 0, NULL, NULL}};
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Kylas result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0);
    check_prior(&out, raw, saved, parts);
    free(error);
    error = NULL;

    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Kylas result") && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&out, raw, saved, parts);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Kylas result"));
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&out, raw, saved, parts);
    out.cap = capacity;
    free(error);
    error = NULL;

    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && out.items[0].raw.data == raw && out.items[0].secret_parts == parts);
    test_key_result(&out.items[1], 272, key, "key");
    test_key_result(&out.items[2], 272, other, "key");
    br_results_clear(&out);
}

int main(void)
{
    test_secret(key, 36, 0);
    test_secret(other, 36, 11);
    const br_detector *detector = descriptor();
    extraction(detector);
    duplicates(detector);
    nov_and_nil(detector);
    statuses(detector);
    send_failures(detector);
    allocation_rollback(detector);
    return test_finish("Kylas");
}
