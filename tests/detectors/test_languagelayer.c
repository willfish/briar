/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_languagelayer_init(const br_detector **out, char **error);

static char key[33], other[33];
static size_t fail_part_after;
static const char prefix[] = "https://api.languagelayer.com/languages?access_key=";
static const char restricted[] =
    "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
static const char results_body[] = "xx results yy";
static const char info_body[] =
    "pre\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"post";
static const unsigned char nul_body[] = {0, 'r', 'e', 's', 'u', 'l', 't', 's'};

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32 && strlen(prefix) == 51);
    CHECK(br_languagelayer_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LanguageLayer detector output"));
    free(error);
    error = NULL;
    CHECK(br_languagelayer_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_languagelayer_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 489 && detector->version == 0 && !strcmp(detector->name, "LanguageLayer"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "LanguageLayer is an API service for language detection. The access key can be used to authenticate and use the API."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "languagelayer"));
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
        test_key_result(&out.items[0], 489, expected, "key");
        CHECK(!out.items[0].verified && !out.items[0].verification_error && out.items[0].raw.len == 32);
    }
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[160], changed[34];
    const char *accepted[] = {"languagelayer %s", "LANGUAGELAYER %s", "LanguageLayer=%s",
                              "languagelayer\t%s", "languagelayer\n%s"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        CHECK(snprintf(input, sizeof(input), accepted[i], key) > 0);
        expect_nov(detector, input, strlen(input), key);
    }
    char gap[100];
    memcpy(gap, "languagelayer", 13);
    memset(gap + 13, ' ', 40);
    memcpy(gap + 53, key, 32);
    gap[85] = '\0';
    expect_nov(detector, gap, 85, key);
    memset(gap + 13, ' ', 41);
    memcpy(gap + 54, key, 32);
    gap[86] = '\0';
    expect_nov(detector, gap, 86, NULL);
    char vt[48];
    memcpy(vt, "languagelayer", 13);
    vt[13] = '\v';
    memcpy(vt + 14, key, 32);
    vt[46] = '\0';
    expect_nov(detector, vt, 46, key);

    memcpy(changed, key, 33);
    changed[4] = 'A';
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", changed) == 46);
    expect_nov(detector, input, 46, NULL);
    memcpy(changed, key, 33);
    changed[4] = '-';
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", changed) == 46);
    expect_nov(detector, input, 46, NULL);
    memcpy(changed, key, 31);
    changed[31] = '\0';
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", changed) == 45);
    expect_nov(detector, input, 45, NULL);
    memcpy(changed, key, 32);
    changed[32] = 'a';
    changed[33] = '\0';
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", changed) == 47);
    expect_nov(detector, input, 47, NULL);
    CHECK(snprintf(input, sizeof(input), "languagelayer%s", key) == 45);
    expect_nov(detector, input, 45, NULL);
    CHECK(snprintf(input, sizeof(input), "%s languagelayer", key) == 46);
    expect_nov(detector, input, 46, NULL);
    expect_nov(detector, key, 32, NULL);
    expect_nov(detector, "languagelayer", 13, NULL);
    expect_nov(detector, "", 0, NULL);
}

typedef struct {
    const char *key;
    int status, send_rc;
    const char *send_error, *body_error;
    const void *body;
    size_t body_len;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    const char *url;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 489 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && request->url);
    CHECK(strlen(request->url) == sizeof(prefix) - 1 + 32);
    CHECK(!memcmp(request->url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(request->url + sizeof(prefix) - 1, row->key, 32));
    CHECK(!strchr(request->url, '%'));
    CHECK(request->nheaders == 1 && request->headers && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(request->headers[0].value && !strcmp(request->headers[0].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    steps->url = request->url;
    http->response = (br_http_response){
        .status = row->status,
        .body = {(const unsigned char *)row->body, row->body_len},
        .body_error = row->body_error,
    };
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *steps = http->user;
    size_t at = http->releases;
    CHECK(at < steps->count && steps->url);
    CHECK(!memcmp(steps->url + sizeof(prefix) - 1, steps->rows[at].key, 32));
    steps->url = NULL;
    test_http_release(user, response);
}

static br_results verify_scan(const br_detector *detector, const void *data, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, data, len);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->url);
    return out;
}

static void duplicates(const br_detector *detector)
{
    char input[160];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s languagelayer %s", key, other) == 93);
    br_results out = test_scan(detector, NULL, false, input, 93);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 489, key, "key");
    test_key_result(&out.items[1], 489, other, "key");
    CHECK(!out.items[0].verified && !out.items[1].verified);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "languagelayer %s languagelayer %s", key, key) == 93);
    out = test_scan(detector, NULL, false, input, 93);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 489, key, "key");
    test_key_result(&out.items[1], 489, key, "key");
    br_results_clear(&out);

    int consumed = snprintf(input, sizeof(input), "languagelayer token = '%s' | '%s'", key, key);
    CHECK(consumed == (int)strlen(input) && consumed > 64);
    const reply row = {.key = key, .status = 200, .body = results_body, .body_len = sizeof(results_body) - 1};
    script steps = {.rows = &row, .count = 1};
    out = verify_scan(detector, input, (size_t)consumed, &steps);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    test_key_result(&out.items[0], 489, key, "key");
    br_results_clear(&out);
}

static void nov_and_nil(const br_detector *detector)
{
    char input[128];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s\nlanguagelayer %s", key, other) == 93);
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
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, 93}, &out, &error) == 0);
    CHECK(!error && out.len == 1 && out.items[0].raw.data == raw && out.items[0].secret_parts == parts);
    CHECK(out.items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    br_results_clear(&out);
}

static void check_one(const br_detector *detector, const reply *row, bool verified)
{
    char input[64];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", key) == 46);
    script steps = {.rows = row, .count = 1};
    br_results out = verify_scan(detector, input, 46, &steps);
    CHECK(out.len == 1 && out.items[0].verified == verified && !out.items[0].verification_error);
    test_key_result(&out.items[0], 489, key, "key");
    br_results_clear(&out);
}

static void needles(const br_detector *detector)
{
    const reply results = {.key = key, .status = 200, .body = results_body, .body_len = sizeof(results_body) - 1};
    const reply info = {.key = key, .status = 299, .body = info_body, .body_len = sizeof(info_body) - 1};
    const reply embedded = {.key = key, .status = 204, .body = nul_body, .body_len = sizeof(nul_body)};
    check_one(detector, &results, true);
    check_one(detector, &info, true);
    check_one(detector, &embedded, true);

    const char *misses[] = {"result", "RESULTS", "\"info\":\"Access Restricted\"", "languages"};
    for (size_t i = 0; i < sizeof(misses) / sizeof(misses[0]); ++i) {
        reply row = {.key = key, .status = 200, .body = misses[i], .body_len = strlen(misses[i])};
        check_one(detector, &row, false);
    }
    reply empty = {.key = key, .status = 200};
    check_one(detector, &empty, false);
    reply non2xx[] = {
        {.key = key, .status = 199, .body = results_body, .body_len = sizeof(results_body) - 1},
        {.key = key, .status = 300, .body = restricted, .body_len = sizeof(restricted) - 1},
        {.key = key, .status = 401, .body = "results", .body_len = 7},
    };
    for (size_t i = 0; i < sizeof(non2xx) / sizeof(non2xx[0]); ++i)
        check_one(detector, &non2xx[i], false);
    const char *errors[] = {"synthetic read failure", ""};
    for (size_t i = 0; i < 2; ++i) {
        reply row = {.key = key, .status = 200, .body = results_body, .body_len = sizeof(results_body) - 1,
                     .body_error = errors[i]};
        check_one(detector, &row, false);
    }
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void send_failures(const br_detector *detector)
{
    reply row = {.key = key, .status = 200, .send_rc = 1, .send_error = "net/http: nil Context",
                 .body = results_body, .body_len = sizeof(results_body) - 1};
    check_one(detector, &row, false);
    row.send_rc = -7;
    row.send_error = key;
    row.body_error = "ignored when send fails";
    check_one(detector, &row, false);

    char input[64];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", key) == 46);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    br_results out = test_scan(detector, &ctx, true, input, 46);
    CHECK(out.len == 1 && http.calls == 0 && http.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    test_key_result(&out.items[0], 489, key, "key");
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
    char input[128];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s languagelayer %s", key, other) == 93);
    br_slice data = {(const unsigned char *)input, 93};
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
    const reply rows[] = {
        {.key = key, .status = 200, .body = results_body, .body_len = sizeof(results_body) - 1},
        {.key = other, .status = 200, .body = restricted, .body_len = sizeof(restricted) - 1},
    };
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LanguageLayer result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0);
    check_prior(&out, raw, saved, parts);
    free(error);
    error = NULL;

    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LanguageLayer result") && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1 && !steps.url);
    check_prior(&out, raw, saved, parts);
    free(error);
    error = NULL;
    http.calls = http.releases = 0;

    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append LanguageLayer result"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.url);
    check_prior(&out, raw, saved, parts);
    out.cap = capacity;
    free(error);

    CHECK(detector->scan(detector, &ctx, false, data, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && out.items[0].raw.data == raw && out.items[0].secret_parts == parts);
    test_key_result(&out.items[1], 489, key, "key");
    test_key_result(&out.items[2], 489, other, "key");
    br_results_clear(&out);
}

static void policy_regressions(const br_detector *detector)
{
    char input[64];
    CHECK(snprintf(input, sizeof(input), "languagelayer %s", key) == 46);
    br_slice data = {(const unsigned char *)input, 46};
    test_http unused = {0};
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
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(unused.calls == 0 && unused.releases == 0);
    check_prior(&out, raw, saved, parts);

    const reply invalid = {.key = key, .status = 404, .body = NULL, .body_len = 4};
    script steps = {.rows = &invalid, .count = 1};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "invalid LanguageLayer response body"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.url);
    check_prior(&out, raw, saved, parts);
    free(error);
    br_results_clear(&out);

    reply body_error = {.key = key, .status = 200, .body = results_body,
                        .body_len = sizeof(results_body) - 1, .body_error = "synthetic read failure"};
    check_one(detector, &body_error, false);
    reply results = {.key = key, .status = 200, .body = results_body, .body_len = sizeof(results_body) - 1};
    reply info = {.key = key, .status = 200, .body = restricted, .body_len = sizeof(restricted) - 1};
    check_one(detector, &results, true);
    check_one(detector, &info, true);
    reply miss = {.key = key, .status = 200, .body = "result", .body_len = 6};
    check_one(detector, &miss, false);
    reply server = {.key = key, .status = 500, .body = results_body, .body_len = sizeof(results_body) - 1};
    check_one(detector, &server, false);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    const br_detector *detector = descriptor();
    extraction(detector);
    duplicates(detector);
    nov_and_nil(detector);
    needles(detector);
    send_failures(detector);
    allocation_rollback(detector);
    policy_regressions(detector);
    return test_finish("LanguageLayer");
}
