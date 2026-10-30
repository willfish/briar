/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include "../../src/detectors/neutrinoapi.c"

static const char key[] = "mHvIoyAsS593j9zKRHEGO81aEMPKgQxmzfWnuDSkWGZZ6qof";
static const char other[] = "mHvIoyAsS593j9zKRHEGO81aEMPKgQxmzfWnuDSkWGZZ6qoe";
static const char id[] = "yWT99sOl6";
static const char id_two[] = "abcdef";
static const char body_bytes[] =
    "--BriarNeutrinoBoundary\r\n"
    "Content-Disposition: form-data; name=\"url\"\r\n"
    "\r\n"
    "https://google.com\r\n"
    "--BriarNeutrinoBoundary--\r\n";
static size_t fail_part_after;
static const unsigned char *live_body;
static size_t live_body_len;
static const char *live_url;
static const char *live_type;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 48 && strlen(other) == 48 && strlen(id) == 9 && strlen(id_two) == 6);
    CHECK(br_neutrinoapi_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid NeutrinoApi detector output"));
    free(error);
    error = NULL;
    CHECK(br_neutrinoapi_init(NULL, NULL) == -1);
    CHECK(br_neutrinoapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_neutrinoapi_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 623 && detector->version == 0);
    CHECK(!strcmp(detector->name, "NeutrinoApi") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Neutrino API provides a variety of services including data tools, security tools, and more. Neutrino API keys can be used to access these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "neutrinoapi"));
    CHECK(detector->max_credential_span == 1024 && detector->scan && !detector->false_positive);
    return detector;
}

static void expect_key(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 623, secret, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void grammar(const br_detector *detector)
{
    char input[256];
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s", key, id) > 0);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "neutrinoapi mHvIoyAsS593j9zKRH?GO81aEMPKgQxmzfWnuDSkWGZZ6qof neutrinoapi yWT?9sOl6") > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);

    char short_key[48], long_key[50], id24[25], id25[26], id5[] = "abcde";
    memcpy(short_key, key, 47);
    memcpy(long_key, key, 48);
    long_key[48] = 'Z';
    memset(id24, 'a', 24);
    id24[24] = '\0';
    memset(id25, 'b', 25);
    id25[25] = '\0';
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %.*s neutrinoapi %s", 47, short_key, id) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %.*s neutrinoapi %s", 49, long_key, id) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s", key, id5) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s", key, id25) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "NeutrinoAPI %s NEUTRINOAPI %s", key, id24) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    char wide[160];
    memcpy(wide, "neutrinoapi", 11);
    memset(wide + 11, ' ', 40);
    memcpy(wide + 51, key, 48);
    memcpy(wide + 99, " neutrinoapi ", 13);
    memcpy(wide + 112, id, 9);
    wide[121] = '\0';
    out = test_scan(detector, NULL, false, wide, 121);
    CHECK(out.len == 1);
    br_results_clear(&out);
    memset(wide + 11, ' ', 41);
    memcpy(wide + 52, key, 48);
    memcpy(wide + 100, " neutrinoapi ", 13);
    memcpy(wide + 113, id, 9);
    out = test_scan(detector, NULL, false, wide, 122);
    CHECK(out.len == 0);
    br_results_clear(&out);

    char vertical[128];
    CHECK(snprintf(vertical, sizeof(vertical), "neutrinoapi\v%s neutrinoapi %s", key, id) > 0);
    out = test_scan(detector, NULL, false, vertical, strlen(vertical));
    CHECK(out.len == 1);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s %s neutrinoapi %s", key, other, id) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s neutrinoapi %s neutrinoapi %s",
                   key, other, id, id_two) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], key, false);
    expect_key(&out.items[2], other, false);
    expect_key(&out.items[3], other, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s neutrinoapi %s", key, key, id) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], key, false);
    br_results_clear(&out);

    char far[1200];
    memset(far, 'x', 1100);
    memcpy(far + 1100, " neutrinoapi ", 13);
    memcpy(far + 1113, key, 48);
    memcpy(far + 1161, " neutrinoapi ", 13);
    memcpy(far + 1174, id, 9);
    out = test_scan(detector, NULL, false, far, 1183);
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
}

typedef struct {
    const char *id, *key;
    int status, send_rc;
    const char *send_error, *body_error;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx);
    const reply *row = &steps->rows[at];
    char url[160];
    CHECK(snprintf(url, sizeof(url), "https://neutrinoapi.net/url-info?user-id=%s&api-key=%s",
                   row->id, row->key) > 0);
    CHECK(!strcmp(request->method, "POST") && request->url && !strcmp(request->url, url));
    CHECK(request->detector_type == 623 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "multipart/form-data; boundary=BriarNeutrinoBoundary"));
    CHECK(!strchr(request->headers[0].value, '"'));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    CHECK(request->body.len == sizeof(body_bytes) - 1);
    CHECK(request->body.data && !memcmp(request->body.data, body_bytes, request->body.len));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    live_body = request->body.data;
    live_body_len = request->body.len;
    live_url = request->url;
    live_type = request->headers[0].value;
    http->response = (br_http_response){.status = row->status, .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    CHECK(live_body && live_body_len == sizeof(body_bytes) - 1);
    CHECK(!memcmp(live_body, body_bytes, live_body_len));
    CHECK(live_url && !strncmp(live_url, "https://neutrinoapi.net/url-info?user-id=", 41));
    CHECK(strstr(live_url, "&api-key="));
    CHECK(live_type && !strcmp(live_type, "multipart/form-data; boundary=BriarNeutrinoBoundary"));
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

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void verification(const br_detector *detector)
{
    char input[192];
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s neutrinoapi %s",
                   key, id, id_two) > 0);
    const reply rows[] = {
        {.id = id, .key = key, .status = 200, .body_error = "synthetic read failure"},
        {.id = id_two, .key = key, .status = 299},
    };
    script steps = {.rows = rows, .count = 2};
    br_results out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, true);
    expect_key(&out.items[1], key, true);
    br_results_clear(&out);

    const int statuses[] = {199, 300, 401, 500};
    for (size_t i = 0; i < 4; ++i) {
        const reply row = {.id = id, .key = key, .status = statuses[i],
                           .send_error = "unexpected status code: 500"};
        steps = (script){.rows = &row, .count = 1};
        CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s", key, id) > 0);
        out = verify_scan(detector, input, strlen(input), &steps);
        CHECK(out.len == 1);
        expect_key(&out.items[0], key, false);
        br_results_clear(&out);
    }

    const reply failed = {.id = id, .key = key, .status = 200, .send_rc = 1,
                          .send_error = "dial unexpected status code: 500"};
    steps = (script){.rows = &failed, .count = 1};
    out = verify_scan(detector, input, strlen(input), &steps);
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    neutrino_field_fail = 1;
    test_http quiet = {0};
    br_transport transport = test_transport(&quiet);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && quiet.calls == 0 && quiet.releases == 0 && neutrino_field_fail == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    neutrino_field_fail = 0;

    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 0 && quiet.calls == 0 && quiet.releases == 0);
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .cancelled = cancelled};
    out = test_scan(detector, &stopped, true, input, strlen(input));
    CHECK(out.len == 1 && quiet.calls == 0 && quiet.releases == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
}

static void owned_failures(const br_detector *detector)
{
    char input[192];
    CHECK(snprintf(input, sizeof(input), "neutrinoapi %s neutrinoapi %s neutrinoapi %s",
                   key, other, id) > 0);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    prior.extra_data = json_object_new_object();
    CHECK(prior.verification_error && prior.extra_data);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *extra = out.items[0].extra_data;
    size_t capacity = out.cap;
    br_slice data = {(const unsigned char *)input, strlen(input)};
    const reply rows[] = {
        {.id = id, .key = key, .status = 200},
        {.id = id, .key = other, .status = 200},
    };
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    steps.ctx = &ctx;
    char *error = NULL;

    const reply survivor = {.id = id, .key = other, .status = 200};
    steps.rows = &survivor;
    steps.count = 1;
    neutrino_field_fail = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == 0 && !error);
    CHECK(!neutrino_field_fail && http.calls == 1 && http.releases == 1 && out.len == 2);
    expect_key(&out.items[1], other, true);
    CHECK(out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    CHECK(out.items[0].extra_data == extra);
    br_result_clear(&out.items[1]);
    out.len = 1;

    char one[96];
    CHECK(snprintf(one, sizeof(one), "neutrinoapi %s neutrinoapi %s", key, id) > 0);
    br_slice one_data = {(const unsigned char *)one, strlen(one)};
    neutrino_copy_fail = 1;
    http.calls = 0;
    http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, one_data, &out, &error) == 0 && !error);
    CHECK(!neutrino_copy_fail && http.calls == 0 && http.releases == 0 && out.len == 1);
    CHECK(out.items[0].raw.data == raw);

    neutrino_field_fail = -1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate NeutrinoApi request body") && !neutrino_field_fail);
    CHECK(http.calls == 0 && http.releases == 0 && out.len == 1 && out.items[0].extra_data == extra);
    free(error);
    error = NULL;

    neutrino_alloc_fail = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate NeutrinoApi request body") && !neutrino_alloc_fail);
    CHECK(http.calls == 0 && out.len == 1 && out.items[0].verification_error == saved);
    free(error);
    error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NeutrinoApi result") && !fail_part_after);
    CHECK(http.calls == 0 && http.releases == 0 && out.len == 1);
    free(error);
    error = NULL;

    const reply rolled = {.id = id, .key = key, .status = 200};
    steps.rows = &rolled;
    steps.count = 1;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create NeutrinoApi result") && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1 && out.len == 1);
    CHECK(out.items[0].raw.data == raw && out.items[0].extra_data == extra);
    CHECK(out.items[0].verification_error == saved && out.items[0].verified);
    free(error);
    error = NULL;
    http.calls = 0;
    http.releases = 0;

    const reply first = {.id = id, .key = key, .status = 200};
    steps.rows = &first;
    steps.count = 1;
    http.calls = 0;
    http.releases = 0;
    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append NeutrinoApi result"));
    CHECK(http.calls == 1 && http.releases == 1 && out.len == 1);
    CHECK(out.items[0].raw.data == raw && out.items[0].extra_data == extra);
    out.cap = capacity;
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    grammar(detector);
    verification(detector);
    owned_failures(detector);
    return test_finish("NeutrinoApi");
}
