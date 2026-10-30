/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

extern int br_parsehub_init(const br_detector **out, char **error);

static const char key[] = "vZrEclFwOqeA";
static const char other[] = "0123456789ab";
static size_t fail_size, fail_after, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 12 && strlen(other) == 12);
    CHECK(br_parsehub_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Parsehub detector output"));
    free(error); error = NULL;
    CHECK(br_parsehub_init(NULL, NULL) == -1);
    CHECK(br_parsehub_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_parsehub_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 803 && detector->version == 0 && !strcmp(detector->name, "Parsehub"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Parsehub is a web scraping service that allows users to extract data from websites. Parsehub API keys can be used to access and manage scraping projects."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "parsehub"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 803, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len,
                            const char *const *expected, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], expected[i], false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, len);
    CHECK(out.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], expected[i], false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    const char *one[] = {key}, *both[] = {key, other}, *same[] = {key, key};
    const char *accepted[] = {"parsehub token = '%s'", "PARSEHUB=%s", "preparsehubsuffix:%s", "parsehub\r\n%s"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        int n = snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, (size_t)n, one, 1);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "parsehub%*s%s", gap, "", key);
        extraction_case(detector, input, (size_t)n, gap == 40 ? one : NULL, gap == 40 ? 1u : 0u);
    }
    const char *shaped[] = {"%s", "%s parsehub", "parse hub %s", "parsehub%s"};
    const char *bad_keys[] = {"vZrEclFwOqe", "vZrEclFwOqeAA", "vZrEcl?wOqeA"};
    for (size_t i = 0; i < sizeof(shaped) / sizeof(shaped[0]); ++i) {
        int n = snprintf(input, sizeof(input), shaped[i], key);
        extraction_case(detector, input, (size_t)n, NULL, 0);
    }
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        int n = snprintf(input, sizeof(input), "parsehub %s", bad_keys[i]);
        extraction_case(detector, input, (size_t)n, NULL, 0);
    }
    /* One parsehub prefix is consumed. This is not a uniqueness filter. */
    int n = snprintf(input, sizeof(input), "parsehub token = '%s' | '%s'", key, key);
    extraction_case(detector, input, (size_t)n, one, 1);
    n = snprintf(input, sizeof(input), "parsehub %s parsehub %s", key, other);
    extraction_case(detector, input, (size_t)n, both, 2);
    n = snprintf(input, sizeof(input), "parsehub %s PARSEHUB %s", key, key);
    extraction_case(detector, input, (size_t)n, same, 2);
    n = snprintf(input, sizeof(input), "parsehub keyword is not close to the real key in the data\n = '%s'", key);
    extraction_case(detector, input, (size_t)n, NULL, 0);
    extraction_case(detector, "", 0, NULL, 0);
    extraction_case(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *key; int status, send_rc; const char *send_error, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    char expected[96];
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(snprintf(expected, sizeof(expected),
                   "https://www.parsehub.com/api/v2/projects?api_key=%s&limit=1", row->key) > 0);
    CHECK(request->detector_type == 803 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected) && !strchr(request->url, '%'));
    CHECK(strstr(request->url, "?api_key=") && strstr(request->url, "&limit=1"));
    CHECK(strstr(request->url, "?api_key=") < strstr(request->url, "&limit=1"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)},
        .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static br_results run(const br_detector *detector, const void *input, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, input, len);
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    char one[64], both_input[96];
    int one_len = snprintf(one, sizeof(one), "parsehub %s", key);
    int both_len = snprintf(both_input, sizeof(both_input), "parsehub %s PARSEHUB %s", key, other);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .body_error = i % 2 ? "synthetic read failure" : ""};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, one, (size_t)one_len, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const reply rows[] = {
        {key, 200, 0, NULL, "ignored"},
        {other, 401, 0, NULL, "synthetic read failure"},
    };
    script steps = {.rows = rows, .count = 2};
    br_results out = run(detector, both_input, (size_t)both_len, &steps);
    CHECK(out.len == 2);
    check_result(&out.items[0], key, true);
    check_result(&out.items[1], other, false);
    br_results_clear(&out);
    reply failed = {.key = key, .status = 200, .send_rc = 1, .send_error = "context deadline exceeded",
        .body_error = "synthetic read failure"};
    script fail_steps = {.rows = &failed, .count = 1};
    out = run(detector, one, (size_t)one_len, &fail_steps);
    CHECK(out.len == 1);
    check_result(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, one, (size_t)one_len);
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, both_input, (size_t)both_len);
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, one, (size_t)one_len);
    CHECK(out.len == 1);
    check_result(&out.items[0], key, false);
    br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_send(const br_detector *detector)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "parsehub %s PARSEHUB %s", key, other);
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, input, (size_t)n);
        CHECK(out.len == 2 && !http.calls && http.releases == (mode == 0 ? 0u : 2u));
        check_result(&out.items[0], key, false);
        check_result(&out.items[1], other, false);
        br_results_clear(&out);
    }
}

static void preserve_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(out->items[0].secret_parts == parts);
}

static void owned_failures(const br_detector *detector)
{
    char input[64];
    int n = snprintf(input, sizeof(input), "parsehub %s", key);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    test_http http = {0};

    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    preserve_prior(&out, raw, saved, parts);

    fail_size = 2 * sizeof(br_span);
    fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory iterating regex") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!strcmp(error, "out of memory creating detector result") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reply row = {.key = key, .status = 200};
    script steps = {.rows = &row, .count = 1, .ctx = &ctx};
    http.inspect = inspect_request;
    http.user = &steps;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == 0 && !error);
    CHECK(http.calls == 1 && http.releases == 1 && out.len == 2);
    check_result(&out.items[1], key, true);
    br_result_clear(&out.items[1]);
    out.len = 1;
    preserve_prior(&out, raw, saved, parts);

    http.calls = http.releases = 0;
    size_t cap = out.cap;
    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "out of memory appending detector result") && http.calls == 1 && http.releases == 1);
    out.cap = cap;
    free(error);
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    shared_send(detector);
    owned_failures(detector);
    return test_finish("Parsehub");
}
