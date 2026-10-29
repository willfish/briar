/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

extern int br_kanbantool_init(const br_detector **out, char **error);

static const char key[] = "H1EC2BUPZ22S";
static const char other_key[] = "ABCDE1234567";
static const char domain[] = "86DzV1nrzA53SPRijUoX2o";
static const char sample[] = "kanbantool 'H1EC2BUPZ22S' kanbantool '86DzV1nrzA53SPRijUoX2o'";
static const char suffix[] = ".kanbantool.com/api/v3/users/current.json";
static size_t fail_size, fail_after, fail_part_after;
static bool fail_next_malloc, arm_url;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "key") && arm_url) {
        arm_url = false;
        fail_next_malloc = true;
    }
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 12 && strlen(other_key) == 12 && strlen(domain) == 22);
    CHECK(br_kanbantool_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_kanbantool_init(NULL, NULL) == -1);
    CHECK(br_kanbantool_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_kanbantool_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 853 && detector->version == 0 && !strcmp(detector->name, "Kanbantool"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Kanbantool is a project management software that uses API keys for accessing and modifying project data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "kanbantool"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 853, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_count(const br_detector *detector, const void *input, size_t len,
                         const char *const *raws, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], raws[i], false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, len);
    CHECK(out.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], raws[i], false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[1400];
    const char *same[] = {key, key};
    const char *two_keys[] = {key, key, other_key, other_key};
    const char *only[] = {key};
    expect_count(detector, sample, strlen(sample), same, 2);
    snprintf(input, sizeof(input), "KANBANTOOL '%s' kanbantool '%s'", key, domain);
    expect_count(detector, input, strlen(input), same, 2);
    snprintf(input, sizeof(input), "kanbantool '%s'", key);
    expect_count(detector, input, strlen(input), only, 1);
    /* The first match consumes its keyword. A later key inside 40 runes is not
     * a second match unless another keyword remains. */
    snprintf(input, sizeof(input), "kanbantool '%s' '%s'", key, other_key);
    expect_count(detector, input, strlen(input), only, 1);
    snprintf(input, sizeof(input), "kanbantool '%s' kanbantool '%s'", key, other_key);
    expect_count(detector, input, strlen(input), two_keys, 4);
    snprintf(input, sizeof(input), "kanbantool ab %s", key);
    expect_count(detector, input, strlen(input), only, 1);
    for (int gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "kanbantool%*s%s", gap, "", key);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_count(detector, input, (size_t)n, gap == 40 ? only : NULL, gap == 40 ? 1u : 0u);
    }
    snprintf(input, sizeof(input), "kanbantool\r\n%s", key);
    expect_count(detector, input, strlen(input), only, 1);
    expect_count(detector, "kanbantool keyword is not close to the real key in the data\n key = 'H1EC2BUPZ22S' domain: '86DzV1nrzA53SPRijUoX2o'",
                 strlen("kanbantool keyword is not close to the real key in the data\n key = 'H1EC2BUPZ22S' domain: '86DzV1nrzA53SPRijUoX2o'"), NULL, 0);
    expect_count(detector, "kanbantool key = '?1EC2BU=Z22S' secret = '?6DzV1nrA53SPRijUoX2o='",
                 strlen("kanbantool key = '?1EC2BU=Z22S' secret = '?6DzV1nrA53SPRijUoX2o='"), NULL, 0);
    snprintf(input, sizeof(input), "kanbantool %s", "H1EC2BUPZ22");
    expect_count(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "kanbantool %s", "h1ec2bupz22s");
    expect_count(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "%s %s", key, domain);
    expect_count(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "kanbantool%s", key);
    expect_count(detector, input, strlen(input), NULL, 0);
    memset(input, '.', 1100);
    int n = snprintf(input + 1100, sizeof(input) - 1100, "kanbantool %s", domain);
    CHECK(n > 0 && 1100 + (size_t)n < sizeof(input));
    memcpy(input, "kanbantool ", 11);
    memcpy(input + 11, key, 12);
    expect_count(detector, input, 1100 + (size_t)n, same, 2);
    expect_count(detector, "", 0, NULL, 0);
    expect_count(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *key, *domain; int status, send_rc; const char *send_error, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    char url[80], bearer[32];
    CHECK(snprintf(url, sizeof(url), "https://%s%s", row->domain, suffix) < (int)sizeof(url));
    CHECK(snprintf(bearer, sizeof(bearer), "Bearer %s", row->key) < (int)sizeof(bearer));
    CHECK(request->detector_type == 853 && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, bearer));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->suffix ? "TruffleHog kanbantool-offline" : "TruffleHog"));
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
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "kanbantool-offline" : NULL};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, input, len);
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    char one[40];
    CHECK(snprintf(one, sizeof(one), "kanbantool %s", key) < (int)sizeof(one));
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .domain = key, .status = statuses[i],
            .body_error = i % 2 ? "synthetic read failure" : ""};
        script steps = {.rows = &row, .count = 1, .suffix = true};
        br_results out = run(detector, one, strlen(one), &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    char stolen[40];
    CHECK(snprintf(stolen, sizeof(stolen), "kanbantool ab %s", key) < (int)sizeof(stolen));
    reply stolen_row = {.key = key, .domain = "ab", .status = 200};
    script stolen_steps = {.rows = &stolen_row, .count = 1};
    br_results out = run(detector, stolen, strlen(stolen), &stolen_steps);
    CHECK(out.len == 1);
    check_result(&out.items[0], key, true);
    br_results_clear(&out);

    const reply pairs[] = {
        {key, key, 204, 0, NULL, "ignored"},
        {key, domain, 401, 0, NULL, NULL},
    };
    script steps = {.rows = pairs, .count = 2};
    out = run(detector, sample, strlen(sample), &steps);
    CHECK(out.len == 2);
    check_result(&out.items[0], key, true);
    check_result(&out.items[1], key, false);
    br_results_clear(&out);

    char two[80];
    CHECK(snprintf(two, sizeof(two), "kanbantool '%s' kanbantool '%s'", key, other_key) < (int)sizeof(two));
    const reply ordered[] = {
        {key, key, 200, 0, NULL, NULL},
        {key, other_key, 500, 0, NULL, "synthetic read failure"},
        {other_key, key, 299, 0, NULL, NULL},
        {other_key, other_key, 199, 0, NULL, NULL},
    };
    script order = {.rows = ordered, .count = 4};
    out = run(detector, two, strlen(two), &order);
    CHECK(out.len == 4);
    check_result(&out.items[0], key, true);
    check_result(&out.items[1], key, false);
    check_result(&out.items[2], other_key, true);
    check_result(&out.items[3], other_key, false);
    br_results_clear(&out);

    const char *causes[] = {"net/http: nil Context", "context deadline exceeded", key, NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply failed_rows[] = {
            {key, key, 200, i % 2 ? -7 : 1, causes[i], "synthetic read failure"},
            {key, domain, 200, i % 2 ? -7 : 1, causes[i], "synthetic read failure"},
        };
        script failed = {.rows = failed_rows, .count = 2};
        out = run(detector, sample, strlen(sample), &failed);
        CHECK(out.len == 2);
        check_result(&out.items[0], key, false);
        check_result(&out.items[1], key, false);
        br_results_clear(&out);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx live = {.transport = &transport};
    char *error = NULL;
    br_results dropped = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)sample, strlen(sample)},
                         &dropped, &error) == 0 && !error);
    CHECK(dropped.len == 0 && !http.calls && !http.releases);
    br_results_clear(&dropped);
    reply kept = {.key = key, .domain = key, .status = 200};
    script kept_steps = {.rows = &kept, .count = 1, .ctx = &live};
    http.inspect = inspect_request;
    http.user = &kept_steps;
    br_results sent = test_scan(detector, &live, true, one, strlen(one));
    CHECK(sent.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&sent.items[0], key, true);
    br_results_clear(&sent);
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_send(const br_detector *detector)
{
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, sample, strlen(sample));
        CHECK(out.len == 2 && !http.calls && http.releases == (mode == 0 ? 0u : 2u));
        check_result(&out.items[0], key, false);
        check_result(&out.items[1], key, false);
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
    br_slice data = {(const unsigned char *)sample, strlen(sample)};
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
    fail_size = 2 * sizeof(br_span);
    fail_after = 2;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)"kanbantool", 10}, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    preserve_prior(&out, raw, saved, parts);

    fail_size = 2 * sizeof(br_span);
    fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Kanbantool result") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    arm_url = true;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error);
    CHECK(!arm_url && !fail_next_malloc && !strcmp(error, "cannot allocate Kanbantool URL"));
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    br_slice bad = {NULL, 4};
    CHECK(detector->scan(detector, NULL, true, bad, &out, &error) == -1 && error);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot create Kanbantool result") && !fail_part_after);
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    reply row = {.key = key, .domain = key, .status = 200};
    script steps = {.rows = &row, .count = 1};
    http.inspect = inspect_request; http.user = &steps; steps.ctx = &ctx;
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot append Kanbantool result"));
    CHECK(http.calls == 1 && http.releases == 1);
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
    return test_finish("Kanbantool");
}
