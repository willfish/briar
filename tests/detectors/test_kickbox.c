/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

extern int br_kickbox_init(const br_detector **out, char **error);

static const char prefix[] = "https://api.kickbox.com/v2/verify?email=kickbox@example.com&apikey=";
static const char upstream[] = "_DN4IVERUcAbdO2ibFCriJAyfyuaDys7u08ilesdQxON2oUsobOusDu1UFkclGq8P";
static char key[301], other[81];
static size_t fail_size, fail_after, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void fill_key(char *out, size_t len, int underscore_at)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    CHECK(len >= 65 && len < 301);
    for (size_t i = 0; i < len; ++i) out[i] = alphabet[i % (sizeof(alphabet) - 1)];
    if (underscore_at >= 0 && (size_t)underscore_at < len - 64) out[underscore_at] = '_';
    out[len] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 300 && strlen(other) == 80 && strlen(upstream) == 65);
    CHECK(br_kickbox_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_kickbox_init(NULL, NULL) == -1);
    CHECK(br_kickbox_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_kickbox_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 573 && detector->version == 0 && !strcmp(detector->name, "Kickbox"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Kickbox is an email verification service that allows users to verify email addresses in real-time. Kickbox API keys can be used to access and utilize the email verification services provided by Kickbox."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "kickbox"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 573, expected, "key");
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
    char input[720], changed[82];
    const char *one[] = {key}, *both[] = {key, other}, *same[] = {other, other};
    const char *accepted[] = {"kickbox token = '%s'", "KICKBOX=%s", "prekickboxsuffix:%s",
        "kickbox\r\n%s", "kickbox\r%s", "kickbox\n%s"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], other);
        extraction_case(detector, input, strlen(input), (const char *const []){other}, 1);
    }
    extraction_case(detector, "kickbox token = '_DN4IVERUcAbdO2ibFCriJAyfyuaDys7u08ilesdQxON2oUsobOusDu1UFkclGq8P'",
                    strlen("kickbox token = '_DN4IVERUcAbdO2ibFCriJAyfyuaDys7u08ilesdQxON2oUsobOusDu1UFkclGq8P'"),
                    (const char *const []){upstream}, 1);
    for (int gap = 40; gap <= 41; ++gap) {
        int n = snprintf(input, sizeof(input), "kickbox%*s%s", gap, "", other);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        extraction_case(detector, input, (size_t)n, gap == 40 ? (const char *const []){other} : NULL, gap == 40 ? 1u : 0u);
    }
    snprintf(input, sizeof(input), "kickbox %s", other);
    extraction_case(detector, input, strlen(input), (const char *const []){other}, 1);
    memcpy(changed, other, 81); changed[64] = '\0';
    snprintf(input, sizeof(input), "kickbox %s", changed);
    extraction_case(detector, input, strlen(input), NULL, 0);
    memcpy(changed, other, 81); changed[79] = '_';
    snprintf(input, sizeof(input), "kickbox %s", changed);
    extraction_case(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "kickbox = '?DN4IVERUcAbdO2ibFCriJAyfyuaDys7u08ilesdQxON2oUsobOusDu1UFkclGq8='");
    extraction_case(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "kickbox %s=", other);
    extraction_case(detector, input, strlen(input), (const char *const []){other}, 1);
    snprintf(input, sizeof(input), "%s", other);
    extraction_case(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "kickbox%s", other);
    extraction_case(detector, input, strlen(input), NULL, 0);
    /* One long token is one match. A second copy needs its own keyword. */
    snprintf(input, sizeof(input), "kickbox %s", key);
    extraction_case(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "kickbox token = '%s' | '%s'", other, other);
    extraction_case(detector, input, strlen(input), (const char *const []){other}, 1);
    snprintf(input, sizeof(input), "kickbox %s kickbox %s", key, other);
    extraction_case(detector, input, strlen(input), both, 2);
    snprintf(input, sizeof(input), "kickbox %s kickbox %s", other, other);
    extraction_case(detector, input, strlen(input), same, 2);
    extraction_case(detector, "", 0, NULL, 0);
    extraction_case(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *key; int status, send_rc; const char *send_error, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; bool suffix; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    size_t key_len = strlen(row->key);
    CHECK(request->detector_type == 573 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(strlen(request->url) == sizeof(prefix) - 1 + key_len);
    CHECK(!memcmp(request->url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(request->url + sizeof(prefix) - 1, row->key, key_len + 1));
    CHECK(!strstr(request->url, "%"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->suffix ? "TruffleHog kickbox-offline" : "TruffleHog"));
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)},
        .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static br_results run(const br_detector *detector, const void *input, size_t len, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "kickbox-offline" : NULL};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input, len);
    CHECK(http.calls == (verify ? steps->count : 0u) && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    char input[400];
    int n = snprintf(input, sizeof(input), "kickbox %s kickbox %s", other, other);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = other, .status = statuses[i], .body_error = i % 2 ? "synthetic read failure" : ""};
        script steps = {.rows = &row, .count = 1, .suffix = true};
        char one[96];
        CHECK(snprintf(one, sizeof(one), "kickbox %s", other) < (int)sizeof(one));
        br_results out = run(detector, one, strlen(one), true, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], other, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    reply long_row = {.key = key, .status = 200, .body_error = "synthetic read failure"};
    script long_steps = {.rows = &long_row, .count = 1};
    char long_input[320];
    CHECK(snprintf(long_input, sizeof(long_input), "kickbox %s", key) < (int)sizeof(long_input));
    br_results out = run(detector, long_input, strlen(long_input), true, &long_steps);
    CHECK(out.len == 1 && out.items[0].raw.len == 300);
    check_result(&out.items[0], key, true);
    br_results_clear(&out);

    const reply rows[] = {{other, 204, 0, NULL, "ignored"}, {other, 401, 0, NULL, NULL}};
    script steps = {.rows = rows, .count = 2};
    out = run(detector, input, (size_t)n, true, &steps);
    CHECK(out.len == 2);
    check_result(&out.items[0], other, true);
    check_result(&out.items[1], other, false);
    br_results_clear(&out);

    const char *causes[] = {"net/http: nil Context", "context deadline exceeded", other, NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {.key = other, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i],
            .body_error = "synthetic read failure"};
        script failed = {.rows = &row, .count = 1};
        char one[96];
        CHECK(snprintf(one, sizeof(one), "kickbox %s", other) < (int)sizeof(one));
        out = run(detector, one, strlen(one), true, &failed);
        CHECK(out.len == 1);
        check_result(&out.items[0], other, false);
        br_results_clear(&out);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx live = {.transport = &transport};
    char *error = NULL;
    br_results dropped = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n},
                         &dropped, &error) == 0 && !error);
    CHECK(dropped.len == 0 && !http.calls && !http.releases);
    br_results_clear(&dropped);
    reply kept = {.key = other, .status = 200};
    script kept_steps = {.rows = &kept, .count = 1, .ctx = &live};
    http.inspect = inspect_request;
    http.user = &kept_steps;
    char one[96];
    CHECK(snprintf(one, sizeof(one), "kickbox %s", other) < (int)sizeof(one));
    br_results sent = test_scan(detector, &live, true, one, strlen(one));
    CHECK(sent.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&sent.items[0], other, true);
    br_results_clear(&sent);
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_send(const br_detector *detector)
{
    char input[96];
    CHECK(snprintf(input, sizeof(input), "kickbox %s", other) < (int)sizeof(input));
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        check_result(&out.items[0], other, false);
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
    char input[200];
    int n = snprintf(input, sizeof(input), "kickbox %s kickbox %s", other, other);
    CHECK(n > 0 && (size_t)n < sizeof(input));
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

    fail_size = sizeof(prefix) + 80;
    fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory allocating Kickbox URL") && !http.calls && !http.releases);
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
    CHECK(!strcmp(error, "out of memory creating detector result") && !fail_part_after);
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_size = sizeof(prefix) + 80;
    fail_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory allocating Kickbox URL"));
    CHECK(!http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    reply row = {.key = other, .status = 200};
    script steps = {.rows = &row, .count = 1};
    http.inspect = inspect_request; http.user = &steps; steps.ctx = &ctx;
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "out of memory appending detector result"));
    CHECK(http.calls == 1 && http.releases == 1);
    out.cap = cap;
    free(error);
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);
}

int main(void)
{
    fill_key(key, 300, 4);
    fill_key(other, 80, 0);
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    shared_send(detector);
    owned_failures(detector);
    return test_finish("Kickbox");
}
