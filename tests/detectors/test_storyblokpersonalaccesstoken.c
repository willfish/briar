/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_storyblokpersonalaccesstoken_init(const br_detector **out, char **error);

static char pat[53], other[53];
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 52 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[53]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void make_pat(char out[53], char left, char right)
{
    memset(out, left, 22);
    memcpy(out + 22, "tt-", 3);
    memcpy(out + 25, "123456", 6);
    out[31] = '-';
    memset(out + 32, right, 20);
    out[52] = '\0';
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 1016, expected, "key");
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    make_pat(pat, 'A', 'B'); make_pat(other, 'c', 'd');
    CHECK(strlen(pat) == 52);
    CHECK(br_storyblokpersonalaccesstoken_init(NULL, &error) == -1); free(error);
    CHECK(!br_storyblokpersonalaccesstoken_init(&detector, &error) && !error);
    CHECK(detector->type == 1016 && !strcmp(detector->name, "StoryblokPersonalAccessToken"));
    CHECK(!strcmp(detector->description,
        "Storyblok is a headless CMS that allows developers to build flexible and powerful content management solutions.\n"
        "\t\t\tStoryblok personal access tokens can be used with management APIs.\n"
        "\t\t\tThe Storyblok Management API allows you to create, edit, update, and delete content using a common interface"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "storyblok"));
    CHECK(detector->max_credential_span == -1 && detector->version == 0 && detector->scan);
    return detector;
}

typedef struct { const char *token, *send_error; int status; } reply;
typedef struct { reply rows[1]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; reply *step = &steps->rows[0];
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://mapi.storyblok.com/v1/spaces/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1016);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, step->token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    http->response = (br_http_response){.status = step->status, .body_error = "ignored drain"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static void extraction(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "storyblok %s\nSTORYBLOK %s\nstoryblok %s", pat, other, pat);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], pat, false, NULL);
    check_result(&results.items[1], other, false, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "storyblok%*s%s", 40, "", pat);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "storyblok%*s%s", 41, "", pat);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s storyblok", pat);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "storyblok %s", pat);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], pat, false, "net/http: nil Context");
    br_results_clear(&results);
    const int codes[] = {200, 401, 403, 500};
    const char *causes[] = {NULL, NULL, "unexpected status code: 403", "unexpected status code: 500"};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = pat, .status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], pat, codes[i] == 200, causes[i]);
        br_results_clear(&results);
    }
    char noisy[80]; snprintf(noisy, sizeof(noisy), "dial %s refused", pat);
    script steps = {.count = 1}; steps.rows[0] = (reply){.token = pat, .send_error = noisy};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    check_result(&results.items[0], pat, false, noisy); /* Setter receives no secrets. */
    br_results_clear(&results);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("StoryblokPersonalAccessToken raw authorization + unique token + unredacted setter");
}
