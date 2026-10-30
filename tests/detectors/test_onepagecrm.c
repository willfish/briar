/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_onepagecrm_init(const br_detector **out, char **error);

#define br_results_push onepagecrm_real_push
#define br_result_set_verification_error onepagecrm_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[45];
static char other[45];
static const char id[] = "b7c9d2e5f6g8h3j4k1m0n2p4";
static const char id_other[] = "z9y8x7w6v5u4t3s2r1q0p9n8";
static const char url[] =
    "https://app.onepagecrm.com/api/v3/contacts.json?per_page=20&page=1";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return onepagecrm_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return onepagecrm_real_setter(result, cause, secrets, count);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 273);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
    CHECK(request->nheaders >= 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    const char *value = request->headers[0].value;
    char *expected = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)id, 24},
                             (br_slice){(const unsigned char *)key, 44}, &expected, NULL) == 0 && expected);
    CHECK(!strcmp(value, expected));
    free(expected);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid OnepageCRM detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 273 && detector->version == 0 && !strcmp(detector->name, "OnepageCRM"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "OnepageCRM is a simple CRM system designed for small businesses. The API keys can be used to access and manage contacts, deals, and other CRM data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "onepagecrm"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->false_positive);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[260];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    /* The key grammar has no trailing boundary, so a longer run can still be
     * captured at its 44-byte prefix; the ID grammar requires both boundaries. */
    snprintf(input, sizeof(input), "onepagecrm %s\nonepagecrm %s", key, id);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 273, key, "key");
    CHECK(!out.items[0].raw_v2.data);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "onepagecrm %s\nonepagecrm %s\nonepagecrm %s",
             key, id, id_other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 273, key, "key");
    test_key_result(&out.items[1], 273, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "onepagecrm %s\nonepagecrm %s", other, id);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 273, other, "key");
    br_results_clear(&out);
    /* A key alone and an ID alone produce nothing. */
    char key_only[80];
    snprintf(key_only, sizeof(key_only), "onepagecrm %s", key);
    const char *single[] = {key_only, "onepagecrm b7c9d2e5f6g8h3j4k1m0n2p4"};
    for (size_t i = 0; i < sizeof(single) / sizeof(single[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, single[i], strlen(single[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
    const char *bad_id[] = {"onepagecrm B7C9D2E5F6G8H3J4K1M0N2P4", "onepagecrm b7c9d2e5f6g8h3j4k1m0n2p"};
    for (size_t i = 0; i < sizeof(bad_id) / sizeof(bad_id[0]); ++i) {
        char both[160];
        snprintf(both, sizeof(both), "onepagecrm %s\n%s", key, bad_id[i]);
        br_results none = test_scan(detector, &ctx, false, both, strlen(both));
        CHECK(!none.len);
        br_results_clear(&none);
    }
}

static void verify_policy(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "onepagecrm %s\nonepagecrm %s", key, id);
    test_http http = {.inspect = inspect};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; bool verified; } cases[] = {
        {200, true}, {201, true}, {299, true}, {300, false}, {401, false}, {500, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7}, .body_error = "read failed"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.response = (br_http_response){.status = 200};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
}

static void rollback(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "onepagecrm %s\nonepagecrm %s", key, id);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && onepagecrm_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append OnepageCRM result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(http.calls == 1 && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
}

int main(void)
{
    for (size_t i = 0; i < 44; ++i) { key[i] = "ab12"[i % 4]; other[i] = "X9y8"[i % 4]; }
    key[44] = other[44] = '\0';
    CHECK(strlen(key) == 44 && strlen(other) == 44 && strlen(id) == 24 && strlen(id_other) == 24);
    const br_detector *detector = open_detector(br_onepagecrm_init);
    grammar(detector);
    verify_policy(detector);
    rollback(detector);
    CHECK(!setter_calls);
    return test_finish("OnepageCRM");
}
