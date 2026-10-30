/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "mDrW4HFb6fVh2ii74V41bh6EH52sWirlQuKr3svxfgGueyj32HW7OhIhNLZSgicW";
static const char other[] = "mDrW4HFb6fVh2ii74V41bh6EH52sWirlQuKr3svxfgGueyj32HW7OhIhNLZSgicX";
static const char url[] = "https://api.partnerstack.com/api/v2/partnerships";
static int captures_rc;
static size_t fail_part_after;
static const char *expected_auth;
static char seen_auth[2][80];
static size_t seen_auth_count;
static int (*partnerstack_real_captures)(const br_regex *, br_slice, br_captures *, bool, char **) =
    br_captures_find;

static int partnerstack_intercept_captures(const br_regex *regex, br_slice input, br_captures *values,
                                           bool unique, char **error)
{
    if (captures_rc) {
        int rc = captures_rc;
        captures_rc = 0;
        if (error) *error = strdup("injected Partnerstack capture failure");
        return rc;
    }
    return partnerstack_real_captures(regex, input, values, unique, error);
}

#define br_captures_find partnerstack_intercept_captures
#include "../../src/detectors/partnerstack.c"
#undef br_captures_find

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && request->headers[1].value);
    CHECK(strncmp(request->headers[1].value, "Bearer ", 7) == 0);
    if (expected_auth) CHECK(!strcmp(request->headers[1].value, expected_auth));
    if (seen_auth_count < 2)
        snprintf(seen_auth[seen_auth_count++], sizeof(seen_auth[0]), "%s", request->headers[1].value);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 545);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    CHECK(br_partnerstack_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Partnerstack detector output"));
    free(error);
    error = NULL;
    CHECK(br_partnerstack_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_partnerstack_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 545 && detector->version == 0 && !strcmp(detector->name, "Partnerstack"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "PartnerStack is a partner management platform that helps companies manage their partner programs. PartnerStack API keys can be used to access and manage these programs."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "partnerstack"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 545, secret, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void plant(br_results *out, unsigned char **raw, char **saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "caller-secret", "key") == 0);
    prior.verification_error = strdup("caller-error");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *raw = out->items[0].raw.data;
    *saved = out->items[0].verification_error;
}

static void check_prior(const br_results *out, unsigned char *raw, char *saved)
{
    CHECK(out->len == 1 && out->items[0].raw.data == raw && out->items[0].verification_error == saved);
    CHECK(!strcmp(saved, "caller-error") && !strcmp((char *)raw, "caller-secret"));
}

static bool always_cancelled(void *user)
{
    (void)user;
    return true;
}

static void extraction(const br_detector *detector)
{
    char input[256];
    CHECK(snprintf(input, sizeof(input), "partnerstack token = '%s'", key) > 0);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "PARTNERSTACK token = '%s'", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    /* One keyword cannot see the second copy. That is prefix consumption, not a map. */
    CHECK(snprintf(input, sizeof(input), "partnerstack token = '%s' | '%s'", key, key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "partnerstack %s partnerstack %s", key, other) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], other, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input),
                   "partnerstack keyword is not close to the real key in the data\n = '%s'", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);

    char gap[128];
    memcpy(gap, "partnerstack", 12);
    memset(gap + 12, ' ', 40);
    gap[32] = '\v';
    memcpy(gap + 52, key, 64);
    out = test_scan(detector, NULL, false, gap, 116);
    CHECK(out.len == 1);
    br_results_clear(&out);
    memset(gap + 12, ' ', 41);
    memcpy(gap + 53, key, 64);
    out = test_scan(detector, NULL, false, gap, 117);
    CHECK(out.len == 0);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "partnerstack%s", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "partnerstack = '%s'",
                   "mDrW4HFb6fVh2ii74V41bh6EH52sWirl?uKr3svxfgGueyj32HW7OhIhNLZSgicW") > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, "", 0);
    CHECK(out.len == 0);
    br_results_clear(&out);
}

static void verification(const br_detector *detector)
{
    char input[256];
    seen_auth_count = 0;
    CHECK(snprintf(input, sizeof(input), "partnerstack %s partnerstack %s", key, other) > 0);
    test_http http = {.response = {.status = 200, .body_error = "read failed"}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && seen_auth_count == 2);
    {
        char first[80], second[80];
        CHECK(snprintf(first, sizeof(first), "Bearer %s", key) == 71);
        CHECK(snprintf(second, sizeof(second), "Bearer %s", other) == 71);
        CHECK(!strcmp(seen_auth[0], first) && !strcmp(seen_auth[1], second));
    }
    expect_key(&out.items[0], key, true);
    expect_key(&out.items[1], other, true);
    br_results_clear(&out);

    char bearer[80];
    CHECK(snprintf(bearer, sizeof(bearer), "Bearer %s", key) == 71);
    expected_auth = bearer;
    int statuses[] = {199, 200, 299, 300, 401, 500};
    bool verified[] = {false, true, true, false, false, false};
    CHECK(snprintf(input, sizeof(input), "partnerstack %s", key) > 0);
    for (size_t i = 0; i < 6; ++i) {
        http = (test_http){.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        transport = test_transport(&http);
        ctx = (br_scan_ctx){.transport = &transport};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        expect_key(&out.items[0], key, verified[i]);
        br_results_clear(&out);
    }

    http = (test_http){.send_rc = 1, .send_error = "lookup failed: no such host", .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    http = (test_http){.send_rc = 1, .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    http = (test_http){.inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport, .cancelled = always_cancelled};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 0 && http.releases == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    ctx = (br_scan_ctx){0};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "partnerstack %s partnerstack %s", key, other) > 0);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
}

static void failures(const br_detector *detector)
{
    char input[256], *error = NULL;
    CHECK(snprintf(input, sizeof(input), "partnerstack %s partnerstack %s", key, other) > 0);
    unsigned char *raw = NULL;
    char *saved = NULL;
    br_results prior = {0};
    plant(&prior, &raw, &saved);
    captures_rc = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "injected Partnerstack capture failure") && !captures_rc);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Partnerstack result") && !fail_part_after);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    char bearer[80];
    CHECK(snprintf(bearer, sizeof(bearer), "Bearer %s", key) == 71);
    expected_auth = bearer;
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Partnerstack result") && http.calls == 0 && http.releases == 0);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    fail_part_after = 2;
    http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Partnerstack result"));
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    prior.cap = 0;
    http = (test_http){.response = {.status = 200}, .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Partnerstack result"));
    CHECK(http.calls == 1 && http.releases == 1);
    check_prior(&prior, raw, saved);
    free(error);
    br_results_clear(&prior);

    br_results empty = {0};
    CHECK(detector->scan(NULL, &ctx, false, (br_slice){NULL, 1}, &empty, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized Partnerstack scan"));
    free(error);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    failures(detector);
    return test_finish("Partnerstack");
}
