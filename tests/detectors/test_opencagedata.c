/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

static const char key[] = "dc07kkpxqkraj009u95s7ay7wpgfjt4j";
static const char other[] = "dc07kkpxqkraj009u95s7ay7wpgfjt4k";
static const char prefix[] = "https://api.opencagedata.com/geocode/v1/json?q=12.8797,121.7740&key=";
static int captures_rc;
static size_t fail_part_after;
static int url_fail_at, url_fail_rc, url_builds;
static char built_urls[2][128];
static int script_on, script_rc, script_status, script_set_error;
static const char *script_body_error;
static size_t seen_sends;
static char seen_urls[2][128];
static unsigned char seen_dedup[2][36];
static int seen_headers;
static char guard_error[64];
static int (*opencagedata_real_captures)(const br_regex *, br_slice, br_captures *, bool, char **) =
    br_captures_find;
static int (*opencagedata_real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *,
                                     char **) = br_http_send;

static int opencagedata_intercept_captures(const br_regex *regex, br_slice input, br_captures *values,
                                           bool unique, char **error)
{
    if (captures_rc) {
        int rc = captures_rc;
        captures_rc = 0;
        if (error) *error = strdup("injected OpenCageData capture failure");
        return rc;
    }
    return opencagedata_real_captures(regex, input, values, unique, error);
}

static int opencagedata_test_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    if (url_fail_at && --url_fail_at == 0) return url_fail_rc;
    va_list ap;
    va_start(ap, fmt);
    int wrote = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    if (wrote > 0 && buf && (size_t)wrote < n && url_builds < 2)
        memcpy(built_urls[url_builds], buf, (size_t)wrote + 1);
    if (wrote >= 0) url_builds++;
    return wrote;
}

static int opencagedata_test_send(const br_scan_ctx *ctx, const br_http_request *request,
                                  br_http_response *response, char **error)
{
    if (seen_sends < 2 && request && request->url && strlen(request->url) < sizeof(seen_urls[0]))
        memcpy(seen_urls[seen_sends], request->url, strlen(request->url) + 1);
    if (seen_sends < 2 && request && request->dedup_key.len == 36 && request->dedup_key.data)
        memcpy(seen_dedup[seen_sends], request->dedup_key.data, 36);
    if (request && (request->nheaders || request->headers || request->body.data || request->body.len))
        seen_headers = 1;
    seen_sends++;
    if (script_on) {
        if (response) {
            memset(response, 0, sizeof(*response));
            response->status = script_status;
            response->body_error = (char *)script_body_error;
        }
        if (script_rc && script_set_error && error && script_body_error)
            *error = strdup(script_body_error);
        return script_rc;
    }
    char *local = NULL;
    int rc = opencagedata_real_send(ctx, request, response, &local);
    if (local && strlen(local) < sizeof(guard_error)) memcpy(guard_error, local, strlen(local) + 1);
    if (error) *error = local;
    else free(local);
    return rc;
}

#define br_captures_find opencagedata_intercept_captures
#define snprintf opencagedata_test_snprintf
#define br_http_send opencagedata_test_send
#include "../../src/detectors/opencagedata.c"
#undef br_http_send
#undef snprintf
#undef br_captures_find

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32 && strlen(prefix) == 68);
    CHECK(br_opencagedata_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid OpenCageData detector output"));
    free(error);
    error = NULL;
    CHECK(br_opencagedata_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_opencagedata_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 533 && detector->version == 0 && !strcmp(detector->name, "OpenCageData"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "OpenCageData provides a geocoding API to convert coordinates to and from places. OpenCageData keys can be used to access the service's geocoding capabilities."));
    CHECK(detector->nkeywords == 1 && detector->keywords && !strcmp(detector->keywords[0], "opencagedata"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_key(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 533, secret, "key");
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

static void expect_dedup(size_t slot, const char *secret)
{
    CHECK(!memcmp(seen_dedup[slot], "533:", 4));
    CHECK(!memcmp(seen_dedup[slot] + 4, secret, 32));
}

static void extraction(const br_detector *detector)
{
    char input[192];
    CHECK(snprintf(input, sizeof(input), "opencagedata token = '%s'", key) > 0);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "OPENCAGEDATA token = '%s'", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "opencagedata token = '%s' | '%s'", key, key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "opencagedata %s opencagedata %s", key, other) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], other, false);
    br_results_clear(&out);

    char gap[128];
    memcpy(gap, "opencagedata", 12);
    memset(gap + 12, ' ', 40);
    gap[20] = '\v';
    memcpy(gap + 52, key, 32);
    out = test_scan(detector, NULL, false, gap, 84);
    CHECK(out.len == 1);
    br_results_clear(&out);
    memset(gap + 12, ' ', 41);
    memcpy(gap + 53, key, 32);
    out = test_scan(detector, NULL, false, gap, 85);
    CHECK(out.len == 0);
    br_results_clear(&out);

    CHECK(snprintf(input, sizeof(input), "opencagedata%s", key) > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "opencagedata token = 'dc07kkpxqkraj009?95s7ay7wpgfjt4j'") > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    CHECK(snprintf(input, sizeof(input), "opencagedata token = 'DC07kkpxqkraj009u95s7ay7wpgfjt4j'") > 0);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, "", 0);
    CHECK(out.len == 0);
    br_results_clear(&out);
}

static void verification(const br_detector *detector)
{
    char input[160], expected[128];
    CHECK(snprintf(expected, sizeof(expected), "%s%s", prefix, key) == 100);
    CHECK(snprintf(input, sizeof(input), "opencagedata %s opencagedata %s", key, other) > 0);
    url_builds = seen_sends = seen_headers = 0;
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 0 && url_builds == 2 && seen_sends == 0 && !seen_headers);
    CHECK(!strcmp(built_urls[0], expected));
    CHECK(snprintf(expected, sizeof(expected), "%s%s", prefix, other) == 100);
    CHECK(!strcmp(built_urls[1], expected));
    br_results_clear(&out);

    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    url_builds = seen_sends = 0;
    guard_error[0] = '\0';
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 0 && http.releases == 2 && seen_sends == 2 && !seen_headers);
    CHECK(!strcmp(guard_error, "unsupported HTTP request coalescing"));
    expect_key(&out.items[0], key, false);
    expect_key(&out.items[1], other, false);
    CHECK(snprintf(expected, sizeof(expected), "%s%s", prefix, key) == 100);
    CHECK(!strcmp(seen_urls[0], expected));
    expect_dedup(0, key);
    CHECK(snprintf(expected, sizeof(expected), "%s%s", prefix, other) == 100);
    CHECK(!strcmp(seen_urls[1], expected));
    expect_dedup(1, other);
    br_results_clear(&out);

    script_on = 1;
    CHECK(snprintf(input, sizeof(input), "opencagedata %s", key) > 0);
    int statuses[] = {199, 200, 299, 300, 401, 500};
    bool verified[] = {false, true, true, false, false, false};
    const char *bodies[] = {NULL, "read failed", "read failed", NULL, "ignored", NULL};
    for (size_t i = 0; i < 6; ++i) {
        script_rc = 0;
        script_status = statuses[i];
        script_body_error = bodies[i];
        script_set_error = 0;
        http = (test_http){0};
        transport = test_transport(&http);
        ctx = (br_scan_ctx){.transport = &transport};
        seen_sends = 0;
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 0 && http.releases == 1 && seen_sends == 1);
        expect_key(&out.items[0], key, verified[i]);
        expect_dedup(0, key);
        br_results_clear(&out);
    }

    script_rc = 1;
    script_status = 200;
    script_body_error = NULL;
    script_set_error = 0;
    http = (test_http){0};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    seen_sends = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1 && seen_sends == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);

    script_body_error = "lookup failed: no such host";
    script_set_error = 1;
    http.calls = http.releases = seen_sends = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    expect_key(&out.items[0], key, false);
    br_results_clear(&out);
    script_on = 0;

    ctx = (br_scan_ctx){0};
    seen_sends = 0;
    guard_error[0] = '\0';
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && seen_sends == 1 && !out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strcmp(guard_error, "HTTP transport not installed"));
    br_results_clear(&out);
}

static void failures(const br_detector *detector)
{
    char input[160], *error = NULL;
    CHECK(snprintf(input, sizeof(input), "opencagedata %s opencagedata %s", key, other) > 0);
    unsigned char *raw = NULL;
    char *saved = NULL;
    br_results prior = {0};
    plant(&prior, &raw, &saved);
    captures_rc = 1;
    url_builds = seen_sends = 0;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "injected OpenCageData capture failure"));
    CHECK(!url_builds && !seen_sends);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create OpenCageData result") && !url_builds && !seen_sends);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    url_fail_at = 1;
    url_fail_rc = -1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot format OpenCageData URL") && !seen_sends);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    url_fail_at = 1;
    url_fail_rc = 200;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot format OpenCageData URL") && !seen_sends);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 2;
    url_builds = seen_sends = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create OpenCageData result"));
    CHECK(http.calls == 0 && http.releases == 1 && seen_sends == 1);
    check_prior(&prior, raw, saved);
    free(error);
    error = NULL;

    prior.cap = 0;
    http = (test_http){0};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    seen_sends = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append OpenCageData result"));
    CHECK(http.calls == 0 && http.releases == 1 && seen_sends == 1);
    check_prior(&prior, raw, saved);
    free(error);
    br_results_clear(&prior);

    br_results empty = {0};
    CHECK(detector->scan(NULL, &ctx, false, (br_slice){NULL, 1}, &empty, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized OpenCageData scan"));
    free(error);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    failures(detector);
    return test_finish("OpenCageData");
}
