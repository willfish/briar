/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_planviewleankit_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char sub[] = "pYwPPnHSc";
static const char *input;

static void expect_raw(const br_results *results, size_t index)
{
    CHECK(results->items[index].detector_type == 734);
    CHECK(results->items[index].raw.len == 128);
    CHECK(!memcmp(results->items[index].raw.data, key, 128));
    CHECK(!results->items[index].raw_v2.data && !results->items[index].raw_v2.len);
    br_json *part = NULL;
    CHECK(results->items[index].secret_parts && json_object_object_get_ex(results->items[index].secret_parts, "key", &part));
    CHECK(part && !strcmp(json_object_get_string(part), key));
}

static void test_metadata(void)
{
    const br_detector *d = NULL;
    char *error = NULL;
    CHECK(br_planviewleankit_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_planviewleankit_init(&d, &error) == 0 && !error && d);
    CHECK(d->type == 734 && d->version == 0 && !strcmp(d->name, "PlanviewLeanKit"));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "planviewleankit") && !strcmp(d->keywords[1], "planview"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
}

static void test_extraction(void)
{
    const br_detector *d = NULL;
    CHECK(br_planviewleankit_init(&d, NULL) == 0);
    char text[512];
    snprintf(text, sizeof(text), "planview %s planview subdomain.%s planview %s planview subdomain.%s", key, sub, key, sub);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 4); /* two subdomains times two keys, source order, duplicates kept */
    for (size_t i = 0; i < 4; ++i) expect_raw(&results, i);
    br_results_clear(&results);
    char far[320];
    snprintf(far, sizeof(far), "planview%*s%s subdomain.%s", 41, "", key, sub);
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)far, strlen(far)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    const char *upper = "planview ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 planview subdomain.pYwPPnHSc";
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)upper, strlen(upper)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static char *seen_url, *seen_auth;
static uint32_t seen_timeout;
static br_http_profile seen_profile;

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    seen_url = strdup(request->url);
    seen_auth = strdup(request->headers[0].value);
    seen_timeout = request->timeout_ms;
    seen_profile = request->profile;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->nheaders == 2); /* Authorization plus synthesized User-Agent */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000);
    CHECK(request->detector_type == 734);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user;
    http->releases++;
    memset(response, 0, sizeof(*response));
}

static void test_verify(void)
{
    const br_detector *d = NULL;
    CHECK(br_planviewleankit_init(&d, NULL) == 0);
    char text[256];
    snprintf(text, sizeof(text), "planview %s planview subdomain.%s", key, sub);
    input = text;
    int statuses[] = {200, 299, 199, 401};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}};
        br_transport transport = {.user = &http, .send = inspect, .release = release};
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = {0};
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        expect_raw(&results, 0);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        char want[96];
        snprintf(want, sizeof(want), "https://%s.leankit.com/io/account", sub);
        CHECK(seen_url && !strcmp(seen_url, want));
        CHECK(seen_auth && !strncmp(seen_auth, "Bearer ", 7) && !strcmp(seen_auth + 7, key));
        free(seen_url); seen_url = NULL; free(seen_auth); seen_auth = NULL;
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = -1, .send_error = "dial tcp: connection refused"};
    br_transport transport = {.user = &failed, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    br_scan_ctx bare = {0};
    CHECK(d->scan(d, &bare, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    (void)seen_timeout; (void)seen_profile;
}

int main(void)
{
    test_metadata();
    test_extraction();
    test_verify();
    return test_finish("planviewleankit");
}
