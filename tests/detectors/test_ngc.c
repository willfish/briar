/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

static int ngc_fail_push_on;
static int ngc_push_calls;

static int ngc_push_hook(br_results *out, br_result *owned)
{
    ++ngc_push_calls;
    if (ngc_fail_push_on && ngc_push_calls == ngc_fail_push_on) return 1;
    return br_results_push(out, owned);
}
#define br_results_push ngc_push_hook
#include "../../src/detectors/ngc.c"
#undef br_results_push

static const char encoded[] = "WGtMOGtDWWFaZEpSbWpKTktWQTQ2VWNKYk06VWxhRjFvMEotS2FEUS0za1hkLVBtekktblJLM0VoZEJPMXAw";
static const char plaintext[] = "XkL8kCYaZdJRmjJNKVA46UcJbM:UlaF1o0J-KaDQ-3kXd-PmzI-nRK3EhdBO1p0";

typedef struct {
    char method[8];
    char url[80];
    char names[2][32];
    char values[2][256];
    size_t nheaders;
    int profile;
    uint32_t timeout;
    int32_t type;
    bool had_body;
} seen_request;

static seen_request seen;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    memset(&seen, 0, sizeof(seen));
    if (!request) return;
    seen.nheaders = request->nheaders;
    seen.profile = (int)request->profile;
    seen.timeout = request->timeout_ms;
    seen.type = request->detector_type;
    seen.had_body = request->body.len != 0 || request->body.data != NULL;
    if (request->method) snprintf(seen.method, sizeof(seen.method), "%s", request->method);
    if (request->url) snprintf(seen.url, sizeof(seen.url), "%s", request->url);
    for (size_t i = 0; i < request->nheaders && i < 2; ++i) {
        if (request->headers[i].name)
            snprintf(seen.names[i], sizeof(seen.names[i]), "%s", request->headers[i].name);
        if (request->headers[i].value)
            snprintf(seen.values[i], sizeof(seen.values[i]), "%s", request->headers[i].value);
    }
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_ngc_init(NULL, &error) != 0 && error && !strcmp(error, "invalid NGC detector output"));
    free(error);
    error = NULL;
    CHECK(br_ngc_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_ngc_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 896 && detector->version == 0 && !strcmp(detector->name, "NGC"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Nvidia's API for AI related things"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ngc"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean);
    return detector;
}

static void expect_absent(const br_detector *detector, const char *input)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char mixed[256];
    snprintf(mixed, sizeof(mixed), "ngc token - '%s'\nngc token - '%s'\n", encoded, plaintext);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, mixed, strlen(mixed));
    CHECK(results.len == 1 && !http.calls && !http.releases);
    test_key_result(&results.items[0], 896, encoded, "key");
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    results = test_scan(detector, &ctx, false, encoded, strlen(encoded));
    CHECK(results.len == 1 && !http.calls);
    test_key_result(&results.items[0], 896, encoded, "key");
    br_results_clear(&results);

    char far[1200];
    memset(far, '\n', sizeof(far));
    memcpy(far + 1100, encoded, strlen(encoded));
    results = test_scan(detector, &ctx, false, far, sizeof(far));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 896, encoded, "key");
    br_results_clear(&results);

    char twice[180];
    snprintf(twice, sizeof(twice), "%s %s", encoded, encoded);
    results = test_scan(detector, &ctx, false, twice, strlen(twice));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 896, encoded, "key");
    test_key_result(&results.items[1], 896, encoded, "key");
    br_results_clear(&results);

    expect_absent(detector, plaintext);
    expect_absent(detector, "WGtMOGtDWWFaZE?SbWpKTktWQTQ2VWNKYk06VWxhRjFvMEotS2FEUS0za1hkLVBtekktblJLM0VoZEJPMXAw");
}

static void expect_request(const br_detector *detector, int status, int send_rc, bool verified)
{
    memset(&seen, 0, sizeof(seen));
    test_http http = {.response = {.status = status, .body = {(const unsigned char *)"ignored", 7},
                                   .body_error = "read failed"},
                      .send_rc = send_rc, .send_error = send_rc ? "dial failed" : NULL, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, encoded, strlen(encoded));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(results.items[0].verified == verified && !results.items[0].verification_error);
    test_key_result(&results.items[0], 896, encoded, "key");
    CHECK(!strcmp(seen.method, "GET"));
    CHECK(!strcmp(seen.url, "https://authn.nvidia.com/token?service=ngc"));
    CHECK(seen.nheaders >= 2 && seen.profile == BR_HTTP_SANE && seen.timeout == 5000 && seen.type == 896);
    CHECK(!seen.had_body);
    CHECK(!strcmp(seen.names[0], "accept") && !strcmp(seen.values[0], "*/*"));
    CHECK(!strcmp(seen.names[1], "Authorization"));
    char *basic = NULL;
    char *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)"$oauthtoken", 11},
                             (br_slice){(const unsigned char *)encoded, strlen(encoded)}, &basic, &error) == 0);
    CHECK(!error && basic && !strcmp(seen.values[1], basic));
    free(basic);
    br_results_clear(&results);
}

static void test_verify(const br_detector *detector)
{
    expect_request(detector, 200, 0, true);
    expect_request(detector, 299, 0, true);
    expect_request(detector, 199, 0, false);
    expect_request(detector, 300, 0, false);
    expect_request(detector, 401, 0, false);
    expect_request(detector, 200, 1, false);

    br_results results = {0};
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)encoded, strlen(encoded)},
                         &results, &error) == 0);
    CHECK(!error && !results.len);
    br_results_clear(&results);
}

typedef struct {
    br_results *out;
    const char *basic;
    const unsigned char *key;
    int status[4];
    int send_rc[4];
    size_t calls, releases;
    int release_status[4];
    size_t release_rows[4];
    const char *url[4];
    const char *accept_name[4];
    const char *accept_value[4];
    const char *authorization[4];
} ngc_watch;

static void seed_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "synthetic-caller", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void expect_caller(const br_results *out, const br_result *saved)
{
    CHECK(out->len && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.data == saved->raw.data);
    CHECK(out->items[0].verification_error == saved->verification_error);
    CHECK(out->items[0].secret_parts == saved->secret_parts);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static int watch_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    (void)ctx;
    ngc_watch *watch = user;
    size_t slot = watch->calls++;
    CHECK(slot < 4 && request && request->headers && request->nheaders >= 2);
    CHECK(request->nheaders >= 3); /* prepared User-Agent is not retained past send */
    watch->url[slot] = request->url;
    watch->accept_name[slot] = request->headers[0].name;
    watch->accept_value[slot] = request->headers[0].value;
    watch->authorization[slot] = request->headers[1].value;
    *response = (br_http_response){.status = watch->status[slot],
                                   .body = {(const unsigned char *)"ignored", 7},
                                   .body_error = "read failed"};
    if (watch->send_rc[slot]) {
        *error = strdup("dial failed");
        CHECK(*error);
        return watch->send_rc[slot];
    }
    *error = NULL;
    return 0;
}

static void expect_release_values(const ngc_watch *watch, int status)
{
    size_t slot = 4;
    for (size_t i = 0; i < watch->calls && i < 4; ++i)
        if (watch->status[i] == status) slot = i;
    CHECK(slot < 4);
    CHECK(watch->url[slot] && !strcmp(watch->url[slot], "https://authn.nvidia.com/token?service=ngc"));
    CHECK(watch->accept_name[slot] && !strcmp(watch->accept_name[slot], "accept"));
    CHECK(watch->accept_value[slot] && !strcmp(watch->accept_value[slot], "*/*"));
    CHECK(watch->authorization[slot] && watch->basic && !strcmp(watch->authorization[slot], watch->basic));
    CHECK(watch->key && !memcmp(watch->key, encoded, strlen(encoded)));
    if (watch->out->len >= 2) {
        CHECK(watch->out->items[1].raw.len == strlen(encoded));
        CHECK(!memcmp(watch->out->items[1].raw.data, encoded, strlen(encoded)));
    }
    if (watch->out->len >= 3) {
        CHECK(watch->out->items[2].raw.len == strlen(encoded));
        CHECK(!memcmp(watch->out->items[2].raw.data, encoded, strlen(encoded)));
    }
}

static void watch_release(void *user, br_http_response *response)
{
    ngc_watch *watch = user;
    CHECK(response);
    size_t slot = watch->releases++;
    CHECK(slot < 4);
    watch->release_status[slot] = response->status;
    watch->release_rows[slot] = watch->out->len;
    expect_release_values(watch, response->status);
}

static void test_deferred_release(const br_detector *detector)
{
    char *basic = NULL;
    char *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)"$oauthtoken", 11},
                             (br_slice){(const unsigned char *)encoded, strlen(encoded)},
                             &basic, &error) == 0);
    CHECK(!error && basic);
    char input[180];
    snprintf(input, sizeof(input), "%s %s", encoded, encoded);
    br_result saved = {0};
    br_results results = {0};
    seed_caller(&results, &saved);
    ngc_watch watch = {.out = &results, .basic = basic, .key = (const unsigned char *)input};
    watch.status[0] = 201;
    watch.status[1] = 202;
    br_transport transport = {&watch, watch_send, watch_release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == 0);
    CHECK(!error && results.len == 3 && watch.calls == 2 && watch.releases == 2);
    CHECK(watch.release_status[0] == 202 && watch.release_status[1] == 201);
    CHECK(watch.release_rows[0] == 3 && watch.release_rows[1] == 3);
    expect_caller(&results, &saved);
    CHECK(results.items[1].verified && results.items[2].verified);
    CHECK(!results.items[1].verification_error && !results.items[2].verification_error);
    br_results_clear(&results);

    results = (br_results){0};
    seed_caller(&results, &saved);
    watch = (ngc_watch){.out = &results, .basic = basic, .key = (const unsigned char *)encoded};
    watch.status[0] = 500;
    watch.send_rc[0] = 1;
    transport = (br_transport){&watch, watch_send, watch_release};
    ctx = (br_scan_ctx){.transport = &transport};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)encoded, strlen(encoded)},
                         &results, &error) == 0);
    CHECK(!error && results.len == 2 && watch.calls == 1 && watch.releases == 1);
    CHECK(watch.release_status[0] == 500 && watch.release_rows[0] == 1);
    expect_caller(&results, &saved);
    CHECK(!results.items[1].verified && !results.items[1].verification_error);
    br_results_clear(&results);

    results = (br_results){0};
    seed_caller(&results, &saved);
    watch = (ngc_watch){.out = &results, .basic = basic, .key = (const unsigned char *)encoded};
    watch.status[0] = 401;
    transport = (br_transport){&watch, watch_send, watch_release};
    ctx = (br_scan_ctx){.transport = &transport};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)encoded, strlen(encoded)},
                         &results, &error) == 0);
    CHECK(!error && results.len == 2 && watch.releases == 1 && watch.release_rows[0] == 2);
    CHECK(!results.items[1].verified && !results.items[1].verification_error);
    br_results_clear(&results);

    results = (br_results){0};
    seed_caller(&results, &saved);
    watch = (ngc_watch){.out = &results, .basic = basic, .key = (const unsigned char *)input};
    watch.status[0] = 201;
    watch.status[1] = 202;
    transport = (br_transport){&watch, watch_send, watch_release};
    ctx = (br_scan_ctx){.transport = &transport};
    ngc_push_calls = 0;
    ngc_fail_push_on = 2;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append NGC finding"));
    CHECK(results.len == 1 && watch.calls == 2 && watch.releases == 2);
    CHECK(watch.release_status[0] == 202 && watch.release_status[1] == 201);
    CHECK(watch.release_rows[0] == 2 && watch.release_rows[1] == 2);
    expect_caller(&results, &saved);
    free(error);
    br_results_clear(&results);
    ngc_fail_push_on = 0;
    free(basic);
}

int main(void)
{
    const br_detector *detector = descriptor();
    test_extraction(detector);
    test_verify(detector);
    test_deferred_release(detector);
    return test_finish("NGC");
}
