/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

#define KEY_A "Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5"
#define KEY_B "Zy8xWv5Ut2Sr9Qp6Zy8xWv5Ut2Sr9Qp6Zy8xWv5Ut2Sr9Qp6Zy8xWv5Ut2Sr9Qp6"
static const char key[] = KEY_A;
static const char key2[] = KEY_B;
static size_t fail_size, fail_after, fail_part;

/* Use the existing native tests' narrow allocation/map failure technique. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s)
{
    return (br_slice){(const unsigned char *)s, strlen(s)};
}
static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 355, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(key) == 65 && sizeof(key2) == 65);
    CHECK(br_html2pdf_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_html2pdf_init(NULL, NULL) != 0);
    CHECK(br_html2pdf_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_html2pdf_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 355 && !detector->version && !strcmp(detector->name, "Html2Pdf"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Html2Pdf is a service that converts HTML content into PDF documents. API keys for Html2Pdf can be used to authenticate and authorize access to this service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "html2pdf"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void extraction(const br_detector *detector)
{
    const struct { const char *input, *capture; } cases[] = {
        {"HTML2PDF \"" KEY_A "\"", key},
        {"preHtMl2PdFpost\r\n" KEY_B, key2},
        {"html2pdf " KEY_A, key},
        {"html2pdf " "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl"},
        {"html2pdf " "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKL"},
        {"html2pdf " "0123456789012345678901234567890123456789012345678901234567890123", "0123456789012345678901234567890123456789012345678901234567890123"},
        {KEY_A, NULL},
        {KEY_A " html2pdf", NULL},
        {"html2pdf _" KEY_A, NULL},
        {"html2pdf " KEY_A "_", NULL},
        {"html2pdf " KEY_A "X", NULL},
        {"html2pdf " "Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5-Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5", NULL},
        {"html2pdf " "Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm5Ab3dEf6Gh9Jk2Lm", NULL},
    };
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = test_scan(detector, &ctx, false, cases[i].input, strlen(cases[i].input));
        CHECK(out.len == (cases[i].capture ? 1u : 0u) && !http.calls && !http.releases);
        if (out.len) result_is(&out.items[0], cases[i].capture, false);
        br_results_clear(&out);
    }
    unsigned char input[320];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "html2pdf", 8);
        memset(input + 8, '.', gap);
        memcpy(input + 8 + gap, key, 64);
        br_results out = test_scan(detector, NULL, false, input, 72 + gap);
        CHECK(out.len == (gap == 40 ? 1u : 0u));
        if (out.len) result_is(&out.items[0], key, false);
        br_results_clear(&out);
    }
    static const unsigned char binary[] = "html2pdf\0" KEY_A;
    br_results out = test_scan(detector, NULL, false, binary, sizeof(binary) - 1);
    CHECK(out.len == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    const char *occurrences = "html2pdf " KEY_A "\nhtml2pdf " KEY_B "\nhtml2pdf " KEY_A;
    out = test_scan(detector, NULL, false, occurrences, strlen(occurrences));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false); result_is(&out.items[1], key2, false);
    result_is(&out.items[2], key, false); br_results_clear(&out);
    const char *one_prefix = "html2pdf " KEY_A " " KEY_B;
    out = test_scan(detector, NULL, false, one_prefix, strlen(one_prefix));
    CHECK(out.len == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    out = test_scan(detector, NULL, false, NULL, 0);
    CHECK(!out.len); br_results_clear(&out);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_transport *transport;
    const br_http_request *borrowed_request;
    const char *borrowed_key;
} expected;
static void request_is(const br_http_request *request, const char *capture)
{
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.html2pdf.app/v1/generate"));
    CHECK(request->profile == BR_HTTP_PRIVATE_DEFAULT_CLIENT && !request->timeout_ms);
    CHECK(request->detector_type == 355 && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    char body[128];
    int len = snprintf(body, sizeof(body), "{\"html\":\"Helloworld\",\"apiKey\":\"%s\"}", capture);
    CHECK(len > 0 && (size_t)len < sizeof(body));
    CHECK(request->body.len == (size_t)len && !memcmp(request->body.data, body, (size_t)len));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    CHECK(e && http->calls <= e->count && !e->borrowed_request);
    CHECK(ctx && ctx->transport == e->transport && !ctx->deadline_monotonic_ms);
    CHECK(!ctx->cancelled && !ctx->cancel_user && !ctx->user_agent && !ctx->endpoints && !ctx->options);
    e->borrowed_key = e->keys[http->calls - 1];
    request_is(request, e->borrowed_key);
    /* Retain only the provider's request, never the helper's background context. */
    e->borrowed_request = request;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    CHECK(e && e->borrowed_request);
    request_is(e->borrowed_request, e->borrowed_key);
    CHECK(response->status == http->response.status && response->body.data == http->response.body.data);
    CHECK(response->body.len == http->response.body.len && response->body_error == http->response.body_error);
    e->borrowed_request = NULL;
    e->borrowed_key = NULL;
    test_http_release(user, response);
}
static bool cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void verification(const br_detector *detector)
{
    static const unsigned char binary[] = "not a PDF\0not JSON";
    const struct { int status; br_slice body; const char *body_error; } cases[] = {
        {0, {0}, NULL}, {199, {0}, NULL},
        {200, {0}, NULL}, {201, {binary, sizeof(binary) - 1}, "synthetic read failure"},
        {204, {0}, ""}, {206, {binary, sizeof(binary) - 1}, NULL},
        {299, {0}, "ignored read failure"}, {300, {0}, NULL},
        {301, {binary, sizeof(binary) - 1}, NULL}, {401, {0}, "ignored"},
        {403, {0}, NULL}, {429, {0}, NULL}, {500, {0}, NULL},
    };
    const char *keys[] = {key};
    const char input[] = "html2pdf " KEY_A;
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        expected e = {.keys = keys, .count = 1};
        test_http http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].body_error}, .inspect = inspect, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        e.transport = &transport;
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "must-not-be-copied"};
        br_results out = test_scan(detector, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_request);
        result_is(&out.items[0], key, cases[i].status >= 200 && cases[i].status < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {-7, NULL}, {1, "synthetic setup failure"}, {7, KEY_A},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        expected e = {.keys = keys, .count = 1};
        test_http http = {.response = {.status = 200, .body_error = ""}, .send_rc = errors[i].rc, .send_error = errors[i].cause, .inspect = inspect, .user = &e};
        br_transport transport = {&http, test_http_send, release_response};
        e.transport = &transport;
        br_scan_ctx ctx = {.transport = &transport};
        br_results out = test_scan(detector, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !e.borrowed_request);
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *duplicates[] = {key, key2, key};
    expected e = {.keys = duplicates, .count = 3};
    test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    e.transport = &transport;
    size_t cancellations = 0;
    const char *configured[] = {"not an endpoint"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "ignored", .use_cloud = true, .use_found = true};
    br_json *options = json_object_new_object(); CHECK(options);
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = 1,
        .cancelled = cancelled, .cancel_user = &cancellations, .user_agent = "invalid\r\nagent",
        .endpoints = &endpoints, .options = options};
    br_scan_ctx original = ctx;
    const char repeated[] = "html2pdf " KEY_A "\nhtml2pdf " KEY_B "\nhtml2pdf " KEY_A;
    br_results out = test_scan(detector, &ctx, true, repeated, sizeof(repeated) - 1);
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && !e.borrowed_request && !cancellations);
    CHECK(!memcmp(&ctx, &original, sizeof(ctx)));
    for (size_t i = 0; i < out.len; ++i) result_is(&out.items[i], duplicates[i], true);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, false, input, sizeof(input) - 1);
    CHECK(out.len == 1 && !http.calls && !http.releases && !cancellations);
    result_is(&out.items[0], key, false); br_results_clear(&out);
    json_object_put(options);

    br_scan_ctx missing = {0};
    const br_scan_ctx *contexts[] = {NULL, &missing};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        out = test_scan(detector, contexts[i], true, input, sizeof(input) - 1);
        CHECK(out.len == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    /* A helper rejection still reaches one ordinary release on the original
     * transport, even though no send callback can run. */
    http = (test_http){0};
    transport = (br_transport){.user = &http, .release = test_http_release};
    missing.transport = &transport;
    out = test_scan(detector, &missing, true, input, sizeof(input) - 1);
    CHECK(out.len == 1 && !http.calls && http.releases == 1);
    result_is(&out.items[0], key, false); br_results_clear(&out);
}

static void prior_is(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}
static void resources(const br_detector *detector)
{
    const char input[] = "html2pdf " KEY_A "\nhtml2pdf " KEY_B;
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(5); CHECK(prior.raw.data);
    memcpy(prior.raw.data, "prior", 5); prior.raw.len = 5;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char *error = NULL;
    for (size_t mode = 0; mode < 4; ++mode) {
        test_http http = {.response = {.status = 200}, .send_rc = mode == 3 ? 7 : 0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        const br_scan_ctx *context = mode == 1 ? NULL : &ctx;
        bool verify = mode != 0;
        for (size_t failure = 0; failure < 5; ++failure) {
            if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
            if (failure == 1) { fail_size = 8 * sizeof(char *); fail_after = 1; }
            if (failure == 2) { fail_size = 65; fail_after = 2; }
            /* Two capture arrays are also 64 bytes; the fourth is second Raw. */
            if (failure == 3) { fail_size = 64; fail_after = 4; }
            if (failure == 4) fail_part = 2;
            CHECK(detector->scan(detector, context, verify, text(input), &out, &error) != 0);
            CHECK(error && !fail_after && !fail_part);
            CHECK(http.calls == (mode >= 2 && failure >= 3 ? 1u : 0u) && http.releases == http.calls);
            prior_is(&out, &prior);
            free(error); error = NULL; http.calls = http.releases = 0;
        }
        size_t cap = out.cap; out.cap = 0;
        CHECK(detector->scan(detector, context, verify, text(input), &out, &error) != 0 && error);
        out.cap = cap;
        CHECK(http.calls == (mode >= 2 ? 1u : 0u) && http.releases == http.calls);
        prior_is(&out, &prior); free(error); error = NULL;
    }
    br_results_clear(&out);
    CHECK(detector->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
    CHECK(!fail_after && !fail_part);
    out = test_scan(detector, NULL, false, input, sizeof(input) - 1);
    CHECK(out.len == 2); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); resources(detector);
    return test_finish("Html2Pdf grammar/occurrences/metadata/ordered-JSON/DefaultClient-background/status/errors/release/rollback");
}
