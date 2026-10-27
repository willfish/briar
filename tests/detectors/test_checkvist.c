/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char key[] = "AbCdEf12345678", other_key[] = "ZyXwVu98765432";
static const char email[] = "User+tag@Example.test", other_email[] = "user+tag@example.test";
static const char quoted[] = "\"A\\ B+\x01Z\"@Example.test";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t tracked_form_size, form_allocations, fail_form_after;

/* Same narrow allocation seam as Chartmogul/Censys. The simple email fixtures
 * encode to 25 bytes, giving a 35+25=60-byte form. Do NOT fail HTTP setup/Do. */
void *malloc(size_t size)
{
    if (tracked_form_size && size == tracked_form_size) {
        ++form_allocations;
        if (fail_form_after && --fail_form_after == 0) return NULL;
    }
    return calloc(1, size);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 14 && strlen(other_key) == 14);
    CHECK(br_checkvist_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Checkvist detector output")); free(error); error = NULL;
    CHECK(!br_checkvist_init(&detector, &error) && detector && !error);
    CHECK(!br_checkvist_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 709 && detector->version == 0 && !strcmp(detector->name, "Checkvist") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Checkvist is an online task management tool. The credentials found can be used to access and manage tasks and data within Checkvist."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "checkvist"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void text_part(br_json *object, const char *name, br_slice expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len && !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void check_result(const br_result *result, const char *expected_key, br_slice expected_email, bool verified)
{
    CHECK(result->detector_type == 709 && !result->detector_name && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 14 && !memcmp(result->raw.data, expected_key, 14));
    CHECK(result->raw_v2.len == 14 + expected_email.len && !memcmp(result->raw_v2.data, expected_key, 14));
    CHECK(!memcmp(result->raw_v2.data + 14, expected_email.data, expected_email.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    text_part(result->secret_parts, "key", (br_slice){(const unsigned char *)expected_key, 14}); text_part(result->secret_parts, "email", expected_email);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static char *input_for(const br_slice *emails, size_t ne, const char *const *keys, size_t nk)
{
    size_t size = 1;
    for (size_t i = 0; i < ne; ++i) size += 11 + emails[i].len;
    size += nk * 25; char *out = malloc(size); CHECK(out); size_t at = 0;
    for (size_t i = 0; i < ne; ++i) {
        memcpy(out + at, "checkvist", 9); at += 9;
        /* The source's leading word boundary needs a word just before a
         * quoted local part. X is OUTSIDE capture 1, not part of the email. */
        out[at++] = emails[i].data[0] == '"' ? 'X' : ' ';
        memcpy(out + at, emails[i].data, emails[i].len); at += emails[i].len; out[at++] = '\n';
    }
    for (size_t i = 0; i < nk; ++i) { memcpy(out + at, "checkvist ", 10); at += 10; memcpy(out + at, keys[i], 14); at += 14; out[at++] = '\n'; }
    CHECK(at + 1 == size); out[at] = '\0'; return out;
}

static void expect_one(const br_detector *detector, const char *input, const char *expected_key, br_slice expected_email)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected_key ? 1u : 0u));
    if (expected_key) check_result(&results.items[0], expected_key, expected_email, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[16];
    snprintf(input, sizeof(input), "CHECKVIST %s\n%s\nChEcKvIsT %s", email, isolation, key); expect_one(detector, input, key, TEXT(email));
    snprintf(input, sizeof(input), "checkvist %s", key); expect_one(detector, input, NULL, TEXT(email));
    snprintf(input, sizeof(input), "checkvist %s", email); expect_one(detector, input, NULL, TEXT(email));
    snprintf(input, sizeof(input), "%s\n%s\ncheckvist %s", email, isolation, key); expect_one(detector, input, NULL, TEXT(email));
    snprintf(input, sizeof(input), "checkvist %s\n%s\n%s", email, isolation, key); expect_one(detector, input, NULL, TEXT(email));
    memcpy(changed, key, sizeof(key)); changed[13] = 0; snprintf(input, sizeof(input), "checkvist %s\n%s\ncheckvist %s", email, isolation, changed); expect_one(detector, input, NULL, TEXT(email));
    snprintf(changed, sizeof(changed), "%sZ", key); snprintf(input, sizeof(input), "checkvist %s\n%s\ncheckvist %s", email, isolation, changed); expect_one(detector, input, NULL, TEXT(email));
    memcpy(changed, key, sizeof(key)); changed[5] = '-'; snprintf(input, sizeof(input), "checkvist %s\n%s\ncheckvist %s", email, isolation, changed); expect_one(detector, input, NULL, TEXT(email));
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "checkvist%*s%s\n%s\ncheckvist %s", gap, "", email, isolation, key); expect_one(detector, input, gap == 40 ? key : NULL, TEXT(email));
        snprintf(input, sizeof(input), "checkvist %s\n%s\ncheckvist%*s%s", email, isolation, gap, "", key); expect_one(detector, input, gap == 40 ? key : NULL, TEXT(email));
    }
    snprintf(input, sizeof(input), "checkvist %s\n%s\ncheckvist _%s", email, isolation, key); expect_one(detector, input, NULL, TEXT(email));
    snprintf(input, sizeof(input), "checkvistX%s\n%s\ncheckvist %s", quoted, isolation, key); expect_one(detector, input, key, TEXT(quoted));
    snprintf(input, sizeof(input), "checkvist a@[127.0.0.1]X\n%s\ncheckvist %s", isolation, key); expect_one(detector, input, key, TEXT("a@[127.0.0.1]"));
}

typedef struct { const char *key, *encoded, *send_error; br_slice email; int status, send_rc; } reply;
typedef struct { reply rows[6]; size_t count, allocation_size; const br_scan_ctx *expected_ctx; } script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static int hex_value(unsigned char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 6 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 709 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://checkvist.com/auth/login.json?version=2"));
    CHECK(request->body.data && request->body.len > 35 && !request->dedup_key.len && request->nheaders == 2);
    CHECK(header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/x-www-form-urlencoded"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Authorization") && !header(request, "Accept") && !header(request, "Content-Length"));
    char prefix[40]; CHECK(snprintf(prefix, sizeof(prefix), "remote_key=%s&username=", step->key) == 35); CHECK(!memcmp(request->body.data, prefix, 35));
    if (step->encoded) CHECK(request->body.len == 35 + strlen(step->encoded) && !memcmp(request->body.data + 35, step->encoded, strlen(step->encoded)));
    /* Independently decode the entire username, checking uppercase escapes
     * and exact original bytes/case/controls, not a truncated C string. */
    size_t decoded = 0;
    for (size_t i = 35; i < request->body.len;) {
        unsigned char c = request->body.data[i++];
        if (c == '%') {
            CHECK(request->body.len - i >= 2); int hi = hex_value(request->body.data[i]), lo = hex_value(request->body.data[i + 1]); CHECK(hi >= 0 && lo >= 0); c = (unsigned char)(hi * 16 + lo); i += 2;
        } else if (c == '+') c = ' ';
        else CHECK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~');
        CHECK(decoded < step->email.len && c == step->email.data[decoded++]);
    }
    CHECK(decoded == step->email.len);
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    form_allocations = 0; tracked_form_size = steps->allocation_size; br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); tracked_form_size = 0;
    CHECK(http.calls == steps->count && http.releases == steps->count); if (steps->allocation_size) CHECK(form_allocations == (verify ? steps->count : 0)); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    if (!step.key) step.key = key;
    if (!step.email.data) step.email = TEXT(email);
    const char *keys[] = {step.key}; char *input = input_for(&step.email, 1, keys, 1); script steps = {.count = 1}; steps.rows[0] = step;
    br_results results = run(detector, input, true, &steps); free(input); CHECK(results.len == 1); check_result(&results.items[0], step.key, step.email, !step.send_error && !step.send_rc && step.status >= 200 && step.status < 300); return results;
}

static void products_and_overlap(const br_detector *detector)
{
    const br_slice emails[] = {TEXT(email), TEXT(other_email), TEXT(email)}; const char *keys[] = {key, other_key, key}; char *input = input_for(emails, 3, keys, 3);
    script steps = {.count = 6, .allocation_size = 60};
    for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 3; ++k) steps.rows[e * 3 + k] = (reply){.key = keys[k], .email = emails[e], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {.allocation_size = 60}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 6);
        for (size_t e = 0; e < 2; ++e) for (size_t k = 0; k < 3; ++k) check_result(&results.items[e * 3 + k], keys[k], emails[e], verify);
        br_results_clear(&results);
    }
    form_allocations = 0; tracked_form_size = 60; br_results results = test_scan(detector, NULL, true, input, strlen(input)); tracked_form_size = 0; CHECK(!results.len && form_allocations == 6); br_results_clear(&results); free(input);
    const br_slice overlap[] = {TEXT("AbCdEf12345678@Example.test"), TEXT("AbCdEf12345678@Example.test")}; input = input_for(overlap, 2, NULL, 0);
    steps = (script){.count = 2}; for (size_t i = 0; i < 2; ++i) steps.rows[i] = (reply){.key = key, .email = overlap[0], .status = 200};
    results = run(detector, input, true, &steps); CHECK(results.len == 2); /* Unique email, TWO local-part key occurrences, no explicit key record. */
    for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], key, overlap[0], true);
    br_results_clear(&results); free(input);
}

static void encoding_and_status(const br_detector *detector)
{
    br_results results = single(detector, (reply){.status = 200, .encoded = "User%2Btag%40Example.test"}); br_results_clear(&results);
    results = single(detector, (reply){.status = 200, .email = TEXT(quoted), .encoded = "%22A%5C+B%2B%01Z%22%40Example.test"}); br_results_clear(&results);
    results = single(detector, (reply){.status = 200, .email = TEXT("a-_.~+%=&?@Example.test"), .encoded = "a-_.~%2B%25%3D%26%3F%40Example.test"}); br_results_clear(&results);
    size_t local_len = 8193; char *large = malloc(local_len + sizeof("@Example.test")); CHECK(large); memset(large, 'A', local_len); memcpy(large + local_len, "@Example.test", sizeof("@Example.test"));
    results = single(detector, (reply){.status = 299, .email = {(const unsigned char *)large, local_len + sizeof("@Example.test") - 1}}); br_results_clear(&results); free(large);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) { results = single(detector, (reply){.status = statuses[i]}); br_results_clear(&results); }
    const char *causes[] = {"unsupported: curl adapter supports bodyless GET or POST", "out of memory constructing HTTP headers", "net/http: nil Context", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) { results = single(detector, (reply){.status = 200, .send_error = causes[i], .send_rc = 1}); br_results_clear(&results); }
}

static void form_resource_boundary(const br_detector *detector)
{
    const br_slice emails[] = {TEXT(email)}; const char *keys[] = {key, other_key}; char *input = input_for(emails, 1, keys, 2);
    script steps = {.count = 2, .allocation_size = 60}; for (size_t i = 0; i < 2; ++i) steps.rows[i] = (reply){.key = keys[i], .email = emails[0], .status = 200};
    for (int nil = 0; nil < 2; ++nil) {
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        form_allocations = 0; fail_form_after = 2; tracked_form_size = 60;
        int rc = detector->scan(detector, nil ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); tracked_form_size = 0;
        CHECK(rc == -1 && !fail_form_after && form_allocations == 2 && error && !strcmp(error, "cannot construct Checkvist form body"));
        CHECK(http.calls == (nil ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); text_part(results.items[0].secret_parts, "key", TEXT("prior"));
        free(error); br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2);
    for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], keys[i], emails[0], true);
    br_results_clear(&results); free(input);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products_and_overlap(detector); encoding_and_status(detector); form_resource_boundary(detector);
    return test_finish("Checkvist capture-1 unique emails x key occurrences + complete GET form + resource-before-skip");
}
