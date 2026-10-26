/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

static char key[30], other[30];
static const char id[] = "ABCDEF01-23456789-ABCDEF01-23456789AB";
static const char other_id[] = "12345678-ABCDEF01-23456789-ABCDEF0123";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 29 && strlen(other) == 29 && strlen(id) == 37 && strlen(other_id) == 37);
    CHECK(br_bulksms_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Bulksms detector output")); free(error); error = NULL;
    CHECK(!br_bulksms_init(&detector, &error) && detector && !error);
    CHECK(!br_bulksms_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 833 && detector->version == 0 && !strcmp(detector->name, "Bulksms"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "BulkSMS is a service used for sending SMS messages in bulk. BulkSMS credentials can be used to access and send messages through the BulkSMS API."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bulksms"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_text(br_json *object, const char *name, const char *text)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value)); CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(text) && !memcmp(json_object_get_string(value), text, strlen(text)));
}

static void check_result(const br_result *result, const char *expected_id, const char *expected_key)
{
    size_t klen = strlen(expected_key), ilen = strlen(expected_id);
    CHECK(result->detector_type == 833 && !result->detector_name);
    CHECK(result->raw.len == klen && !memcmp(result->raw.data, expected_key, klen));
    CHECK(result->raw_v2.len == klen + ilen && !memcmp(result->raw_v2.data, expected_key, klen));
    CHECK(!memcmp(result->raw_v2.data + klen, expected_id, ilen));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "key", expected_key); check_text(result->secret_parts, "id", expected_id);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void input_for(char *out, size_t size, const char *const *ids, size_t nids, const char *const *keys, size_t nkeys)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < nids + nkeys; ++i) {
        const char *value = i < nids ? ids[i] : keys[i - nids];
        int n = snprintf(out + at, size - at, "bulksms %s\n", value); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void expect_one(const br_detector *detector, const char *input, const char *expected_id, const char *expected_key)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected_id ? 1u : 0u));
    if (expected_id) { check_result(&results.items[0], expected_id, expected_key); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[1024], changed_id[39], changed_key[31]; const char *ids[] = {id}, *keys[] = {key};
    input_for(input, sizeof(input), ids, 1, keys, 1); expect_one(detector, input, id, key);
    snprintf(input, sizeof(input), "BULKSMS %s\n%s\nBuLkSmS %s", id, isolation, key); expect_one(detector, input, id, key);
    input_for(input, sizeof(input), ids, 1, NULL, 0); expect_one(detector, input, NULL, NULL);
    input_for(input, sizeof(input), NULL, 0, keys, 1); expect_one(detector, input, NULL, NULL);
    memcpy(changed_id, id, sizeof(id)); changed_id[0] = 'a'; snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", changed_id, key); expect_one(detector, input, NULL, NULL);
    changed_id[0] = 'G'; snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", changed_id, key); expect_one(detector, input, NULL, NULL);
    memcpy(changed_id, id, sizeof(id)); changed_id[36] = '\0'; snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", changed_id, key); expect_one(detector, input, NULL, NULL);
    snprintf(changed_id, sizeof(changed_id), "%sF", id); snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", changed_id, key); expect_one(detector, input, NULL, NULL);
    memset(changed_id, 'A', 37); changed_id[37] = '\0'; snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", changed_id, key); expect_one(detector, input, changed_id, key); /* Not a UUID grammar. */
    const char invalid[] = "_- ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed_key, key, sizeof(key)); changed_key[10] = invalid[i];
        snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", id, changed_key); expect_one(detector, input, NULL, NULL);
    }
    memcpy(changed_key, key, sizeof(key)); changed_key[28] = '\0'; snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", id, changed_key); expect_one(detector, input, NULL, NULL);
    snprintf(changed_key, sizeof(changed_key), "%sX", other); snprintf(input, sizeof(input), "bulksms %s\nbulksms %s", id, changed_key); expect_one(detector, input, NULL, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "bulksms%*s%s\n%s\nbulksms %s", gap, "", id, isolation, key); expect_one(detector, input, gap == 40 ? id : NULL, key);
        snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms%*s%s", id, isolation, gap, "", key); expect_one(detector, input, gap == 40 ? id : NULL, key);
    }
    memcpy(changed_id, id, sizeof(id)); changed_id[0] = '-';
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms %s", changed_id, isolation, key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "bulksms%s\n%s\nbulksms %s", changed_id, isolation, key); expect_one(detector, input, changed_id, key);
    memcpy(changed_id, id, sizeof(id)); changed_id[36] = '-';
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms %s", changed_id, isolation, key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "bulksms %sA\n%s\nbulksms %s", changed_id, isolation, key); expect_one(detector, input, changed_id, key);
    memcpy(changed_key, other, sizeof(other)); changed_key[0] = '!';
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms %s", id, isolation, changed_key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms%s", id, isolation, changed_key); expect_one(detector, input, id, changed_key);
    memcpy(changed_key, other, sizeof(other)); changed_key[28] = ')';
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms %s", id, isolation, changed_key); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms %sX", id, isolation, changed_key); expect_one(detector, input, id, changed_key);
    memset(changed_key, '!', 29); changed_key[29] = '\0'; snprintf(input, sizeof(input), "bulksms %s\n%s\nbulksms%sX", id, isolation, changed_key); expect_one(detector, input, id, changed_key); /* No entropy/symbol exclusion. */
}

typedef struct { const char *id, *key; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply replies[4]; size_t count, releases, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 4 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 833 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.bulksms.com/v1/messages"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && !strncmp(auth, "Basic ", 6) && strlen(auth) == 98 && !strcmp(auth + 96, "=="));
    unsigned char decoded[72]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 92) == 69);
    CHECK(!memcmp(decoded, step->id, 37) && decoded[37] == ':' && !memcmp(decoded + 38, step->key, 29));
    static const unsigned char body[] = "\xff\0not JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->releases); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    const char *ids[] = {step.id}, *keys[] = {step.key}; char input[128]; input_for(input, sizeof(input), ids, 1, keys, 1);
    script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], step.id, step.key); return results;
}

static void unique_product_and_overlap(const br_detector *detector)
{
    const char *ids[] = {id, other_id, id}, *keys[] = {key, key, other}; char input[512]; input_for(input, sizeof(input), ids, 3, keys, 3);
    script steps = {.count = 4, .releases = 4}; const char *unique_ids[] = {id, other_id}, *unique_keys[] = {key, other};
    for (size_t i = 0; i < 2; ++i) for (size_t k = 0; k < 2; ++k) steps.replies[i * 2 + k] = (reply){.id = unique_ids[i], .key = unique_keys[k], .status = 200};
    script none = {0}; br_results results = scan(detector, input, false, &none); CHECK(results.len == 4);
    for (size_t i = 0; i < 2; ++i) for (size_t k = 0; k < 2; ++k) { check_result(&results.items[i * 2 + k], unique_ids[i], unique_keys[k]); check_error(&results.items[i * 2 + k], false, NULL); }
    br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 4);
    for (size_t i = 0; i < 2; ++i) for (size_t k = 0; k < 2; ++k) { check_result(&results.items[i * 2 + k], unique_ids[i], unique_keys[k]); check_error(&results.items[i * 2 + k], true, NULL); }
    br_results_clear(&results);
    char fragment[30], overlapping_id[38]; memset(fragment, 'A', 29); fragment[29] = '\0';
    memcpy(overlapping_id, fragment, 29); overlapping_id[29] = '-'; memset(overlapping_id + 30, 'B', 7); overlapping_id[37] = '\0';
    snprintf(input, sizeof(input), "bulksms %s", overlapping_id); expect_one(detector, input, overlapping_id, fragment); /* No explicit key record. */
    steps = (script){.count = 1, .releases = 1}; steps.replies[0] = (reply){.id = overlapping_id, .key = fragment, .status = 200};
    results = scan(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], overlapping_id, fragment); check_error(&results.items[0], true, NULL); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const int codes[] = {200, 401, 201, 400, 403, 429, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.id = id, .key = key, .status = codes[i]});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]);
        check_error(&results.items[0], codes[i] == 200, codes[i] == 200 || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char plain[68], auth[100], cause[320]; snprintf(plain, sizeof(plain), "%s:%s", id, key); memcpy(auth, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)auth + 6, (const unsigned char *)plain, 67) == 92);
    snprintf(cause, sizeof(cause), "unredacted id=%s key=%s auth=%s", id, key, auth);
    br_results results = single(detector, (reply){.id = id, .key = key, .status = 200, .send_error = cause});
    check_error(&results.items[0], false, cause); CHECK(strstr(results.items[0].verification_error, id) && strstr(results.items[0].verification_error, key) && strstr(results.items[0].verification_error, auth)); br_results_clear(&results);
    results = single(detector, (reply){.id = id, .key = key, .send_rc = -1}); check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
}

static void context_and_resource_failure(const br_detector *detector)
{
    const char *ids[] = {id}, *keys[] = {key, other}; char input[256]; input_for(input, sizeof(input), ids, 1, keys, 1);
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1); check_result(&results.items[0], id, key); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    input_for(input, sizeof(input), ids, 1, keys, 2); script steps = {.count = 2, .releases = 2};
    steps.replies[0] = (reply){.id = id, .key = key, .status = 200}; steps.replies[1] = (reply){.id = id, .key = other, .status = 503};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true; int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot verify Bulksms candidate") && http.calls == 2 && http.releases == 2);
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], id, key); check_result(&results.items[1], id, other);
    check_error(&results.items[0], true, NULL); check_error(&results.items[1], false, status_503); br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 29, 1); test_secret(other, 29, 13); memcpy(key + 5, "!@#$%^&*()", 10); key[0] = 'a'; key[3] = 'Q'; other[0] = 'z';
    const br_detector *detector = init();
    extraction(detector); unique_product_and_overlap(detector); verification(detector); context_and_resource_failure(detector);
    return test_finish("Bulksms independent unique sets + ID-major product + unredacted Basic verification");
}
