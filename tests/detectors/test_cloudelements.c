/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

static char key[44], other_key[44], organization[33], other_organization[33];
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_part_after;

/* Existing narrow finding-allocation seam. Captures are fixed, non-NUL ASCII;
 * forwarding preserves all bytes. No auth builder seam or heap auth duplicate. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 43 || len == 32 || len == 5); /* 5 is the caller-owned sentinel. */
    if (fail_part_after && --fail_part_after == 0) return NULL;
    char copy[44]; memcpy(copy, value, (size_t)len); copy[len] = '\0'; return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other_key) == 43 && strlen(organization) == 32 && strlen(other_organization) == 32);
    CHECK(br_cloudelements_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CloudElements detector output")); free(error); error = NULL;
    CHECK(!br_cloudelements_init(&detector, &error) && detector && !error);
    CHECK(!br_cloudelements_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 650 && detector->version == 0 && !strcmp(detector->name, "CloudElements") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "CloudElements is an API integration platform that enables developers to connect their applications with various cloud services. CloudElements credentials can be used to access and manage these integrations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloudelements"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void text_part(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected) && !memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *expected_key, const char *expected_org, bool verified)
{
    CHECK(result->detector_type == 650 && !result->detector_name && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 43 && !memcmp(result->raw.data, expected_key, 43));
    CHECK(result->raw_v2.len == 75 && !memcmp(result->raw_v2.data, expected_key, 43) && !memcmp(result->raw_v2.data + 43, expected_org, 32));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2); text_part(result->secret_parts, "key", expected_key); text_part(result->secret_parts, "organization", expected_org);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static void input_for(char *out, size_t size, const char *const *keys, size_t nk, const char *const *orgs, size_t no)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < nk + no; ++i) {
        int n = snprintf(out + at, size - at, "cloudelements %s\n", i < nk ? keys[i] : orgs[i - nk]); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void expect_one(const br_detector *detector, const char *input, const char *expected_key, const char *expected_org)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected_key ? 1u : 0u));
    if (expected_key) check_result(&results.items[0], expected_key, expected_org, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed_key[45], changed_org[34]; const char *keys[] = {key}, *orgs[] = {organization};
    input_for(input, sizeof(input), keys, 1, orgs, 1); expect_one(detector, input, key, organization);
    snprintf(input, sizeof(input), "CLOUDELEMENTS %s\n%s\nClOuDeLeMeNtS %s", key, isolation, organization); expect_one(detector, input, key, organization);
    input_for(input, sizeof(input), keys, 1, NULL, 0); expect_one(detector, input, NULL, NULL);
    input_for(input, sizeof(input), NULL, 0, orgs, 1); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "%s\n%s\ncloudelements %s", key, isolation, organization); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cloudelements %s\n%s\n%s", key, isolation, organization); expect_one(detector, input, NULL, NULL);
    memcpy(changed_key, key, sizeof(key)); changed_key[42] = 0; snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", changed_key, isolation, organization); expect_one(detector, input, NULL, NULL);
    snprintf(changed_key, sizeof(changed_key), "%sZ", key); snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", changed_key, isolation, organization); expect_one(detector, input, NULL, NULL);
    memcpy(changed_key, key, sizeof(key)); changed_key[10] = '_'; snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", changed_key, isolation, organization); expect_one(detector, input, NULL, NULL);
    memcpy(changed_org, organization, sizeof(organization)); changed_org[0] = 'Z'; snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", key, isolation, changed_org); expect_one(detector, input, NULL, NULL);
    memcpy(changed_org, organization, sizeof(organization)); changed_org[31] = 0; snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", key, isolation, changed_org); expect_one(detector, input, NULL, NULL);
    snprintf(changed_org, sizeof(changed_org), "%sz", organization); snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", key, isolation, changed_org); expect_one(detector, input, NULL, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "cloudelements%*s%s\n%s\ncloudelements %s", gap, "", key, isolation, organization); expect_one(detector, input, gap == 40 ? key : NULL, organization);
        snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements%*s%s", key, isolation, gap, "", organization); expect_one(detector, input, gap == 40 ? key : NULL, organization);
    }
    snprintf(input, sizeof(input), "cloudelements _%s\n%s\ncloudelements %s", key, isolation, organization); expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s_", key, isolation, organization); expect_one(detector, input, NULL, NULL);
    memset(changed_org, 'z', 32); changed_org[32] = 0; snprintf(input, sizeof(input), "cloudelements %s\n%s\ncloudelements %s", key, isolation, changed_org); expect_one(detector, input, key, changed_org); /* Lower alnum, not hex; no entropy gate. */
}

typedef struct { const char *key, *organization, *send_error; int status, send_rc; } reply;
typedef struct { reply rows[9]; size_t count; const br_scan_ctx *expected_ctx; } script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 9 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 650 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://staging.cloud-elements.com/elements/api-v2/accounts"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && strlen(auth) == 95);
    CHECK(!memcmp(auth, "User ", 5) && !memcmp(auth + 5, step->key, 43));
    CHECK(!memcmp(auth + 48, ", Organization ", 15) && !memcmp(auth + 63, step->organization, 32) && auth[95] == '\0');
    static const unsigned char body[] = "\xff\0ignored body";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->count); return results;
}

static void occurrences_and_nil(const br_detector *detector)
{
    const char *keys[] = {key, other_key, key}, *orgs[] = {organization, other_organization, organization}; char input[512]; input_for(input, sizeof(input), keys, 3, orgs, 3);
    script steps = {.count = 9}; for (size_t k = 0; k < 3; ++k) for (size_t o = 0; o < 3; ++o) steps.rows[k * 3 + o] = (reply){.key = keys[k], .organization = orgs[o], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 9);
        for (size_t k = 0; k < 3; ++k) for (size_t o = 0; o < 3; ++o) check_result(&results.items[k * 3 + o], keys[k], orgs[o], verify);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const char *keys[] = {key}, *orgs[] = {organization}; char input[128]; input_for(input, sizeof(input), keys, 1, orgs, 1);
    const int codes[] = {199, 200, 201, 204, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .organization = organization, .status = codes[i]}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, organization, codes[i] >= 200 && codes[i] < 300); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "synthetic Do failure", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .organization = organization, .status = 200, .send_error = causes[i], .send_rc = 1}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, organization, false); br_results_clear(&results);
    }
}

static void resource_boundary(const br_detector *detector)
{
    const char *keys[] = {key}, *orgs[] = {organization, other_organization}; char input[192]; input_for(input, sizeof(input), keys, 1, orgs, 2);
    script steps = {.count = 2}; for (size_t o = 0; o < 2; ++o) steps.rows[o] = (reply){.key = key, .organization = orgs[o], .status = 200};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        fail_part_after = 4; /* Second tuple's organization allocation, after RawV2 allocation. */
        int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && !fail_part_after && error && !strcmp(error, "cannot create CloudElements result"));
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); text_part(results.items[0].secret_parts, "key", "prior"); free(error); br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2);
    for (size_t o = 0; o < 2; ++o) check_result(&results.items[o], key, orgs[o], true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 43, 1); key[0] = 'A'; key[9] = 'Z'; test_secret(other_key, 43, 13); other_key[0] = 'Q';
    test_secret(organization, 32, 3); organization[0] = 'z'; test_secret(other_organization, 32, 17); other_organization[0] = 'q';
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_nil(detector); verification(detector); resource_boundary(detector);
    return test_finish("CloudElements occurrence products + complete 95-byte staging auth + nil skip/resource rollback");
}
