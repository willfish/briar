/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char cloud[] = "MiXeD-Cloud", other_cloud[] = "Second-Cloud";
static const char key[] = "000123456789012", other_key[] = "009876543210987";
static char secret[28], other_secret[28];
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static const char status_503[] = "unexpected HTTP response status 503";
static bool track_basic, fail_status_copy;
static size_t basic_allocations, fail_basic_after, fail_secret_after;

void *malloc(size_t size)
{
    /* Existing narrow resource check: Basic(KEY15, SECRET27) owns 67 bytes. */
    if (track_basic && size == 67) { ++basic_allocations; if (fail_basic_after && --fail_basic_after == 0) return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "api_secret") && fail_secret_after && --fail_secret_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 15 && strlen(other_key) == 15 && strlen(secret) == 27 && strlen(other_secret) == 27);
    CHECK(br_cloudinary_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Cloudinary detector output")); free(error); error = NULL;
    CHECK(!br_cloudinary_init(&detector, &error) && detector && !error);
    CHECK(!br_cloudinary_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1048 && detector->version == 0 && !strcmp(detector->name, "Cloudinary") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Cloudinary is a cloud-based media management platform. Cloudinary API keys can be used to upload, manage, and deliver media assets."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloudinary"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void part(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected) && !memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *expected_cloud, const char *expected_key, const char *expected_secret, bool verified, const char *error)
{
    size_t clen = strlen(expected_cloud);
    CHECK(result->detector_type == 1048 && !result->detector_name && result->verified == verified);
    CHECK(result->raw.len == 15 && !memcmp(result->raw.data, expected_key, 15));
    CHECK(result->raw_v2.len == clen + 44 && !memcmp(result->raw_v2.data, expected_cloud, clen));
    CHECK(result->raw_v2.data[clen] == ':' && !memcmp(result->raw_v2.data + clen + 1, expected_key, 15));
    CHECK(result->raw_v2.data[clen + 16] == ':' && !memcmp(result->raw_v2.data + clen + 17, expected_secret, 27));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    part(result->secret_parts, "cloud_name", expected_cloud); part(result->secret_parts, "api_key", expected_key); part(result->secret_parts, "api_secret", expected_secret);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void input_for(char *out, size_t size, const char *const *clouds, size_t nc, const char *const *keys, size_t nk, const char *const *secrets, size_t ns)
{
    size_t at = 0; *out = '\0';
    for (size_t i = 0; i < nc + nk + ns; ++i) {
        const char *value = i < nc ? clouds[i] : i < nc + nk ? keys[i - nc] : secrets[i - nc - nk];
        int n = snprintf(out + at, size - at, "cloudinary %s%s\n%s\n", i < nc ? "name " : "", value, isolation); CHECK(n > 0 && (size_t)n < size - at); at += (size_t)n;
    }
}

static void expect_one(const br_detector *detector, const char *input, const char *expected_cloud)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected_cloud ? 1u : 0u));
    if (expected_cloud) check_result(&results.items[0], expected_cloud, key, secret, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[1024], changed[53]; const char *clouds[] = {cloud}, *keys[] = {key}, *secrets[] = {secret};
    input_for(input, sizeof(input), clouds, 1, keys, 1, secrets, 1); expect_one(detector, input, cloud);
    snprintf(input, sizeof(input), "CLOUDINARY NAME %s\n%s\ncloudinary %s\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, cloud);
    snprintf(input, sizeof(input), "cloudinary://credentials@%s\n%s\ncloudinary %s\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, cloud);
    input_for(input, sizeof(input), NULL, 0, keys, 1, secrets, 1); expect_one(detector, input, NULL);
    input_for(input, sizeof(input), clouds, 1, NULL, 0, secrets, 1); expect_one(detector, input, NULL);
    input_for(input, sizeof(input), clouds, 1, keys, 1, NULL, 0); expect_one(detector, input, NULL);
    const struct { const char *raw, *expected; } names[] = {{"Ab", NULL}, {"123Cloud", NULL}, {"Abc", "Abc"}, {"Ab-_", "Ab-"}, {"Abcd-", "Abcd"}};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        const char *value[] = {names[i].raw}; input_for(input, sizeof(input), value, 1, keys, 1, secrets, 1); expect_one(detector, input, names[i].expected);
    }
    memset(changed, 'A', 50); changed[50] = 0; const char *value[] = {changed}; input_for(input, sizeof(input), value, 1, keys, 1, secrets, 1); expect_one(detector, input, changed);
    changed[50] = 'A'; changed[51] = 0; input_for(input, sizeof(input), value, 1, keys, 1, secrets, 1); expect_one(detector, input, NULL);
    for (int gap = 47; gap <= 48; ++gap) {
        snprintf(input, sizeof(input), "cloudinary%*sname %s\n%s\ncloudinary %s\n%s\ncloudinary %s", gap, "", cloud, isolation, key, isolation, secret); expect_one(detector, input, gap == 47 ? cloud : NULL);
    }
    for (int gap = 10; gap <= 11; ++gap) {
        memset(changed, ':', (size_t)gap); changed[gap] = 0; snprintf(input, sizeof(input), "cloudinary name%s%s\n%s\ncloudinary %s\n%s\ncloudinary %s", changed, cloud, isolation, key, isolation, secret); expect_one(detector, input, gap == 10 ? cloud : NULL);
    }
    snprintf(input, sizeof(input), "cloudinary\nname %s\n%s\ncloudinary %s\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, cloud);
    snprintf(input, sizeof(input), "cloudinary name\n%s\n%s\ncloudinary %s\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, NULL); /* Second dot gap excludes LF. */
    snprintf(input, sizeof(input), "cloudinary name %s\n%s\ncloudinary %.14s\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "cloudinary name %s\n%s\ncloudinary %s1\n%s\ncloudinary %s", cloud, isolation, key, isolation, secret); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "cloudinary name %s\n%s\ncloudinary %s\n%s\ncloudinary %.26s", cloud, isolation, key, isolation, secret); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "cloudinary name %s\n%s\ncloudinary %s\n%s\ncloudinary %sZ", cloud, isolation, key, isolation, secret); expect_one(detector, input, NULL);
}

typedef struct { const char *cloud, *key, *secret, *send_error; int status, send_rc; } reply;
typedef struct { reply rows[8]; size_t count; bool track, mutate_error, mutated; char *returned_error; const br_scan_ctx *expected_ctx; } script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 8 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 1048 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    char url[96]; snprintf(url, sizeof(url), "https://api.cloudinary.com/v1_1/%s/usage", step->cloud); CHECK(!strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog")); CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && strlen(auth) == 66 && !memcmp(auth, "Basic ", 6) && auth[64] == '=' && auth[65] == '=');
    unsigned char decoded[48]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 60) == 45);
    CHECK(!memcmp(decoded, step->key, 15) && decoded[15] == ':' && !memcmp(decoded + 16, step->secret, 27));
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; script *steps = http->user; int rc = test_http_send(user, ctx, request, response, error); steps->returned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->mutate_error && steps->returned_error) { memset(steps->returned_error, '!', strlen(steps->returned_error)); steps->mutated = true; }
    steps->returned_error = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    basic_allocations = 0; track_basic = steps->track; br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); track_basic = false;
    CHECK(http.calls == steps->count && http.releases == steps->count);
    if (steps->track) CHECK(basic_allocations == (verify ? steps->count : 0));
    return results;
}

static br_results single(const br_detector *detector, reply step)
{
    if (!step.cloud) step.cloud = cloud;
    if (!step.key) step.key = key;
    if (!step.secret) step.secret = secret;
    const char *clouds[] = {step.cloud}, *keys[] = {step.key}, *secrets[] = {step.secret}; char input[512]; input_for(input, sizeof(input), clouds, 1, keys, 1, secrets, 1);
    script steps = {.count = 1}; steps.rows[0] = step; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); return results;
}

static void products_and_nil(const br_detector *detector)
{
    const char *clouds[] = {cloud, other_cloud, cloud}, *keys[] = {key, other_key, key}, *secrets[] = {secret, other_secret, secret}; char input[1536]; input_for(input, sizeof(input), clouds, 3, keys, 3, secrets, 3);
    script steps = {.count = 8, .track = true}; for (size_t c = 0; c < 2; ++c) for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) steps.rows[c * 4 + k * 2 + s] = (reply){.cloud = clouds[c], .key = keys[k], .secret = secrets[s], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {.track = true}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 8);
        for (size_t c = 0; c < 2; ++c) for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) check_result(&results.items[c * 4 + k * 2 + s], clouds[c], keys[k], secrets[s], verify, NULL);
        br_results_clear(&results);
    }
    basic_allocations = 0; track_basic = true; br_results results = test_scan(detector, NULL, true, input, strlen(input)); track_basic = false; CHECK(results.len == 8 && !basic_allocations);
    for (size_t c = 0; c < 2; ++c) for (size_t k = 0; k < 2; ++k) for (size_t s = 0; s < 2; ++s) check_result(&results.items[c * 4 + k * 2 + s], clouds[c], keys[k], secrets[s], false, "net/http: nil Context");
    br_results_clear(&results);
    /* A 27-byte cloud value can itself supply the secret capture. No equality
     * filter and no separate secret record are allowed to erase that product. */
    const char *same[] = {"Cloud000123456789012AbCdEfG"}; CHECK(strlen(same[0]) == 27); input_for(input, sizeof(input), same, 1, keys, 1, NULL, 0);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1); check_result(&results.items[0], same[0], key, same[0], false, NULL); br_results_clear(&results);
}

static void statuses_and_redaction(const br_detector *detector)
{
    const int codes[] = {200, 401, 201, 204, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.status = codes[i]}); char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", codes[i]);
        check_result(&results.items[0], cloud, key, secret, codes[i] == 200, codes[i] == 200 || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[256]; snprintf(cause, sizeof(cause), "cloud=%s key=%s secret=%s", cloud, key, secret);
    br_results results = single(detector, (reply){.status = 200, .send_error = cause}); check_result(&results.items[0], cloud, key, secret, false, "cloud=[REDACTED] key=[REDACTED] secret=[REDACTED]"); br_results_clear(&results);
    results = single(detector, (reply){.status = 200, .send_rc = 1}); check_result(&results.items[0], cloud, key, secret, false, "HTTP transport failed"); br_results_clear(&results);
    const char *overlap = "Cloud000123456789012AbCdEfG"; const char *clouds[] = {"Cloud"}, *keys[] = {key}, *secrets[] = {overlap}; char input[512]; input_for(input, sizeof(input), clouds, 1, keys, 1, secrets, 1);
    snprintf(cause, sizeof(cause), "cloud=Cloud key=%s secret=%s", key, overlap);
    script steps = {.count = 1, .mutate_error = true}; steps.rows[0] = (reply){.cloud = "Cloud", .key = key, .secret = overlap, .status = 200, .send_error = cause};
    results = run(detector, input, true, &steps); CHECK(results.len == 1 && steps.mutated);
    check_result(&results.items[0], "Cloud", key, overlap, false, "cloud=[REDACTED] key=[REDACTED] secret=[REDACTED][REDACTED]AbCdEfG"); br_results_clear(&results); /* Source ORDER, not longest-secret-first. */
    const char *edge_clouds[] = {"Ab-_"}, *edge_secrets[] = {secret}; input_for(input, sizeof(input), edge_clouds, 1, keys, 1, edge_secrets, 1);
    steps = (script){.count = 1}; steps.rows[0] = (reply){.cloud = "Ab-", .key = key, .secret = secret, .status = 200};
    results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], "Ab-", key, secret, true, NULL); br_results_clear(&results);
    char maximum[51]; memset(maximum, 'A', 50); maximum[50] = 0;
    results = single(detector, (reply){.cloud = maximum, .status = 200}); check_result(&results.items[0], maximum, key, secret, true, NULL); br_results_clear(&results);
}

static void resource_boundaries(const br_detector *detector)
{
    char *auth = NULL, *error = NULL; basic_allocations = 0; fail_basic_after = 1; track_basic = true;
    int rc = br_http_basic_auth(TEXT(key), (br_slice){(const unsigned char *)secret, 27}, &auth, &error); track_basic = false;
    CHECK(rc == 1 && !auth && error && !fail_basic_after && basic_allocations == 1); free(error); error = NULL;
    br_result probe = {0}; fail_status_copy = true; CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy); br_result_clear(&probe);
    br_json *object = json_object_new_object(), *value = json_object_new_string("probe"); CHECK(object && value); fail_secret_after = 1; CHECK(json_object_object_add(object, "api_secret", value) == 1 && !fail_secret_after); json_object_put(value); json_object_put(object);
    const char *clouds[] = {cloud}, *keys[] = {key}, *secrets[] = {secret, other_secret}; char input[512]; input_for(input, sizeof(input), clouds, 1, keys, 1, secrets, 2);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2}; for (size_t s = 0; s < 2; ++s) steps.rows[s] = (reply){.cloud = cloud, .key = key, .secret = secrets[s], .status = mode == 1 && s == 1 ? 503 : 200};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        basic_allocations = 0; track_basic = true;
        if (mode == 0) fail_basic_after = 2;
        if (mode == 1) fail_status_copy = true;
        if (mode == 2) fail_secret_after = 2;
        rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_basic = false;
        CHECK(rc == -1 && error && !strcmp(error, mode == 2 ? "cannot create Cloudinary result" : "cannot verify Cloudinary candidate"));
        CHECK(!fail_basic_after && !fail_status_copy && !fail_secret_after && basic_allocations == (mode == 2 ? 1u : 2u));
        CHECK(http.calls == (mode == 0 || mode == 2 ? 1u : 2u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); part(results.items[0].secret_parts, "key", "prior"); free(error); error = NULL; br_results_clear(&results);
        results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], cloud, key, secret, true, NULL); check_result(&results.items[1], cloud, key, other_secret, mode != 1, mode == 1 ? status_503 : NULL); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(secret, 27, 3); secret[0] = 'A'; secret[9] = '_'; secret[18] = '-'; test_secret(other_secret, 27, 17); other_secret[0] = 'Q'; other_secret[10] = '-'; other_secret[20] = '_';
    const br_detector *detector = descriptor(); extraction(detector); products_and_nil(detector); statuses_and_redaction(detector); resource_boundaries(detector);
    return test_finish("Cloudinary independent unique triples + exact layout/path/Basic + ordered redaction + resource rollback");
}
