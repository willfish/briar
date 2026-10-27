/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char key[] = "AbCd0123EfGh4567IjKl8901Mn", other_key[] = "ZyXw9876VuTs5432RqPo1098Op", third_key[] = "QrSt0246UvWx1357YzAb2468Cd";
static const char account[] = "Acme", other_account[] = "Beta-Shop";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static const char status_503[] = "unexpected status code: 503";
static bool track_basic, fail_status_copy;
static size_t basic_allocations, fail_basic_after, fail_docs_after;

void *malloc(size_t size)
{
    /* Basic(KEY26, KEY26): 7+4*ceil(53/3)=79 bytes, distinct from Do setup. */
    if (track_basic && size == 79) { ++basic_allocations; if (fail_basic_after && --fail_basic_after == 0) return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "Rebrading Docs") && fail_docs_after && --fail_docs_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 26 && strlen(other_key) == 26 && strlen(third_key) == 26);
    CHECK(br_clientary_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Clientary detector output")); free(error); error = NULL;
    CHECK(!br_clientary_init(&detector, &error) && detector && !error);
    CHECK(!br_clientary_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 307 && detector->version == 0 && !strcmp(detector->name, "Clientary") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Clientary is a one software app to manage Clients, Invoices, Projects, Proposals, Estimates, Hours, Payments, Contractors and Staff. Clientary keys can be used to access and manage invoices and other resources."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "ronin") && !strcmp(detector->keywords[1], "clientary"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void part(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected) && !memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *expected_key, const char *id, bool verified, const char *error)
{
    size_t klen = strlen(expected_key), ilen = strlen(id);
    CHECK(result->detector_type == 307 && !result->detector_name && result->verified == verified);
    CHECK(result->raw.len == klen && !memcmp(result->raw.data, expected_key, klen));
    CHECK(result->raw_v2.len == klen + 1 + ilen && !memcmp(result->raw_v2.data, expected_key, klen));
    CHECK(result->raw_v2.data[klen] == ':' && !memcmp(result->raw_v2.data + klen + 1, id, ilen));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2); part(result->secret_parts, "key", expected_key); part(result->secret_parts, "id", id);
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object) && json_object_object_length(result->extra_data) == (verified ? 1 : 0));
    if (verified) part(result->extra_data, "Rebrading Docs", "https://www.clientary.com/articles/a-new-brand/");
    br_json *wrong = NULL; CHECK(!json_object_object_get_ex(result->extra_data, "Rebranding Docs", &wrong));
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static char *input_for(const char *const *ids, size_t ni, const char *const *keys, size_t nk)
{
    size_t size = 1; for (size_t i = 0; i < ni + nk; ++i) size += strlen(i < ni ? ids[i] : keys[i - ni]) + 76;
    char *out = malloc(size); CHECK(out); size_t at = 0;
    for (size_t i = 0; i < ni + nk; ++i) {
        const char *value = i < ni ? ids[i] : keys[i - ni]; size_t len = strlen(value);
        memcpy(out + at, "clientary ", 10); at += 10; memcpy(out + at, value, len); at += len; out[at++] = '\n';
        /* Isolate records so failed ID matches on 26-byte keys cannot instead
         * capture a later prefix word within the source's 40-byte gap. */
        memcpy(out + at, isolation, 64); at += 64; out[at++] = '\n';
    }
    CHECK(at + 1 == size); out[at] = '\0'; return out;
}

static void expect_one(const br_detector *detector, const char *input, const char *id)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (id ? 1u : 0u));
    if (id) check_result(&results.items[0], key, id, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "RONIN %s\n%s\nClIeNtArY %s\n%s", account, isolation, key, isolation); expect_one(detector, input, account);
    snprintf(input, sizeof(input), "ronin clientary\n%s\nronin %s\n%s", isolation, key, isolation); expect_one(detector, input, "clientary"); /* Context/keyword IDs remain eligible. */
    const struct { const char *raw, *id; } cases[] = {{"Abc", NULL}, {"ABcd", "ABcd"}, {"ABCDEFGHIJKLMNOPQRSTUVWXY", "ABCDEFGHIJKLMNOPQRSTUVWXY"}, {"ABCDEFGHIJKLMNOPQRSTUVWXYZ", NULL}, {"_-Abc", "-Abc"}, {"Abc-_", "Abc-"}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), "clientary %s\n%s\nclientary %s\n%s", cases[i].raw, isolation, key, isolation); expect_one(detector, input, cases[i].id);
    }
    snprintf(input, sizeof(input), "clientary %s\n%s", key, isolation); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "clientary %s\n%s", account, isolation); expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "clientary%*s%s\n%s\nclientary %s\n%s", gap, "", account, isolation, key, isolation); expect_one(detector, input, gap == 40 ? account : NULL);
        snprintf(input, sizeof(input), "clientary %s\n%s\nclientary%*s%s\n%s", account, isolation, gap, "", key, isolation); expect_one(detector, input, gap == 40 ? account : NULL);
    }
}

typedef struct { const char *key, *id, *send_error; int status, send_rc; bool echo; } reply;
typedef struct {
    reply rows[6]; size_t count; bool track, mutate_error, mutated; char echo[320], expected_echo[320]; char *returned_error;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 6 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 307 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    char url[96]; snprintf(url, sizeof(url), "https://%s.clientary.com/api/v2/invoices", step->id); CHECK(!strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 3);
    CHECK(header(request, "Accept") && !strcmp(header(request, "Accept"), "application/json"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog")); CHECK(!header(request, "Content-Type") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); size_t klen = strlen(step->key), encoded = 4 * ((klen * 2 + 3) / 3);
    CHECK(auth && strlen(auth) == 6 + encoded && !memcmp(auth, "Basic ", 6));
    unsigned char decoded[56]; int n = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, (int)encoded); CHECK(n >= 0);
    size_t padding = (auth[5 + encoded] == '=') + (auth[4 + encoded] == '='); CHECK((size_t)n == klen * 2 + 1 + padding);
    CHECK(!memcmp(decoded, step->key, klen) && decoded[klen] == ':' && !memcmp(decoded + klen + 1, step->key, klen));
    static const unsigned char body[] = "\xff\0account not found";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
    if (step->echo) {
        CHECK(snprintf(steps->echo, sizeof(steps->echo), "key=%s id=%s auth=%s", step->key, step->id, auth) > 0);
        CHECK(snprintf(steps->expected_echo, sizeof(steps->expected_echo), "key=[REDACTED] id=%s auth=%s", step->id, auth) > 0);
        http->send_error = steps->echo; http->send_rc = -1;
    }
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

static void products_equality_nil(const br_detector *detector)
{
    const char *ids[] = {account, other_account, account}, *keys[] = {key, other_key, key}; char *input = input_for(ids, 3, keys, 3);
    script steps = {.count = 4, .track = true}; for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < 2; ++i) steps.rows[k * 2 + i] = (reply){.key = keys[k], .id = ids[i], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {.track = true}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 4);
        for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < 2; ++i) check_result(&results.items[k * 2 + i], keys[k], ids[i], verify, NULL);
        br_results_clear(&results);
    }
    basic_allocations = 0; track_basic = true; br_results results = test_scan(detector, NULL, true, input, strlen(input)); track_basic = false; CHECK(results.len == 4 && !basic_allocations);
    for (size_t k = 0; k < 2; ++k) for (size_t i = 0; i < 2; ++i) check_result(&results.items[k * 2 + i], keys[k], ids[i], false, NULL);
    br_results_clear(&results); free(input);
    const char *overlap_keys[] = {"AbCd0123EfGh4567IjKl8901", "AbCd0123EfGh4567IjKl8901X"}; input = input_for(ids, 1, overlap_keys, 2);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 4);
    check_result(&results.items[0], overlap_keys[0], account, false, NULL); check_result(&results.items[1], overlap_keys[0], overlap_keys[1], false, NULL);
    check_result(&results.items[2], overlap_keys[1], account, false, NULL); check_result(&results.items[3], overlap_keys[1], overlap_keys[0], false, NULL); br_results_clear(&results); free(input);
    const char *case_keys[] = {"AbCd0123EfGh4567IjKl8901", "abCd0123EfGh4567IjKl8901"}; input = input_for(NULL, 0, case_keys, 2);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2); check_result(&results.items[0], case_keys[0], case_keys[1], false, NULL); check_result(&results.items[1], case_keys[1], case_keys[0], false, NULL); br_results_clear(&results); free(input);
}

static void statuses_and_errors(const br_detector *detector)
{
    const char *ids[] = {account}, *keys[] = {key}; char *input = input_for(ids, 1, keys, 1); const int codes[] = {200, 401, 403, 201, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .id = account, .status = codes[i]}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", codes[i]); check_result(&results.items[0], key, account, codes[i] == 200, codes[i] == 200 || codes[i] == 401 || codes[i] == 403 ? NULL : expected); br_results_clear(&results);
    }
    script steps = {.count = 1, .mutate_error = true}; steps.rows[0] = (reply){.key = key, .id = account, .status = 200, .echo = true};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 1 && steps.mutated); check_result(&results.items[0], key, account, false, steps.expected_echo); br_results_clear(&results);
    steps = (script){.count = 1}; steps.rows[0] = (reply){.key = key, .id = account, .send_rc = 1}; results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, account, false, "HTTP transport failed"); br_results_clear(&results); free(input);
}

static void deletion_scope(const br_detector *detector)
{
    const char *ids[] = {"Gone", "Live"}, *keys[] = {key, other_key, third_key}; char *input = input_for(ids, 2, keys, 3);
    script steps = {.count = 5};
    steps.rows[0] = (reply){.key = key, .id = ids[0], .status = 200}; steps.rows[1] = (reply){.key = key, .id = ids[1], .status = 200};
    steps.rows[2] = (reply){.key = other_key, .id = ids[0], .status = 404}; steps.rows[3] = (reply){.key = other_key, .id = ids[1], .status = 401}; steps.rows[4] = (reply){.key = third_key, .id = ids[1], .status = 200};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 4); /* 404 read error is ignored; prior Gone finding stays, later Gone pair disappears. */
    check_result(&results.items[0], key, ids[0], true, NULL); check_result(&results.items[1], key, ids[1], true, NULL); check_result(&results.items[2], other_key, ids[1], false, NULL); check_result(&results.items[3], third_key, ids[1], true, NULL); br_results_clear(&results);
    steps = (script){.count = 6}; for (size_t k = 0; k < 3; ++k) for (size_t i = 0; i < 2; ++i) steps.rows[k * 2 + i] = (reply){.key = keys[k], .id = ids[i], .status = 200};
    results = run(detector, input, true, &steps); CHECK(results.len == 6); br_results_clear(&results); /* IDs return in a fresh invocation: no cache. */
    steps.rows[0].status = 404; steps.rows[0].send_error = "account not found";
    results = run(detector, input, true, &steps); CHECK(results.len == 6); check_result(&results.items[0], key, ids[0], false, "account not found"); check_result(&results.items[4], third_key, ids[0], true, NULL); br_results_clear(&results); free(input); /* Equal TEXT is not sentinel identity. */
}

static void resource_boundaries(const br_detector *detector)
{
    char *auth = NULL, *error = NULL; basic_allocations = 0; fail_basic_after = 1; track_basic = true;
    int code = br_http_basic_auth(TEXT(key), TEXT(key), &auth, &error); track_basic = false; CHECK(code == 1 && !auth && error && !fail_basic_after && basic_allocations == 1); free(error); error = NULL;
    br_result probe = {0}; fail_status_copy = true; CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy); br_result_clear(&probe);
    br_json *object = json_object_new_object(), *value = json_object_new_string("probe"); CHECK(object && value); fail_docs_after = 1; CHECK(json_object_object_add(object, "Rebrading Docs", value) == 1 && !fail_docs_after); json_object_put(value); json_object_put(object);
    const char *ids[] = {account, "Live"}, *keys[] = {key}; char *input = input_for(ids, 2, keys, 1);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2}; for (size_t i = 0; i < 2; ++i) steps.rows[i] = (reply){.key = key, .id = ids[i], .status = mode == 1 && i == 1 ? 503 : 200};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        basic_allocations = 0; track_basic = true;
        if (mode == 0) fail_basic_after = 2;
        if (mode == 1) fail_status_copy = true;
        if (mode == 2) fail_docs_after = 2;
        code = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_basic = false;
        CHECK(code == -1 && error && !strcmp(error, mode == 2 ? "cannot attach Clientary rebranding metadata" : "cannot verify Clientary candidate"));
        CHECK(!fail_basic_after && !fail_status_copy && !fail_docs_after && basic_allocations == 2 && http.calls == (mode == 0 ? 1u : 2u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); part(results.items[0].secret_parts, "key", "prior"); free(error); error = NULL; br_results_clear(&results);
        results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], key, ids[0], true, NULL); check_result(&results.items[1], key, ids[1], mode != 1, mode == 1 ? status_503 : NULL); br_results_clear(&results);
    }
    free(input);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products_equality_nil(detector); statuses_and_errors(detector); deletion_scope(detector); resource_boundaries(detector);
    return test_finish("Clientary unique products + exact equality + identity-only local deletion + Rebrading Docs + resource rollback");
}
