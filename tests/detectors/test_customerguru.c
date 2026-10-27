/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

int br_customerguru_init(const br_detector **out, char **error);

static const char key[] = "A7b9C2d5E6f8G3h4J1k0M2n4P6q8R1";
static const char other_key[] = "Z9y8X7w6V5u4T3s2R1q0P9n8M7k6J5";
static const char id[] = "S3t5U7v9W2x4Y6z8A1b3" "C5d7E9f2G4h6J8k0M3n5" "P7q9R2s4T6";
static const char other_id[] = "U8v6W4x2Y0z9A7b5C3d1" "E8f6G4h2J0k9M7n5P3q1" "R8s6T4u2V0";
static const char url_format[] = "https://customer.guru/export/customers?api_secret=%.*s&api_token=%.*s";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;
static size_t fail_format_after, format_failures, formatted_urls;
static bool truncate_format;

/* Actual capture/finding/format boundaries, never an invented heap URL seam. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static bool fail_url_format(const char *format)
{
    if (strcmp(format, url_format)) return false;
    ++formatted_urls;
    if (!fail_format_after || --fail_format_after != 0) return false;
    ++format_failures;
    return true;
}

int snprintf(char *buffer, size_t size, const char *format, ...)
{
    if (fail_url_format(format)) return truncate_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buffer, size, format, args);
    va_end(args);
    return n;
}

#if defined(__GLIBC__) && defined(__USE_FORTIFY_LEVEL) && __USE_FORTIFY_LEVEL > 0
/* Nix hardening routes the same actual boundary through this fortified symbol. */
int __snprintf_chk(char *buffer, size_t size, int flag, size_t capacity, const char *format, ...)
{
    if (fail_url_format(format)) return truncate_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int n = __vsnprintf_chk(buffer, size, flag, capacity, format, args);
    va_end(args);
    return n;
}
#endif

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 30 && strlen(other_key) == 30);
    CHECK(strlen(id) == 50 && strlen(other_id) == 50);
    CHECK(br_customerguru_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    /* Fail each pattern's actual prefix allocation, including partial-init retry. */
    for (size_t after = 1; after <= 2; ++after) {
        fail_alloc_size = sizeof("(?i:guru)(?s:.){0,40}?"); fail_alloc_after = after;
        CHECK(br_customerguru_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
        CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
        free(error); error = NULL;
    }
    CHECK(br_customerguru_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_customerguru_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 226 && detector->version == 0 && !strcmp(detector->name, "CustomerGuru"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "CustomerGuru is a feedback platform used to collect and analyze customer feedback. API keys and secrets can be used to access and manage this feedback data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "customerguru"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected_key, const char *expected_id, bool verified)
{
    CHECK(result->detector_type == 226 && !result->detector_name);
    CHECK(result->raw.len == 30 && !memcmp(result->raw.data, expected_key, 30));
    CHECK(result->raw_v2.len == 80 && !memcmp(result->raw_v2.data, expected_key, 30));
    CHECK(!memcmp(result->raw_v2.data + 30, expected_id, 50));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 30 && !memcmp(json_object_get_string(part), expected_key, 30));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 50 && !memcmp(json_object_get_string(part), expected_id, 50));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len,
                            const char *expected_key, const char *expected_id)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = formatted_urls;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected_key ? 1u : 0u) && !http.calls && !http.releases && formatted_urls == before);
    if (expected_key) check_result(&results.items[0], expected_key, expected_id, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[52];
    const char *accepted[] = {"guru '%s'\nguru '%s'", "CuStOmErGuRu %s\r\nGURU %s", "pregurusuffix:%s\rGURU:%s", "guru-%s-\nguru-%s-", "guru %s %s"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key, id);
        extraction_case(detector, input, strlen(input), key, id);
    }
    snprintf(input, sizeof(input), "guru %s\nguru %s", id, key);
    extraction_case(detector, input, strlen(input), key, id); /* ID can precede key. */
    const char *prefixes[] = {"guru", "customerguru"};
    for (size_t p = 0; p < 2; ++p) {
        for (size_t gap = 40; gap <= 41; ++gap) {
            snprintf(input, sizeof(input), "%s%*s%s\nguru %s", prefixes[p], (int)gap, "", key, id);
            extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL, id);
            snprintf(input, sizeof(input), "guru %s\n%s%*s%s", key, prefixes[p], (int)gap, "", id);
            extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL, id);
        }
    } /* The trailing guru in customerguru gets the full 40-character gap. */
    const char *tokens[] = {key, id};
    const size_t lengths[] = {30, 50};
    for (size_t part = 0; part < 2; ++part) {
        const char *bad_frames[] = {"_%s", "%s_", "x%s", "%s9"};
        for (size_t f = 0; f < 4; ++f) {
            snprintf(changed, sizeof(changed), bad_frames[f], tokens[part]);
            snprintf(input, sizeof(input), "guru %s\nguru %s", part == 0 ? changed : key, part == 1 ? changed : id);
            extraction_case(detector, input, strlen(input), NULL, NULL);
        }
        for (int delta = -1; delta <= 1; delta += 2) {
            memcpy(changed, tokens[part], lengths[part]);
            changed[lengths[part]] = 'A'; changed[lengths[part] + delta] = '\0';
            snprintf(input, sizeof(input), "guru %s\nguru %s", part == 0 ? changed : key, part == 1 ? changed : id);
            extraction_case(detector, input, strlen(input), NULL, NULL);
        }
        const char invalid[] = "_-+/";
        for (size_t c = 0; c < sizeof(invalid) - 1; ++c) {
            memcpy(changed, tokens[part], lengths[part] + 1); changed[lengths[part] / 2] = invalid[c];
            snprintf(input, sizeof(input), "guru %s\nguru %s", part == 0 ? changed : key, part == 1 ? changed : id);
            extraction_case(detector, input, strlen(input), NULL, NULL);
        }
    }
    snprintf(input, sizeof(input), "%s %s", key, id); extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "guru %s", key); extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "guru %s", id); extraction_case(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "guru %s %s\nguru %s", key, other_key, id);
    extraction_case(detector, input, strlen(input), key, id); /* Non-overlapping matches within each list. */
    char low_key[31], low_id[51]; memset(low_key, 'A', 30); low_key[30] = '\0'; memset(low_id, 'A', 50); low_id[50] = '\0';
    snprintf(input, sizeof(input), "guru %s\nguru %s", low_key, low_id);
    extraction_case(detector, input, strlen(input), low_key, low_id); /* No entropy or equal-content rejection. */
    char distant[1400]; size_t len = (size_t)snprintf(distant, sizeof(distant), "guru %s", key);
    memset(distant + len, ' ', 1100); len += 1100;
    len += (size_t)snprintf(distant + len, sizeof(distant) - len, "guru %s", id);
    extraction_case(detector, distant, len, key, id); /* 1024 is an engine hint, not a FromData pairing filter. */
    extraction_case(detector, NULL, 0, NULL, NULL);
}

typedef struct { const char *key, *id, *send_error; int status, send_rc, body_kind; } reply;
typedef struct {
    reply rows[9];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[sizeof("https://customer.guru/export/customers?api_secret=&api_token=") + 80];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 9 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 226 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    int length = snprintf(steps->expected_url, sizeof(steps->expected_url), "https://customer.guru/export/customers?api_secret=%s&api_token=%s", step->id, step->key);
    CHECK(length == (int)sizeof(steps->expected_url) - 1);
    CHECK(strlen(request->url) == (size_t)length && !memcmp(request->url, steps->expected_url, (size_t)length + 1));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog customerguru-offline" : "TruffleHog"));
    /* Complete effective header set: no invented Auth, Type, Accept or CL. */
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status,
        .body = step->body_kind == 0 ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->body_kind == 0 ? NULL : step->body_kind == 1 ? "" : "synthetic ignored body read error",
    };
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == sizeof(steps->expected_url) - 1);
    CHECK(!strcmp(steps->borrowed_url, steps->expected_url));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void products_and_nil_context(const br_detector *detector)
{
    const char *keys[] = {key, other_key, key}, *ids[] = {id, other_id, id};
    unsigned char input[3 * 94 + 1]; size_t len = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, "guru ", 5); len += 5; memcpy(input + len, ids[i], 50); len += 50;
        input[len++] = '\0'; input[len++] = '\r';
        memcpy(input + len, "GuRu ", 5); len += 5; memcpy(input + len, keys[i], 30); len += 30;
        input[len++] = '\0'; input[len++] = '\n';
    }
    input[len++] = 0xff; /* No subject-wide UTF-8 guard. */
    br_slice data = {input, len};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 9u : 0u, .agent_suffix = "customerguru-offline"};
        for (size_t k = 0; k < 3; ++k)
            for (size_t i = 0; i < 3; ++i)
                steps.rows[k * 3 + i] = (reply){.key = keys[k], .id = ids[i], .status = 200 + (int)(k * 3 + i), .body_kind = 2};
        steps.rows[0].send_rc = 1; steps.rows[0].send_error = "net/http: nil Context";
        steps.rows[2].send_rc = -1; steps.rows[2].send_error = "synthetic timeout";
        br_results results = run(detector, data, verify, &steps);
        CHECK(results.len == 9);
        for (size_t k = 0; k < 3; ++k)
            for (size_t i = 0; i < 3; ++i)
                check_result(&results.items[k * 3 + i], keys[k], ids[i], verify && k * 3 + i != 0 && k * 3 + i != 2);
        br_results_clear(&results);
        size_t before = formatted_urls;
        results = test_scan(detector, NULL, verify, data.data, data.len);
        CHECK(results.len == (verify ? 0u : 9u) && formatted_urls == before + (verify ? 9u : 0u));
        for (size_t k = 0; !verify && k < 3; ++k)
            for (size_t i = 0; i < 3; ++i) check_result(&results.items[k * 3 + i], keys[k], ids[i], false);
        br_results_clear(&results);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "guru %s\nguru %s", key, id);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .id = id, .status = status, .body_kind = status % 3};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, id, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .id = id, .status = rejected[i], .body_kind = 2};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, id, false); br_results_clear(&results);
    }
    char sensitive[160]; snprintf(sensitive, sizeof(sensitive), "synthetic api_secret=%s api_token=%s", id, key);
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create CustomerGuru result", sensitive, "unsupported native client configuration", "context canceled", "context deadline exceeded", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .id = id, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, id, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "guru %s\nguru %s", key, id);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t before = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, id, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
    CHECK(results->items[0].secret_parts == parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "guru %s\nguru %s\nguru %s\nguru %s", key, other_key, id, other_id);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    const struct { size_t size, after, part; const char *error; } faults[] = {
        {2 * sizeof(br_span), 1, 0, "out of memory iterating regex"},
        {2 * sizeof(br_span), 2, 0, "out of memory iterating regex"},
        {31, 2, 0, "out of memory copying detector capture"},
        {51, 2, 0, "out of memory copying detector capture"},
        {30, 2, 0, "cannot create CustomerGuru result"},
        {80, 2, 0, "cannot create CustomerGuru result"},
        {0, 0, 3, "cannot create CustomerGuru result"},
        {0, 0, 4, "cannot create CustomerGuru result"},
        {0, 0, 0, "cannot format CustomerGuru URL"},
        {0, 0, 0, "cannot format CustomerGuru URL"},
    };
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 4};
        const char *keys[] = {key, other_key}, *ids[] = {id, other_id};
        for (size_t k = 0; k < 2; ++k)
            for (size_t i = 0; i < 2; ++i) steps.rows[k * 2 + i] = (reply){.key = keys[k], .id = ids[i], .status = 204, .body_kind = 2};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        for (size_t f = 0; f < (mode == 0 ? 8u : 10u); ++f) {
            if (f < 6) { fail_alloc_size = faults[f].size; fail_alloc_after = faults[f].after; }
            else if (f < 8) fail_part_after = faults[f].part;
            else { fail_format_after = 2; truncate_format = f == 9; }
            size_t before = format_failures, before_urls = formatted_urls, before_alloc = allocation_failures;
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_alloc_after && !fail_part_after && !fail_format_after);
            CHECK(!strcmp(error, faults[f].error) && format_failures == before + (f >= 8 ? 1u : 0u));
            CHECK(allocation_failures == before_alloc + (f < 6 ? 1u : 0u));
            CHECK(formatted_urls == before_urls + (mode == 0 || f < 4 ? 0u : f < 8 ? 1u : 2u));
            CHECK(http.calls == (mode == 1 && f >= 4 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* The actual positive +1 append rejection is fatal, never a skip. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append CustomerGuru result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(results.len == 4);
    check_result(&results.items[0], key, id, false); check_result(&results.items[1], key, other_id, false);
    check_result(&results.items[2], other_key, id, false); check_result(&results.items[3], other_key, other_id, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); products_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("CustomerGuru");
}
