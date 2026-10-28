/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[49], other[49];
static size_t fail_size, fail_after, allocation_failures, fail_field_after;
static const char *fail_field;
static bool arm_raw_v2;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_field_after && !strcmp(name, fail_field) && --fail_field_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && arm_raw_v2 && !strcmp(name, "key")) { arm_raw_v2 = false; fail_size = 96; fail_after = 1; }
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 48 && strlen(other) == 48);
    CHECK(br_foursquare_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:foursquare)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_foursquare_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_foursquare_init(&d, &error) == 0 && d && !error && br_foursquare_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 454 && d->version == 0 && !strcmp(d->name, "FourSquare") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Foursquare is a technology company that uses location intelligence to build meaningful consumer experiences and business solutions. Foursquare API keys can be used to access and interact with their services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "foursquare"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *expected_key, const char *expected_secret, bool verified)
{
    CHECK(r->detector_type == 454 && r->raw.len == 48 && !memcmp(r->raw.data, expected_key, 48));
    CHECK(r->raw_v2.data && r->raw_v2.len == 96 && !memcmp(r->raw_v2.data, expected_key, 48) && !memcmp(r->raw_v2.data + 48, expected_secret, 48));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *part_key = NULL, *part_secret = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2 && json_object_object_get_ex(r->secret_parts, "key", &part_key) && json_object_object_get_ex(r->secret_parts, "secret", &part_secret));
    CHECK(json_object_is_type(part_key, json_type_string) && json_object_is_type(part_secret, json_type_string));
    CHECK(!strcmp(json_object_get_string(part_key), expected_key) && !strcmp(json_object_get_string(part_secret), expected_secret));
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(d, &ctx, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, expected, false); /* ONE occurrence must self-pair. */
    br_results_clear(&results);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[50];
    const char *accepted[] = {"foursquare = '%s'", "FoUrSqUaRe\r\n%s", "preFOURSQUAREsuffix:%s", "foursquare-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(d, input, key);
    }
    const char *rejected[] = {"%s", "%s foursquare", "four square %s", "foursquare%s", "foursquare _%s", "foursquare %s_", "foursquare X%s", "foursquare %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(d, input, NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "foursquare%*s%s", gap, "", key); extraction_case(d, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[47] = '\0'; snprintf(input, sizeof(input), "foursquare %s", changed); extraction_case(d, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[48] = 'Z'; changed[49] = '\0'; snprintf(input, sizeof(input), "foursquare %s", changed); extraction_case(d, input, NULL);
    const char invalid[] = "agz_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[24] = invalid[i]; snprintf(input, sizeof(input), "FOURSQUARE %s", changed); extraction_case(d, input, NULL);
    }
    memset(changed, 'Z', 48); changed[48] = '\0'; snprintf(input, sizeof(input), "foursquare %s", changed); extraction_case(d, input, changed); /* Not hex; no local filter/validation. */
    snprintf(input, sizeof(input), "foursquare %s %s", key, other); extraction_case(d, input, key);
    char far[1400]; int n = snprintf(far, sizeof(far), "foursquare %s", key); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "foursquare %s", other);
    br_results results = test_scan(d, NULL, false, far, strlen(far)); CHECK(results.len == 4);
    check_result(&results.items[0], key, key, false); check_result(&results.items[1], key, other, false);
    check_result(&results.items[2], other, key, false); check_result(&results.items[3], other, other, false); br_results_clear(&results);
}

typedef struct { const char *key, *secret, *send_error; int status, send_rc; bool empty_body; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; const char *borrowed_url; char expected_url[187]; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 454 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && strlen(row->key) == 48 && strlen(row->secret) == 48);
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://api.foursquare.com/v2/venues/trending?client_id=%s&client_secret=%s&v=20211019&near=LA", row->key, row->secret) == 186);
    CHECK(strlen(request->url) == 186 && !memcmp(request->url, steps->expected_url, 187)); /* ID first, fixed historical date, literal LA. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog foursquare-offline"));
    steps->borrowed_url = request->url;
    static const unsigned char body[] = "\0\xff invalid JSON \"status\":401";
    http->response = (br_http_response){.status = row->status,
        .body = row->empty_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = row->empty_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, steps->expected_url, 187));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *d, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "foursquare-offline"}; steps->ctx = &ctx;
    br_results results = test_scan(d, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void products_and_verification(const br_detector *d)
{
    const char *values[] = {key, other, key}; char input[256]; snprintf(input, sizeof(input), "foursquare %s; FOURSQUARE %s; foursquare %s", key, other, key);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 500, 201}; reply rows[9];
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.key = values[i / 3], .secret = values[i % 3], .status = statuses[i], .empty_body = i % 2 != 0};
    rows[0].send_rc = 1; rows[0].send_error = "cannot create FourSquare result";
    rows[8].send_rc = -7; rows[8].send_error = "cannot append FourSquare result";
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 9u : 0u}; br_results results = run(d, input, verify, &steps); CHECK(results.len == 9);
        for (size_t i = 0; i < 9; ++i) check_result(&results.items[i], values[i / 3], values[i % 3], verify && !rows[i].send_rc && statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
        results = test_scan(d, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 9u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], values[i / 3], values[i % 3], false);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static void shared_failures(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "foursquare %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && !fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *r, unsigned char *raw, char *cause, br_json *parts)
{
    CHECK(r->len == 1 && r->items[0].detector_type == 777 && r->items[0].verified && r->items[0].raw.data == raw && r->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(r->items[0].verification_error == cause && !strcmp(cause, "caller-owned") && r->items[0].secret_parts == parts);
}

static void own_resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "foursquare %s; foursquare %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply row = {.key = key, .secret = key, .status = 200}; script steps = {.rows = &row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "foursquare-offline"}; steps.ctx = &ctx;
        fail_field = "secret"; fail_field_after = 2; /* Late second-part failure after first product appended or skipped. */
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FourSquare result") && !fail_field_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url); check_prior(&results, raw, cause, parts); free(error); error = NULL;
        arm_raw_v2 = true; /* Genuine RawV2 allocation, armed after successful key part, BEFORE nil-context constructor. */
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FourSquare result") && !arm_raw_v2 && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_field = "key"; fail_field_after = 1;
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FourSquare result") && !fail_field_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1;
        CHECK(d->scan(d, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0;
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FourSquare result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 48, 0); test_secret(other, 48, 11);
    for (size_t i = 0; i < 48; ++i) { if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A'; if (other[i] >= 'a' && other[i] <= 'z') other[i] -= 'a' - 'A'; }
    const br_detector *d = descriptor(); extraction(d); products_and_verification(d); shared_failures(d); own_resources(d);
    return test_finish("FourSquare");
}
