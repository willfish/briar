/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_nul_push;

/* Native ownership/shared-setup fault boundaries only. The bounded Bearer has
 * no heap allocation or artificial formatter failure in production. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, previous < size ? previous : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key")) {
        if (arm_http_headers) { arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1; }
        if (arm_nul_push) { arm_nul_push = false; fail_push_size = 2 * sizeof(br_result); }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
typedef struct { unsigned char data[200]; size_t len; } fixture;
static br_slice bytes(const fixture *value) { return (br_slice){value->data, value->len}; }
static fixture token(br_slice first, br_slice second, bool underscores)
{
    fixture out = {0}; size_t at = 0;
    memset(out.data + at, 'A', 36); at += 36;
    CHECK(at + first.len <= sizeof(out.data)); memcpy(out.data + at, first.data, first.len); at += first.len;
    memset(out.data + at, 'b', 92); at += 92;
    CHECK(at + second.len + 44 <= sizeof(out.data)); memcpy(out.data + at, second.data, second.len); at += second.len;
    memset(out.data + at, underscores ? '_' : 'C', 43); at += 43;
    out.data[at] = '\0'; out.len = at; return out;
}
static br_bytes input_for(br_slice candidate)
{
    static const char prefix[] = "edenai "; br_bytes out = {.len = sizeof(prefix) - 1 + candidate.len};
    out.data = malloc(out.len + 1); CHECK(out.data); memcpy(out.data, prefix, sizeof(prefix) - 1);
    memcpy(out.data + sizeof(prefix) - 1, candidate.data, candidate.len); out.data[out.len] = '\0'; return out;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_edenai_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_edenai_init(&d, &error) == 0 && d && !error);
    CHECK(br_edenai_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 568 && d->version == 0 && !strcmp(d->name, "EdenAI") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "EdenAI provides a unified API to access multiple AI engines. EdenAI API keys can be used to access and utilize these AI services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "edenai"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *result, br_slice expected, bool verified)
{
    CHECK(result->detector_type == 568 && !result->detector_name && result->raw.len == expected.len && !memcmp(result->raw.data, expected.data, expected.len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->extra_data && !result->structured_data && !result->verification_error);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == expected.len && !memcmp(json_object_get_string(part), expected.data, expected.len));
    CHECK(result->verified == verified && !result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}
static void extraction_case(const br_detector *d, br_slice input, const br_slice *expected)
{
    br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == (expected ? 1u : 0u));
    if (expected) finding(&out.items[0], *expected, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    fixture key = token(TEXT("."), TEXT("."), false); CHECK(key.len == 173); br_slice expected = bytes(&key);
    extraction_case(d, expected, NULL);
    br_bytes input = input_for(expected); extraction_case(d, (br_slice){input.data, input.len}, &expected);
    memcpy(input.data, "EdEnAI", 6); extraction_case(d, (br_slice){input.data, input.len}, &expected); free(input.data);
    const struct { br_slice first, second; } wildcards[] = {
        {TEXT("X"), TEXT("Y")}, {TEXT(" "), TEXT("\r")}, {TEXT("\v"), TEXT("\t")},
        {TEXT("\0"), TEXT(".")}, {TEXT("."), TEXT("\0")}, {TEXT("λ"), TEXT("🌲")}, {TEXT("🌲"), TEXT("🚀")},
        {TEXT("\""), TEXT("\\")}, {TEXT("-"), TEXT("_")},
    };
    for (size_t i = 0; i < sizeof(wildcards) / sizeof(*wildcards); ++i) {
        fixture varied = token(wildcards[i].first, wildcards[i].second, true); br_slice want = bytes(&varied);
        CHECK(varied.len == 171 + wildcards[i].first.len + wildcards[i].second.len);
        input = input_for(want); extraction_case(d, (br_slice){input.data, input.len}, &want); free(input.data);
    }
    const struct { size_t at; unsigned char invalid; } bad[] = {
        {10, '_'}, {10, '-'}, {80, '_'}, {80, '-'}, {150, '-'}, {36, '\n'}, {129, '\n'},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        fixture changed = key; changed.data[bad[i].at] = bad[i].invalid; input = input_for(bytes(&changed));
        extraction_case(d, (br_slice){input.data, input.len}, NULL); free(input.data);
    }
    fixture two_runes = token(TEXT(".."), TEXT("."), false); input = input_for(bytes(&two_runes));
    extraction_case(d, (br_slice){input.data, input.len}, NULL); free(input.data);
    unsigned char boundary[220]; memcpy(boundary, "edenai _", 8); memcpy(boundary + 8, key.data, key.len);
    extraction_case(d, (br_slice){boundary, key.len + 8}, NULL);
    memcpy(boundary, "edenai ", 7); memcpy(boundary + 7, key.data, key.len); boundary[key.len + 7] = '_';
    extraction_case(d, (br_slice){boundary, key.len + 8}, NULL);
    for (size_t distance = 40; distance <= 41; ++distance) {
        memcpy(boundary, "edenai", 6); memset(boundary + 6, ' ', distance); memcpy(boundary + 6 + distance, key.data, key.len);
        extraction_case(d, (br_slice){boundary, 6 + distance + key.len}, distance == 40 ? &expected : NULL);
    }
    input = input_for(expected); input.data[0] = '\0'; extraction_case(d, (br_slice){input.data, input.len}, NULL); free(input.data);
    extraction_case(d, (br_slice){0}, NULL);
}

typedef struct { br_slice key; const char *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; size_t arm_call, arm_size, arm_after, arm_push;
} script;
static void authorization(const char *actual, br_slice expected)
{
    CHECK(actual && expected.len <= 179 && strlen(actual) == expected.len + 7 && !memcmp(actual, "Bearer ", 7));
    CHECK(!memcmp(actual + 7, expected.data, expected.len) && actual[7 + expected.len] == '\0');
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(request->detector_type == 568 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.edenai.run/v1/automl/text/project"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, steps->rows[at].key); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog edenai-offline" : "TruffleHog"));
    row *reply = &steps->rows[at];
    http->response = (br_http_response){.status = reply->status, .body = TEXT("not JSON\0\xff"), .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key); steps->borrowed_auth = NULL;
    test_http_release(user, response);
}
static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "edenai-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth); return rc;
}
static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void wildcard_headers_and_nul_order(const br_detector *d)
{
    const struct { br_slice first, second; } valid[] = {
        {TEXT("."), TEXT(".")}, {TEXT("X"), TEXT("Y")}, {TEXT(" "), TEXT("\t")},
        {TEXT("\""), TEXT("\\")}, {TEXT("🌲"), TEXT("🚀")},
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(*valid); ++i) {
        fixture key = token(valid[i].first, valid[i].second, true); br_bytes input = input_for(bytes(&key));
        if (i == 4) CHECK(key.len == 179);
        script steps = {.count = 1, .suffix = true}; steps.rows[0] = (row){.key = bytes(&key), .status = 200, .read_error = "ignored"};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], bytes(&key), true); br_results_clear(&out);
        out = test_scan(d, NULL, true, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    const struct { br_slice first, second; bool nul; } rejected[] = {
        {TEXT("\0"), TEXT("."), true}, {TEXT("."), TEXT("\0"), true}, {TEXT("\0"), TEXT("\0"), true},
        {TEXT("\r"), TEXT("."), false}, {TEXT("."), TEXT("\v"), false},
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(*rejected); ++i) {
        fixture key = token(rejected[i].first, rejected[i].second, true); br_bytes input = input_for(bytes(&key));
        test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results out = test_scan(d, &ctx, true, input.data, input.len);
        CHECK(out.len == 1 && !http.calls && http.releases == (rejected[i].nul ? 0u : 1u));
        finding(&out.items[0], bytes(&key), false); br_results_clear(&out);
        out = test_scan(d, NULL, true, input.data, input.len); CHECK(!out.len); br_results_clear(&out); /* Constructor SKIP wins over NUL false-retention. */
        out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); finding(&out.items[0], bytes(&key), false); br_results_clear(&out); free(input.data);
    }
}

static void statuses_occurrences_and_suppression(const br_detector *d)
{
    fixture key = token(TEXT("."), TEXT("."), false); br_bytes input = input_for(bytes(&key));
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = bytes(&key), .status = status, .read_error = status % 2 ? "ignored read" : ""};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], bytes(&key), true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = bytes(&key), .status = statuses[i], .read_error = "ignored"};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], bytes(&key), false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = bytes(&key), .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], bytes(&key), false); br_results_clear(&out);
    }
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input.data, input.len);
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], bytes(&key), false); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], bytes(&key), false); br_results_clear(&out);
    fixture unicode = token(TEXT("🌲"), TEXT("🚀"), true); br_bytes second = input_for(bytes(&unicode));
    size_t length = input.len * 2 + second.len + 2; unsigned char combined[640]; CHECK(length <= sizeof(combined));
    size_t at = 0; memcpy(combined + at, input.data, input.len); at += input.len; combined[at++] = '\n';
    memcpy(combined + at, second.data, second.len); at += second.len; combined[at++] = '\n'; memcpy(combined + at, input.data, input.len); at += input.len;
    CHECK(at == length);
    script steps = {.count = 3}; steps.rows[0] = (row){.key = bytes(&key), .status = 401};
    steps.rows[1] = (row){.key = bytes(&unicode), .status = 299}; steps.rows[2] = (row){.key = bytes(&key), .status = 200};
    out = run(d, (br_slice){combined, length}, &steps); CHECK(out.len == 3);
    finding(&out.items[0], bytes(&key), false); finding(&out.items[1], bytes(&unicode), true); finding(&out.items[2], bytes(&key), true);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, false, combined, length); CHECK(out.len == 3);
    finding(&out.items[0], bytes(&key), false); finding(&out.items[1], bytes(&unicode), false); finding(&out.items[2], bytes(&key), false);
    br_results_clear(&out); free(second.data); free(input.data);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key"); free(error); br_results_clear(out);
}
static void own_resources_before_skip_and_suppression(const br_detector *d)
{
    fixture key = token(TEXT("."), TEXT("."), false); br_bytes input = input_for(bytes(&key));
    const size_t sizes[] = {174, 173};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, (br_slice){input.data, input.len}, &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, (br_slice){input.data, input.len}, &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = bytes(&key), .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; size_t before = allocation_failures;
    rc = invoke(d, (br_slice){input.data, input.len}, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    unsigned char twice[400]; CHECK(input.len * 2 + 1 <= sizeof(twice));
    memcpy(twice, input.data, input.len); twice[input.len] = '\n'; memcpy(twice + input.len + 1, input.data, input.len);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 173, .arm_after = 1}; steps.rows[0] = (row){.key = bytes(&key), .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, (br_slice){twice, input.len * 2 + 1}, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); free(input.data);
    fixture nul = token(TEXT("\0"), TEXT("."), true); input = input_for(bytes(&nul));
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; before = allocation_failures; fail_size = nul.len; fail_after = 1;
    rc = d->scan(d, &ctx, true, (br_slice){input.data, input.len}, &out, &error);
    CHECK(!http.calls && !http.releases && !fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    /* NUL suppression retains a finding, so its append resource failure remains
     * fatal even though no request can be represented/sent through ABI1. */
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures; arm_nul_push = true;
    rc = d->scan(d, &ctx, true, (br_slice){input.data, input.len}, &out, &error);
    CHECK(!arm_nul_push && !fail_push_size && !http.calls && !http.releases && allocation_failures == before + 1); rolled_back(&out, rc, error); free(input.data);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    wildcard_headers_and_nul_order(d);
    statuses_occurrences_and_suppression(d);
    own_resources_before_skip_and_suppression(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers && !arm_nul_push);
    return test_finish("EdenAI");
}
