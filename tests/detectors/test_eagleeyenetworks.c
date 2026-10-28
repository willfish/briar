/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define KEY_A "AbCdEfGhIjKlM01"
#define KEY_B "0123456789aBcDe"
static const char key[] = KEY_A, other[] = KEY_B;
static const char keyword[] = "eagleeyenetworks";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers;

/* Actual native capture/finding/shared-HTTP/append resources. The bounded
 * literal payload has NO heap allocation or artificial formatting seam. */
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
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_http_headers && !strcmp(name, "key")) {
        /* Finding is complete. Target the REAL shared request-header array,
         * not another same-sized allocation inside finding construction. */
        arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 15 && strlen(other) == 15);
    CHECK(br_eagleeyenetworks_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_eagleeyenetworks_init(&d, &error) == 0 && d && !error);
    CHECK(br_eagleeyenetworks_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 639 && d->version == 0 && !strcmp(d->name, "EagleEyeNetworks") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Eagle Eye Networks provides cloud-based video surveillance solutions. The credentials can be used to access and manage surveillance data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], keyword));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

/* Email must stay hidden even after successful verification. */
static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 639, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static br_bytes input_for(const char *candidate, br_slice email)
{
    size_t key_len = strlen(candidate), prefix = strlen(keyword);
    br_bytes out = {.len = prefix + 1 + key_len + 1 + prefix + 1 + email.len};
    out.data = malloc(out.len + 1); CHECK(out.data); size_t at = 0;
    memcpy(out.data + at, keyword, prefix); at += prefix; out.data[at++] = ' ';
    memcpy(out.data + at, candidate, key_len); at += key_len; out.data[at++] = '\n';
    memcpy(out.data + at, keyword, prefix); at += prefix; out.data[at++] = ' ';
    memcpy(out.data + at, email.data, email.len); at += email.len; out.data[at] = '\0';
    CHECK(at == out.len); return out;
}

static void extraction(const br_detector *d)
{
    br_results out = test_scan(d, NULL, false, NULL, 0); CHECK(!out.len); br_results_clear(&out);
    const char *missing[] = {"eagleeyenetworks " KEY_A, "eagleeyenetworks abc@de.fg", KEY_A " abc@de.fg"};
    for (size_t i = 0; i < 3; ++i) { out = test_scan(d, NULL, false, missing[i], strlen(missing[i])); CHECK(!out.len); br_results_clear(&out); }
    br_bytes input = input_for(key, TEXT("AbC@DE.Fg"));
    /* Keyword-only CI, with case bytes preserved in both captures. */
    memcpy(input.data, "EaGlEeYeNeTwOrKs", strlen(keyword));
    memcpy(input.data + strlen(keyword) + 1 + 15 + 1, "EAGLEEYENETWORKS", strlen(keyword));
    out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out); free(input.data);
    const br_slice bad_emails[] = {TEXT("ab@de.fg"), TEXT("abc@d.fg"), TEXT("abc@de.abcdef"),
        TEXT("_abc@de.fg"), TEXT("abc@de.fg_"), TEXT("abc@de\nfg"), TEXT("abcdefghijklmnopqrstu@de.fg")};
    for (size_t i = 0; i < sizeof(bad_emails) / sizeof(*bad_emails); ++i) {
        input = input_for(key, bad_emails[i]); out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    const char *bad_keys[] = {"AbCdEfGhIjKlM0", "AbCdEfGhIjKlM012", "_" KEY_A, KEY_A "_", "AbCdEf_hIjKlM01"};
    for (size_t i = 0; i < 5; ++i) {
        input = input_for(bad_keys[i], TEXT("abc@de.fg")); out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
    char gap[256];
    for (size_t distance = 40; distance <= 41; ++distance) {
        size_t at = (size_t)snprintf(gap, sizeof(gap), "%s %s\n%s", keyword, key, keyword);
        memset(gap + at, ' ', distance); at += distance; memcpy(gap + at, "abc@de.fg", 10);
        out = test_scan(d, NULL, false, gap, at + 9); CHECK(out.len == (distance == 40 ? 1u : 0u)); br_results_clear(&out);
        at = strlen(keyword); memcpy(gap, keyword, at); memset(gap + at, ' ', distance); at += distance;
        memcpy(gap + at, key, 15); at += 15; at += (size_t)snprintf(gap + at, sizeof(gap) - at, "\n%s abc@de.fg", keyword);
        out = test_scan(d, NULL, false, gap, at); CHECK(out.len == (distance == 40 ? 1u : 0u)); br_results_clear(&out);
    }
    input = input_for("AAAAAAAAAAAAAAA", TEXT("abc@de.fg")); out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], "AAAAAAAAAAAAAAA", false); br_results_clear(&out); free(input.data);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct {
    row rows[12]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const unsigned char *borrowed_body; size_t borrowed_len;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void body_values(br_slice actual, br_slice expected)
{
    CHECK(actual.data && actual.len == expected.len && actual.len <= 89 && !memcmp(actual.data, expected.data, expected.len));
    CHECK(actual.data[actual.len] == '\0'); /* Complete terminator, even if there is an EARLIER NUL. */
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 12 && ctx == steps->ctx && http->releases == at);
    CHECK(request->detector_type == 639 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://login.eagleeyenetworks.com/g/aaa/authenticate"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog eagleeye-offline" : "TruffleHog"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    row *reply = &steps->rows[at]; body_values(request->body, reply->body);
    steps->borrowed_body = request->body.data; steps->borrowed_len = request->body.len;
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
    body_values((br_slice){steps->borrowed_body, steps->borrowed_len}, steps->rows[http->calls - 1].body);
    steps->borrowed_body = NULL; steps->borrowed_len = 0; test_http_release(user, response);
}
static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "eagleeye-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_body && !steps->borrowed_len); return rc;
}
static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static const char normal_body[] = "{\"username\": \"abc@de.fg\", \"password\": \"" KEY_A "\"}";

static void wildcard_original_payloads(const br_detector *d)
{
    const struct { br_slice email, body; } cases[] = {
        {TEXT("abc@de.fg"), TEXT("{\"username\": \"abc@de.fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de fg"), TEXT("{\"username\": \"abc@de fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\rfg"), TEXT("{\"username\": \"abc@de\rfg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\vfg"), TEXT("{\"username\": \"abc@de\vfg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\tfg"), TEXT("{\"username\": \"abc@de\tfg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\"fg"), TEXT("{\"username\": \"abc@de\"fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\\fg"), TEXT("{\"username\": \"abc@de\\fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de\0fg"), TEXT("{\"username\": \"abc@de\0fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@deλfg"), TEXT("{\"username\": \"abc@deλfg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abc@de🌲fg"), TEXT("{\"username\": \"abc@de🌲fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("AbC@DE.Fg"), TEXT("{\"username\": \"AbC@DE.Fg\", \"password\": \"" KEY_A "\"}")},
        {TEXT("abcdefghijklmnopqrst@abcdefghijkl🌲ABCDE"), TEXT("{\"username\": \"abcdefghijklmnopqrst@abcdefghijkl🌲ABCDE\", \"password\": \"" KEY_A "\"}")},
    };
    CHECK(cases[11].email.len == 42 && cases[11].body.len == 89);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_bytes input = input_for(key, cases[i].email); script steps = {.count = 1, .suffix = true};
        steps.rows[0] = (row){.key = key, .status = 200, .body = cases[i].body, .read_error = "ignored"};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
        out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
        out = test_scan(d, NULL, true, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    }
}

static void occurrence_products_and_fragments(const br_detector *d)
{
    char input[512];
    snprintf(input, sizeof(input), "%s %s\n%s %s\n%s %s\n%s abc@de.fg\n%s Z9x@AB cd\n%s abc@de.fg", keyword, key, keyword, other, keyword, key, keyword, keyword, keyword);
    const char *keys[] = {key, other, key};
    const br_slice bodies[2][2] = {
        {TEXT("{\"username\": \"abc@de.fg\", \"password\": \"" KEY_A "\"}"), TEXT("{\"username\": \"Z9x@AB cd\", \"password\": \"" KEY_A "\"}")},
        {TEXT("{\"username\": \"abc@de.fg\", \"password\": \"" KEY_B "\"}"), TEXT("{\"username\": \"Z9x@AB cd\", \"password\": \"" KEY_B "\"}")},
    };
    script steps = {.count = 9};
    for (size_t k = 0; k < 3; ++k) for (size_t e = 0; e < 3; ++e)
        steps.rows[k * 3 + e] = (row){.key = keys[k], .status = 200, .body = bodies[k == 1][e == 1]};
    br_results out = run(d, text(input), &steps); CHECK(out.len == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t e = 0; e < 3; ++e) finding(&out.items[k * 3 + e], keys[k], true);
    CHECK(out.items[0].raw.data != out.items[6].raw.data && out.items[0].secret_parts != out.items[6].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 9);
    for (size_t k = 0; k < 3; ++k) for (size_t e = 0; e < 3; ++e) finding(&out.items[k * 3 + e], keys[k], false);
    br_results_clear(&out);
    /* This 15-character local part is ALSO a valid source key occurrence. */
    br_bytes fragment_input = input_for(key, TEXT("ABCDEFGHIJKLMNO@de.fg"));
    steps = (script){.count = 2};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"username\": \"ABCDEFGHIJKLMNO@de.fg\", \"password\": \"" KEY_A "\"}")};
    steps.rows[1] = (row){.key = "ABCDEFGHIJKLMNO", .status = 200, .body = TEXT("{\"username\": \"ABCDEFGHIJKLMNO@de.fg\", \"password\": \"ABCDEFGHIJKLMNO\"}")};
    out = run(d, (br_slice){fragment_input.data, fragment_input.len}, &steps); CHECK(out.len == 2);
    finding(&out.items[0], key, true); finding(&out.items[1], "ABCDEFGHIJKLMNO", true); br_results_clear(&out); free(fragment_input.data);
    snprintf(input, sizeof(input), "%s %s %s\n%s abc@de.fg", keyword, other, key, keyword);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 1); finding(&out.items[0], other, false); br_results_clear(&out); /* Context is not filtered; consumed prefix is not reused. */
}

static void status_read_and_send_policy(const br_detector *d)
{
    br_bytes input = input_for(key, TEXT("abc@de.fg"));
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = status, .body = text(normal_body), .read_error = status % 2 ? "ignored read" : ""};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = statuses[i], .body = text(normal_body), .read_error = "ignored"};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .body = text(normal_body), .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, (br_slice){input.data, input.len}, &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input.data, input.len);
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input.data, input.len); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input.data, input.len); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out); free(input.data);
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
static void own_resources_before_skip_and_append(const br_detector *d)
{
    br_bytes input = input_for(key, TEXT("abc@de.fg"));
    const size_t sizes[] = {16, 10, 15}; /* Key capture, email capture, finding Raw. */
    for (size_t i = 0; i < 3; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, (br_slice){input.data, input.len}, &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, (br_slice){input.data, input.len}, &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 200, .body = text(normal_body)};
    out = caller_owned(); out.cap = out.len; error = NULL; size_t before = allocation_failures;
    rc = invoke(d, (br_slice){input.data, input.len}, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error); free(input.data);
    /* First pair is appended; a resource failure on its next email must undo
     * the invocation's append without touching the caller-owned finding. */
    char products[192]; snprintf(products, sizeof(products), "%s %s\n%s abc@de.fg\n%s abc@de.fg", keyword, key, keyword, keyword);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 15, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .body = text(normal_body)};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(products), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    wildcard_original_payloads(d);
    occurrence_products_and_fragments(d);
    status_read_and_send_policy(d);
    own_resources_before_skip_and_append(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers);
    return test_finish("EagleEyeNetworks");
}
