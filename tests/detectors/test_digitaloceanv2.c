/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
static const char access[] = "dop_v1_" HEX64;
static const char oauth[] = "doo_v1_" HEX64;
static const char refresh[] = "dor_v1_" HEX64;
static size_t fail_size, fail_after, allocation_failures, fail_add_after;

/* Actual native allocator and JSON ownership boundaries, not production seams. */
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

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(access) == 71 && strlen(oauth) == 71 && strlen(refresh) == 71);
    CHECK(br_digitaloceanv2_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_digitaloceanv2_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_digitaloceanv2_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 897 && detector->version == 0 && !strcmp(detector->name, "DigitalOceanV2"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DigitalOcean is a cloud service provider offering scalable compute and storage solutions. DigitalOcean API keys can be used to access and manage these resources."));
    CHECK(detector->nkeywords == 3 && !strcmp(detector->keywords[0], "dop_v1_") && !strcmp(detector->keywords[1], "doo_v1_") && !strcmp(detector->keywords[2], "dor_v1_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result(const br_result *value, const char *original, br_slice key, bool verified, const char *error)
{
    CHECK(value->detector_type == 897 && !value->detector_name);
    CHECK(value->raw.len == 71 && !memcmp(value->raw.data, original, 71));
    CHECK(!value->raw_v2.data && !value->raw_v2.len && !value->redacted && !value->extra_data && !value->structured_data);
    CHECK(value->secret_parts && json_object_object_length(value->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(value->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == key.len && (!key.len || !memcmp(json_object_get_string(part), key.data, key.len)));
    CHECK(value->verified == verified && !value->verification_from_cache);
    CHECK((value->verification_error != NULL) == (error != NULL));
    if (error) CHECK(!strcmp(value->verification_error, error));
    CHECK(!value->primary_secret.data && !value->primary_secret.len && !value->primary_line && !value->chunk_offset && !value->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, text(expected), false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[73];
    extraction_case(detector, access, 71, access); extraction_case(detector, oauth, 71, oauth); extraction_case(detector, refresh, 71, refresh);
    const char *accepted[] = {"'%s'", "(%s)\r\n", "-%s-", "no-provider-prefix %s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), accepted[i], access); extraction_case(detector, input, strlen(input), access); }
    const char *bad[] = {"_%s", "%s_", "x%s", "%s0", "%.70s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], access); extraction_case(detector, input, strlen(input), NULL); }
    const char invalid[] = "Ag-_/";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, access, sizeof(access)); changed[30] = invalid[i]; extraction_case(detector, changed, 71, NULL); }
    memcpy(changed, access, sizeof(access)); changed[0] = 'D'; extraction_case(detector, changed, 71, NULL);
    memcpy(changed, access, sizeof(access)); changed[3] = '-'; extraction_case(detector, changed, 71, NULL);
    memcpy(changed, "dor_v1_", 7); memset(changed + 7, '0', 64); changed[71] = '\0';
    extraction_case(detector, changed, 71, changed); /* No entropy/local filtering. */
    input[0] = '\0'; memcpy(input + 1, access, 71); input[72] = '\n'; input[73] = (char)0xff;
    extraction_case(detector, input, 74, access);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *token, *send_error, *read_error; int status, rc; br_slice body; } reply;
typedef struct {
    reply rows[3]; size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_auth;
    char *read_storage[3], *transport_storage[3];
    unsigned char *body_storage[3];
    bool copy_body, suffix;
    size_t arm_size, arm_after, arm_call;
} script;

static void request_values(const char *url, const char *auth, const char *token)
{
    if (!strncmp(token, "dor_v1_", 7)) {
        char expected[157];
        CHECK(snprintf(expected, sizeof(expected), "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token=%s", token) == 156);
        CHECK(url && strlen(url) == 156 && !memcmp(url, expected, sizeof(expected)) && !auth);
    } else {
        CHECK(url && !strcmp(url, "https://api.digitalocean.com/v2/account"));
        CHECK(auth && strlen(auth) == 78 && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, token, 72));
    }
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    reply *row = &steps->rows[at]; bool is_refresh = !strncmp(row->token, "dor_v1_", 7);
    CHECK(request->detector_type == 897 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, is_refresh ? "POST" : "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == (is_refresh ? 1u : 2u));
    if (!is_refresh) CHECK(!strcmp(request->headers[0].name, "Authorization"));
    const char *auth = is_refresh ? NULL : request->headers[0].value;
    request_values(request->url, auth, row->token);
    const br_header *ua = &request->headers[is_refresh ? 0 : 1];
    CHECK(!strcmp(ua->name, "User-Agent") && !strcmp(ua->value, steps->suffix ? "TruffleHog digitalocean-offline" : "TruffleHog"));
    steps->borrowed_url = request->url; steps->borrowed_auth = auth;
    br_slice body = row->body;
    if (steps->copy_body && body.len) {
        steps->body_storage[at] = malloc(body.len); CHECK(steps->body_storage[at]);
        memcpy(steps->body_storage[at], body.data, body.len); body.data = steps->body_storage[at];
    }
    if (row->read_error) { steps->read_storage[at] = strdup(row->read_error); CHECK(steps->read_storage[at]); }
    http->response = (br_http_response){.status = row->status, .body = body, .body_error = steps->read_storage[at]};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *steps = http->user;
    steps->transport_storage[http->calls - 1] = *error; /* Borrowed from provider-owned output. */
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; size_t at = http->calls - 1;
    request_values(steps->borrowed_url, steps->borrowed_auth, steps->rows[at].token);
    steps->borrowed_url = steps->borrowed_auth = NULL;
    /* Mutate borrowed diagnostics before freeing storage: final errors must
     * already be independent copies, not aliases or stripped diagnostic text. */
    if (steps->read_storage[at]) memset(steps->read_storage[at], '!', strlen(steps->read_storage[at]));
    if (steps->transport_storage[at]) memset(steps->transport_storage[at], '!', strlen(steps->transport_storage[at]));
    steps->transport_storage[at] = NULL; /* Provider frees the owned send error. */
    if (steps->body_storage[at]) memset(steps->body_storage[at], '!', response->body.len);
    free(steps->body_storage[at]); steps->body_storage[at] = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *detector, br_slice input, bool verify, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "digitalocean-offline" : NULL}; steps->ctx = &ctx;
    int rc = detector->scan(detector, &ctx, verify, input, out, error);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_url && !steps->borrowed_auth);
    for (size_t i = 0; i < 3; ++i) { free(steps->read_storage[i]); steps->read_storage[i] = NULL; CHECK(!steps->body_storage[i]); }
    return rc;
}

static br_results run(const br_detector *detector, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL;
    int rc = invoke(detector, input, true, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void uniqueness_and_requests(const br_detector *detector)
{
    char input[512]; int len = snprintf(input, sizeof(input), "%s\n%s\n%s\n%s\n%s", refresh, access, oauth, refresh, access);
    br_slice data = {(const unsigned char *)input, (size_t)len}; const char *tokens[] = {refresh, access, oauth};
    script steps = {0}; br_results out = {0}; char *error = NULL;
    CHECK(invoke(detector, data, false, &steps, &out, &error) == 0 && !error && out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], tokens[i], text(tokens[i]), false, NULL);
    br_results_clear(&out);
    steps = (script){.count = 3, .suffix = true};
    steps.rows[0] = (reply){.token = refresh, .status = 200, .body = TEXT("{\"access_token\":\"issued-only-never-requested\"}")};
    steps.rows[1] = (reply){.token = access, .status = 200, .body = TEXT("\xff"), .read_error = "ignored access read failure"};
    steps.rows[2] = (reply){.token = oauth, .status = 401};
    out = run(detector, data, &steps); CHECK(out.len == 3); /* Native order, not upstream map-order parity. */
    result(&out.items[0], refresh, TEXT("issued-only-never-requested"), true, NULL);
    result(&out.items[1], access, text(access), true, NULL); result(&out.items[2], oauth, text(oauth), false, NULL); br_results_clear(&out);
    out = test_scan(detector, NULL, true, data.data, data.len); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], tokens[i], text(tokens[i]), false, "net/http: nil Context");
    br_results_clear(&out);
}

static void statuses_and_leaf_errors(const br_detector *detector)
{
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = access, .status = statuses[i], .body = TEXT("\xff"), .read_error = "ignored access error"};
        char error[64]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        br_results out = run(detector, text(access), &steps);
        result(&out.items[0], access, text(access), statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : error); br_results_clear(&out);
    }
    const int refresh_statuses[] = {200, 201, 401, 403, 500};
    char echoed[128]; snprintf(echoed, sizeof(echoed), "reader leaf %s", refresh);
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = refresh, .status = refresh_statuses[i], .body = TEXT("\xff"), .read_error = i % 2 ? "" : echoed};
        br_results out = run(detector, text(refresh), &steps);
        result(&out.items[0], refresh, text(refresh), false, i % 2 ? "" : echoed); br_results_clear(&out); /* Read error before EVERY status. */
    }
    for (size_t i = 1; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = refresh, .status = refresh_statuses[i], .body = TEXT("\xff")};
        char error[64]; snprintf(error, sizeof(error), "unexpected status code: %d", refresh_statuses[i]);
        br_results out = run(detector, text(refresh), &steps);
        result(&out.items[0], refresh, text(refresh), false, refresh_statuses[i] == 401 ? NULL : error); br_results_clear(&out);
    }
    const char *leaves[] = {echoed, "failed to make request: injected leaf", "net/http: nil Context", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); ++i) {
        const char *original = i % 2 ? access : refresh;
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = original, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = leaves[i], .read_error = "unreached read error"};
        br_results out = run(detector, text(original), &steps);
        result(&out.items[0], original, text(original), false, leaves[i] ? leaves[i] : "HTTP transport failed"); br_results_clear(&out);
    }
}

static void refresh_maps(const br_detector *detector)
{
    const struct { br_slice body, issued; const char *error; bool echo; } cases[] = {
        {TEXT("{\"access_token\":\"issued\"}"), TEXT("issued"), NULL, false},
        {TEXT("{\"access_token\":\"\"}"), TEXT(""), NULL, false},
        {TEXT("{\"access_token\":\"\\u03bb\\u0000\\u2603\"}"), TEXT("\xce\xbb\0\xe2\x98\x83"), NULL, false},
        {TEXT("{\"access_token\":\"\xce\xbb\xe2\x98\x83\"}"), TEXT("\xce\xbb\xe2\x98\x83"), NULL, false},
        {TEXT("{\"access_token\":\"first\",\"access_token\":null,\"access_token\":17,\"access_token\":\"last\"}"), TEXT("last"), NULL, false},
        {TEXT("{\"access_token\":\"first\",\"access_token\":null}"), {0}, NULL, true},
        {TEXT("{\"access_token\":\"first\",\"access_token\":false}"), {0}, NULL, true},
        {TEXT("{\"access_token\":\"real\",\"ACCESS_TOKEN\":null}"), TEXT("real"), NULL, false},
        {TEXT("{\"access_token\":\"real\",\"access_token\\u0000x\":\"wrong\"}"), TEXT("real"), NULL, false},
        {TEXT("{\"access_token\\u0000x\":\"wrong\"}"), {0}, NULL, true},
        {TEXT("{\"access_token\\u0000x\":\"wrong\",\"access_token\":\"real\"}"), TEXT("real"), NULL, false},
        {TEXT("{\"\\u0061ccess_token\":\"escaped-name\"}"), TEXT("escaped-name"), NULL, false},
        {TEXT("null"), {0}, NULL, true}, {TEXT("{}"), {0}, NULL, true},
        {TEXT(" \r\n{ \"ACCESS_TOKEN\": \"wrong\", \"n\": 1 } \t"), {0}, NULL, true},
        {TEXT("{\"n\":\"\\u0000\",\"access_token\":[]}"), {0}, NULL, true},
        {TEXT("{\"n\":\"1e10000\",\"access_token\":\"ok\"}"), TEXT("ok"), NULL, false},
        {TEXT("{\"access_token\":\"ok\",\"n\":1e-10000}"), TEXT("ok"), NULL, false},
        {TEXT("{\"access_token\":\"ok\",\"n\":9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}"), TEXT("ok"), NULL, false},
        {TEXT("[1e10000]"), {0}, "json: cannot unmarshal array into Go value of type map[string]interface {}", false},
        {TEXT("1e10000"), {0}, "json: cannot unmarshal number into Go value of type map[string]interface {}", false},
        {TEXT("false"), {0}, "json: cannot unmarshal bool into Go value of type map[string]interface {}", false},
        {TEXT("{\"access_token\":\"ok\",\"unknown\":1e10000}"), {0}, "json: cannot unmarshal number 1e10000 into Go value of type float64", false},
        {TEXT("{\"access_token\":\"ok\",\"unknown\":{\"nested\":[1e10000]}}"), {0}, "json: cannot unmarshal number 1e10000 into Go value of type float64", false},
        {TEXT("{\"n\":1e10000,\"n\":0,\"access_token\":\"ok\"}"), {0}, "json: cannot unmarshal number 1e10000 into Go value of type float64", false},
        {TEXT("{\"access_token\":1e10000,\"access_token\":\"ok\"}"), {0}, "json: cannot unmarshal number 1e10000 into Go value of type float64", false},
        {TEXT("{\"n\":1e10000} {}"), {0}, "invalid character '{' after top-level value", false},
        {TEXT(""), {0}, "unexpected end of JSON input", false},
        {TEXT("{}\0"), {0}, "invalid character '\\x00' after top-level value", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char echo[1024]; const char *error = cases[i].error;
        if (cases[i].echo) {
            static const char prefix[] = "access_token not found in response: ";
            CHECK(sizeof(prefix) + cases[i].body.len <= sizeof(echo));
            memcpy(echo, prefix, sizeof(prefix) - 1); memcpy(echo + sizeof(prefix) - 1, cases[i].body.data, cases[i].body.len);
            echo[sizeof(prefix) - 1 + cases[i].body.len] = '\0'; error = echo;
        }
        script steps = {.count = 1, .copy_body = true}; steps.rows[0] = (reply){.token = refresh, .status = 200, .body = cases[i].body};
        br_results out = run(detector, text(refresh), &steps); CHECK(out.len == 1);
        result(&out.items[0], refresh, cases[i].issued.data ? cases[i].issued : text(refresh), cases[i].issued.data != NULL, error); br_results_clear(&out);
    }
    char body[160], echo[256]; snprintf(body, sizeof(body), "{\"unknown\":\"%s\"}", refresh);
    snprintf(echo, sizeof(echo), "access_token not found in response: %s", body);
    script steps = {.count = 1, .copy_body = true}; steps.rows[0] = (reply){.token = refresh, .status = 200, .body = text(body)};
    br_results out = run(detector, text(refresh), &steps);
    result(&out.items[0], refresh, text(refresh), false, echo); br_results_clear(&out); /* Zero secret arguments: exact unredacted echo. */
}

static void prior_check(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static bool cancelled(void *user) { (void)user; return true; }

static void resources_and_contexts(const br_detector *detector)
{
    br_result prior = {0}; br_results out = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
    const char huge[] = "{\"n\":9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}";
    for (int f = 0; f < 7; ++f) {
        script steps = {.count = f == 0 ? 0u : 1u};
        steps.rows[0] = (reply){.token = refresh, .status = 200, .body = TEXT("{\"access_token\":\"issued\"}")};
        const char *expected;
        if (f == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (f == 1) { fail_add_after = 2; expected = "cannot replace DigitalOceanV2 secret key"; }
        else {
            steps.arm_call = 1; steps.arm_after = 1;
            if (f == 2) { steps.rows[0].body = TEXT("{}"); steps.arm_size = sizeof("access_token not found in response: ") + 2; expected = "cannot create DigitalOceanV2 response cause"; }
            else if (f == 3) { steps.rows[0].rc = 1; steps.rows[0].send_error = "synthetic borrowed leaf"; steps.arm_size = sizeof("synthetic borrowed leaf"); expected = "cannot copy DigitalOceanV2 verification error"; }
            else if (f == 4) { steps.rows[0].body = TEXT(huge); steps.arm_size = sizeof(huge); expected = "cannot decode DigitalOceanV2 refresh response"; }
            else if (f == 5) {
                steps.rows[0].body = TEXT("{\"n\":1e10000}"); steps.arm_size = sizeof("1e10000");
                /* json-c first duplicates the number for its formatting data;
                 * target the subsequent explicit float-check token allocation. */
                steps.arm_after = 2; expected = "cannot project DigitalOceanV2 refresh response";
            }
            else { steps.rows[0].body = TEXT("[]"); steps.arm_size = sizeof("json: cannot unmarshal array into Go value of type map[string]interface {}"); expected = "cannot create DigitalOceanV2 root type cause"; }
        }
        CHECK(invoke(detector, text(refresh), true, &steps, &out, &error) == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_add_after); prior_check(&out, raw, saved, parts); free(error); error = NULL;
    }
    /* An ordinary private JSON cause transfers without an extra owned-string copy. */
    script steps = {.count = 1, .arm_call = 1, .arm_after = 2,
        .arm_size = sizeof("json: cannot unmarshal array into Go value of type map[string]interface {}")};
    steps.rows[0] = (reply){.token = refresh, .status = 200, .body = TEXT("[]")};
    br_results normal = run(detector, text(refresh), &steps);
    CHECK(fail_after == 1); fail_after = 0;
    result(&normal.items[0], refresh, text(refresh), false, "json: cannot unmarshal array into Go value of type map[string]interface {}"); br_results_clear(&normal);

    char input[160]; int len = snprintf(input, sizeof(input), "%s\n%s", access, refresh);
    steps = (script){.count = 1}; steps.rows[0] = (reply){.token = access, .status = 200}; fail_size = 71; fail_after = 2;
    CHECK(invoke(detector, (br_slice){(const unsigned char *)input, (size_t)len}, true, &steps, &out, &error) == -1 && error && !fail_after);
    prior_check(&out, raw, saved, parts); free(error); error = NULL;
    size_t cap = out.cap; out.cap = 0; steps = (script){0};
    CHECK(invoke(detector, text(access), false, &steps, &out, &error) == -1 && error && !strcmp(error, "cannot append DigitalOceanV2 result"));
    out.cap = cap; prior_check(&out, raw, saved, parts); free(error); error = NULL;
    fail_size = 71; fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, text(refresh), &out, &error) == -1 && error && !strcmp(error, "cannot create DigitalOceanV2 result") && !fail_after);
    prior_check(&out, raw, saved, parts); free(error); error = NULL;
    steps = (script){.count = 1}; steps.rows[0] = (reply){.token = refresh, .status = 200, .body = TEXT("{\"access_token\":\"\xff\"}")};
    CHECK(invoke(detector, text(refresh), true, &steps, &out, &error) == -1 && error && strstr(error, "invalid UTF-8 refresh JSON"));
    prior_check(&out, raw, saved, parts); free(error); br_results_clear(&out);

    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < 3; ++i) {
        http.calls = http.releases = 0;
        normal = test_scan(detector, &contexts[i], true, refresh, 71);
        CHECK(normal.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result(&normal.items[0], refresh, text(refresh), false, causes[i]); br_results_clear(&normal);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); uniqueness_and_requests(detector); statuses_and_leaf_errors(detector); refresh_maps(detector); resources_and_contexts(detector);
    return test_finish("DigitalOceanV2");
}
