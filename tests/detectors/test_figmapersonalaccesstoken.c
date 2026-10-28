/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char tokens[3][60], alternate[3][60];
static size_t fail_size, fail_after, allocation_failures, fail_field_after, fail_duplicate_after;
static const char *fail_field, *fail_duplicate;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_duplicate_after && !strcmp(text, fail_duplicate) && --fail_duplicate_after == 0) { ++allocation_failures; return NULL; }
    size_t len = strlen(text) + 1; char *out = malloc(len);
    if (out) memcpy(out, text, len);
    return out;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_field_after && !strcmp(name, fail_field) && --fail_field_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

typedef int (*factory)(const br_detector **, char **);
static const factory factories[] = {br_figmapersonalaccesstoken_v1_init, br_figmapersonalaccesstoken_v2_init, br_figmapersonalaccesstoken_v3_init};

static void descriptors(const br_detector **out)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(tokens[0]) == 43 && strlen(tokens[1]) == 45 && strlen(tokens[2]) == 45);
    for (size_t v = 0; v < 3; ++v) {
        const br_detector *again = NULL; char *error = NULL;
        CHECK(factories[v](NULL, &error) == -1 && error); free(error); error = NULL;
        if (v < 2) {
            fail_size = sizeof("(?i:figma)(?s:.){0,40}?"); fail_after = 1;
            CHECK(factories[v](&out[v], &error) == -1 && !out[v] && error && !fail_after);
            CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
        }
        CHECK(factories[v](&out[v], &error) == 0 && out[v] && !error);
        CHECK(factories[v](&again, &error) == 0 && again == out[v] && !error);
        const br_detector *d = out[v];
        CHECK(d->type == 113 && d->version == (int)v + 1 && !strcmp(d->name, "FigmaPersonalAccessToken"));
        CHECK(d->custom_name && !*d->custom_name);
        CHECK(!strcmp(d->description, v == 0 ? "Figma is a web-based design tool. Personal Access Tokens can be used to access and modify design files and other resources." : "Figma is a collaborative interface design tool. Figma Personal Access Tokens can be used to access and manipulate design files and other resources on behalf of a user."));
        CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], v == 2 ? "figp_" : "figma"));
        CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
        CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
        CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    }
    CHECK(out[0] != out[1] && out[1] != out[2] && out[0]->state != out[1]->state && out[1]->state != out[2]->state);
}

static void check_result(const br_result *r, const br_detector *d, const char *token, bool verified, const char *cause)
{
    CHECK(r->detector_type == 113 && r->verified == verified && !r->verification_from_cache);
    CHECK(r->raw.len == strlen(token) && !memcmp(r->raw.data, token, r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->detector_name && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *part = NULL, *version = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), token));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1 && json_object_object_get_ex(r->extra_data, "version", &version));
    CHECK(json_object_is_type(version, json_type_string) && !strcmp(json_object_get_string(version), d->version == 1 ? "1" : d->version == 2 ? "2" : "3"));
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}

static void input_for(char *out, size_t size, const br_detector *d, const char *token)
{
    CHECK(snprintf(out, size, d->version == 3 ? "%s;" : "FiGmA %s", token) > 0);
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], d, expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector **d)
{
    char input[320], changed[64];
    for (size_t v = 0; v < 2; ++v) {
        snprintf(input, sizeof(input), "preFIGMAsuffix:%s", tokens[v]); extraction_case(d[v], input, tokens[v]);
        extraction_case(d[v], tokens[v], NULL);
        snprintf(input, sizeof(input), "figma _%s", tokens[v]); extraction_case(d[v], input, NULL);
        snprintf(input, sizeof(input), "figma %s_", tokens[v]); extraction_case(d[v], input, NULL);
        for (int gap = 40; gap <= 41; ++gap) {
            snprintf(input, sizeof(input), "figma%*s%s", gap, "", tokens[v]); extraction_case(d[v], input, gap == 40 ? tokens[v] : NULL);
        }
    }
    strcpy(changed, tokens[0]); changed[0] = 'a'; input_for(input, sizeof(input), d[0], changed); extraction_case(d[0], input, NULL);
    strcpy(changed, tokens[0]); changed[7] = 'G'; input_for(input, sizeof(input), d[0], changed); extraction_case(d[0], input, NULL);
    strcpy(changed, tokens[0]); changed[6] = '_'; input_for(input, sizeof(input), d[0], changed); extraction_case(d[0], input, NULL);
    strcpy(changed, tokens[0]); changed[42] = '\0'; input_for(input, sizeof(input), d[0], changed); extraction_case(d[0], input, NULL);
    /* V2's one-character literal class, not nested alternatives. */
    const char literal_class[] = "duorh|()?";
    for (size_t i = 0; i < sizeof(literal_class) - 1; ++i) {
        strcpy(changed, tokens[1]); changed[3] = literal_class[i]; input_for(input, sizeof(input), d[1], changed); extraction_case(d[1], input, changed);
    }
    snprintf(changed, sizeof(changed), "figuh_%.40s", tokens[1] + 5); input_for(input, sizeof(input), d[1], changed); extraction_case(d[1], input, NULL);
    strcpy(changed, tokens[1]); changed[0] = 'F'; input_for(input, sizeof(input), d[1], changed); extraction_case(d[1], input, NULL);
    strcpy(changed, tokens[1]); changed[44] = '-'; snprintf(input, sizeof(input), "figma %sq", changed); extraction_case(d[1], input, changed);
    input_for(input, sizeof(input), d[1], changed); extraction_case(d[1], input, NULL); /* Nonword '-' at EOF has no boundary. */
    /* V3 is DIRECT, case-sensitive, no left boundary; group1 excludes delimiter. */
    extraction_case(d[2], tokens[2], tokens[2]);
    snprintf(input, sizeof(input), "before%s!", tokens[2]); extraction_case(d[2], input, tokens[2]);
    strcpy(changed, tokens[2]); changed[0] = 'F'; extraction_case(d[2], changed, NULL);
    memcpy(changed, "figp_", 5); test_secret(changed + 5, 39, 2); extraction_case(d[2], changed, NULL);
    test_secret(changed + 5, 54, 2); changed[58] = '='; extraction_case(d[2], changed, changed);
    snprintf(input, sizeof(input), "%s,", changed); extraction_case(d[2], input, changed);
    changed[58] = '-'; extraction_case(d[2], changed, changed);
    changed[59] = 'x'; changed[60] = '\0'; extraction_case(d[2], changed, NULL);
    snprintf(input, sizeof(input), "%s%s", tokens[2], alternate[2]); extraction_case(d[2], input, alternate[2]);
    snprintf(input, sizeof(input), "%s;%s", tokens[2], alternate[2]);
    br_results results = test_scan(d[2], NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], d[2], tokens[2], false, NULL); check_result(&results.items[1], d[2], alternate[2], false, NULL); br_results_clear(&results);
}

typedef struct { const char *token, *body, *read_error, *send_error; int status, send_rc; } reply;
typedef struct {
    const reply *rows; size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_token;
    size_t arm_size;
    const char *arm_duplicate;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 113 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.figma.com/v1/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Figma-Token") && !strcmp(request->headers[0].value, row->token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog figma-offline"));
    steps->borrowed_token = request->headers[0].value;
    http->response = (br_http_response){.status = row->status, .body_error = row->read_error,
        .body = {(const unsigned char *)row->body, row->body ? strlen(row->body) : 0}};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
    if (steps->arm_size) { fail_size = steps->arm_size; fail_after = 1; }
    if (steps->arm_duplicate) { fail_duplicate = steps->arm_duplicate; fail_duplicate_after = 1; }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_token && !strcmp(steps->borrowed_token, steps->rows[http->calls - 1].token));
    steps->borrowed_token = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *d, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "figma-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(d, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_token); return results;
}

static void occurrences_and_outcomes(const br_detector **d)
{
    char input[320], message[240];
    for (size_t v = 0; v < 3; ++v) {
        const char *label = v == 2 ? "" : "figma ";
        snprintf(input, sizeof(input), "%s%.59s; %s%.59s; %s%.59s;", label, tokens[v], label, alternate[v], label, tokens[v]);
        snprintf(message, sizeof(message), "decoding 403 response body: literal %.59s %.59s", tokens[v], tokens[v]);
        reply rows[] = {{.token = tokens[v], .status = 200, .body = "not JSON", .read_error = "ignored"},
                        {.token = alternate[v], .status = 403, .body = "{\"ERR\":\"Invalid scope(s):\\u0000\\u00e9\"}"},
                        {.token = tokens[v], .status = 200, .send_rc = -7, .send_error = message}};
        for (int verify = 0; verify < 2; ++verify) {
            script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(d[v], input, verify, &steps); CHECK(results.len == 3);
            check_result(&results.items[0], d[v], tokens[v], verify, NULL); check_result(&results.items[1], d[v], alternate[v], verify, NULL);
            check_result(&results.items[2], d[v], tokens[v], false, verify ? "decoding 403 response body: literal [REDACTED] [REDACTED]" : NULL); br_results_clear(&results);
            results = test_scan(d[v], NULL, verify, input, strlen(input)); CHECK(results.len == 3);
            for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], d[v], i == 1 ? alternate[v] : tokens[v], false, verify ? "net/http: nil Context" : NULL);
            br_results_clear(&results);
        }
    }
}

static void typed_403_and_statuses(const br_detector **d)
{
    static const struct { int status; const char *body, *read_error; bool verified; const char *cause; } cases[] = {
        {200, "!", "ignored", true, NULL}, {401, "!", "ignored", false, NULL},
        {204, "{\"err\":\"Invalid scope(s):\"}", NULL, false, "unexpected HTTP response status 204"},
        {429, "", "ignored", false, "unexpected HTTP response status 429"},
        {403, "{\"err\":\"Invalid token\"}", NULL, false, NULL},
        {403, "{\"err\":\"Invalid scope(s):\"}trailing junk", NULL, true, NULL},
        {403, "{\"err\":\"Invalid scope(s):\"}", "", true, NULL},
        {403, "{\"err\":\"Invalid scope(s):\\u0000\\u00e9\"}", NULL, true, NULL},
        {403, "{\"unknown\":1e10000,\"err\":\"Invalid scope(s):\"}", NULL, true, NULL},
        {403, "{\"err\":\"Invalid scope(s):\",\"ERR\":null}", NULL, true, NULL},
        {403, "{\"err\":null,\"eRr\":\"Invalid scope(s):\"}", NULL, true, NULL},
        {403, "{\"err\":\"Invalid scope(s):\",\"ERR\":\"Invalid token\"}", NULL, false, NULL},
        {403, "{\"err\":\"Invalid token\",\"Err\":\"Invalid scope(s):\"}", NULL, true, NULL},
        {403, "{\"err\":7,\"ERR\":\"Invalid scope(s):\"}", NULL, false, "json: cannot unmarshal number into Go struct field .err of type string"},
        {403, "{\"err\":false,\"err\":7,\"err\":\"Invalid scope(s):\"}", NULL, false, "json: cannot unmarshal bool into Go struct field .err of type string"},
        {403, "{\"err\":[]}", NULL, false, "json: cannot unmarshal array into Go struct field .err of type string"},
        {403, "[]", NULL, false, "json: cannot unmarshal array into Go value of type struct { Err string \"json:\\\"err\\\"\" }"},
        {403, "{}", NULL, false, "unexpected 403 response: \"\""},
        {403, "null", NULL, false, "unexpected 403 response: \"\""},
        {403, "{\"err\\u0000\":\"Invalid scope(s):\"}", NULL, false, "unexpected 403 response: \"\""},
        {403, "{\"err\":\"Invalid token\\u0000\"}", NULL, false, "unexpected 403 response: \"Invalid token\\x00\""},
        {403, "{\"err\":\" Invalid scope(s):\"}", NULL, false, "unexpected 403 response: \" Invalid scope(s):\""},
        {403, "", NULL, false, "EOF"}, {403, "{", NULL, false, "unexpected EOF"},
        {403, "!", NULL, false, "invalid character '!' looking for beginning of value"},
        {403, "", "", false, ""}, {403, "{", "decoding 403 response body: literal read leaf", false, "decoding 403 response body: literal read leaf"},
    };
    char input[96];
    for (size_t v = 0; v < 3; ++v) {
        input_for(input, sizeof(input), d[v], tokens[v]);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            reply row = {.token = tokens[v], .status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error};
            script steps = {.rows = &row, .count = 1}; br_results results = run(d[v], input, true, &steps); CHECK(results.len == 1);
            check_result(&results.items[0], d[v], tokens[v], cases[i].verified, cases[i].cause); br_results_clear(&results);
        }
    }
}

static void quoting(const br_detector **d)
{
    char body[512], input[96]; size_t at = (size_t)snprintf(body, sizeof(body), "{\"err\":\"");
    for (unsigned int c = 0; c < 32; ++c) at += (size_t)snprintf(body + at, sizeof(body) - at, "\\u%04x", c);
    snprintf(body + at, sizeof(body) - at, "\\u007f\\\"\\\\'\"}");
    const char *expected = "unexpected 403 response: \"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\a\\b\\t\\n\\v\\f\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x7f\\\"\\\\'\"";
    for (size_t v = 0; v < 3; ++v) {
        input_for(input, sizeof(input), d[v], tokens[v]);
        reply row = {.token = tokens[v], .status = 403, .body = body}; script steps = {.rows = &row, .count = 1};
        br_results results = run(d[v], input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], d[v], tokens[v], false, expected); br_results_clear(&results);
        char redaction[240]; snprintf(redaction, sizeof(redaction), "{\"err\":\"%.59s %.59s\\n\"}", tokens[v], tokens[v]); row.body = redaction;
        results = run(d[v], input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], d[v], tokens[v], false, "unexpected 403 response: \"[REDACTED] [REDACTED]\\n\""); br_results_clear(&results);
    }
    /* Complete diagnostic, not an invented display cap or temporary quotation. */
    char long_body[4110], long_cause[4130]; memcpy(long_body, "{\"err\":\"", 8); memset(long_body + 8, 'x', 4096); memcpy(long_body + 4104, "\"}", 3);
    memcpy(long_cause, "unexpected 403 response: \"", 26); memset(long_cause + 26, 'x', 4096); memcpy(long_cause + 4122, "\"", 2);
    input_for(input, sizeof(input), d[2], tokens[2]); reply row = {.token = tokens[2], .status = 403, .body = long_body}; script steps = {.rows = &row, .count = 1};
    br_results results = run(d[2], input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], d[2], tokens[2], false, long_cause); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }

static void shared_failures(const br_detector **d)
{
    char input[96];
    for (size_t v = 0; v < 3; ++v) {
        input_for(input, sizeof(input), d[v], tokens[v]);
        for (int mode = 0; mode < 3; ++mode) {
            test_http http = {0}; br_transport transport = test_transport(&http);
            br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
            size_t before = allocation_failures; br_results results = test_scan(d[v], &ctx, true, input, strlen(input));
            CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
            CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
            CHECK(!results.items[0].verified && results.items[0].verification_error);
            check_result(&results.items[0], d[v], tokens[v], false, results.items[0].verification_error); br_results_clear(&results);
        }
    }
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, unsigned char *raw, char *cause, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned") && results->items[0].secret_parts == parts);
}

static void finding_resources(const br_detector **d)
{
    char input[240];
    for (size_t v = 0; v < 3; ++v) {
        const char *label = v == 2 ? "" : "figma ";
        snprintf(input, sizeof(input), "%s%.59s; %s%.59s;", label, tokens[v], label, alternate[v]); br_slice data = {(const unsigned char *)input, strlen(input)};
        for (int mode = 0; mode < 3; ++mode) {
            br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
            reply rows[] = {{.token = tokens[v], .status = 200}, {.token = alternate[v], .status = 200}}; script steps = {.rows = rows, .count = 2};
            test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
            br_scan_ctx ctx = {.transport = &transport, .user_agent = "figma-offline"}; steps.expected_ctx = &ctx; char *error = NULL;
            fail_field = "token"; fail_field_after = 2;
            CHECK(d[v]->scan(d[v], mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FigmaPersonalAccessToken result") && !fail_field_after);
            CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.calls == http.releases && !steps.borrowed_token);
            check_prior(&results, raw, cause, parts); free(error); error = NULL;
            fail_field = "version"; fail_field_after = 1;
            CHECK(d[v]->scan(d[v], NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FigmaPersonalAccessToken version metadata") && !fail_field_after);
            check_prior(&results, raw, cause, parts); free(error); error = NULL;
            fail_size = 2 * sizeof(br_span); fail_after = 1;
            CHECK(d[v]->scan(d[v], NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
            check_prior(&results, raw, cause, parts); free(error); error = NULL;
            size_t cap = results.cap; results.cap = 0;
            CHECK(d[v]->scan(d[v], &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FigmaPersonalAccessToken result"));
            results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
        }
    }
}

static void verification_resources(const br_detector **d)
{
    /* Genuine decoder-cause, anonymous-root, projector, quote and setter failures;
     * injection stays in this named test, never in provider/shared interfaces. */
    const struct { int status; const char *body, *duplicate, *fatal; size_t size; } cases[] = {
        {403, "", "EOF", "cannot decode Figma 403 response", 0},
        {403, "[]", "json: cannot unmarshal array into Go value of type struct { Err string \"json:\\\"err\\\"\" }", "cannot decode Figma 403 response", 0},
        {403, "{\"err\":1}", "json: cannot unmarshal number into Go struct field .err of type string", "cannot decode Figma 403 response", 0},
        {403, "{}", NULL, "cannot allocate Figma 403 cause", sizeof("unexpected 403 response: \"\"")},
        {429, "", "unexpected HTTP response status 429", "cannot set Figma verification error", 0},
        {403, "{\"err\":\"denied \\u00e9\"}", NULL, "unsupported: Figma non-ASCII 403 diagnostic requires Go quoting", 0},
    };
    char input[160];
    for (size_t v = 0; v < 3; ++v) {
        input_for(input, sizeof(input), d[v], tokens[v]); br_slice data = {(const unsigned char *)input, strlen(input)};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
            reply row = {.token = tokens[v], .status = cases[i].status, .body = cases[i].body};
            script steps = {.rows = &row, .count = 1, .arm_size = cases[i].size, .arm_duplicate = cases[i].duplicate};
            test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
            br_scan_ctx ctx = {.transport = &transport, .user_agent = "figma-offline"}; steps.expected_ctx = &ctx; char *error = NULL;
            CHECK(d[v]->scan(d[v], &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, cases[i].fatal));
            CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_token && !fail_after && !fail_duplicate_after);
            check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
        }
        /* Late unsupported diagnostic rolls back a previously verified occurrence. */
        snprintf(input, sizeof(input), v == 2 ? "%.59s;%.59s;" : "figma %.59s;figma %.59s;", tokens[v], alternate[v]);
        reply rows[] = {{.token = tokens[v], .status = 200}, {.token = alternate[v], .status = 403, .body = "{\"err\":\"\\u00e9\"}"}};
        script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "figma-offline"}; steps.expected_ctx = &ctx;
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
        CHECK(d[v]->scan(d[v], &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error);
        CHECK(http.calls == 2 && http.releases == 2 && !steps.borrowed_token); check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    strcpy(tokens[0], "123456-ghijklmn-opqr-stuv-wxyz-0123456789az"); strcpy(alternate[0], tokens[0]); alternate[0][0] = '9';
    memcpy(tokens[1], "figd_", 5); test_secret(tokens[1] + 5, 40, 0); tokens[1][9] = 'Z';
    memcpy(alternate[1], "figu_", 5); test_secret(alternate[1] + 5, 40, 9);
    memcpy(tokens[2], "figp_", 5); test_secret(tokens[2] + 5, 40, 7); tokens[2][19] = '='; tokens[2][24] = '-';
    memcpy(alternate[2], "figp_", 5); test_secret(alternate[2] + 5, 40, 19);
    const br_detector *d[3] = {0}; descriptors(d); extraction(d); occurrences_and_outcomes(d);
    typed_403_and_statuses(d); quoting(d); shared_failures(d); finding_resources(d); verification_resources(d);
    return test_finish("FigmaPersonalAccessToken v1/v2/v3");
}
