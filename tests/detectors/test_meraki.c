/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_json.h"
#include "../../src/detectors/json.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_meraki_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Existing inclusion seam: real shared HTTP/JSON/string/result helpers, plus
 * local observations for the explicit owned-failure and lifetime requirements. */
static void *checked_malloc(size_t);
static void *checked_realloc(void *, size_t);
static char *checked_strdup(const char *);
static void checked_free(void *);
static int checked_compile(const char *const *, size_t, const char *, br_regex **, char **);
static void checked_regex_free(br_regex *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static void checked_captures_clear(br_captures *);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static br_json *checked_extra(void);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_document(br_slice, const char *, br_json **, size_t *, char **);
static int checked_elements(br_slice, br_json_element_fn, void *);
static int checked_members(br_slice, br_json_member_fn, void *);
static int checked_text(br_json *, br_slice *, br_bytes *, char **);
static int checked_type(br_json *, const char *, const char *, char **);
static int checked_json_put(br_json *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static br_json *checked_name(const char *, int);
static int checked_metadata(br_json *, const char *, br_json *);
static int checked_push(br_results *, br_result *);
static int checked_format(char *, size_t, const char *, ...);
#define malloc checked_malloc
#define realloc checked_realloc
#define strdup checked_strdup
#define free checked_free
#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_regex_free
#define br_captures_find checked_captures
#define br_captures_clear checked_captures_clear
#define br_finding_key_bytes checked_finding
#define json_object_new_object checked_extra
#define br_http_send checked_send
#define br_http_release checked_release
#define br_json_first_document checked_document
#define br_json_each_element checked_elements
#define br_json_each_member checked_members
#define br_gcp_json_text checked_text
#define br_json_type_cause checked_type
#define json_object_put checked_json_put
#define br_result_set_verification_error checked_setter
#define json_object_new_string_len checked_name
#define json_object_object_add checked_metadata
#define br_results_push checked_push
#define snprintf checked_format
#define br_meraki_init observed_meraki_init
#include "../../src/detectors/meraki.c"
#undef malloc
#undef realloc
#undef strdup
#undef free
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef json_object_new_object
#undef br_http_send
#undef br_http_release
#undef br_json_first_document
#undef br_json_each_element
#undef br_json_each_member
#undef br_gcp_json_text
#undef br_json_type_cause
#undef json_object_put
#undef br_result_set_verification_error
#undef json_object_new_string_len
#undef json_object_object_add
#undef br_results_push
#undef snprintf
#undef br_meraki_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
#define FIELD_CAUSE(field, type) "json: cannot unmarshal " type " into Go struct field merakiOrganizations." field " of type string"
#define ROOT_CAUSE(type) "json: cannot unmarshal " type " into Go value of type []meraki.merakiOrganizations"
#define ELEMENT_CAUSE(type) "json: cannot unmarshal " type " into Go value of type meraki.merakiOrganizations"
static char key_a[41], key_b[41];
static const char url[] = "https://api.meraki.com/api/v1/organizations";
typedef enum { NONE, COMPILE, CAPTURE, FINDING, EXTRA, DOCUMENT, ELEMENTS, MEMBERS,
               TEXT, CAUSE, ALLOC, STAGE, COPY, FORMAT, SETTER, NAME, METADATA, PUSH } fault_site;
static fault_site fault;
static size_t nth;
static bool fault_hit;
static size_t compiles, regex_frees, capture_clears, findings, extras, sends, releases, documents;
static size_t arrays, elements, objects, members, texts, causes, mallocs, stages, copies, setters, names, metadata, pushes, metadata_at_finding;
static void *allocations[128];
static size_t nallocations;
static br_json *held_document, *pending_name;
static br_result *candidate;
static br_slice original_key;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static const char *send_cause, *setter_cause;
/* Narrow consumed post-client/codec outcomes, not backend or guard emulation. */
static bool projected_send, null_first_type;
static int projected_send_rc, projected_document_rc;
static br_http_response projected_response;
static size_t null_setters;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true; return true;
}

static void remember(void *value)
{
    if (!value) return;
    CHECK(nallocations < sizeof(allocations) / sizeof(*allocations));
    for (size_t i = 0; i < nallocations; ++i) CHECK(allocations[i] != value);
    allocations[nallocations++] = value;
}

static void reset_observation(void)
{
    CHECK(!nallocations && !held_document && !pending_name && !original_request && !original_context && !send_cause && !setter_cause);
    fault = NONE; nth = 0; fault_hit = false; candidate = NULL; original_key = (br_slice){0};
    projected_send = null_first_type = false;
    projected_send_rc = projected_document_rc = 0; projected_response = (br_http_response){0}; null_setters = 0;
    compiles = regex_frees = capture_clears = findings = extras = sends = releases = documents = 0;
    arrays = elements = objects = members = texts = causes = mallocs = stages = copies = setters = names = metadata = pushes = metadata_at_finding = 0;
}

static void *checked_malloc(size_t size)
{
    ++mallocs;
    if (hit(ALLOC)) return NULL;
    void *value = malloc(size); remember(value); return value;
}

static void *checked_realloc(void *old, size_t size)
{
    ++stages;
    if (hit(STAGE)) return NULL;
    size_t index = nallocations;
    if (old) { for (size_t i = 0; i < nallocations; ++i) if (allocations[i] == old) index = i; CHECK(index < nallocations); }
    void *value = realloc(old, size);
    if (value) { if (index < nallocations) allocations[index] = value; else remember(value); }
    return value;
}

static char *checked_strdup(const char *text)
{
    ++copies;
    if (hit(COPY)) return NULL;
    char *value = strdup(text); remember(value); return value;
}

static void checked_free(void *value)
{
    if (value && value == send_cause) { CHECK(!original_request && !original_context); send_cause = NULL; }
    if (value && value == setter_cause) { CHECK(sends == releases && !original_request); setter_cause = NULL; }
    for (size_t i = 0; i < nallocations; ++i)
        if (allocations[i] == value) { allocations[i] = allocations[--nallocations]; break; }
    free(value);
}

static int checked_compile(const char *const *keywords, size_t count, const char *pattern, br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "meraki") && !strcmp(pattern, "([0-9a-f]{40})")); ++compiles;
    int rc = br_regex_compile_prefixed(keywords, count, pattern, out, error);
    if (rc == 0 && hit(COMPILE)) { *error = strdup("synthetic compile failure"); CHECK(*error); remember(*error); return 1; }
    return rc;
}

static void checked_regex_free(br_regex *regex)
{
    if (regex) ++regex_frees;
    br_regex_free(regex);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) { *error = strdup("synthetic capture failure"); CHECK(*error); remember(*error); return 1; }
    return rc;
}

static void checked_captures_clear(br_captures *values)
{
    CHECK(!original_request && !original_context && !held_document && !pending_name && sends == releases);
    br_captures_clear(values); ++capture_clears;
    CHECK(!values->items && !values->lengths && !values->len && !values->cap);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    CHECK(!original_request && key.len == 40 && type == 1000 && !strcmp(part, "key"));
    candidate = result; original_key = key; metadata_at_finding = metadata; ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static br_json *checked_extra(void)
{
    ++extras; CHECK(candidate && !candidate->verified && !candidate->extra_data);
    return hit(EXTRA) ? NULL : json_object_new_object();
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data);
    CHECK(!candidate->verified && !candidate->verification_error && candidate->extra_data);
    CHECK(!json_object_object_length(candidate->extra_data));
    CHECK(!strcmp(original_request->method, "GET") && !strcmp(original_request->url, url));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms && original_request->detector_type == 1000);
    CHECK(original_request->nheaders == 1 && !strcmp(original_request->headers[0].name, "X-Cisco-Meraki-Api-Key"));
    CHECK(original_request->headers[0].value == (const char *)original_key.data && !memcmp(original_request->headers[0].value, original_key.data, 40));
    CHECK(!original_request->body.data && !original_request->body.len);
    CHECK(original_request->dedup_key.len == 45 && !memcmp(original_request->dedup_key.data, "1000:", 5));
    CHECK(!memcmp(original_request->dedup_key.data + 5, original_key.data, 40));
    CHECK(candidate->raw.len == 40 && !memcmp(candidate->raw.data, original_key.data, 40));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases);
    original_request = request; original_context = ctx; ++sends; provider_values();
    int rc;
    if (projected_send) {
        CHECK(!ctx->transport); /* No actual client/backend/guard claim in this mode. */
        *response = projected_response; *error = NULL; rc = projected_send_rc;
    } else rc = br_http_send(ctx, request, response, error);
    send_cause = *error; remember(*error); return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == original_context && releases + 1 == sends && !held_document && !pending_name);
    provider_values();
    br_http_release(ctx, response); ++releases;
    original_request = NULL; original_context = NULL;
}

static int checked_document(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    ++documents; CHECK(!held_document && metadata == metadata_at_finding);
    if (projected_document_rc) {
        *out = NULL; *end = 0; *cause = NULL;
        return projected_document_rc;
    }
    int rc = br_json_first_document(body, read_error, out, end, cause);
    held_document = *out; remember(*cause);
    return rc == 0 && hit(DOCUMENT) ? 2 : rc; /* +1 is the explicit ordinary decode domain. */
}

typedef struct { br_json_member_fn fn; void *user; } member_probe;
static int probe_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    member_probe *probe = user; ++members;
    int rc = probe->fn(probe->user, name, value, encoded);
    if (value && json_object_is_type(value, json_type_string)) {
        /* Deterministically invalidate borrowed callback string storage. Retaining
         * only the separately parsed top document cannot make this safe. */
        CHECK(json_object_set_string_len(value, "clobbered temporary value", 25) == 1);
    }
    CHECK(metadata == metadata_at_finding);
    return rc;
}

static int checked_members(br_slice body, br_json_member_fn fn, void *user)
{
    ++objects; member_probe probe = {fn, user};
    int rc = br_json_each_member(body, probe_member, &probe);
    return rc == 0 && hit(MEMBERS) ? 1 : rc;
}

typedef struct { br_json_element_fn fn; void *user; } element_probe;
static int probe_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    element_probe *probe = user; ++elements;
    int rc = probe->fn(probe->user, index, value, encoded);
    CHECK(metadata == metadata_at_finding);
    if (candidate) CHECK(!candidate->verified && !candidate->verification_error && !json_object_object_length(candidate->extra_data));
    return rc;
}

static int checked_elements(br_slice body, br_json_element_fn fn, void *user)
{
    ++arrays; element_probe probe = {fn, user};
    int rc = br_json_each_element(body, probe_element, &probe);
    return rc == 0 && hit(ELEMENTS) ? 1 : rc;
}

static int checked_text(br_json *value, br_slice *out, br_bytes *repair, char **error)
{
    ++texts; CHECK(metadata == metadata_at_finding);
    int rc = br_gcp_json_text(value, out, repair, error); remember(repair->data);
    if (rc == 0 && hit(TEXT)) { *error = strdup("synthetic string repair failure"); CHECK(*error); remember(*error); return 1; }
    return rc;
}

static int checked_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++causes;
    int rc = br_json_type_cause(value, field, expected, cause);
    if (rc == 0 && null_first_type && causes == 1) { free(*cause); *cause = NULL; }
    remember(*cause);
    return rc == 0 && hit(CAUSE) ? 1 : rc;
}

static int checked_json_put(br_json *value)
{
    if (value && value == held_document) held_document = NULL;
    if (value && value == pending_name) pending_name = NULL;
    return json_object_put(value); /* Normal refcount deletion result is not an error status. */
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    CHECK(result == candidate && (cause || projected_send || null_first_type) && !secrets && !nsecrets && !result->verified);
    CHECK(!original_request && !original_context && sends == releases && !held_document && metadata == metadata_at_finding);
    CHECK(result->extra_data && !json_object_object_length(result->extra_data));
    ++setters; if (!cause) ++null_setters; setter_cause = cause;
    int rc = br_result_set_verification_error(result, cause, secrets, nsecrets);
    return rc == 0 && hit(SETTER) ? 1 : rc;
}

static br_json *checked_name(const char *name, int length)
{
    CHECK(!original_request && !original_context && sends == releases && !held_document && candidate && candidate->verified && !candidate->verification_error);
    CHECK(!pending_name); ++names;
    if (hit(NAME)) return NULL;
    pending_name = json_object_new_string_len(name, length); return pending_name;
}

static int checked_metadata(br_json *object, const char *key, br_json *value)
{
    CHECK(object == candidate->extra_data && candidate->verified && value == pending_name && !strncmp(key, "organization_", 13));
    CHECK(sends == releases && !held_document && !original_request); ++metadata;
    if (hit(METADATA)) return 1; /* Failure leaves value ownership with caller. */
    int rc = json_object_object_add(object, key, value);
    if (rc == 0) pending_name = NULL;
    return rc;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_context && sends == releases && !held_document && !pending_name && !nallocations);
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object)); ++pushes;
    int rc = br_results_push(out, result);
    return rc == 0 && hit(PUSH) ? 1 : rc;
}

static int checked_format(char *out, size_t size, const char *format, ...)
{
    if (hit(FORMAT)) return (int)size;
    va_list ap; va_start(ap, format); int n = vsnprintf(out, size, format, ap); va_end(ap); return n;
}

typedef struct { test_http http; const br_http_request *held; bool destroyed; } owned_fixture;
static void wire_values(const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(!ctx->cancelled && !ctx->cancel_user && ctx->deadline_monotonic_ms > 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && request->profile == BR_HTTP_SANE && request->detector_type == 1000);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 5000 && !request->body.data && !request->body.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Cisco-Meraki-Api-Key"));
    CHECK(strlen(request->headers[0].value) == 40 && request->dedup_key.len == 45);
    CHECK(!memcmp(request->dedup_key.data, "1000:", 5) && !memcmp(request->dedup_key.data + 5, request->headers[0].value, 40));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog meraki-offline"));
}

static int raw_send(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    owned_fixture *fixture = user; CHECK(!fixture->held && !fixture->destroyed);
    fixture->held = request; wire_values(ctx, request);
    return test_http_send(&fixture->http, ctx, request, response, error);
}

static void raw_release(void *user, br_http_response *response)
{
    owned_fixture *fixture = user; CHECK(fixture->held && !fixture->destroyed);
    const br_http_request *request = fixture->held;
    CHECK(request->dedup_key.len == 45 && !memcmp(request->dedup_key.data, "1000:", 5));
    CHECK(!memcmp(request->dedup_key.data + 5, request->headers[0].value, 40));
    CHECK(!strcmp(request->url, url) && request->nheaders == 2 && !strcmp(request->headers[1].value, "TruffleHog meraki-offline"));
    test_http_release(&fixture->http, response); fixture->held = NULL;
}

static void raw_destroy(void *user)
{
    owned_fixture *fixture = user; CHECK(!fixture->held && !fixture->destroyed); fixture->destroyed = true;
}

static br_http_client *owned_client(owned_fixture *fixture, br_scan_ctx *ctx)
{
    br_http_owned_backend backend = {.transport = {fixture, raw_send, raw_release}, .destroy = raw_destroy};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(!br_http_client_init(&client, backend, BR_HTTP_SANE, &error) && client && !error);
    *ctx = (br_scan_ctx){.transport = br_http_client_transport(client), .user_agent = "meraki-offline"}; return client;
}

static void finish_client(br_http_client *client, owned_fixture *fixture)
{
    char *error = NULL; CHECK(!br_http_client_drain(client, &error) && !error);
    br_http_client_destroy(client); CHECK(fixture->destroyed && !fixture->held);
}

static void check_result(const br_result *result, const char *key, bool verified, const char *cause)
{
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object));
    br_result plain = *result; plain.extra_data = NULL; test_key_result(&plain, 1000, key, "key");
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static void check_extra(const br_result *result, const char *key, br_slice expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(result->extra_data, key, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void extraction(const br_detector *actual, const br_detector *observed)
{
    const br_detector *d = NULL; char *error = NULL;
    CHECK(!br_meraki_init(&d, &error) && !error && d == actual);
    CHECK(d->type == 1000 && !d->version && !strcmp(d->name, "Meraki") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.Meraki APIs make it possible to rapidly deploy and manage networks at scale, build on a platform of intelligent, cloud-connected IT products, and engage with users in powerful new ways."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "meraki") && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    char input[512], upper[41]; for (size_t i = 0; i < 40; ++i) upper[i] = key_a[i] >= 'a' ? (char)(key_a[i] - 'a' + 'A') : key_a[i]; upper[40] = 0;
    const struct { const char *format, *token; size_t count; } cases[] = {
        {"meraki%s", key_a, 1}, {"preMERAKIX%sz", key_a, 1}, {"meraki%sabcdef", key_a, 1},
        {"meraki %s", upper, 0}, {"meraki %.39s", key_a, 0}, {"provider %s", key_a, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, cases[i].token);
        br_results r = test_scan(actual, NULL, false, input, strlen(input)); CHECK(r.len == cases[i].count);
        if (r.len) { check_result(&r.items[0], key_a, false, NULL); CHECK(!json_object_object_length(r.items[0].extra_data)); }
        br_results_clear(&r);
    }
    for (size_t runes = 40; runes <= 41; ++runes) {
        size_t at = 0; memcpy(input, "meraki", 6); at = 6;
        for (size_t i = 0; i < runes; ++i) { input[at++] = (char)0xc3; input[at++] = (char)0xa9; }
        memcpy(input + at, key_a, 40); at += 40;
        br_results r = test_scan(actual, NULL, false, input, at); CHECK(r.len == (runes == 40 ? 1u : 0u)); br_results_clear(&r);
    }
    memcpy(input, "meraki", 6); memset(input + 6, '#', 40); input[9] = '\n'; input[18] = '\r'; input[22] = 0; memcpy(input + 46, key_a, 40);
    br_results r = test_scan(actual, NULL, false, input, 86); CHECK(r.len == 1); br_results_clear(&r);
    snprintf(input, sizeof(input), "meraki %s\nmeraki %s\nmeraki %s", key_a, key_b, key_a);
    reset_observation(); fault = SETTER; nth = 1;
    r = test_scan(observed, NULL, false, input, strlen(input)); CHECK(r.len == 2 && findings == 2 && extras == 2 && pushes == 2 && !sends && !documents && !stages && !setters && !fault_hit);
    bool a = false, b = false;
    for (size_t i = 0; i < r.len; ++i) {
        bool is_a = !memcmp(r.items[i].raw.data, key_a, 40); a |= is_a; b |= !is_a;
        check_result(&r.items[i], is_a ? key_a : key_b, false, NULL); CHECK(!json_object_object_length(r.items[i].extra_data));
    }
    CHECK(a && b); br_results_clear(&r); reset_observation();
}

static void guarded_and_nil(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "meraki %s", key_a);
    reset_observation(); br_results r = test_scan(d, NULL, true, input, strlen(input));
    CHECK(r.len == 1 && !sends && !releases && setters == 1 && extras == 1 && !documents);
    check_result(&r.items[0], key_a, false, "net/http: nil Context"); CHECK(!json_object_object_length(r.items[0].extra_data)); br_results_clear(&r);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == 1 && !http.calls && http.releases == 1 && !documents);
    check_result(&r.items[0], key_a, false, "unsupported HTTP request coalescing"); br_results_clear(&r);
    reset_observation(); ctx.transport = NULL; r = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == 1 && !documents);
    check_result(&r.items[0], key_a, false, "HTTP transport not installed"); br_results_clear(&r); reset_observation();
}

static void responses(const br_detector *actual, const br_detector *d)
{
    const struct { const char *body, *cause; bool verified; size_t extra_count; } cases[] = {
        {"null", NULL, true, 0}, {"[] ignored trailing bytes", NULL, true, 0}, {"[] {", NULL, true, 0},
        {"[null]", NULL, true, 1}, {"[{}]", NULL, true, 1},
        {"[{\"id\":\"one\",\"name\":\"First\"},{\"id\":\"one\",\"name\":\"Last\"}]", NULL, true, 1},
        {"[{\"ID\":\"one\",\"id\":null,\"NAME\":\"First\",\"NaMe\":null}]", NULL, true, 1},
        {"[{\"\\u0069d\":\"one\",\"id\":\"two\",\"name\":\"First\",\"name\":\"Last\"}]", NULL, true, 1},
        {"[{\"id\":\"one\",\"other\":1e9999,\"nested\":{\"n\":99999999999999999999999999999},\"name\":\"A\\u0000B\"}]", NULL, true, 1},
        {"[{\"id\":\"one\",\"id\\u0000\":7,\"name\":\"First\"}]", NULL, true, 1},
        {"[{\"id\":\"one\",\"name\":\"\xff\xfe\"}]", NULL, true, 1},
        {"{}", ROOT_CAUSE("object"), false, 0}, {"true", ROOT_CAUSE("bool"), false, 0},
        {"42", ROOT_CAUSE("number"), false, 0}, {"\"x\"", ROOT_CAUSE("string"), false, 0},
        {"[1,{}]", ELEMENT_CAUSE("number"), false, 0}, {"[[]]", ELEMENT_CAUSE("array"), false, 0},
        {"[{\"id\":7,\"id\":\"one\",\"name\":false},{\"id\":\"two\"}]", FIELD_CAUSE("id", "number"), false, 0},
        {"[{\"name\":[],\"id\":{},\"name\":\"later\"}]", FIELD_CAUSE("name", "array"), false, 0},
        {"[{\"id\":\"a\\u0000b\",\"name\":\"ok\"},{\"name\":7}]", FIELD_CAUSE("name", "number"), false, 0},
        {"[{\"id\":7,\"name\":\"later\"}] [", FIELD_CAUSE("id", "number"), false, 0},
        {"", "EOF", false, 0}, {"[", "unexpected EOF", false, 0},
    };
    owned_fixture fixture = {0}; br_scan_ctx ctx; br_http_client *client = owned_client(&fixture, &ctx);
    char input[128]; snprintf(input, sizeof(input), "meraki %s\nmeraki %s", key_a, key_a);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation(); fixture.http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}};
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && findings == 1 && documents == 1 && setters == (cases[i].cause ? 1u : 0u));
        CHECK(fixture.http.calls == i + 1 && fixture.http.releases == i + 1 && !nallocations);
        check_result(&r.items[0], key_a, cases[i].verified, cases[i].cause);
        CHECK((size_t)json_object_object_length(r.items[0].extra_data) == cases[i].extra_count);
        if (i == 3 || i == 4) check_extra(&r.items[0], "organization_", (br_slice)BYTES(""));
        if (i == 5) check_extra(&r.items[0], "organization_one", (br_slice)BYTES("Last"));
        if (i == 6 || i == 9) check_extra(&r.items[0], "organization_one", (br_slice)BYTES("First"));
        if (i == 7) check_extra(&r.items[0], "organization_two", (br_slice)BYTES("Last"));
        if (i == 8) check_extra(&r.items[0], "organization_one", (br_slice)BYTES("A\0B"));
        if (i == 10) check_extra(&r.items[0], "organization_one", (br_slice)BYTES("\xef\xbf\xbd\xef\xbf\xbd"));
        if (i == 17) CHECK(elements == 2 && members == 4 && causes == 2 && texts == 2);
        if (i == 19) CHECK(elements == 2 && members == 3 && texts == 2 && !metadata && setters == 1);
        br_results_clear(&r);
    }
    reset_observation(); fixture.http.response = (br_http_response){.status = 200, .body = BYTES("[{\"id\":\"x\",\"name\":\"one\"},{\"id\":\"x\",\"name\":null},null,{\"name\":\"empty ID\"}]")};
    br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && metadata == 4 && !setters);
    check_extra(&r.items[0], "organization_x", (br_slice)BYTES("")); check_extra(&r.items[0], "organization_", (br_slice)BYTES("empty ID")); br_results_clear(&r);
    reset_observation(); /* The actual production object also reaches synthetic full HTTP/metadata. */
    r = test_scan(actual, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && !sends && !nallocations);
    check_result(&r.items[0], key_a, true, NULL); check_extra(&r.items[0], "organization_", (br_slice)BYTES("empty ID")); br_results_clear(&r);
    finish_client(client, &fixture); reset_observation();
}

static void client_outcomes(const br_detector *d)
{
    /* The real shared backend helper still supplies its own missing-error
     * diagnostic. Nullable CONSUMED outcomes below must not invent one. */
    char echo[192]; snprintf(echo, sizeof(echo), "out of memory %s / %s", key_a, key_a);
    const struct { int status, rc; const char *body_error, *send_error, *cause; } cases[] = {
        {401, 0, NULL, NULL, NULL}, {201, 0, NULL, NULL, "unexpected status code: 201"},
        {403, 0, NULL, NULL, "unexpected status code: 403"}, {500, 0, NULL, NULL, "unexpected status code: 500"},
        {200, 1, NULL, echo, echo}, {401, -7, NULL, echo, echo}, {200, 1, NULL, NULL, "HTTP transport failed"},
        {200, 0, echo, NULL, echo}, {401, 0, "", NULL, ""}, {503, 0, echo, NULL, echo},
    };
    owned_fixture fixture = {0}; br_scan_ctx ctx; br_http_client *client = owned_client(&fixture, &ctx);
    char input[64]; snprintf(input, sizeof(input), "meraki %s", key_a);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation(); fixture.http.response = (br_http_response){.status = cases[i].status, .body = BYTES("[] trailing"), .body_error = cases[i].body_error};
        fixture.http.send_rc = cases[i].rc; fixture.http.send_error = cases[i].send_error;
        br_results r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && sends == 1 && releases == 1 && !documents && !metadata && setters == (cases[i].cause ? 1u : 0u));
        CHECK(fixture.http.calls == i + 1 && fixture.http.releases == i + 1);
        check_result(&r.items[0], key_a, false, cases[i].cause); CHECK(!json_object_object_length(r.items[0].extra_data)); br_results_clear(&r);
    }
    reset_observation(); ctx.user_agent = "invalid\r\nagent"; size_t before = fixture.http.calls;
    br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && sends == 1 && releases == 1 && setters == 1 && fixture.http.calls == before && fixture.http.releases == before);
    check_result(&r.items[0], key_a, false, "invalid HTTP user agent"); br_results_clear(&r);
    finish_client(client, &fixture); reset_observation();
}

static void projected_reader(void)
{
    /* Component-only injected post-client bytes: do NOT bypass the borrowed
     * keyed guard to manufacture an override transport. The real owned client
     * promotion is covered separately above. */
    const struct { const char *body, *read_error, *cause; size_t count; } cases[] = {
        {"[{\"id\":\"one\",\"name\":\"First\"}]trailing", "late read error", NULL, 1},
        {"[]", "", NULL, 0}, {"[{", "reader leaf", "reader leaf", 0},
        {"[{\"id\":false}]", "late read error", FIELD_CAUSE("id", "bool"), 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation(); meraki_organizations organizations = {0}; char *cause = NULL, *error = NULL; bool has_error = false;
        CHECK(!meraki_decode((br_slice){(const unsigned char *)cases[i].body, strlen(cases[i].body)}, cases[i].read_error, &organizations, &has_error, &cause, &error) && !error);
        CHECK(has_error == (cases[i].cause != NULL));
        CHECK(organizations.len == cases[i].count && documents == 1 && !held_document);
        if (cases[i].cause) CHECK(cause && !strcmp(cause, cases[i].cause)); else CHECK(!cause);
        if (i == 0) { CHECK(organizations.items[0].id.len == 3 && !memcmp(organizations.items[0].id.data, "one", 3)); CHECK(organizations.items[0].name.len == 5 && !memcmp(organizations.items[0].name.data, "First", 5)); }
        checked_free(cause); meraki_organizations_clear(&organizations); CHECK(!nallocations);
    }
    reset_observation();
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 9, .verified = true}; prior.raw.data = malloc(5); CHECK(prior.raw.data); memcpy(prior.raw.data, "prior", 5); prior.raw.len = 5;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); prior.extra_data = json_object_new_object(); CHECK(prior.extra_data);
    CHECK(!json_object_object_add(prior.extra_data, "keep", json_object_new_string("prior metadata")));
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); return out;
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].detector_type == 9 && out->items[0].verified && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
    CHECK(out->items[0].extra_data == prior->extra_data && json_object_object_length(out->items[0].extra_data) == 1);
    CHECK(!nallocations && !held_document && !pending_name && sends == releases);
}

static void nullable_outcomes(const br_detector *d)
{
    static const char sticky[] = "[{\"id\":false,\"name\":\"\xff\",\"name\":7,\"id\":\"a\\u0000b\",\"name\":\"later\"},{\"id\":\"next\",\"name\":\"valid\"}]";
    static const char nine[] = "[false,{},{},{},{},{},{},{},{}]";
    const struct {
        int send_rc, document_rc, status; const char *body; bool null_type, verified;
        fault_site site; size_t nth, keys; bool fatal; size_t expected_setters;
    } cases[] = {
        {1,0,200,sticky,false,false,NONE,0,1,false,1},
        {-7,0,200,sticky,false,false,NONE,0,1,false,1},
        {0,1,200,sticky,false,false,NONE,0,1,false,1},
        {0,0,200,"null",false,true,SETTER,1,1,false,0},
        {0,0,401,sticky,false,false,SETTER,1,1,false,0},
        {0,0,200,sticky,true,false,NONE,0,1,false,1},
        {1,0,200,sticky,false,false,SETTER,2,2,true,2},
        {0,1,200,sticky,false,false,SETTER,2,2,true,2},
        {0,0,200,sticky,true,false,SETTER,1,1,true,1},
        {0,0,200,sticky,true,false,TEXT,1,1,true,0},
        {0,0,200,sticky,true,false,CAUSE,2,1,true,0},
        {0,0,200,sticky,true,false,MEMBERS,1,1,true,0},
        {0,0,200,sticky,true,false,ELEMENTS,1,1,true,0},
        {0,0,200,nine,true,false,STAGE,2,1,true,0},
        {0,-1,200,sticky,false,false,NONE,0,1,true,0},
        {0,2,200,sticky,false,false,NONE,0,1,true,0},
    };
    char input[128]; int length = snprintf(input, sizeof(input), "meraki %s\nmeraki %s", key_a, key_b);
    CHECK(length > 0 && (size_t)length < sizeof(input));
    br_scan_ctx ctx = {0};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation();
        projected_send = true; projected_send_rc = cases[i].send_rc; projected_document_rc = cases[i].document_rc;
        projected_response = (br_http_response){.status = cases[i].status, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}};
        null_first_type = cases[i].null_type; fault = cases[i].site; nth = cases[i].nth;
        size_t input_length = cases[i].keys == 2 ? (size_t)length : 47; /* keyword, space, raw40. */
        br_results out = prior_results(); br_result prior = out.items[0]; char *error = NULL;
        int rc = d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, input_length}, &out, &error);
        CHECK(sends == cases[i].keys && releases == sends && setters == cases[i].expected_setters && null_setters == setters && !metadata);
        if (cases[i].send_rc || cases[i].status != 200) CHECK(!documents);
        else CHECK(documents == sends);
        if (cases[i].fatal) {
            CHECK(rc == -1 && error && pushes == (cases[i].keys == 2 ? 1u : 0u));
            if (cases[i].site == SETTER) CHECK(!strcmp(error, "cannot set Meraki verification error"));
            CHECK(cases[i].site == NONE ? !fault_hit : fault_hit);
            checked_free(error); check_prior(&out, &prior);
        } else {
            CHECK(rc == 0 && !error && out.len == 2 && pushes == 1 && !fault_hit && !copies);
            check_result(&out.items[1], key_a, cases[i].verified, NULL);
            CHECK(!json_object_object_length(out.items[1].extra_data));
            br_result added = out.items[--out.len]; check_prior(&out, &prior); br_result_clear(&added);
        }
        if (cases[i].null_type && (!cases[i].fatal || cases[i].site == SETTER || cases[i].site == ELEMENTS))
            CHECK(elements == 2 && members == 7 && causes == 2 && texts == 5);
        br_results_clear(&out);
    }
    reset_observation();
}

static void failures(const br_detector *d)
{
    static const char normal[] = "[{\"id\":\"one\",\"name\":\"First\"}]";
    static const char sticky[] = "[{\"id\":false,\"name\":\"\xff\",\"id\":{},\"name\":\"later\"},{\"name\":\"next\"}]";
    static const char nine[] = "[false,{},{},{},{},{},{},{},{}]";
    static const char nul[] = "[{\"id\":\"a\\u0000b\",\"name\":\"First\"},{\"id\":\"two\",\"name\":\"Last\"}]";
    const struct { fault_site site; size_t nth; const char *body; int status; bool nilctx, nov; size_t calls; } cases[] = {
        {CAPTURE,1,normal,200,true,false,0}, {FINDING,2,normal,200,false,false,1},
        {EXTRA,1,normal,200,true,true,0}, {EXTRA,2,normal,200,false,false,1},
        {DOCUMENT,1,normal,200,false,false,1}, {ELEMENTS,1,normal,200,false,false,1},
        {MEMBERS,1,sticky,200,false,false,1}, {TEXT,1,normal,200,false,false,1},
        {TEXT,1,sticky,200,false,false,1}, {CAUSE,1,"{}",200,false,false,1},
        {CAUSE,2,sticky,200,false,false,1}, {ALLOC,1,normal,200,false,false,1},
        {ALLOC,3,normal,200,false,false,1}, {STAGE,1,normal,200,false,false,1},
        {STAGE,2,nine,200,false,false,1}, {COPY,1,normal,200,true,false,0},
        {COPY,1,normal,500,false,false,1}, {FORMAT,1,normal,500,false,false,1},
        {SETTER,2,normal,401,true,false,0}, {SETTER,1,sticky,200,false,false,1},
        {SETTER,1,normal,503,false,false,1}, {NAME,1,normal,200,false,false,1},
        {METADATA,2,normal,200,false,false,2}, {PUSH,2,normal,200,false,false,2},
        {PUSH,2,sticky,200,false,false,2}, {NONE,0,nul,200,false,false,1},
    };
    owned_fixture fixture = {0}; br_scan_ctx ctx; br_http_client *client = owned_client(&fixture, &ctx);
    char input[128]; snprintf(input, sizeof(input), "meraki %s\nmeraki %s", key_a, key_b);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation(); fixture.http.response = (br_http_response){.status = cases[i].status, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}};
        br_results out = prior_results(); br_result prior = out.items[0]; char *error = NULL;
        fault = cases[i].site; nth = cases[i].nth; size_t before = fixture.http.calls;
        CHECK(d->scan(d, cases[i].nilctx ? NULL : &ctx, !cases[i].nov, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
        CHECK(fixture.http.calls == before + cases[i].calls && fixture.http.releases == fixture.http.calls);
        CHECK(cases[i].site == NONE ? !fault_hit : fault_hit);
        if (cases[i].site == NONE) { CHECK(!strcmp(error, "unsupported Meraki organization ID with NUL")); CHECK(elements == 2 && members == 4 && releases == 1 && !setters && !metadata && mallocs == 5); }
        checked_free(error); check_prior(&out, &prior); br_results_clear(&out);
    }
    /* A disallowed setter is never called, including after nil source errors. */
    const int statuses[] = {200, 401};
    for (size_t i = 0; i < 2; ++i) {
        reset_observation(); fixture.http.response = (br_http_response){.status = statuses[i], .body = BYTES("[]")}; fault = SETTER; nth = 1;
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 2 && !setters && !fault_hit && sends == 2 && releases == 2); br_results_clear(&out);
    }
    finish_client(client, &fixture); reset_observation();
    br_results out = prior_results(); br_result prior = out.items[0];
    fault = FINDING; nth = 1;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && fault_hit);
    check_prior(&out, &prior); br_results_clear(&out); reset_observation();
}

int main(void)
{
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 40; ++i) { key_a[i] = hex[i % 16]; key_b[i] = hex[(i + 7) % 16]; }
    key_a[40] = key_b[40] = 0;
    const br_detector *actual = NULL, *observed = NULL; char *error = NULL;
    CHECK(!br_meraki_init(&actual, &error) && actual && !error);
    reset_observation(); fault = COMPILE; nth = 1;
    CHECK(observed_meraki_init(&observed, &error) == -1 && !observed && error && fault_hit && compiles == 1 && regex_frees == 1);
    checked_free(error); error = NULL; reset_observation();
    CHECK(!observed_meraki_init(&observed, &error) && observed && !error && compiles == 1);
    CHECK(!observed_meraki_init(&observed, &error) && !error && compiles == 1);
    CHECK(observed_meraki_init(NULL, &error) == -1 && error); checked_free(error); error = NULL;
    br_results out = {0}; CHECK(observed->scan(observed, NULL, false, (br_slice){NULL,1}, &out, &error) == -1 && error); checked_free(error); error = NULL;
    extraction(actual, observed); guarded_and_nil(observed); responses(actual, observed); client_outcomes(observed); projected_reader(); failures(observed); nullable_outcomes(observed);
    reset_observation();
    return test_finish("Meraki unique/typed organizations/owned client/retention/metadata boundary/rollback");
}
