/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_json.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
#define TYPE(value, field, expected) "json: cannot unmarshal " value " into Go struct field " field " of type " expected
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[38], org_key[43], other[38];

typedef enum {
    NONE, CAPTURES, FINDING, ALLOCATION, GROW, DOCUMENT, MEMBER, ELEMENT,
    CODEC, RETAIN, TYPE_CAUSE, MAP, STRING, INSERT, CAUSE, STATUS_FORMAT, SETTER, PUSH
} fault_kind;
static fault_kind fault;
static size_t fail_nth, fail_size, failures;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE;
    ++failures;
    return true;
}

/* Narrow, module-local seams follow the existing Vault named-test pattern. */
static char projection_order[32];
static size_t order_len;
static bool watch_order;
static void order(char event)
{
    if (!watch_order) return;
    CHECK(order_len + 1 < sizeof(projection_order));
    projection_order[order_len++] = event;
    projection_order[order_len] = 0;
}
static void *checked_malloc(size_t n)
{
    order('A');
    return (!fail_size || fail_size == n) && hit(ALLOCATION) ? NULL : malloc(n);
}
static void *checked_realloc(void *p, size_t n) { return hit(GROW) ? NULL : realloc(p, n); }
static char *checked_strdup(const char *s) { return hit(CAUSE) ? NULL : strdup(s); }
static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    if (hit(STATUS_FORMAT)) return -1;
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}
static int checked_captures(const br_regex *r, br_slice s, br_captures *c, bool unique, char **error)
{
    CHECK(!unique);
    return hit(CAPTURES) ? 7 : br_captures_find(r, s, c, unique, error);
}
static int checked_finding(br_result *r, int32_t type, br_slice k, const char *part)
{
    return hit(FINDING) ? 7 : br_finding_key_bytes(r, type, k, part);
}
static int checked_document(br_slice s, const char *read, br_json **out, size_t *end, char **cause)
{
    return hit(DOCUMENT) ? -1 : br_json_first_document(s, read, out, end, cause);
}
static int checked_member(br_slice s, br_json_member_fn fn, void *u)
{
    return hit(MEMBER) ? 7 : br_json_each_member(s, fn, u);
}
static int checked_element(br_slice s, br_json_element_fn fn, void *u)
{
    return hit(ELEMENT) ? 7 : br_json_each_element(s, fn, u);
}
static int checked_codec(br_json *v, br_slice *s, br_bytes *b, char **error)
{
    return hit(CODEC) ? 7 : br_gcp_json_text(v, s, b, error);
}
static br_json *checked_retain(br_json *v) { return hit(RETAIN) ? NULL : json_object_get(v); }
static int checked_type_cause(br_json *v, const char *f, const char *t, char **cause)
{
    return hit(TYPE_CAUSE) ? 7 : br_json_type_cause(v, f, t, cause);
}
static br_json *checked_map(void) { order('M'); return hit(MAP) ? NULL : json_object_new_object(); }
static br_json *checked_string(const char *s, int n) { return hit(STRING) ? NULL : json_object_new_string_len(s, n); }
static int checked_insert(br_json *m, const char *k, br_json *v)
{
    order(k[0]);
    return hit(INSERT) ? 7 : json_object_object_add(m, k, v);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent;
} expected_request;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static const char *provider_key;
static size_t sends, releases, setters;

static void request_values(const br_http_request *r, bool effective, const char *token)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://huggingface.co/api/whoami-v2"));
    CHECK(r->detector_type == 926 && r->profile == BR_HTTP_SANE);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Authorization"));
    CHECK(!strncmp(r->headers[0].value, "Bearer ", 7) && !strcmp(r->headers[0].value + 7, token));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(!provider_request && ctx);
    if (ctx->transport) {
        test_http *http = ctx->transport->user;
        expected_request *e = http->user;
        CHECK(ctx == e->ctx && http->calls < e->count);
        provider_key = e->keys[http->calls];
    } else provider_key = r->headers[0].value + 7;
    request_values(r, false, provider_key);
    provider_request = r; provider_ctx = ctx;
    ++sends;
    return br_http_send(ctx, r, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && provider_ctx == ctx);
    request_values(provider_request, false, provider_key);
    br_http_release(ctx, response);
    provider_request = NULL; provider_ctx = NULL; provider_key = NULL;
    ++releases;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(!provider_request && sends == releases);
    CHECK(count == 1 && secrets && secrets[0].len == r->raw.len);
    CHECK(!memcmp(secrets[0].data, r->raw.data, r->raw.len));
    ++setters;
    return hit(SETTER) ? 1 : br_result_set_verification_error(r, cause, secrets, count);
}
static int checked_push(br_results *r, br_result *v) { return hit(PUSH) ? 7 : br_results_push(r, v); }

#define malloc checked_malloc
#define realloc checked_realloc
#define strdup checked_strdup
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_json_first_document checked_document
#define br_json_each_member checked_member
#define br_json_each_element checked_element
#define br_gcp_json_text checked_codec
#define json_object_get checked_retain
#define br_json_type_cause checked_type_cause
#define json_object_new_object checked_map
#define json_object_new_string_len checked_string
#define json_object_object_add checked_insert
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#include "../../src/detectors/huggingface.c"
#undef malloc
#undef realloc
#undef strdup
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_each_element
#undef br_gcp_json_text
#undef json_object_get
#undef br_json_type_cause
#undef json_object_new_object
#undef json_object_new_string_len
#undef json_object_object_add
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 37 && strlen(org_key) == 42);
    CHECK(br_huggingface_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid HuggingFace detector output")); free(error);
    CHECK(br_huggingface_init(NULL, NULL) == -1);
    CHECK(!br_huggingface_init(&d, &error) && d && !error);
    CHECK(!br_huggingface_init(&again, NULL) && again == d && again->state == d->state);
    CHECK(d->type == 926 && d->version == 0 && !strcmp(d->name, "HuggingFace") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Hugging Face is a platform for natural language processing tasks and model hosting. Hugging Face API keys can be used to access various services and resources on the platform."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "hf_") && !strcmp(d->keywords[1], "api_org_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *token, bool verified, const char *cause)
{
    CHECK(r->detector_type == 926 && !r->detector_name && r->verified == verified);
    CHECK(r->raw.len == strlen(token) && !memcmp(r->raw.data, token, r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == r->raw.len && !memcmp(json_object_get_string(part), token, r->raw.len));
    if (cause) CHECK(r->verification_error && !strcmp(r->verification_error, cause));
    else CHECK(!r->verification_error);
    CHECK(!r->verification_from_cache && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->chunk_offset && !r->chunk_offset_set);
}
static void field(br_json *map, const char *name, br_slice expected)
{
    br_json *v = NULL;
    CHECK(map && json_object_object_get_ex(map, name, &v) && json_object_is_type(v, json_type_string));
    CHECK((size_t)json_object_get_string_len(v) == expected.len);
    CHECK(!expected.len || !memcmp(json_object_get_string(v), expected.data, expected.len));
}
static void metadata(const br_result *r, br_slice username, br_slice email, br_slice token, const br_slice *orgs)
{
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == (orgs ? 4 : 3));
    field(r->extra_data, "Username", username); field(r->extra_data, "Email", email); field(r->extra_data, "Token", token);
    if (orgs) field(r->extra_data, "Organizations", *orgs);
    else { br_json *v = NULL; CHECK(!json_object_object_get_ex(r->extra_data, "Organizations", &v)); }
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t set = setters, sent = sends;
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setters == set && sends == sent);
    if (expected) { finding(&out.items[0], expected, false, NULL); CHECK(!out.items[0].extra_data); }
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[240], changed[44];
    const char *keys[] = {key, org_key};
    const struct { const char *format; bool match; } cases[] = {
        {"%s", true}, {"'%s'", true}, {"\r\n%s\r\n", true}, {"irrelevant=%s", true},
        {"%s.provider", true}, {"_%s", false}, {"x%s", false}, {"%s_", false}, {"%s9", false},
        {"\xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t k = 0; k < 2; ++k) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
            snprintf(input, sizeof(input), cases[i].format, keys[k]);
            extract(d, input, strlen(input), cases[i].match ? keys[k] : NULL);
        }
        size_t n = strlen(keys[k]);
        memcpy(changed, keys[k], n + 1); changed[n - 1] = 0; extract(d, changed, n - 1, NULL);
        memcpy(changed, keys[k], n + 1); changed[0] -= 'a' - 'A'; extract(d, changed, n, NULL);
        memcpy(changed, keys[k], n + 1); changed[k ? 4 : 1] -= 'a' - 'A'; extract(d, changed, n, NULL);
        memcpy(changed, keys[k], n + 1); changed[n - 4] = '-'; extract(d, changed, n, NULL);
        memcpy(changed, keys[k], n + 1); memset(changed + n - 34, 'A', 34); extract(d, changed, n, changed);
        memcpy(changed, keys[k], n + 1); memset(changed + n - 34, '0', 34); extract(d, changed, n, changed);
    }
    extract(d, "hf_ api_org_", sizeof("hf_ api_org_") - 1, NULL);
    extract(d, NULL, 0, NULL);
    int n = snprintf(input, sizeof(input), "%s%c%s\n%s", key, 0, org_key, key);
    size_t set = setters;
    br_results out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 3 && setters == set);
    finding(&out.items[0], key, false, NULL); finding(&out.items[1], org_key, false, NULL); finding(&out.items[2], key, false, NULL);
    CHECK(!out.items[0].extra_data && !out.items[1].extra_data && !out.items[2].extra_data);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected_request *e = http->user;
    CHECK(ctx == e->ctx && http->calls <= e->count && http->releases + 1 == http->calls);
    request_values(r, true, e->keys[http->calls - 1]);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, e->agent));
}
static int invoke(const br_detector *d, test_http *http, br_scan_ctx *ctx, const char *const *keys,
                  size_t count, const void *input, size_t len, br_results *out, char **error)
{
    expected_request e = {.keys = keys, .count = count, .ctx = ctx,
                          .agent = ctx->user_agent && *ctx->user_agent ? "TruffleHog hf-offline" : "TruffleHog"};
    http->inspect = inspect_request; http->user = &e;
    br_transport transport = test_transport(http); ctx->transport = &transport;
    int rc = d->scan(d, ctx, true, (br_slice){input, len}, out, error);
    CHECK(!provider_request && sends == releases && http->releases >= http->calls);
    return rc;
}
static br_results response(const br_detector *d, const char *token, int status, br_slice body,
                            const char *read, int send_rc, const char *cause)
{
    test_http http = {.response = {.status = status, .body = body, .body_error = read}, .send_rc = send_rc, .send_error = cause};
    br_scan_ctx ctx = {.user_agent = "hf-offline"};
    const char *keys[] = {token};
    br_results out = {0}; char *error = NULL; size_t set = setters;
    CHECK(!invoke(d, &http, &ctx, keys, 1, token, strlen(token), &out, &error) && !error);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setters == set + 1);
    return out;
}
static void json_case(const br_detector *d, br_slice body, const char *read, br_slice username,
                       br_slice email, br_slice token, const br_slice *orgs, const char *cause)
{
    br_results out = response(d, key, 200, body, read, 0, NULL);
    finding(&out.items[0], key, true, cause);
    if (cause) CHECK(!out.items[0].extra_data);
    else metadata(&out.items[0], username, email, token, orgs);
    br_results_clear(&out);
}

static void requests_and_statuses(const br_detector *d)
{
    const int statuses[] = {200, 201, 204, 206, 299, 401, 199, 300, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        int status = statuses[i]; char cause[80];
        bool good = status >= 200 && status < 300;
        snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", status);
        br_results out = response(d, i % 2 ? org_key : key, status, TEXT("{}"), "ignored later read", 0, NULL);
        finding(&out.items[0], i % 2 ? org_key : key, good, good || status == 401 ? NULL : cause);
        if (good) metadata(&out.items[0], TEXT(""), TEXT(""), TEXT("Unknown Token Type"), NULL);
        else CHECK(!out.items[0].extra_data);
        br_results_clear(&out);
    }
    br_results out = response(d, key, 204, (br_slice){0}, NULL, 0, NULL);
    finding(&out.items[0], key, true, "EOF"); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    out = response(d, key, 401, TEXT("not JSON"), "", 0, NULL);
    finding(&out.items[0], key, false, NULL); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    char message[160]; snprintf(message, sizeof(message), "Get failed for %s and %s", key, key);
    out = response(d, key, 200, TEXT("{}"), NULL, 7, message);
    finding(&out.items[0], key, false, "Get failed for [REDACTED] and [REDACTED]"); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    out = response(d, org_key, 200, TEXT("{}"), NULL, 1, "");
    finding(&out.items[0], org_key, false, ""); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    out = response(d, key, 200, TEXT("{}"), NULL, 1, NULL);
    finding(&out.items[0], key, false, "HTTP transport failed"); CHECK(!out.items[0].extra_data); br_results_clear(&out);

    const char *keys[] = {key, org_key, key};
    char input[160]; int n = snprintf(input, sizeof(input), "%s %s %s", key, org_key, key);
    test_http http = {.response = {.status = 201, .body = TEXT("{}")}};
    br_scan_ctx ctx = {0}; char *error = NULL; out = (br_results){0}; size_t set = setters;
    CHECK(!invoke(d, &http, &ctx, keys, 3, input, (size_t)n, &out, &error) && !error);
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && setters == set + 3);
    for (size_t i = 0; i < 3; ++i) { finding(&out.items[i], keys[i], true, NULL); metadata(&out.items[i], TEXT(""), TEXT(""), TEXT("Unknown Token Type"), NULL); }
    CHECK(out.items[0].extra_data != out.items[2].extra_data);
    br_results_clear(&out);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void constructor_and_preparation(const br_detector *d)
{
    size_t set = setters, sent = sends;
    br_results out = test_scan(d, NULL, true, key, strlen(key));
    CHECK(out.len == 1 && sends == sent && setters == set + 1);
    finding(&out.items[0], key, false, NULL); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    br_scan_ctx absent = {0}; out = test_scan(d, &absent, true, key, strlen(key));
    CHECK(out.len == 1); finding(&out.items[0], key, false, "HTTP transport not installed"); br_results_clear(&out);

    const char *keys[] = {key};
    for (size_t i = 0; i < 3; ++i) {
        size_t cancellations = 0;
        br_scan_ctx ctx = {0}; test_http http = {0}; char *error = NULL; out = (br_results){0};
        const char *cause;
        if (!i) { ctx.cancelled = cancelled; ctx.cancel_user = &cancellations; cause = "context canceled"; }
        else if (i == 1) { ctx.deadline_monotonic_ms = 1; cause = "context deadline exceeded"; }
        else { ctx.user_agent = "bad\nagent"; cause = "invalid HTTP user agent"; }
        CHECK(!invoke(d, &http, &ctx, keys, 1, key, strlen(key), &out, &error) && !error);
        CHECK(out.len == 1 && !http.calls && http.releases == 1 && cancellations == (!i ? 1u : 0u));
        finding(&out.items[0], key, false, cause); CHECK(!out.items[0].extra_data); br_results_clear(&out);
    }
    br_result existing = {.verification_error = strdup("keep")};
    char *prior = existing.verification_error;
    CHECK(prior && !br_result_set_verification_error(&existing, NULL, NULL, 0) && existing.verification_error == prior);
    br_result_clear(&existing);
}

static void typed_metadata(const br_detector *d)
{
    const char *zeros[] = {"null", "{}", "{\"name\":null,\"email\":null,\"orgs\":null,\"auth\":null}", "{\"orgs\":[],\"auth\":{\"accessToken\":null,\"type\":null}}"};
    for (size_t i = 0; i < sizeof(zeros) / sizeof(*zeros); ++i)
        json_case(d, text(zeros[i]), NULL, TEXT(""), TEXT(""), TEXT("Unknown Token Type"), NULL, NULL);
    const struct { const char *body, *token; } tokens[] = {
        {"{\"name\":\"user\",\"email\":\"mail\",\"auth\":{\"type\":\"organization\"}}", "organization"},
        {"{\"name\":\"user\",\"email\":\"mail\",\"auth\":{\"type\":\"fallback\",\"accessToken\":{\"displayName\":\"display\"}}}", "display ()"},
        {"{\"name\":\"user\",\"email\":\"mail\",\"auth\":{\"accessToken\":{\"role\":\"read\"}}}", " (read)"},
        {"{\"name\":\"user\",\"email\":\"mail\",\"auth\":{\"accessToken\":{\"displayName\":\"display\",\"role\":\"write\"}}}", "display (write)"},
        {"{\"name\":\"old\",\"name\":\"user\",\"name\":null,\"EMAIL\":\"mail\",\"auth\":{\"accessToken\":{\"displayName\":\"old\",\"role\":\"read\"}},\"AUTH\":{\"ACCESSTOKEN\":{\"DISPLAYNAME\":\"new\",\"role\":null}},\"auth\":null}", "new (read)"},
    };
    for (size_t i = 0; i < sizeof(tokens) / sizeof(*tokens); ++i)
        json_case(d, text(tokens[i].body), NULL, TEXT("user"), TEXT("mail"), text(tokens[i].token), NULL, NULL);
    json_case(d, TEXT("{\"unknown\":1e999999,\"nested\":{\"name\":false,\"x\":99999999999999999999999999999999999}} garbage"), NULL,
              TEXT(""), TEXT(""), TEXT("Unknown Token Type"), NULL, NULL);
    br_slice orgs = TEXT("o\0z:\xef\xbf\xbd");
    json_case(d, TEXT("{\"name\":\"a\\u0000b\",\"email\":\"\xff\",\"auth\":{\"accessToken\":{\"displayName\":\"d\\u0000n\",\"role\":\"\xff\"}},\"orgs\":[{\"name\":\"o\\u0000z\",\"roleInOrg\":\"\xff\"}]}"), NULL,
              TEXT("a\0b"), TEXT("\xef\xbf\xbd"), TEXT("d\0n (\xef\xbf\xbd)"), &orgs, NULL);

    const struct { const char *body, *rows; } organizations[] = {
        {"{\"orgs\":[null]}", ":"},
        {"{\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"read\"},{\"name\":\"a\",\"roleInOrg\":\"read\"},{\"name\":\"b\"}]}", "a:read, a:read, b:"},
        {"{\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"r\"},{\"name\":\"b\",\"roleInOrg\":\"s\"},{\"name\":\"c\",\"roleInOrg\":\"t\"}],\"orgs\":[{\"name\":\"x\"}],\"orgs\":[null,null,{}]}", "x:r, b:s, c:t"},
        {"{\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"r\"},{\"name\":\"b\"}],\"orgs\":[null]}", "a:r"},
        {"{\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"r\"}],\"ORGS\":[{\"NAME\":null,\"ROLEINORG\":\"s\"}]}", "a:s"},
        {"{\"orgs\":[{\"name\":\"a\"},{\"name\":\"hidden\"}],\"orgs\":[null],\"orgs\":[],\"orgs\":[null,null]}", ":, :"},
        {"{\"orgs\":[{\"name\":\"a\"}],\"orgs\":null,\"orgs\":[null]}", ":"},
        {"{\"orgs\":[{\"name\":\"a\"}],\"orgs\":[]}", NULL},
        {"{\"orgs\":[{\"name\":\"a\"}],\"orgs\":null}", NULL},
    };
    for (size_t i = 0; i < sizeof(organizations) / sizeof(*organizations); ++i) {
        br_slice rows = organizations[i].rows ? text(organizations[i].rows) : (br_slice){0};
        json_case(d, text(organizations[i].body), NULL, TEXT(""), TEXT(""), TEXT("Unknown Token Type"), organizations[i].rows ? &rows : NULL, NULL);
    }
    order_len = 0; watch_order = true;
    orgs = TEXT("a:r");
    json_case(d, TEXT("{\"auth\":{\"accessToken\":{\"displayName\":\"d\",\"role\":\"r\"}},\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"r\"}]}"), NULL,
              TEXT(""), TEXT(""), TEXT("d (r)"), &orgs, NULL);
    watch_order = false;
    CHECK(!strcmp(projection_order, "AMUETAAAO"));
}

static void decode_errors(const br_detector *d)
{
    const struct { const char *body, *cause; } cases[] = {
        {"[]", "json: cannot unmarshal array into Go value of type huggingface.whoamiResponse"},
        {"7", "json: cannot unmarshal number into Go value of type huggingface.whoamiResponse"},
        {"{\"name\":7}", TYPE("number", "whoamiResponse.name", "string")},
        {"{\"email\":false}", TYPE("bool", "whoamiResponse.email", "string")},
        {"{\"orgs\":\"x\"}", TYPE("string", "whoamiResponse.orgs", "[]huggingface.organization")},
        {"{\"orgs\":[7]}", TYPE("number", "whoamiResponse.orgs", "huggingface.organization")},
        {"{\"orgs\":[{\"name\":false}]}", TYPE("bool", "organization.orgs.name", "string")},
        {"{\"orgs\":[{\"roleInOrg\":[]}]}", TYPE("array", "organization.orgs.roleInOrg", "string")},
        {"{\"auth\":\"x\"}", TYPE("string", "whoamiResponse.auth", "huggingface.auth")},
        {"{\"auth\":{\"type\":7}}", TYPE("number", "auth.auth.type", "string")},
        {"{\"auth\":{\"accessToken\":false}}", TYPE("bool", "auth.auth.accessToken", "struct { DisplayName string \"json:\\\"displayName,omitempty\\\"\"; Role string \"json:\\\"role,omitempty\\\"\" }")},
        {"{\"auth\":{\"accessToken\":{\"displayName\":{}}}}", TYPE("object", ".auth.accessToken.displayName", "string")},
        {"{\"auth\":{\"accessToken\":{\"role\":false}}}", TYPE("bool", ".auth.accessToken.role", "string")},
        {"{\"email\":false,\"name\":7,\"orgs\":[false,{\"roleInOrg\":{}}],\"auth\":false}", TYPE("bool", "whoamiResponse.email", "string")},
        {"{\"name\":7,\"name\":\"later\"}", TYPE("number", "whoamiResponse.name", "string")},
        {"", "EOF"}, {" \r\n", "EOF"}, {"{", "unexpected EOF"},
        {"{bad", "invalid character 'b' looking for beginning of object key string"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
        json_case(d, text(cases[i].body), NULL, (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, cases[i].cause);
    json_case(d, TEXT("{} invalid trailing document"), "late failure", TEXT(""), TEXT(""), TEXT("Unknown Token Type"), NULL, NULL);
    json_case(d, TEXT("{\"name\":false}"), "late failure", (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, TYPE("bool", "whoamiResponse.name", "string"));
    json_case(d, TEXT("{"), "read failure", (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, "read failure");
    json_case(d, (br_slice){0}, "", (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, "");
    json_case(d, TEXT("{bad"), "read failure", (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, "invalid character 'b' looking for beginning of object key string");
    json_case(d, TEXT("\"scalar\""), "read failure", (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, "read failure");
    char message[120]; snprintf(message, sizeof(message), "reading %s", key);
    json_case(d, TEXT("{"), message, (br_slice){0}, (br_slice){0}, (br_slice){0}, NULL, "reading [REDACTED]");
}

static void sticky_slice_state(void)
{
    hf_whoami whoami = {0};
    const char *body = "{\"orgs\":[{\"name\":\"a\",\"roleInOrg\":\"r\"},{\"name\":\"hidden\"}],\"orgs\":[null],\"orgs\":false,\"email\":7,\"name\":\"after error\"}";
    br_json *root = NULL; char *cause = NULL; size_t end = 0;
    CHECK(!br_json_first_document(text(body), NULL, &root, &end, &cause) && !cause);
    CHECK(!br_json_each_member((br_slice){(const unsigned char *)body, end}, hf_root_member, &whoami));
    json_object_put(root);
    CHECK(whoami.logical_len == 1 && whoami.backing_cap >= 2);
    CHECK(whoami.orgs[1].name.text.len == 6 && !memcmp(whoami.orgs[1].name.text.data, "hidden", 6));
    CHECK(whoami.name.text.len == 11 && !memcmp(whoami.name.text.data, "after error", 11));
    CHECK(whoami.cause && !strcmp(whoami.cause, TYPE("bool", "whoamiResponse.orgs", "[]huggingface.organization")));
    hf_whoami_clear(&whoami);
}

static void resource_failures(const br_detector *d)
{
    const char *body = "{\"name\":\"user\",\"auth\":{\"accessToken\":{\"displayName\":\"display\",\"role\":\"read\"}},\"orgs\":[{\"name\":\"organization\",\"roleInOrg\":\"role\"}]}";
    const struct { fault_kind kind; size_t nth, size; const char *body; int status; bool nov, nil; } cases[] = {
        {CAPTURES, 1, 0, NULL, 200, false, false}, {FINDING, 1, 0, NULL, 200, false, false},
        {DOCUMENT, 1, 0, NULL, 200, false, false}, {MEMBER, 1, 0, NULL, 200, false, false},
        {ELEMENT, 1, 0, NULL, 200, false, false}, {CODEC, 1, 0, NULL, 200, false, false},
        {RETAIN, 1, 0, NULL, 200, false, false}, {GROW, 1, 0, NULL, 200, false, false},
        {TYPE_CAUSE, 1, 0, "{\"name\":false}", 200, false, false},
        {MAP, 1, 0, NULL, 200, false, false}, {STRING, 1, 0, NULL, 200, false, false},
        {INSERT, 1, 0, NULL, 200, false, false}, {INSERT, 4, 0, NULL, 200, false, false},
        {ALLOCATION, 1, 15, NULL, 200, false, false}, /* display (read) + NUL */
        {ALLOCATION, 1, sizeof(br_bytes), NULL, 200, false, false}, /* rows collection */
        {ALLOCATION, 2, 0, "{\"orgs\":[{\"name\":\"a\"}]}", 200, false, false}, /* row */
        {ALLOCATION, 3, 0, "{\"orgs\":[{\"name\":\"a\"}]}", 200, false, false}, /* join */
        {CAUSE, 1, 0, NULL, 503, false, false}, {STATUS_FORMAT, 1, 0, NULL, 503, false, false},
        {SETTER, 1, 0, NULL, 200, false, false}, {SETTER, 1, 0, "{", 200, false, false},
        {SETTER, 1, 0, NULL, 200, false, true}, /* checked even for nil constructor's nil cause */
        {PUSH, 1, 0, NULL, 200, false, false}, {PUSH, 2, 0, NULL, 200, true, false},
        {FINDING, 2, 0, NULL, 200, true, false},
        {CODEC, 1, 0, "{\"name\":false,\"email\":\"later\"}", 200, false, false},
        {RETAIN, 1, 0, "{\"name\":false,\"email\":\"later\"}", 200, false, false},
        {GROW, 1, 0, "{\"name\":false,\"orgs\":[7]}", 200, false, false},
        {GROW, 2, 0, "{\"orgs\":[false,false]}", 200, false, false},
    };
    char input[100]; int n = snprintf(input, sizeof(input), "%s %s", key, other);
    const char *keys[] = {key, other};
    br_results out = {0}; br_result prior = {.verified = true};
    CHECK(!br_finding_key(&prior, 777, "caller", "key"));
    prior.verified = true; prior.verification_error = strdup("untouched");
    CHECK(prior.verification_error && !br_results_push(&out, &prior));
    br_result saved = out.items[0];
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        size_t failed = failures, sent = sends, released = releases, set = setters;
        test_http http = {.response = {.status = cases[i].status, .body = text(cases[i].body ? cases[i].body : body)}};
        br_scan_ctx ctx = {0}; char *error = NULL;
        fault = cases[i].kind; fail_nth = cases[i].nth; fail_size = cases[i].size;
        int rc;
        if (cases[i].nov || cases[i].nil)
            rc = d->scan(d, NULL, !cases[i].nov, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error);
        else rc = invoke(d, &http, &ctx, keys, 2, input, (size_t)n, &out, &error);
        CHECK(rc == -1 && error && fault == NONE && failures == failed + 1);
        CHECK(out.len == 1 && !memcmp(&out.items[0], &saved, sizeof(saved)));
        CHECK(sends - sent == releases - released && !provider_request);
        if (cases[i].kind != SETTER && cases[i].kind != PUSH) CHECK(setters == set);
        free(error); fail_size = 0;
    }
    br_results_clear(&out);
}

int main(void)
{
    memcpy(key, "hf_", 3); test_secret(key + 3, 34, 0); key[3] = 'A'; key[12] = 'Z';
    memcpy(org_key, "api_org_", 8); test_secret(org_key + 8, 34, 7); org_key[8] = 'Q';
    memcpy(other, "hf_", 3); test_secret(other + 3, 34, 13);
    const br_detector *d = descriptor();
    extraction(d);
    requests_and_statuses(d);
    constructor_and_preparation(d);
    typed_metadata(d);
    decode_errors(d);
    sticky_slice_state();
    resource_failures(d);
    CHECK(!provider_request && sends == releases && fault == NONE);
    return test_finish("HuggingFace");
}
