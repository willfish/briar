/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/gcp_oauth.h"
#include "../../src/go_url.h"
#include "../../src/go_unicode.h"
#include "../../src/utf8.h"
#include "../support/detector_test.h"

int br_microsoftteamswebhook_v1_init(const br_detector **out, char **error);
int br_microsoftteamswebhook_v2_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key1[400], key1b[400], key2[500], key2b[500];
static const char base2[] = "https://defaultabc.7.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke";
typedef enum { NONE, COMPILE, CAPTURE, RAW_PUSH, UNIQUE, FINDING, OBJECT, STRING, ADD, ALLOCATE, PARSE, DECODE, QUOTE, SETTER, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, freed_patterns, captures, raw_pushes, uniques, findings, objects, parses, decodes, quotes, sends, releases, setters;
static int version;
static bool desired_verified, auto_request = true, watch, inspect_binary;
static br_slice expected_request, expected_binary;
static const char *expected_agent = "TruffleHog";
static br_result *active_result;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static unsigned char *last_allocation;
static size_t last_allocation_size;
static char events[160];
static size_t nevents;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
/* Existing named-test local seams inject synthetic bytes and explicit owned
 * failures. No live webhook, verdict backend or production test configuration. */
static void *checked_malloc(size_t n)
{
    if (hit(ALLOCATE)) return NULL;
    last_allocation = malloc(n); last_allocation_size = n; return last_allocation;
}
static int checked_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(!strncmp(pattern, "(https:", 7) && !strstr(pattern, "(?i") && !strstr(pattern, "{0,40}"));
    int rc = br_regex_compile(pattern, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *r, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !active_result); ++captures; event('C');
    int rc = br_captures_find(r, input, out, unique, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_each(const br_regex *r, br_slice input, br_match_fn fn, void *user, char **error)
{
    CHECK(version == 2 && !active_result && !provider_request); ++captures; event('C');
    int rc = br_regex_each(r, input, fn, user, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_unique(br_captures *out, br_slice value, bool unique, char **error)
{
    CHECK(version == 2 && !active_result && !provider_request);
    if (unique) { ++uniques; event('U'); } else { ++raw_pushes; event('B'); }
    int rc = br_captures_push(out, value, unique, error);
    return rc == 0 && hit(unique ? UNIQUE : RAW_PUSH) ? 1 : rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice key, const char *part)
{
    CHECK(!active_result && !provider_request && type == 114); active_result = r; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r) { if (r == active_result) active_result = NULL; br_result_clear(r); }
static br_json *checked_object(void)
{
    CHECK(active_result && active_result->raw.len && !active_result->extra_data); ++objects; event('X');
    return hit(OBJECT) ? NULL : json_object_new_object();
}
static br_json *checked_string(const char *s)
{
    CHECK(active_result && active_result->extra_data);
    return hit(STRING) ? NULL : json_object_new_string(s);
}
static int checked_add(br_json *object, const char *key, br_json *value)
{
    CHECK(active_result && object == active_result->extra_data && value);
    return hit(ADD) ? 1 : json_object_object_add(object, key, value);
}
static int checked_parse(br_slice original, br_go_url_parts *out, br_go_url_error *ordinary, char **error)
{
    CHECK(active_result && active_result->extra_data && !provider_request); ++parses; event('A');
    int rc = br_go_url_parse(original, out, ordinary, error);
    if (rc == 0 && hit(PARSE)) { ordinary->kind = BR_GO_URL_CONTROL; return 1; }
    return rc;
}
static int checked_decode(br_slice raw, bool query, br_bytes *out, bool *valid, char **error)
{
    CHECK(active_result && !query && !provider_request); ++decodes;
    int rc = br_go_url_decode(raw, query, out, valid, error);
    if (rc == 0 && hit(DECODE)) { *valid = false; return 1; }
    return rc;
}
static int checked_quote(br_slice raw, unsigned char *out, size_t capacity, size_t *written, char **error)
{
    CHECK(active_result && !provider_request); ++quotes;
    int rc = br_gcp_oauth_quote(raw, out, capacity, written, error);
    return rc == 0 && hit(QUOTE) ? 1 : rc;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_result->extra_data && !active_result->verified && !active_result->verification_error);
    br_slice wanted = auto_request ? (br_slice){active_result->raw.data, active_result->raw.len} : expected_request;
    CHECK(strlen(r->url) == wanted.len && !memcmp(r->url, wanted.data, wanted.len));
    CHECK(!strcmp(r->method, "POST") && r->detector_type == 114 && r->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(r->timeout_ms == (effective ? 10000u : 0u) && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->body.len == 11 && !memcmp(r->body.data, version == 1 ? "{'text':''}" : "{\"text\":\"\"}", 11));
    CHECK(r->nheaders == (effective ? 2u : 1u) && !strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json"));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request); request_values(request, false); provider_request = request; provider_ctx = ctx;
    ++sends; event('H'); return br_http_send(ctx, request, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_ctx); request_values(provider_request, false);
    if (inspect_binary) {
        static const char prefix[] = "unexpected response body: ";
        CHECK(last_allocation && last_allocation_size == sizeof(prefix) + expected_binary.len);
        CHECK(!memcmp(last_allocation, prefix, sizeof(prefix) - 1));
        CHECK(!memcmp(last_allocation + sizeof(prefix) - 1, expected_binary.data, expected_binary.len));
        CHECK(last_allocation[last_allocation_size - 1] == 0); inspect_binary = false;
    }
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_ctx = NULL;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t n)
{
    CHECK(r == active_result && r->verified == desired_verified && !provider_request && sends == releases);
    CHECK(r->extra_data && n == 1 && secrets && secrets[0].len == r->raw.len && !memcmp(secrets[0].data, r->raw.data, r->raw.len));
    ++setters; event('S');
    return hit(SETTER) ? 1 : br_result_set_verification_error(r, cause, secrets, n);
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(r == active_result && r->extra_data && !provider_request && sends == releases); event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
#define malloc checked_malloc
#define br_regex_compile checked_compile
#define br_regex_free checked_free
#define br_regex_each checked_each
#define br_captures_find checked_capture
#define br_captures_push checked_unique
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define json_object_new_object checked_object
#define json_object_new_string checked_string
#define json_object_object_add checked_add
#define br_go_url_parse checked_parse
#define br_go_url_decode checked_decode
#define br_gcp_oauth_quote checked_quote
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#include "../../src/detectors/microsoftteamswebhook.c"
#undef malloc
#undef br_regex_compile
#undef br_regex_free
#undef br_regex_each
#undef br_captures_find
#undef br_captures_push
#undef br_finding_key_bytes
#undef br_result_clear
#undef json_object_new_object
#undef json_object_new_string
#undef json_object_object_add
#undef br_go_url_parse
#undef br_go_url_decode
#undef br_gcp_oauth_quote
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    version = d->version; return test_scan(d, ctx, verify, input.data, input.len);
}
static const br_detector *descriptor(int v)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    int (*init)(const br_detector **, char **) = v == 1 ? br_microsoftteamswebhook_v1_init : br_microsoftteamswebhook_v2_init;
    CHECK(BR_ABI_REVISION == 1 && init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(init(NULL, NULL) == -1); fault = COMPILE; fail_nth = 1; size_t freed = freed_patterns;
    CHECK(init(&d, &error) == -1 && error && !d && fault == NONE && freed_patterns == freed + 1); free(error); error = NULL;
    CHECK(!init(&d, &error) && d && !error && !init(&again, NULL) && again == d);
    CHECK(d->type == 114 && d->version == v && !strcmp(d->name, "MicrosoftTeamsWebhook") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, v == 1 ? "Microsoft Teams Webhooks allow external services to communicate with Teams channels by sending messages to a unique URL." : "Microsoft Teams Webhooks (Power Automate) allow external services to communicate with Teams channels by sending messages to a unique Power Automate workflow URL."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], v == 1 ? "webhook.office.com" : "environment.api.powerplatform.com"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == (v == 1 ? 1024 : -1));
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->validate_endpoints && !d->cloud_endpoint);
    if (v == 1) CHECK(!d->false_positive);
    else { char *reason = (char *)"unchanged"; br_result arbitrary = {0}; CHECK(d->false_positive && !d->false_positive(d, &arbitrary, &reason) && !reason); CHECK(!d->false_positive(NULL, NULL, NULL)); }
    return d;
}
static void result_is(const br_result *r, br_slice key, bool verified, const char *cause)
{
    CHECK(r->detector_type == 114 && r->verified == verified && !r->detector_name);
    CHECK(r->raw.len == key.len && !memcmp(r->raw.data, key.data, key.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *value = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &value));
    CHECK(json_object_is_type(value, json_type_string) && (size_t)json_object_get_string_len(value) == key.len && !memcmp(json_object_get_string(value), key.data, key.len));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == (version == 1 ? 2 : 1));
    CHECK(json_object_object_get_ex(r->extra_data, "version", &value) && !strcmp(json_object_get_string(value), version == 1 ? "1" : "2"));
    if (version == 1) CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &value) && !strcmp(json_object_get_string(value), "https://howtorotate.com/docs/tutorials/microsoftteams/"));
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}
static void extract(const br_detector *d, br_slice input, const br_slice *expected, size_t count)
{
    size_t sent = sends, set = setters, parsed = parses; br_results out = scan(d, NULL, false, input);
    CHECK(out.len == count && sends == sent && setters == set && parses == parsed && !active_result);
    for (size_t i = 0; i < count; ++i) {
        size_t found = 0;
        for (size_t j = 0; j < out.len; ++j) if (out.items[j].raw.len == expected[i].len && !memcmp(out.items[j].raw.data, expected[i].data, expected[i].len)) ++found;
        CHECK(found == (version == 1 && count == 3 && i != 1 ? 2u : 1u));
        if (version == 1) result_is(&out.items[i], expected[i], false, NULL);
        else {
            for (size_t j = 0; j < out.len; ++j) if (out.items[j].raw.len == expected[i].len && !memcmp(out.items[j].raw.data, expected[i].data, expected[i].len)) result_is(&out.items[j], expected[i], false, NULL);
        }
    }
    br_results_clear(&out);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(provider_request && ctx == provider_ctx); request_values(r, true);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static br_results response(const br_detector *d, br_slice key, int status, br_slice body, const char *read,
                            const char *send_error, int send_rc, bool verified)
{
    desired_verified = verified;
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_error = send_error, .send_rc = send_rc};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t sent = sends, released = releases, set = setters;
    nevents = 0; events[0] = 0; watch = true; br_results out = scan(d, &ctx, true, key); watch = false;
    CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && setters == set + 1 && http.calls == 1 && http.releases == 1);
    CHECK(!strcmp(events, version == 1 ? "CFXAHRSP" : "CBUFXAHRSP"));
    return out;
}
static void v1_grammar(const br_detector *d)
{
    br_slice expected = text(key1); extract(d, expected, &expected, 1);
    char input[2000]; snprintf(input, sizeof(input), "before%sAFTER", key1); extract(d, text(input), &expected, 1);
    const char *needles[] = {"https:", "webhook.office.com", "IncomingWebhook"};
    for (size_t i = 0; i < 3; ++i) { strcpy(input, key1); char *p = strstr(input, needles[i]); CHECK(p); p[0] = p[0] == 'I' ? 'i' : (char)(p[0] - 'a' + 'A'); extract(d, text(input), NULL, 0); }
    strcpy(input, key1); char *host = strstr(input, "Z--9"); CHECK(host); host[1] = '_'; extract(d, text(input), NULL, 0);
    snprintf(input, sizeof(input), "%s\n%s\n%s", key1, key1b, key1);
    br_slice values[] = {text(key1), text(key1b), text(key1)}; extract(d, text(input), values, 3);
    char *long_key = malloc(strlen(key1) + 1500); CHECK(long_key);
    memcpy(long_key, "https://", 8); memset(long_key + 8, 'Z', 1400); strcpy(long_key + 1408, key1 + 8);
    expected = text(long_key); extract(d, expected, &expected, 1); free(long_key);
}
static void v2_grammar(const br_detector *d)
{
    br_slice expected = text(key2); extract(d, expected, &expected, 1);
    char input[2000], changed[600];
    const char *queries[] = {"?sig=A.", "?x=1#fragment&sig=A", "?x=1?sig=A", "?sig=1-_%bad", "?sig=%41&sig=B"};
    for (size_t i = 0; i < sizeof(queries) / sizeof(*queries); ++i) { snprintf(changed, sizeof(changed), "%s%s", base2, queries[i]); expected = text(changed); extract(d, expected, &expected, 1); }
    const char *bad[] = {"?SIG=A", "?sig=", "?sig=%41", "?x=1", "?signature=A", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(changed, sizeof(changed), "%s%s", base2, bad[i]); extract(d, text(changed), NULL, 0); }
    const char *needles[] = {"https:", "defaultabc", "0123456789abcdef", "manual"};
    for (size_t i = 0; i < sizeof(needles) / sizeof(*needles); ++i) { strcpy(changed, key2); char *p = strstr(changed, needles[i]); CHECK(p); p[0] = i == 2 ? 'g' : 'X'; extract(d, text(changed), NULL, 0); }
    const unsigned char delimiters[] = {' ', '\t', '\r', '\n', '\f', '"', '\'', '<', '>'};
    for (size_t i = 0; i < sizeof(delimiters); ++i) { snprintf(input, sizeof(input), "%s%cx", key2, delimiters[i]); expected = text(key2); extract(d, text(input), &expected, 1); }
    snprintf(input, sizeof(input), "%s\v\n%s\302\240\n%s\342\200\203\n%s\n%s", key2, key2, key2, key2, key2b);
    br_slice values[] = {text(key2), text(key2b)}; extract(d, text(input), values, 2);
    snprintf(changed, sizeof(changed), "%s\342\200\213", key2); expected = text(changed); extract(d, expected, &expected, 1);
    /* Strict Go TrimSpace is distinct from RE2's permissive query units.
     * Never replace an invalid original byte with RuneError. */
    const unsigned char suffix[] = {'x', 0xff, 0xc2, 0xa0, '\v'};
    br_slice trimmed = teams_trim((br_slice){suffix, sizeof(suffix)}); CHECK(trimmed.len == 2 && trimmed.data[1] == 0xff);
    snprintf(input, sizeof(input), "%s:999999%s", "https://defaultabc.7.environment.api.powerplatform.com", strstr(base2, "/powerautomate"));
    strcat(input, "?sig=A"); expected = text(input); extract(d, expected, &expected, 1);
}
static void query_units_and_progression(const br_detector *d)
{
    const struct { unsigned char bytes[4]; size_t len; } allowed[] = {
        {{0},1}, {{0x0b},1}, {{0x7f},1}, {{0xc2,0x80},2},
        {{0xe0,0x80,0xa0},3}, {{0xed,0xa0,0x80},3}, {{0xf0,0x80,0x80,0xa0},4},
        {{0xf4,0x90,0x80,0x80},4}, {{0xf4,0xbf,0xbf,0xbf},4}, {{0xf0,0x9f,0x92,0xa1},4},
    };
    const struct { unsigned char bytes[4]; size_t len; } barriers[] = {
        {{0xff},1}, {{0x80},1}, {{0xc0},1}, {{0xc1},1}, {{0xf5,0x80,0x80,0x80},4},
        {{0xc2},1}, {{0xe0,0x80},2}, {{0xf0,0x80,0x80},3}, {{0xc2,'x'},2},
    };
    unsigned char input[2400]; size_t key_len = strlen(key2);
    for (size_t i = 0; i < sizeof(allowed) / sizeof(*allowed); ++i) {
        memcpy(input, key2, key_len); memcpy(input + key_len, allowed[i].bytes, allowed[i].len);
        input[key_len + allowed[i].len] = 'x';
        br_slice whole = {input, key_len + allowed[i].len + 1}; extract(d, whole, &whole, 1);
        if (i >= 4 && i <= 8) {
            /* Permissive units encoding overlong ASCII SPACE/surrogates/above
             * max are matched, but STRICT Go trimming keeps their bytes. */
            memcpy(input + key_len + allowed[i].len, "\302\240\v", 3);
            whole.len = key_len + allowed[i].len + 3;
            br_slice expected = {input, key_len + allowed[i].len}; extract(d, whole, &expected, 1);
        }
    }
    for (size_t i = 0; i < sizeof(barriers) / sizeof(*barriers); ++i) {
        memcpy(input, key2, key_len); memcpy(input + key_len, barriers[i].bytes, barriers[i].len);
        br_slice expected = text(key2); extract(d, (br_slice){input, key_len + barriers[i].len}, &expected, 1);
        size_t n = (size_t)snprintf((char *)input, sizeof(input), "%s?", base2);
        memcpy(input + n, barriers[i].bytes, barriers[i].len); n += barriers[i].len;
        memcpy(input + n, "&sig=A", 6); n += 6;
        extract(d, (br_slice){input, n}, NULL, 0);
    }
    size_t n = (size_t)snprintf((char *)input, sizeof(input), "%s?", base2);
    input[n++] = 0xff; memcpy(input + n, key2, key_len); n += key_len;
    br_slice expected = text(key2); extract(d, (br_slice){input, n}, &expected, 1); /* Failed query1+ consumes nothing. */
    char nested[2400];
    snprintf(nested, sizeof(nested), "%s&next=%s", key2, key2b);
    expected = text(nested); size_t pushed = raw_pushes;
    extract(d, expected, &expected, 1); CHECK(raw_pushes == pushed + 1);
    snprintf(nested, sizeof(nested), "%s?x=1&next=%s", base2, key2b);
    expected = text(nested); pushed = raw_pushes;
    extract(d, expected, &expected, 1); CHECK(raw_pushes == pushed + 1); /* Signature only in the nested spelling. */
    snprintf(nested, sizeof(nested), "%s?x=1&next=%s?y=2", base2, base2);
    pushed = raw_pushes; size_t unique = uniques, found = findings;
    fault = RAW_PUSH; fail_nth = 2;
    extract(d, text(nested), NULL, 0);
    CHECK(raw_pushes == pushed + 1 && uniques == unique && findings == found && fault == RAW_PUSH && fail_nth == 1);
    fault = NONE; /* Untrimmed consumed-end still advances for a no-sig match. */
}
static void policies(const br_detector *d)
{
    br_slice key = text(d->version == 1 ? key1 : key2);
    const int statuses[] = {-1, 0, 199, 200, 201, 202, 204, 299, 300, 400, 401, 403, 499, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        bool verified = d->version == 1 ? statuses[i] == 400 : statuses[i] == 202;
        const char *cause = NULL; char error[100];
        if ((d->version == 1 && (statuses[i] < 200 || statuses[i] >= 500)) ||
            (d->version == 2 && statuses[i] != 202 && statuses[i] != 400 && statuses[i] != 401)) {
            snprintf(error, sizeof(error), d->version == 1 ? "unexpected HTTP response status: %d" : "unexpected HTTP response status %d", statuses[i]); cause = error;
        }
        br_results out = response(d, key, statuses[i], TEXT("prefix Text is required suffix"), NULL, NULL, 0, verified);
        result_is(&out.items[0], key, verified, cause); br_results_clear(&out);
        const char *read = "read failure";
        out = response(d, key, statuses[i], TEXT("Text is required"), read, NULL, 0, d->version == 2 && statuses[i] == 202);
        result_is(&out.items[0], key, d->version == 2 && statuses[i] == 202, d->version == 1 ? read : cause); br_results_clear(&out);
    }
    const char *errors[] = {"failed to make request: keep literal leaf", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        br_results out = response(d, key, 400, TEXT("Text is required"), "ignored", errors[i], i % 2 ? -7 : 1, false);
        result_is(&out.items[0], key, false, errors[i] ? errors[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    char error[1000]; snprintf(error, sizeof(error), "visit %.*s twice %.*s sig=SYNTHETIC_key-9", (int)key.len, (const char *)key.data, (int)key.len, (const char *)key.data);
    br_results out = response(d, key, 202, TEXT(""), NULL, error, 1, false);
    result_is(&out.items[0], key, false, "visit [REDACTED] twice [REDACTED] sig=SYNTHETIC_key-9"); br_results_clear(&out);
    if (d->version == 1) {
        out = response(d, key, 400, TEXT("text is required"), NULL, NULL, 0, false);
        result_is(&out.items[0], key, false, "unexpected response body: text is required"); br_results_clear(&out);
        const unsigned char binary[] = {'x', 0, 'T','e','x','t',' ','i','s',' ','r','e','q','u','i','r','e','d', 0xff};
        out = response(d, key, 400, (br_slice){binary, sizeof(binary)}, NULL, NULL, 0, true); result_is(&out.items[0], key, true, NULL); br_results_clear(&out);
        out = response(d, key, 200, TEXT(""), "", NULL, 0, false); result_is(&out.items[0], key, false, ""); br_results_clear(&out);
        out = response(d, key, 400, TEXT(""), NULL, NULL, 0, false); result_is(&out.items[0], key, false, "unexpected response body: "); br_results_clear(&out);
    } else {
        out = response(d, key, 202, (br_slice){NULL, SIZE_MAX}, "ignored invalid buffered slice", NULL, 0, true); result_is(&out.items[0], key, true, NULL); br_results_clear(&out);
    }
}
static void constructor_case(const br_detector *d, br_slice raw, const char *projected, const char *cause, bool nil)
{
    test_http http = {.inspect = inspect, .response = {.status = 202}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    bool sent = !nil && !cause; desired_verified = sent; auto_request = projected == NULL;
    if (projected) expected_request = text(projected);
    size_t send = sends, release = releases, set = setters, parsed = parses;
    br_results out = scan(d, nil ? NULL : &ctx, true, raw);
    CHECK(out.len == 1 && sends == send + (sent ? 1u : 0u) && releases == release + (sent ? 1u : 0u) && setters == set + 1);
    CHECK(parses == parsed + (nil ? 0u : 1u)); result_is(&out.items[0], raw, sent, nil ? "net/http: nil Context" : cause);
    br_results_clear(&out); auto_request = true;
}
static void constructors(const br_detector *one, const br_detector *two)
{
    desired_verified = false; size_t sent = sends, set = setters; br_results out = scan(one, NULL, true, text(key1));
    CHECK(out.len == 1 && sends == sent && setters == set + 1); result_is(&out.items[0], text(key1), false, "net/http: nil Context"); br_results_clear(&out);
    constructor_case(two, text(key2), NULL, NULL, true);
    char raw[800], projected[1000];
    const struct { const char *fragment, *projection; } cases[] = {
        {"#abc[]%7e%2f", "#abc[]%7e%2f"}, {"#abc[]%7e%2f#x", "#abc%5B%5D~/%23x"},
        {"#é[]%7e#x", "#%C3%A9%5B%5D~%23x"}, {"#a\vb", "#a%0Bb"}, {"#a\177b", "#a%7Fb"}, {"#", ""},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(raw, sizeof(raw), "%s&x=+%%2f%%zz%s", key2, cases[i].fragment);
        snprintf(projected, sizeof(projected), "%s&x=+%%2f%%zz%s", key2, cases[i].projection);
        constructor_case(two, text(raw), projected, NULL, false);
    }
    size_t n = (size_t)snprintf(raw, sizeof(raw), "%s#x", key2); raw[n++] = 0; memcpy(raw + n, "tail", 4); n += 4;
    snprintf(projected, sizeof(projected), "%s#x%%00tail", key2); constructor_case(two, (br_slice){(const unsigned char *)raw, n}, projected, NULL, false);
    n = (size_t)snprintf(raw, sizeof(raw), "%s", key2); raw[n++] = 0; raw[n++] = 'x';
    br_slice original = {(const unsigned char *)raw, n}; extract(two, original, &original, 1);
    constructor_case(two, original, NULL, "net/url: invalid control character in URL", false);
    constructor_case(two, original, NULL, NULL, true);
    snprintf(raw, sizeof(raw), "%s\vx", key2); constructor_case(two, text(raw), NULL, "net/url: invalid control character in URL", false);
    snprintf(raw, sizeof(raw), "%s#%%zz", key2); constructor_case(two, text(raw), NULL, "invalid URL escape \"%zz\"", false);
    snprintf(raw, sizeof(raw), "%s#%%", key2); constructor_case(two, text(raw), NULL, "invalid URL escape \"%\"", false);
    n = (size_t)snprintf(raw, sizeof(raw), "%s#%%", key2); raw[n++] = 0; raw[n++] = 'x';
    constructor_case(two, (br_slice){(const unsigned char *)raw, n}, NULL, "invalid URL escape \"%\\x00x\"", false);
    snprintf(raw, sizeof(raw), "%s#%%é", key2); constructor_case(two, text(raw), NULL, NULL, true);
    desired_verified = false; test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results caller = {0}; char *error = NULL; size_t quote = quotes; sent = sends; set = setters; version = 2;
    CHECK(two->scan(two, &ctx, true, text(raw), &caller, &error) == -1 && error && strstr(error, "non-ASCII") && quotes == quote + 1);
    CHECK(!caller.len && sends == sent && setters == set); free(error); br_results_clear(&caller);
    /* Actual source-selected surrogate/overlong units remain ORIGINAL bytes.
     * Fragment projection escapes them; RawQuery is not normalized at all. */
    n = (size_t)snprintf(raw, sizeof(raw), "%s#x", key2); memcpy(raw + n, "\355\240\200y", 4); n += 4;
    original = (br_slice){(const unsigned char *)raw, n}; extract(two, original, &original, 1);
    snprintf(projected, sizeof(projected), "%s#x%%ED%%A0%%80y", key2); constructor_case(two, original, projected, NULL, false);
    n = (size_t)snprintf(raw, sizeof(raw), "%s", key2); memcpy(raw + n, "\360\200\200\240&x=+%zz", 11); n += 11; raw[n] = 0;
    original = (br_slice){(const unsigned char *)raw, n}; extract(two, original, &original, 1); constructor_case(two, original, NULL, NULL, false);
}
static bool cancelled(void *u) { ++*(size_t *)u; return true; }
static void preparation(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    br_slice key = text(d->version == 1 ? key1 : key2); desired_verified = false;
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t sent = sends, released = releases, set = setters; http.calls = http.releases = 0;
        br_results out = scan(d, &contexts[i], true, key);
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && setters == set + 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], key, false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    http.response = (br_http_response){.status = d->version == 1 ? 400 : 202, .body = TEXT("Text is required")}; http.inspect = inspect;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "teams-offline"}; expected_agent = "TruffleHog teams-offline"; desired_verified = true;
    br_results out = scan(d, &ctx, true, key); CHECK(out.len == 1); result_is(&out.items[0], key, true, NULL); br_results_clear(&out); expected_agent = "TruffleHog";
}
static void owned_failures(const br_detector *d)
{
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0]; version = d->version;
    const struct { fault_kind kind; size_t nth; bool nov, nil; int mode; } cases[] = {
        {CAPTURE,1,true,true,0}, {RAW_PUSH,1,true,true,4}, {UNIQUE,2,true,true,0}, {FINDING,1,false,true,0}, {FINDING,2,true,true,0},
        {OBJECT,1,false,true,0}, {STRING,1,true,true,0}, {ADD,1,false,true,0}, {ADD,2,true,true,0},
        {PARSE,1,false,false,0}, {PARSE,2,false,false,0}, {ALLOCATE,1,false,true,0}, {ALLOCATE,2,false,true,0},
        {ALLOCATE,1,false,false,1}, {ALLOCATE,2,false,false,1}, {SETTER,1,false,false,0}, {SETTER,2,false,false,0},
        {SETTER,1,false,true,0}, {SETTER,1,false,false,1}, {PUSH,2,false,false,0}, {PUSH,2,true,true,0},
        {DECODE,1,false,false,2}, {QUOTE,1,false,false,3}, {QUOTE,2,false,false,3}, {ALLOCATE,1,false,false,2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        if ((cases[i].kind == RAW_PUSH || cases[i].kind == UNIQUE || cases[i].kind == DECODE || cases[i].kind == QUOTE || cases[i].mode == 2 ||
             (cases[i].kind == ALLOCATE && cases[i].nth == 2)) && version == 1) continue;
        if (cases[i].kind == ADD && cases[i].nth == 2 && version == 2) continue;
        char input[1600]; snprintf(input, sizeof(input), "%s%s\n%s%s", version == 1 ? key1 : key2, cases[i].mode == 2 ? "#x#y" : cases[i].mode == 3 ? "#%zz" : "", version == 1 ? key1b : key2b, cases[i].mode == 2 ? "#x#y" : cases[i].mode == 3 ? "#%zz" : "");
        if (cases[i].mode == 4) snprintf(input, sizeof(input), "%s?x=no-signature", base2);
        test_http http = {.inspect = inspect, .response = {.status = version == 1 ? 400 : 202, .body = TEXT("Text is required")}, .send_rc = cases[i].mode == 1 ? 1 : 0, .send_error = cases[i].mode == 1 ? "synthetic Do error" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        fault = cases[i].kind; fail_nth = cases[i].nth; desired_verified = !cases[i].nil && cases[i].mode != 1;
        if (cases[i].mode == 3) desired_verified = false;
        size_t failed = failures, sent = sends, released = releases; char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, !cases[i].nov, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && failures == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request && !active_result);
        if (cases[i].nov || cases[i].nil) CHECK(sends == sent);
        free(error);
    }
    if (version == 1) {
        const unsigned char body[] = {'a', 0, 'b', 0xff}; expected_binary = (br_slice){body, sizeof(body)}; inspect_binary = true;
        test_http http = {.inspect = inspect, .response = {.status = 400, .body = expected_binary}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        char *error = NULL; size_t sent = sends, set = setters;
        CHECK(d->scan(d, &ctx, true, text(key1), &out, &error) == -1 && error && strstr(error, "byte-length storage"));
        CHECK(!inspect_binary && sends == sent + 1 && setters == set && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); free(error);
    }
    char *error = NULL; CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL,1}, &out, &error) == -1 && error); free(error);
    fault = FINDING; fail_nth = 1; CHECK(d->scan(d, NULL, false, text(version == 1 ? key1 : key2), &out, NULL) == -1 && fault == NONE);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    char uuid[37], token[33]; memset(uuid, 'G', 36); uuid[36] = 0; uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-'; uuid[3] = '-'; uuid[0] = 'z';
    memset(token, 'Z', 32); token[32] = 0; token[2] = '-';
    snprintf(key1, sizeof(key1), "https://Z--9.webhook.office.com/webhookb2/%s@%s/IncomingWebhook/%s/%s", uuid, uuid, token, uuid);
    strcpy(key1b, key1); key1b[8] = 'Q'; snprintf(key2, sizeof(key2), "%s?api-version=1&sig=SYNTHETIC_key-9", base2); snprintf(key2b, sizeof(key2b), "%s?sig=other", base2);
    const br_detector *one = descriptor(1), *two = descriptor(2);
    v1_grammar(one); v2_grammar(two); query_units_and_progression(two); policies(one); policies(two); constructors(one,two); preparation(one); preparation(two); owned_failures(one); owned_failures(two);
    CHECK(fault == NONE && sends == releases && !active_result && !provider_request && !watch && !inspect_binary);
    return test_finish("MicrosoftTeamsWebhook v1/v2");
}
