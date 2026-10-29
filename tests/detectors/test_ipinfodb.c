/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Use the existing named-test inclusion seam for owned nonzero outcomes and
 * provider-storage lifetime; leave shared preparation and helpers intact. */
static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static size_t checked_find(br_slice, br_slice, size_t);
static int checked_push(br_results *, br_result *);
static int observed_ipinfodb_init(const br_detector **, char **);
static size_t setters;
static inline int forbidden_setter(br_result *r, const char *cause, const br_slice *keys, size_t n)
{
    (void)r; (void)cause; (void)keys; (void)n;
    ++setters;
    CHECK(false);
    return 1;
}
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_slice_find checked_find
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define br_ipinfodb_init observed_ipinfodb_init
#include "../../src/detectors/ipinfodb.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_slice_find
#undef br_results_push
#undef br_result_set_verification_error
#undef br_ipinfodb_init

static char key_a[65], key_b[65];
static const char url_prefix[] = "https://api.ipinfodb.com/v3/ip-country/?key=";
static const char url_suffix[] = "&ip=8.8.8.8&format=json";
static const unsigned char marker[] = "\"statusCode\": \"OK\"";
enum { URL_SIZE = sizeof(url_prefix) - 1 + 64 + sizeof(url_suffix) };
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, urls, url_frees, sends, releases, projections, pushes;
static bool fault_hit, expected_verified, should_project, projected, pushed;
static br_captures *original_keys;
static br_result *candidate;
static br_results *published;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static br_http_response *original_response;
static char *original_url;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_context && !original_response && !original_url);
    fault = NONE; nth = 0; fault_hit = false;
    urls = url_frees = sends = releases = projections = pushes = 0;
    original_keys = NULL; candidate = NULL; published = NULL;
}

static void original_values(void)
{
    CHECK(original_keys && original_url && urls && urls <= original_keys->len);
    CHECK(original_keys->lengths[urls - 1] == 64);
    CHECK(strlen(original_url) == URL_SIZE - 1);
    CHECK(!memcmp(original_url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(original_url + sizeof(url_prefix) - 1, original_keys->items[urls - 1], 64));
    CHECK(!strcmp(original_url + sizeof(url_prefix) - 1 + 64, url_suffix));
    if (original_request) {
        CHECK(original_request->url == original_url && !strcmp(original_request->method, "GET"));
        CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
        CHECK(original_request->detector_type == 530 && !original_request->headers && !original_request->nheaders);
        CHECK(!original_request->body.data && !original_request->body.len);
        CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    }
}

static void *checked_malloc(size_t size)
{
    CHECK(size == URL_SIZE && candidate && candidate->raw.len == 64 && candidate->secret_parts);
    CHECK(!candidate->verified && !candidate->verification_error && !original_url);
    ++urls;
    if (hit(URL)) return NULL;
    original_url = malloc(size);
    return original_url;
}

static void checked_free(void *value)
{
    CHECK(!original_request && !original_context && !original_response);
    if (value && value == original_url) {
        original_values(); original_url = NULL; ++url_frees;
    }
    free(value);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !original_keys);
    original_keys = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 7;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    candidate = result;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 7 : rc;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!original_request && !original_context && !original_response && sends == releases);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    original_request = request; original_context = ctx; original_response = response;
    original_values(); ++sends;
    projected = pushed = false; published = NULL;
    int rc = br_http_send(ctx, request, response, error);
    should_project = rc == 0 && !response->body_error && (response->body.data || !response->body.len);
    expected_verified = should_project && br_slice_find(response->body,
        (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX && response->status >= 200 && response->status < 300;
    return rc;
}

static size_t checked_find(br_slice body, br_slice needle, size_t start)
{
    CHECK(original_request && original_response && should_project && !projected && !pushed);
    CHECK(body.data == original_response->body.data && body.len == original_response->body.len);
    CHECK(needle.len == 18 && !memcmp(needle.data, marker, 18) && !start);
    original_values(); projected = true; ++projections;
    return br_slice_find(body, needle, start);
}

static int checked_push(br_results *out, br_result *result)
{
    ++pushes;
    if (original_request) {
        original_values();
        CHECK(result == candidate && result->verified == expected_verified && !result->verification_error);
        CHECK(projected == should_project && !pushed); pushed = true;
    }
    if (hit(PUSH)) return 7;
    int rc = br_results_push(out, result);
    if (rc == 0 && original_request) published = out;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && response == original_response && sends == releases + 1);
    original_values(); CHECK(projected == should_project);
    if (!fault_hit && should_project) CHECK(pushed);
    const br_result *r = published ? &published->items[published->len - 1] : candidate;
    CHECK(r && r->verified == expected_verified && !r->verification_error && r->raw.len == 64);
    CHECK(!memcmp(r->raw.data, original_keys->items[urls - 1], 64));
    br_http_release(ctx, response);
    original_values();
    original_request = NULL; original_context = NULL; original_response = NULL; ++releases;
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 530 && !d->version && !strcmp(d->name, "IPinfoDB") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "IPinfoDB provides IP address geolocation services. IPinfoDB API keys can be used to access geolocation data for IP addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ipinfodb"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default/native integration belongs to the parent. */
}

static void finding(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 530, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_get_string_len(part) == 64);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding(&out.items[0], key, false);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[320], changed[65];
    const struct { const char *format; bool match; } cases[] = {
        {"ipinfodb '%s'", true}, {"IpInFoDb:%s", true}, {"myIPINFODBsuffix:%s", true},
        {"ipinfodb\r\n%s", true}, {"ipinfodb\r%s", true}, {"ipinfodb\n%s", true},
        {"ipinfodb\t  %s  ", true}, {"ipinfodb-%s-not-a-whole-token", true},
        {"%s", false}, {"%s ipinfodb", false}, {"ipinfo db %s", false},
        {"ipinfodb%s", false}, {"ipinfodb x%s", false}, {"ipinfodb _%s", false},
        {"ipinfodb %s_", false}, {"ipinfodb %s9", false}, {"ipinfodb %.63s", false},
        {"ipinfodb %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "AGZ_-/+=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[32] = invalid[i];
        snprintf(input, sizeof(input), "ipinfodb %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0agxz"; /* No hex-only, randomness, entropy or FP filter. */
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 64); changed[64] = '\0';
        snprintf(input, sizeof(input), "ipinfodb %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ipinfodb", 8); memset(input + 8, '.', gap);
        memcpy(input + 8 + gap, key_a, 64);
        extract_case(d, input, 72 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 8 + 2 * gap, key_a, 64);
        extract_case(d, input, 72 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "ipinfodb%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("IPinfoDB lowercase-alphanumeric/nonhex/prefix 40-41/CR-LF/boundaries/TrimSpace/binary input: 0 failures");
}

typedef struct { const char *const *keys; size_t count; const char *agent; bool invalid_second; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    char expected[URL_SIZE];
    CHECK(snprintf(expected, sizeof(expected), "%s%s%s", url_prefix, script->keys[at], url_suffix) == URL_SIZE - 1);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 530);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    /* Effective request/header-array/synthesized UA is borrowed for send only. */
    if (script->invalid_second && at == 1)
        http->response = (br_http_response){.status = 403, .body = {NULL, 9}};
}

static void occurrences(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "ipinfodb %s\nIPINFODB %s\nipinfodb %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    request_script script = {keys, 3, "TruffleHog ipinfodb-offline", false};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 204, .body = {marker, 18}}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipinfodb-offline"};
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation();
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    puts("IPinfoDB occurrences/duplicates/Raw-key-only metadata/NoV/exact bodyless GET/common UA/no dedup: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "ipinfodb %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog", false};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {marker, 18}};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    static const unsigned char binary[] = "\xff\0not JSON \"statusCode\": \"OK\" trailing";
    const struct { br_slice body; bool verifies; } bodies[] = {
        {{marker, 18}, true}, {text("junk\"statusCode\": \"OK\"suffix"), true}, {{binary, sizeof(binary) - 1}, true},
        {text("{\"statusCode\":\"OK\"}"), false}, {text("{\"statusCode\":  \"OK\"}"), false},
        {text("{\"statusCode\":\t\"OK\"}"), false}, {text("{\"statusCode\":\n\"OK\"}"), false},
        {text("{\"statuscode\": \"OK\"}"), false}, {text("{\"StatusCode\": \"OK\"}"), false},
        {text("{\"statusCode\": \"ok\"}"), false}, {text("statusCode: OK"), false},
        {text("\"statusCode\": \"OK"), false}, {{NULL, 0}, false},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(*bodies); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = bodies[i].body};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, bodies[i].verifies); br_results_clear(&out);
    }
    const struct { int status; br_slice body; const char *cause; } reads[] = {
        {200, {marker, 18}, "partial read"}, {299, {NULL, 9}, ""}, {199, {marker, 18}, "read failed"},
        {401, {marker, 18}, ""}, {500, {NULL, 9}, "read failed"},
    };
    for (size_t i = 0; i < sizeof(reads) / sizeof(*reads); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = reads[i].status, .body = reads[i].body, .body_error = reads[i].cause};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {7, "cannot construct IPinfoDB URL"}, {-7, "out of memory constructing HTTP headers"},
        {1, "invalid IPinfoDB response body slice"}, {1, "net/http: nil Context"},
        {-1, "context canceled"}, {1, "context deadline exceeded"}, {1, key_a}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0; http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = {NULL, 9}};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("IPinfoDB all-status reads/exact 18-byte binary marker/2xx-only/read errors kept false/whole Do ignored/no setter: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "ipinfodb %s\nipinfodb %s", key_a, key_b);
    test_http http = {0}; br_transport transport = test_transport(&http), missing_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        CHECK(sends == 2 && releases == 2 && pushes == 2 && url_frees == 2 && !projections);
        finding(&out.items[0], key_a, false); finding(&out.items[1], key_b, false); br_results_clear(&out);
    }
    CHECK(cancellations == 2);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && urls == 2 && url_frees == 2 && !sends && !pushes); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && !urls && !sends); finding(&out.items[0], key_a, false); finding(&out.items[1], key_b, false);
    br_results_clear(&out);
    puts("IPinfoDB shared setup false-kept/nil constructor full-URL-before-drop/one ordinary release per attempt/provider lifetime: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify,
                        bool nil, int send_rc, const char *read_error, bool invalid_body,
                        const char *message, size_t attempts)
{
    char input[160]; snprintf(input, sizeof(input), "ipinfodb %s\nipinfodb %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    const char *keys[] = {key_a, key_b}; request_script script = {keys, 2, "TruffleHog", invalid_body};
    test_http http = {.inspect = inspect, .user = &script, .send_rc = send_rc,
        .send_error = send_rc ? "cannot create IPinfoDB finding" : NULL,
        .response = {.status = 200, .body = {marker, 18}, .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, text(input), &out, &error) == -1);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && (fault_hit || invalid_body) && !original_request && !original_url);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, NULL, false, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, NULL, false, "cannot create IPinfoDB finding", 0);
    own_failure(d, FINDING, 2, true, false, 0, NULL, false, "cannot create IPinfoDB finding", 1);
    own_failure(d, URL, 1, true, true, 0, NULL, false, "cannot construct IPinfoDB URL", 0);
    own_failure(d, URL, 2, true, true, 0, NULL, false, "cannot construct IPinfoDB URL", 0);
    own_failure(d, URL, 2, true, false, 0, NULL, false, "cannot construct IPinfoDB URL", 1);
    own_failure(d, PUSH, 2, true, false, 0, NULL, false, "cannot append IPinfoDB finding", 2);
    own_failure(d, PUSH, 2, false, false, 0, NULL, false, "cannot append IPinfoDB finding", 0);
    own_failure(d, FINDING, 2, true, false, -7, NULL, false, "cannot create IPinfoDB finding", 1);
    own_failure(d, PUSH, 2, true, false, 0, "", false, "cannot append IPinfoDB finding", 2);
    own_failure(d, NONE, 0, true, false, 0, NULL, true, "invalid IPinfoDB response body slice", 2);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !urls && !sends);
    puts("IPinfoDB owned capture/finding/URL/body-projection/push nonzero fatal before ordinary outcomes/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    test_secret(key_a, 64, 0); test_secret(key_b, 64, 17);
    CHECK(BR_ABI_REVISION == 1 && sizeof(marker) - 1 == 18 && strlen(key_a) == 64 && strlen(key_b) == 64);
    const br_detector *d = descriptor(br_ipinfodb_init);
    grammar(d); occurrences(d); response_policy(d);
    const br_detector *observed = descriptor(observed_ipinfodb_init);
    reset_observation(); occurrences(observed); response_policy(observed);
    setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_response && !original_url && !setters && fault == NONE);
    return test_finish("IPinfoDB ABI1 focused checks");
}
