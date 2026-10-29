/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_kanban_init(const br_detector **out, char **error);

static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_kanban_init observed_kanban_init
#include "../../src/detectors/kanban.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_kanban_init

static const char key_a[] = "11XQ98FVS8WI";
static const char key_b[] = "0123456789AB";
static const char host_a[] = "tn1vjduk6fjhoqscmqx9hpa.kanbantool.com";
static const char host_b[] = "b.kanbantool.com";
static const char keyword[] = "kanban";
static const char accept_value[] = "application/vnd.kanban+json; version=3";
static const char url_format[] = "https://%s/api/v3/users/current.json";
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, captures, findings, urls, url_frees, sends, releases, pushes;
static bool fault_hit;
static br_captures *original_keys, *original_hosts;
static br_result *candidate;
static const br_http_request *original_request;
static char *original_url;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE;
    fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_url);
    captures = findings = urls = url_frees = sends = releases = pushes = 0;
    original_keys = original_hosts = NULL;
    candidate = NULL;
    fault = NONE;
    nth = 0;
    fault_hit = false;
}

static void url_is(const char *url, const char *host)
{
    int needed = snprintf(NULL, 0, url_format, host);
    CHECK(needed > 0);
    char *expected = malloc((size_t)needed + 1);
    CHECK(expected);
    CHECK(snprintf(expected, (size_t)needed + 1, url_format, host) == needed);
    CHECK(!strcmp(url, expected));
    free(expected);
}

static void original_values(void)
{
    CHECK(original_url && original_keys && original_hosts && original_hosts->len && findings);
    size_t pair = findings - 1;
    const char *key = original_keys->items[pair / original_hosts->len];
    const char *host = original_hosts->items[pair % original_hosts->len];
    CHECK(original_keys->lengths[pair / original_hosts->len] == 12);
    url_is(original_url, host);
    if (original_request) {
        char authorization[32];
        CHECK(original_request->url == original_url && original_request->nheaders == 2);
        CHECK(!strcmp(original_request->headers[0].name, "Accept"));
        CHECK(!strcmp(original_request->headers[0].value, accept_value));
        CHECK(!strcmp(original_request->headers[1].name, "Authorization"));
        CHECK(snprintf(authorization, sizeof(authorization), "Bearer %s", key) > 0);
        CHECK(!strcmp(original_request->headers[1].value, authorization));
    }
}

static void *checked_malloc(size_t size)
{
    CHECK(candidate && candidate->raw.len == 12 && candidate->secret_parts);
    CHECK(!candidate->verified && !candidate->verification_error && !original_url);
    CHECK(original_hosts && original_hosts->len && findings);
    size_t pair = findings - 1;
    const char *host = original_hosts->items[pair % original_hosts->len];
    CHECK(size == (size_t)snprintf(NULL, 0, url_format, host) + 1);
    ++urls;
    if (hit(URL)) return NULL;
    original_url = malloc(size);
    return original_url;
}

static void checked_free(void *value)
{
    CHECK(!original_request);
    if (value && value == original_url) {
        original_values();
        original_url = NULL;
        ++url_frees;
    }
    free(value);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && captures < 2);
    CHECK(regex == (captures ? kanban_compiled.host : kanban_compiled.key));
    if (captures++) original_hosts = out;
    else original_keys = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure");
        CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    ++findings;
    candidate = result;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && captures == 2);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->profile != BR_HTTP_SANE);
    CHECK(!request->timeout_ms && request->detector_type == 686);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    original_request = request;
    original_values();
    ++sends;
    return br_http_send(ctx, request, response, error);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && sends == releases + 1 && !candidate->verification_error);
    original_values();
    br_http_release(ctx, response);
    original_values();
    original_request = NULL;
    ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_url);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Kanban detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 686 && !d->version && !strcmp(d->name, "Kanban") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "KanbanTool is a project management software that helps visualize and optimize workflow. Kanban API keys can be used to access and modify project data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], keyword));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding_is(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 686, key, "key");
    CHECK(result->raw.len == 12 && result->verified == verified && !result->verification_error);
}

static void extract(const br_detector *d, const void *input, size_t len, const char *key)
{
    reset_observation();
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding_is(&out.items[0], key, false);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[5000], changed[13];
    snprintf(input, sizeof(input), "%s '%s' %s '%s'", keyword, key_a, keyword, host_a);
    extract(d, input, strlen(input), key_a);
    snprintf(input, sizeof(input), "%s keyword is not close to the real key in the data\n = '%s' url = '%s'",
             keyword, key_a, host_a);
    extract(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%s key = '%s' url = '%s'", keyword, "11?Q98FV=8WI",
             "Tn1vjduk6fjhoqscmqx9hpa.kanbantool.com");
    extract(d, input, strlen(input), NULL);
    const char *good[] = {"KANBAN '%s'\n%s", "Kanban:%s\n%s", "myKANBANsuffix\r\n%s\n%s", "kanban-%s-\n%s", "kanban %s!\n%s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        snprintf(input, sizeof(input), good[i], key_b, host_b);
        extract(d, input, strlen(input), key_b);
    }
    const char *bad[] = {"%s\n%s", "kan ban %s\n%s", "kanban%s\n%s", "kanban %.11s\n%s", "kanban %sX\n%s",
                         "kanban _%s\n%s", "kanban %s_\n%s", "kanban %s", "%s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key_a, host_a);
        extract(d, input, strlen(input), NULL);
    }
    snprintf(input, sizeof(input), "kanban %s\n%s", "11xq98fvs8wi", host_a);
    extract(d, input, strlen(input), NULL);
    const char *plain[] = {"ABCDEFGHIJKL", "000000000000", "ZZZZZZZZZZZZ"};
    for (size_t i = 0; i < sizeof(plain) / sizeof(plain[0]); ++i) {
        snprintf(input, sizeof(input), "kanban %s\n%s", plain[i], host_a);
        extract(d, input, strlen(input), plain[i]);
    }
    const char invalid[] = {'a', '?', '=', '_', '-', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key_a, 13);
        changed[4] = invalid[i];
        snprintf(input, sizeof(input), "kanban %s\n%s", changed, host_a);
        extract(d, input, strlen(input), NULL);
    }
    const struct { const char *host; bool found; } hosts[] = {
        {"a.kanbantool.com", true}, {"0.kanbantool.com", true}, {"https://abc.kanbantool.com", true},
        {"Hidden.kanbantool.com", false}, {"hidden.Kanbantool.com", false}, {"hidden.kanbantool.COM", false},
        {"_hidden.kanbantool.com", false}, {"hidden.kanbantool.com_", false}, {"hidden.kanbantool.comX", false},
        {".kanbantool.com", false}, {"left-right.kanbantool.com", true}, {"hidden.kanbantool.com.extra", true},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "kanban %s\n%s", key_a, hosts[i].host);
        extract(d, input, strlen(input), hosts[i].found ? key_a : NULL);
    }
    snprintf(input, sizeof(input), "%s %s", host_a, key_a);
    extract(d, input, strlen(input), key_a);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, keyword, 6);
        memset(input + 6, ':', gap);
        memcpy(input + 6 + gap, key_a, 12);
        size_t n = 18 + gap;
        input[n++] = '\n';
        memcpy(input + n, host_a, sizeof(host_a));
        extract(d, input, n + sizeof(host_a) - 1, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 6 + 2 * gap, key_a, 12);
        n = 18 + 2 * gap;
        input[n++] = '\n';
        memcpy(input + n, host_a, sizeof(host_a));
        extract(d, input, n + sizeof(host_a) - 1, gap == 40 ? key_a : NULL);
    }
    memcpy(input, "kanban\0", 7);
    memcpy(input + 7, key_a, 12);
    input[19] = '\n';
    memcpy(input + 20, host_a, sizeof(host_a));
    extract(d, input, 20 + sizeof(host_a) - 1, key_a);
    snprintf(input, sizeof(input), "kanban %s %s\n%s", key_a, key_b, host_a);
    extract(d, input, strlen(input), key_a);
    int n = snprintf(input, sizeof(input), "kanban %s", key_a);
    memset(input + n, ':', 3000);
    n += 3000;
    memcpy(input + n, "\n", 1);
    memcpy(input + n + 1, host_a, sizeof(host_a));
    extract(d, input, (size_t)n + 1 + sizeof(host_a) - 1, key_a);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    const char *const *hosts;
    size_t nkeys, nhosts;
    const char *agent;
    const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_accept, *borrowed_authorization;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user;
    size_t pair = http->calls - 1;
    const char *key = script->keys[pair / script->nhosts];
    const char *host = script->hosts[pair % script->nhosts];
    char authorization[32];
    CHECK(ctx == script->ctx && http->calls == http->releases + 1 && pair < script->nkeys * script->nhosts);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->profile != BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 686);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, accept_value));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(snprintf(authorization, sizeof(authorization), "Bearer %s", key) > 0);
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, script->agent));
    url_is(request->url, host);
    CHECK(!script->borrowed_url && !script->borrowed_accept && !script->borrowed_authorization);
    script->borrowed_url = request->url;
    script->borrowed_accept = request->headers[0].value;
    script->borrowed_authorization = request->headers[1].value;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    request_script *script = http->user;
    if (script && script->borrowed_url) {
        size_t pair = http->calls - 1;
        char authorization[32];
        url_is(script->borrowed_url, script->hosts[pair % script->nhosts]);
        CHECK(script->borrowed_accept && !strcmp(script->borrowed_accept, accept_value));
        CHECK(snprintf(authorization, sizeof(authorization), "Bearer %s", script->keys[pair / script->nhosts]) > 0);
        CHECK(script->borrowed_authorization && !strcmp(script->borrowed_authorization, authorization));
        script->borrowed_url = script->borrowed_accept = script->borrowed_authorization = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void products(const br_detector *d)
{
    char input[5000];
    int n = snprintf(input, sizeof(input), "%s\nkanban %s\n%s\nkanban %s", host_b, key_a, host_a, key_b);
    const char *keys[] = {key_a, key_b};
    const char *hosts[] = {host_b, host_a};
    request_script script = {
        .keys = keys, .hosts = hosts, .nkeys = 2, .nhosts = 2, .agent = "TruffleHog kanban-offline",
    };
    test_http http = {.user = &script, .inspect = inspect, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "kanban-offline"};
    script.ctx = &ctx;
    reset_observation();
    br_results out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 4 && !http.calls && !http.releases && !script.borrowed_url);
    for (size_t i = 0; i < 4; ++i) finding_is(&out.items[i], keys[i / 2], false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts);
    br_results_clear(&out);
    reset_observation();
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, (size_t)n);
    CHECK(out.len == 4 && http.calls == 4 && http.releases == 4 && !script.borrowed_url);
    for (size_t i = 0; i < 4; ++i) finding_is(&out.items[i], keys[i / 2], true);
    br_results_clear(&out);
    reset_observation();
    http.calls = http.releases = 0;
    out = test_scan(d, NULL, true, input, (size_t)n);
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
    n = snprintf(input, sizeof(input), "kanban %s\nkanban %s\n%s\n%s", key_a, key_a, host_b, host_b);
    const char *dup_keys[] = {key_a, key_a};
    const char *dup_hosts[] = {host_b, host_b};
    script.keys = dup_keys;
    script.hosts = dup_hosts;
    reset_observation();
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, false, input, (size_t)n);
    CHECK(out.len == 4 && !http.calls);
    for (size_t i = 0; i < 4; ++i) finding_is(&out.items[i], key_a, false);
    CHECK(out.items[0].raw.data != out.items[3].raw.data);
    br_results_clear(&out);
    char long_host[1400];
    memset(long_host, 'a', 1300);
    memcpy(long_host + 1300, ".kanbantool.com", sizeof(".kanbantool.com"));
    const char *special[] = {long_host, "right.kanbantool.com", "hidden.kanbantool.com"};
    const char *source[] = {long_host, "left-right.kanbantool.com", "hidden.kanbantool.com.extra"};
    const char *one_key[] = {key_a};
    script.keys = one_key;
    script.nkeys = script.nhosts = 1;
    for (size_t i = 0; i < sizeof(source) / sizeof(source[0]); ++i) {
        script.hosts = &special[i];
        reset_observation();
        http.calls = http.releases = 0;
        n = snprintf(input, sizeof(input), "kanban %s\n%s", key_a, source[i]);
        out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding_is(&out.items[0], key_a, true);
        br_results_clear(&out);
    }
}

static void status_and_do(const br_detector *d)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "kanban %s\n%s", key_a, host_a);
    const char *keys[] = {key_a};
    const char *hosts[] = {host_a};
    request_script script = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.user = &script, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    script.ctx = &ctx;
    static const unsigned char junk[] = {0xff, 0, '{'};
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 302, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = statuses[i], .body = {junk, sizeof(junk)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "synthetic read failure",
        };
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !script.borrowed_url);
        finding_is(&out.items[0], key_a, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "cannot allocate Kanban URL"},
        {-1, "cannot create Kanban result"}, {1, "out of memory constructing HTTP headers"},
        {-1, "net/http: nil Context"}, {1, key_a}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = failures[i].rc;
        http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {junk, sizeof(junk)}, .body_error = "ignored on Do failure"};
        br_results out = test_scan(d, &ctx, true, input, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !script.borrowed_url);
        finding_is(&out.items[0], key_a, false);
        br_results_clear(&out);
    }
}

static bool cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void setup_and_constructor(const br_detector *d)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "kanban %s\n%s", key_a, host_a);
    test_http http = {0};
    br_transport transport = {&http, test_http_send, release_response};
    br_transport missing_send = {&http, NULL, release_response};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0},
        {.transport = &missing_send},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, (size_t)n);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && urls == 1 && url_frees == 1);
        finding_is(&out.items[0], key_a, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation();
    br_results out = test_scan(d, NULL, true, input, (size_t)n);
    CHECK(!out.len && findings == 1 && urls == 1 && url_frees == 1 && !sends && !releases && !pushes);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(out.len == 1 && findings == 1 && !urls && !sends && pushes == 1);
    finding_is(&out.items[0], key_a, false);
    br_results_clear(&out);
}

static void owned_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                          int send_rc, size_t attempts, bool no_error)
{
    char input[180];
    int n = snprintf(input, sizeof(input), "kanban %s\nkanban %s\n%s", key_a, key_b, host_a);
    br_results out = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    test_http http = {
        .send_rc = send_rc, .send_error = send_rc ? "cannot create Kanban result" : NULL,
        .response = {.status = 200, .body_error = "ignored"},
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    fault = site;
    nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, (size_t)n}, &out,
                  no_error ? NULL : &error) != 0);
    const char *message = site == CAPTURE ? "synthetic capture failure" :
                          site == FINDING ? "cannot create Kanban result" :
                          site == URL ? "cannot allocate Kanban URL" : "cannot append Kanban result";
    CHECK(no_error ? !error : error && !strcmp(error, message));
    free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    owned_failure(d, CAPTURE, 1, true, true, 0, 0, false);
    owned_failure(d, CAPTURE, 2, false, false, 0, 0, false);
    owned_failure(d, FINDING, 1, true, true, 0, 0, false);
    owned_failure(d, FINDING, 2, true, false, 0, 1, false);
    owned_failure(d, URL, 1, true, true, 0, 0, false);
    owned_failure(d, URL, 2, true, false, 1, 1, false);
    owned_failure(d, PUSH, 2, true, false, 0, 2, false);
    owned_failure(d, PUSH, 2, true, false, -7, 2, false);
    owned_failure(d, PUSH, 2, false, true, 0, 0, true);
    reset_observation();
    br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) != 0);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) != 0);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) != 0);
    CHECK(!out.len && !urls && !sends);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 12 && strlen(key_b) == 12);
    const br_detector *d = descriptor(br_kanban_init);
    grammar(d);
    products(d);
    status_and_do(d);
    const br_detector *observed = descriptor(observed_kanban_init);
    grammar(observed);
    products(observed);
    status_and_do(observed);
    setup_and_constructor(observed);
    owned_resources(observed);
    CHECK(!original_request && !original_url && fault == NONE);
    return test_finish("Kanban");
}
