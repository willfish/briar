/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_liveagent_init(const br_detector **out, char **error);

static char key1[33], key2[33];
static const char domain1[] = "https://desk.ladesk.com";
static const char domain2[] = "http://my-desk.ladesk.com";
static const char privilege[] = "You do not have sufficient privileges";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls;
static bool fail_growth, fail_setter;
static char setter_cause[512];

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error liveagent_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "domain") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_cause[0] = '\0';
    if (cause) snprintf(setter_cause, sizeof(setter_cause), "%s", cause);
    if (fail_setter) return 1;
    return liveagent_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_liveagent_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_liveagent_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:liveagent|apikey)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_liveagent_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_liveagent_init(&d, &error) == 0 && d && !error);
    CHECK(br_liveagent_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 165 && d->version == 0 && !strcmp(d->name, "LiveAgent"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "LiveAgent is a help desk software that provides a customer service platform. The API key allows access to various functionalities of the LiveAgent service."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "liveagent") && !strcmp(d->keywords[1], "ladesk"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_pair(const br_result *r, const char *key, const char *domain, bool verified)
{
    CHECK(r->detector_type == 165 && r->verified == verified && !r->verification_error);
    CHECK(r->raw.len == 32 && !memcmp(r->raw.data, key, 32));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    br_json *part = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
    CHECK(json_object_object_get_ex(r->extra_data, "domain", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), domain));
}

static void extract_none(const br_detector *d, const void *text, size_t n)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == 0);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[1400], key_short[32];
    int n = snprintf(input, sizeof(input), "liveagent %s %s", key1, domain1);
    CHECK(n > 0);
    br_results one = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(one.len == 1);
    check_pair(&one.items[0], key1, domain1, false);
    br_results_clear(&one);
    n = snprintf(input, sizeof(input), "APIKEY=%s\n%s.evil", key1, domain2);
    CHECK(n > 0);
    one = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(one.len == 1);
    check_pair(&one.items[0], key1, domain2, false);
    br_results_clear(&one);
    n = snprintf(input, sizeof(input), "ladesk %s %s", key1, domain1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "liveagent %s", key1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    extract_none(d, domain1, strlen(domain1));
    memcpy(input, "liveagent", 9); memcpy(input + 9, key1, 32);
    memcpy(input + 41, " ", 1); memcpy(input + 42, domain1, strlen(domain1));
    extract_none(d, input, 42 + strlen(domain1));
    n = snprintf(input, sizeof(input), "liveagent %.31s %s", key1, domain1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "liveagent %sx %s", key1, domain1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    memcpy(key_short, key1, 32); key_short[4] = '_';
    n = snprintf(input, sizeof(input), "liveagent %.32s %s", key_short, domain1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "liveagent %s https://Desk.Ladesk.com", key1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    n = snprintf(input, sizeof(input), "liveagent %s ftp://desk.ladesk.com", key1);
    CHECK(n > 0); extract_none(d, input, (size_t)n);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "apikey", 6);
        memset(input + 6, '.', gap);
        memcpy(input + 6 + gap, key1, 32);
        int tail = snprintf(input + 6 + gap + 32, sizeof(input) - 6 - gap - 32, " %s", domain1);
        CHECK(tail > 0);
        br_results gap_result = test_scan(d, NULL, false, input, 6 + gap + 32 + (size_t)tail);
        CHECK(gap_result.len == (gap == 40 ? 1u : 0u));
        if (gap == 40) check_pair(&gap_result.items[0], key1, domain1, false);
        br_results_clear(&gap_result);
    }
    memset(input, 'z', 1100);
    n = snprintf(input + 1100, sizeof(input) - 1100, "liveagent %s %s", key1, domain1);
    CHECK(n > 0 && 1100 + n > 1024);
    one = test_scan(d, NULL, false, input, 1100 + (size_t)n);
    CHECK(one.len == 1);
    check_pair(&one.items[0], key1, domain1, false);
    br_results_clear(&one);
    n = snprintf(input, sizeof(input), "liveagent %s\napikey %s\n%s\n%s", key1, key2, domain1, domain2);
    CHECK(n > 0);
    br_results product = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(product.len == 4);
    check_pair(&product.items[0], key1, domain1, false);
    check_pair(&product.items[1], key1, domain2, false);
    check_pair(&product.items[2], key2, domain1, false);
    check_pair(&product.items[3], key2, domain2, false);
    CHECK(product.items[0].raw.data != product.items[2].raw.data);
    br_results_clear(&product);
    n = snprintf(input, sizeof(input), "liveagent %s\nliveagent %s\n%s\n%s", key1, key1, domain1, domain1);
    CHECK(n > 0);
    product = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(product.len == 4);
    for (size_t i = 0; i < 4; ++i) check_pair(&product.items[i], key1, domain1, false);
    CHECK(product.items[0].raw.data != product.items[2].raw.data);
    br_results_clear(&product);
    extract_none(d, NULL, 0);
}

typedef struct {
    const char *const *keys;
    const char *const *domains;
    const char *const *urls;
    size_t count;
    const char *live_urls[4];
    br_header markers[4];
    int statuses[4];
    const char *bodies[4];
    const char *body_errors[4];
    int send_rc[4];
    const char *send_errors[4];
    size_t released_ids[4];
    size_t release_lengths[4];
    size_t sends_at_release[4];
    size_t setter_at_release[4];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static br_slice body_of(const char *text)
{
    return text ? (br_slice){(const unsigned char *)text, strlen(text)} : (br_slice){0};
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->url);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live_urls[i]) { ++failed; continue; }
        CHECK(e->live_urls[i] != request->url && !strcmp(e->live_urls[i], e->urls[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, e->urls[at]));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 165);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(strstr(request->url, "%") == NULL);
    CHECK(!strncmp(request->url, e->domains[at], strlen(e->domains[at])));
    CHECK(!strcmp(request->url + strlen(e->domains[at]), "/api/v3/agents"));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Apikey"));
    CHECK(request->headers[0].value && !strcmp(request->headers[0].value, e->keys[at]));
    CHECK(strncmp(request->headers[0].value, "Bearer ", 7) != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog liveagent-offline"));
    e->live_urls[at] = request->url;
    e->markers[at] = (br_header){"synthetic-attempt", e->urls[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body = body_of(e->bodies[at]), .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_errors[at];
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live_urls[id] && !strcmp(e->live_urls[id], e->urls[id]));
        e->live_urls[id] = NULL;
        e->released_ids[http->releases] = id;
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = http->calls;
        e->setter_at_release[http->releases] = setter_calls;
    } else {
        CHECK(response && !response->headers && e->out);
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = 0;
    }
    test_http_release(user, response);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].verified && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static br_results scan_ok(const br_detector *d, const br_scan_ctx *ctx, const void *data,
                          size_t n, expected *e)
{
    br_results out = {0};
    e->out = &out;
    char *error = NULL;
    int rc = d->scan(d, ctx, true, (br_slice){data, n}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void verification(const br_detector *d)
{
    char input[160], privilege_body[96], other_body[64], number_body[32], null_body[32];
    char duplicate_yes[160], duplicate_no[160], null_after[160], case_body[96], trailing[128];
    char nul_suffix[128], number_then[160];
    int n = snprintf(input, sizeof(input), "liveagent %s %s", key1, domain1);
    CHECK(n > 0);
    CHECK(strlen(privilege) == 37);
    snprintf(privilege_body, sizeof(privilege_body), "{\"message\":\"%s\"}", privilege);
    snprintf(other_body, sizeof(other_body), "{\"message\":\"no\"}");
    snprintf(number_body, sizeof(number_body), "{\"message\":1}");
    snprintf(null_body, sizeof(null_body), "{\"message\":null}");
    snprintf(duplicate_yes, sizeof(duplicate_yes), "{\"message\":\"no\",\"message\":\"%s\"}", privilege);
    snprintf(duplicate_no, sizeof(duplicate_no), "{\"message\":\"%s\",\"message\":\"no\"}", privilege);
    snprintf(null_after, sizeof(null_after), "{\"message\":\"%s\",\"message\":null}", privilege);
    snprintf(case_body, sizeof(case_body), "{\"MESSAGE\":\"%s\"}", privilege);
    snprintf(trailing, sizeof(trailing), "{\"message\":\"%s\"}{\"ignored\":true}", privilege);
    snprintf(nul_suffix, sizeof(nul_suffix), "{\"message\":\"%s\\u0000suffix\"}", privilege);
    snprintf(number_then, sizeof(number_then), "{\"message\":1,\"message\":\"%s\"}", privilege);
    const char *keys[] = {key1};
    const char *domains[] = {domain1};
    char url[80];
    snprintf(url, sizeof(url), "%s/api/v3/agents", domain1);
    const char *urls[] = {url};
    expected e = {.keys = keys, .domains = domains, .urls = urls, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "liveagent-offline"};
    e.ctx = &ctx;
    const struct {
        int status; const char *text; const char *body_error;
        bool verified, kept, setter; const char *cause;
    } cases[] = {
        {200, NULL, NULL, true, true, false, NULL},
        {201, privilege_body, "synthetic read failure", true, true, false, NULL},
        {299, "", "", true, true, false, NULL},
        {199, privilege_body, NULL, false, true, false, NULL},
        {300, privilege_body, "read", false, true, false, NULL},
        {404, privilege_body, NULL, false, true, false, NULL},
        {403, privilege_body, NULL, true, true, false, NULL},
        {403, other_body, NULL, false, true, false, NULL},
        {403, "{}", NULL, false, true, false, NULL},
        {403, "null", NULL, false, true, false, NULL},
        {403, null_body, NULL, false, true, false, NULL},
        {403, null_after, NULL, true, true, false, NULL},
        {403, nul_suffix, NULL, false, true, false, NULL},
        {403, duplicate_yes, NULL, true, true, false, NULL},
        {403, duplicate_no, NULL, false, true, false, NULL},
        {403, case_body, NULL, true, true, false, NULL},
        {403, trailing, NULL, true, true, false, NULL},
        {403, privilege_body, "complete-body read error", true, true, false, NULL},
        {403, number_body, NULL, false, false, true,
            "json: cannot unmarshal number into Go struct field response.message of type string"},
        {403, number_then, NULL, false, false, true,
            "json: cannot unmarshal number into Go struct field response.message of type string"},
        {403, "[]", NULL, false, false, true, NULL},
        {403, "\"text\"", NULL, false, false, true, NULL},
        {403, "{", NULL, false, false, true, NULL},
        {403, "", "empty read", false, false, true, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        setter_calls = 0;
        setter_cause[0] = '\0';
        memset(e.live_urls, 0, sizeof(e.live_urls));
        e.statuses[0] = cases[i].status;
        e.bodies[0] = cases[i].text;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = 0;
        e.send_errors[0] = NULL;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].kept ? 1u : 0u));
        CHECK(setter_calls == (cases[i].setter ? 1u : 0u));
        CHECK(e.setter_at_release[0] == setter_calls);
        if (cases[i].cause) {
            CHECK(!strcmp(setter_cause, cases[i].cause));
            CHECK(!strstr(setter_cause, "response.Message"));
        }
        CHECK(r.len == (cases[i].kept ? 1u : 0u));
        if (cases[i].kept) check_pair(&r.items[0], key1, domain1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));
    e.statuses[0] = 403;
    e.bodies[0] = privilege_body;
    e.body_errors[0] = NULL;
    e.send_rc[0] = 1;
    e.send_errors[0] = "synthetic send error";
    br_results failed = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(failed.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 1 && !e.live_urls[0]);
    check_pair(&failed.items[0], key1, domain1, false);
    br_results_clear(&failed);
    http.calls = http.releases = 0;
    setter_calls = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "liveagent-offline"};
    br_results prepared = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(prepared.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_pair(&prepared.items[0], key1, domain1, false);
    br_results_clear(&prepared);
}

static void product_and_nil(const br_detector *d)
{
    char input[240], url_a[80], url_b[80];
    int n = snprintf(input, sizeof(input), "liveagent %s\napikey %s\n%s\n%s", key1, key2, domain1, domain2);
    CHECK(n > 0);
    snprintf(url_a, sizeof(url_a), "%s/api/v3/agents", domain1);
    snprintf(url_b, sizeof(url_b), "%s/api/v3/agents", domain2);
    const char *keys[] = {key1, key1, key2, key2};
    const char *domains[] = {domain1, domain2, domain1, domain2};
    const char *urls[] = {url_a, url_b, url_a, url_b};
    expected e = {.keys = keys, .domains = domains, .urls = urls, .count = 4,
                  .statuses = {204, 204, 204, 204}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "liveagent-offline"};
    e.ctx = &ctx;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 4 && http.calls == 4 && http.releases == 4 && !setter_calls);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(!e.live_urls[i]);
        CHECK(e.released_ids[i] == 3 - i);
        CHECK(e.release_lengths[i] == 4 && e.sends_at_release[i] == 4);
    }
    check_pair(&r.items[0], key1, domain1, true);
    check_pair(&r.items[1], key1, domain2, true);
    check_pair(&r.items[2], key2, domain1, true);
    check_pair(&r.items[3], key2, domain2, true);
    br_results_clear(&r);

    char order_input[220];
    int order_n = snprintf(order_input, sizeof(order_input), "liveagent %s\napikey %s\nliveagent %s\n%s",
                           key1, key2, key1, domain1);
    CHECK(order_n > 0);
    const char *order_keys[] = {key1, key2, key1};
    const char *order_domains[] = {domain1, domain1, domain1};
    const char *order_urls[] = {url_a, url_a, url_a};
    const char *number = "{\"message\":1}";
    expected mixed = {.keys = order_keys, .domains = order_domains, .urls = order_urls, .count = 3,
                      .statuses = {200, 403, 201}, .bodies = {NULL, number, NULL}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "liveagent-offline"};
    mixed.ctx = &mixed_ctx;
    setter_calls = 0;
    br_results published = scan_ok(d, &mixed_ctx, order_input, (size_t)order_n, &mixed);
    CHECK(published.len == 2 && mixed_http.calls == 3 && mixed_http.releases == 3 && setter_calls == 1);
    CHECK(!strcmp(setter_cause, "json: cannot unmarshal number into Go struct field response.message of type string"));
    for (size_t i = 0; i < 3; ++i) {
        CHECK(mixed.released_ids[i] == 2 - i);
        CHECK(mixed.sends_at_release[i] == 3 && mixed.release_lengths[i] == 2);
        CHECK(!mixed.live_urls[i]);
    }
    CHECK(mixed.setter_at_release[0] == 1);
    check_pair(&published.items[0], key1, domain1, true);
    check_pair(&published.items[1], key1, domain1, true);
    br_results_clear(&published);

    expected failed_send = {.keys = order_keys, .domains = order_domains, .urls = order_urls, .count = 3,
                            .statuses = {200, 403, 201},
                            .send_rc = {0, 4, 0}, .send_errors = {NULL, "synthetic send error", NULL}};
    test_http failed_http = {.inspect = inspect, .user = &failed_send};
    br_transport failed_transport = {&failed_http, test_http_send, release_response};
    br_scan_ctx failed_ctx = {.transport = &failed_transport, .user_agent = "liveagent-offline"};
    failed_send.ctx = &failed_ctx;
    setter_calls = 0;
    br_results mixed_fail = scan_ok(d, &failed_ctx, order_input, (size_t)order_n, &failed_send);
    CHECK(mixed_fail.len == 3 && failed_http.calls == 3 && failed_http.releases == 3 && !setter_calls);
    CHECK(failed_send.released_ids[0] == 1 && failed_send.sends_at_release[0] == 2);
    CHECK(failed_send.release_lengths[0] == 1);
    CHECK(failed_send.released_ids[1] == 2 && failed_send.released_ids[2] == 0);
    CHECK(failed_send.sends_at_release[1] == 3 && failed_send.sends_at_release[2] == 3);
    CHECK(failed_send.release_lengths[1] == 3 && failed_send.release_lengths[2] == 3);
    check_pair(&mixed_fail.items[0], key1, domain1, true);
    check_pair(&mixed_fail.items[1], key2, domain1, false);
    check_pair(&mixed_fail.items[2], key1, domain1, true);
    br_results_clear(&mixed_fail);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == 0 && !error);
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);

    fail_size = strlen(domain1) + sizeof("/api/v3/agents"); fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate LiveAgent URL"));
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[220];
    int n = snprintf(input, sizeof(input), "liveagent %s\napikey %s\n%s", key1, key2, domain1);
    CHECK(n > 0);
    char url[80];
    snprintf(url, sizeof(url), "%s/api/v3/agents", domain1);
    const char *keys[] = {key1, key2};
    const char *domains[] = {domain1, domain1};
    const char *urls[] = {url, url};
    expected e = {.keys = keys, .domains = domains, .urls = urls, .count = 2, .statuses = {200, 200}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "liveagent-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    e.out = &out;
    char *error = NULL;

    fail_size = 33; fail_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !e.live_urls[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot store LiveAgent domain"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append LiveAgent result"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_urls[0] && !e.live_urls[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    CHECK(e.sends_at_release[0] == 2 && e.sends_at_release[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain LiveAgent response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !e.live_urls[0] && !e.live_urls[1]);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    e.fail_retain = false;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live_urls, 0, sizeof(e.live_urls));

    e.count = 1;
    e.statuses[0] = 403;
    e.bodies[0] = "{\"message\":1}";
    setter_calls = 0;
    fail_setter = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && setter_calls == 1);
    CHECK(!strcmp(error, "cannot record LiveAgent verification error"));
    CHECK(http.calls == 1 && http.releases == 1 && !e.live_urls[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 1 && e.setter_at_release[0] == 1);
    CHECK(!strcmp(setter_cause, "json: cannot unmarshal number into Go struct field response.message of type string"));
    check_prior(&out, &prior);
    fail_setter = false;
    e.count = 2;
    e.statuses[0] = 200;
    e.bodies[0] = NULL;
    free(error);
    br_results_clear(&out);
}

#include "../../src/detectors/json.h"

enum { hook_off = 0, hook_null_cause = 1, hook_second_plus = 2, hook_document_plus2 = 3,
       hook_null_setter = 4 };
static int hook_mode;
static size_t hook_type_calls;
static bool setter_null;

static int liveagent_projected_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++hook_type_calls;
    if (hook_mode == hook_second_plus && hook_type_calls == 2) {
        if (cause) *cause = NULL;
        return 1;
    }
    int rc = br_json_type_cause(value, field, expected, cause);
    if (!rc && cause && (hook_mode == hook_null_cause || hook_mode == hook_null_setter) &&
        hook_type_calls == 1) {
        free(*cause);
        *cause = NULL;
    }
    return rc;
}

static int liveagent_projected_document(br_slice body, const char *read_error, br_json **out,
                                        size_t *end, char **cause)
{
    if (hook_mode == hook_document_plus2) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return 2;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

static int liveagent_projected_setter(br_result *result, const char *cause,
                                      const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_null = cause == NULL;
    setter_cause[0] = '\0';
    if (cause) snprintf(setter_cause, sizeof(setter_cause), "%s", cause);
    if (hook_mode == hook_null_setter && !cause) return 1;
    return liveagent_real_setter(result, cause, secrets, count);
}

#define br_json_type_cause liveagent_projected_type
#define br_json_first_document liveagent_projected_document
#define br_result_set_verification_error liveagent_projected_setter
#define br_liveagent_init liveagent_hooked_init
#include "../../src/detectors/liveagent.c"
#undef br_liveagent_init
#undef br_result_set_verification_error
#undef br_json_first_document
#undef br_json_type_cause

static void seam_reset(test_http *http, expected *e)
{
    http->calls = http->releases = 0;
    setter_calls = hook_type_calls = 0;
    setter_null = false;
    setter_cause[0] = '\0';
    memset(e->live_urls, 0, sizeof(e->live_urls));
    memset(e->released_ids, 0, sizeof(e->released_ids));
    memset(e->release_lengths, 0, sizeof(e->release_lengths));
}

static void typed_seams(void)
{
    const br_detector *hooked = NULL;
    char *error = NULL;
    CHECK(liveagent_hooked_init(&hooked, &error) == 0 && hooked && !error);
    char input[160], url[80];
    int n = snprintf(input, sizeof(input), "liveagent %s %s", key1, domain1);
    CHECK(n > 0);
    snprintf(url, sizeof(url), "%s/api/v3/agents", domain1);
    const char *keys[] = {key1};
    const char *domains[] = {domain1};
    const char *urls[] = {url};
    const char *number_then = "{\"message\":1,\"message\":\"You do not have sufficient privileges\"}";
    const char *number_bool = "{\"message\":1,\"message\":true}";
    expected e = {.keys = keys, .domains = domains, .urls = urls, .count = 1, .statuses = {403}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "liveagent-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    e.out = &out;

    seam_reset(&http, &e);
    hook_mode = hook_null_cause;
    e.bodies[0] = number_then;
    CHECK(hooked->scan(hooked, &ctx, true, data, &out, &error) == 0 && !error);
    CHECK(out.len == 1 && setter_calls == 1 && setter_null && !setter_cause[0] && hook_type_calls == 1);
    CHECK(http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 1);
    check_prior(&out, &prior);

    seam_reset(&http, &e);
    hook_mode = hook_second_plus;
    e.bodies[0] = number_bool;
    CHECK(hooked->scan(hooked, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot decode LiveAgent response"));
    CHECK(hook_type_calls == 2 && !setter_calls);
    CHECK(http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;

    seam_reset(&http, &e);
    hook_mode = hook_document_plus2;
    e.bodies[0] = "{}";
    CHECK(hooked->scan(hooked, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot decode LiveAgent response"));
    CHECK(!hook_type_calls && !setter_calls);
    CHECK(http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;

    seam_reset(&http, &e);
    hook_mode = hook_null_setter;
    e.bodies[0] = "{\"message\":1}";
    CHECK(hooked->scan(hooked, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot record LiveAgent verification error"));
    CHECK(setter_calls == 1 && setter_null && hook_type_calls == 1);
    CHECK(http.calls == 1 && http.releases == 1 && e.release_lengths[0] == 1);
    CHECK(e.setter_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error);
    hook_mode = hook_off;
    br_results_clear(&out);
}

int main(void)
{
    test_secret(key1, 32, 0);
    test_secret(key2, 32, 5);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    product_and_nil(d);
    owned_failures(d);
    typed_seams();
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !fail_setter);
    return test_finish("LiveAgent");
}
