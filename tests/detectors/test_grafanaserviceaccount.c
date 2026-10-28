/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"
#include <curl/curl.h>

static char a[47], b[47];
static const char domain[] = "Synthetic-7.grafana.net";
static size_t fail_size, fail_after, failed_allocations, fail_domain_after;
static bool fail_status, fail_agent;
static const char *borrowed_url, *borrowed_auth, *expected_domain, *expected_key;

void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, n);
}
char *strdup(const char *s)
{
    if ((fail_status && !strcmp(s, "unexpected HTTP response status 503")) ||
        (fail_agent && !strcmp(s, "TruffleHog"))) {
        fail_status = fail_agent = false; ++failed_allocations; return NULL;
    }
    size_t n = strlen(s) + 1; char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "domain") && fail_domain_after && --fail_domain_after == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}
static void check_result(const br_result *r, const char *key, const char *host, bool verified)
{
    size_t n = strlen(host);
    CHECK(r->detector_type == 963 && r->verified == verified);
    CHECK(r->raw.len == 46 && !memcmp(r->raw.data, key, 46));
    CHECK(r->raw_v2.len == n + 47 && !memcmp(r->raw_v2.data, host, n));
    CHECK(r->raw_v2.data[n] == ':' && !memcmp(r->raw_v2.data + n + 1, key, 46));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_get_string_len(part) == 46 && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(r->secret_parts, "domain", &part) && (size_t)json_object_get_string_len(part) == n && !strcmp(json_object_get_string(part), host));
    CHECK(!r->detector_name && !r->redacted && !r->extra_data && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_grafanaserviceaccount_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_grafanaserviceaccount_init(NULL, NULL) != 0);
    CHECK(br_grafanaserviceaccount_init(&d, &error) == 0 && d && !error);
    CHECK(br_grafanaserviceaccount_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 963 && !d->version && !strcmp(d->name, "GrafanaServiceAccount") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Grafana service accounts are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "glsa_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extract(const br_detector *d, const char *text, const char *key, const char *host)
{
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    br_results out = test_scan(d, &ctx, false, text, strlen(text));
    CHECK(out.len == (key && host ? 1u : 0u) && !http.calls && !http.releases);
    if (out.len) { check_result(&out.items[0], key, host, false); CHECK(!out.items[0].verification_error); }
    br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[512], key[64];
    const struct { const char *text, *captured; } hosts[] = {
        {"Synthetic-7.grafana.net", "Synthetic-7.grafana.net"}, {"-abc.grafana.net", "abc.grafana.net"},
        {"abc-.grafana.net", "abc-.grafana.net"}, {"_-abc.grafana.net", "-abc.grafana.net"},
        {"_abc.grafana.net", NULL}, {"abc.Grafana.net", NULL}, {"abc.grafana.NET", NULL},
        {"abc.grafana.net_", NULL}, {"abc.grafana.net9", NULL}, {"abc.grafana.net-more", "abc.grafana.net"},
        {"long.prefix.abc.grafana.net", "abc.grafana.net"}, {"---.grafana.net", NULL},
        {"a--b.grafana.net", "a--b.grafana.net"}, {"a.grafanaXnet", NULL},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "%s\n%s", hosts[i].text, a);
        extract(d, input, a, hosts[i].captured);
    }
    const struct { const char *format; bool match; } keys[] = {
        {"%s", true}, {"(%s)", true}, {"X%s", false}, {"_%s", false}, {"%sX", false},
        {"%s_", false}, {"%.45s", false}, {"-%s-", true},
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        snprintf(key, sizeof(key), keys[i].format, a);
        snprintf(input, sizeof(input), "%s %s", key, domain);
        extract(d, input, keys[i].match ? a : NULL, domain);
    }
    memcpy(key, a, 47); key[0] = 'G'; snprintf(input, sizeof(input), "%s %s", key, domain); extract(d, input, NULL, domain);
    memcpy(key, a, 47); key[20] = '-'; snprintf(input, sizeof(input), "%s %s", key, domain); extract(d, input, NULL, domain);
    extract(d, a, NULL, NULL); extract(d, domain, NULL, NULL); extract(d, "", NULL, NULL);
}
typedef struct { const char *const *keys, *const *hosts; size_t count; const br_scan_ctx *ctx; const char *agent; } expectation;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expectation *e = http->user; size_t i = http->calls - 1;
    CHECK(i < e->count && ctx == e->ctx && http->releases == i && !borrowed_url);
    expected_key = e->keys[i]; expected_domain = e->hosts[i]; size_t n = strlen(expected_domain);
    CHECK(r->profile == BR_HTTP_DETECTOR_PUBLIC && r->timeout_ms == 10000 && r->detector_type == 963);
    CHECK(!strcmp(r->method, "GET") && strlen(r->url) == 8 + n + strlen("/api/access-control/user/permissions"));
    CHECK(!memcmp(r->url, "https://", 8) && !memcmp(r->url + 8, expected_domain, n) && !strcmp(r->url + 8 + n, "/api/access-control/user/permissions"));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len && r->nheaders == 2);
    CHECK(!strcmp(r->headers[0].name, "Authorization") && !memcmp(r->headers[0].value, "Bearer ", 7) && !strcmp(r->headers[0].value + 7, expected_key));
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, e->agent));
    borrowed_url = r->url; borrowed_auth = r->headers[0].value;
}
static void release(void *user, br_http_response *response)
{
    if (borrowed_url) {
        CHECK(!memcmp(borrowed_url + 8, expected_domain, strlen(expected_domain)));
        CHECK(!strcmp(borrowed_url + 8 + strlen(expected_domain), "/api/access-control/user/permissions"));
        CHECK(!memcmp(borrowed_auth, "Bearer ", 7) && !strcmp(borrowed_auth + 7, expected_key));
        borrowed_url = borrowed_auth = expected_domain = expected_key = NULL;
    }
    if (!((test_http *)user)->calls) {
        const br_http_response empty = {0};
        CHECK(!memcmp(response, &empty, sizeof(empty)));
    }
    test_http_release(user, response);
}
static void products_and_long(const br_detector *d)
{
    char input[512]; snprintf(input, sizeof(input), "%s %s %s %s other.grafana.net %s", a, b, a, domain, domain);
    const char *keys[] = {a,a,a,b,b,b,a,a,a};
    const char *hosts[] = {domain,"other.grafana.net",domain,domain,"other.grafana.net",domain,domain,"other.grafana.net",domain};
    expectation e = {keys, hosts, 9, NULL, "TruffleHog synthetic"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 299, .body_error = "ignored"}};
    br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &t, .user_agent = "synthetic"}; e.ctx = &ctx;
    br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t i = 0; i < 9; ++i) check_result(&out.items[i], keys[i], hosts[i], true);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 9); br_results_clear(&out);
    char host[4110], large[6200]; memset(host, 'A', 4096); memcpy(host + 4096, ".grafana.net", 13);
    memcpy(large, a, 46); memset(large + 46, ' ', 1500); strcpy(large + 1546, host);
    extract(d, large, a, host);
    const char *longkeys[] = {a}, *longhosts[] = {host}; e = (expectation){longkeys, longhosts, 1, &ctx, "TruffleHog synthetic"};
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, large, strlen(large)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); check_result(&out.items[0], a, host, true); br_results_clear(&out);
}
static bool arm_headers(void *u) { (void)u; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *u) { (void)u; fail_agent = true; return false; }
static bool cancelled(void *u) { (void)u; return true; }
static void statuses_and_setup(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "%s %s", a, domain);
    const char *keys[] = {a}, *hosts[] = {domain}; expectation e = {keys, hosts, 1, NULL, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e}; br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &t}; e.ctx = &ctx;
    const int statuses[] = {199,200,201,204,299,300,401,403,503};
    const unsigned char body[] = {0,0xff,'!'};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i], .body = {body,sizeof(body)}, .body_error = i % 2 ? "ignored" : ""};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], a, domain, statuses[i] >= 200 && statuses[i] < 300);
        if (statuses[i] == 401 || (statuses[i] >= 200 && statuses[i] < 300)) CHECK(!out.items[0].verification_error);
        else { char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]); CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cause)); }
        br_results_clear(&out);
    }
    char cause[240]; snprintf(cause, sizeof(cause), "%s %s %s", a, domain, a);
    const char *causes[] = {cause, "out of memory constructing HTTP headers", "net/http: nil Context", "context canceled", NULL};
    for (size_t i = 0; i < sizeof(causes)/sizeof(causes[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = i % 2 ? 7 : -7; http.send_error = causes[i]; http.response = (br_http_response){0};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); check_result(&out.items[0], a, domain, false);
        CHECK(out.items[0].verification_error && !strstr(out.items[0].verification_error, a));
        if (!i) CHECK(strstr(out.items[0].verification_error, domain) && strstr(out.items[0].verification_error, "[REDACTED]"));
        br_results_clear(&out);
    }
    http.inspect = NULL;
    br_scan_ctx contexts[] = {{0}, {.transport=&t,.cancelled=arm_headers}, {.transport=&t,.cancelled=arm_agent}, {.transport=&t,.cancelled=cancelled}, {.transport=&t,.deadline_monotonic_ms=1}, {.transport=&t,.user_agent="bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts)/sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; size_t before = failed_allocations;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input)); CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!out.items[0].verified && out.items[0].verification_error && !fail_after && !fail_agent);
        CHECK(failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u)); br_results_clear(&out);
    }
    char *error = NULL; const br_transport *native = br_curl_transport_init(&error); CHECK(native && !error);
    ctx = (br_scan_ctx){.transport = native}; br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && out.items[0].verification_error && !strcmp(out.items[0].verification_error, "unsupported: native curl HTTP client profile")); br_results_clear(&out);
    curl_global_cleanup();
}
static void resources(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "%s %s %s", a, b, domain);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    br_result probe = {0}; fail_status = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected HTTP response status 503", NULL, 0) == 1 && !fail_status);
    CHECK(br_result_set_verification_error(&out.items[0], NULL, NULL, 0) == 0 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    test_http http = {.response = {.status = 503}}; br_transport t = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &t};
    for (size_t i = 0; i < 7; ++i) {
        http.calls = http.releases = 0;
        if (i == 0) { fail_size = 47; fail_after = 2; } /* second capture */
        if (i == 1) { fail_size = 46; fail_after = 2; } /* second finding Raw */
        if (i == 2) { fail_size = strlen(domain) + 47; fail_after = 2; } /* second RawV2 */
        if (i == 3) fail_domain_after = 2;
        if (i == 4) { fail_size = sizeof("https://") - 1 + strlen(domain) + sizeof("/api/access-control/user/permissions"); fail_after = 2; }
        if (i == 5) fail_status = true;
        size_t cap = out.cap; if (i == 6) out.cap = 0;
        char *error = NULL; CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error);
        if (i == 6) out.cap = cap;
        CHECK(!fail_after && !fail_domain_after && !fail_status && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(http.calls == (i == 0 ? 0u : 1u) && http.releases == http.calls);
        CHECK(!borrowed_url); free(error);
    }
    http.calls = http.releases = 0; fail_size = sizeof(domain); fail_after = 1;
    char *capture_error = NULL;
    CHECK(d->scan(d, &ctx, true, data, &out, &capture_error) != 0 && capture_error && !fail_after);
    CHECK(!http.calls && !http.releases && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    free(capture_error);
    /* Own URL and metadata failures must precede the nil-context skip. */
    for (size_t i = 0; i < 4; ++i) {
        if (i == 0) { fail_size = 46; fail_after = 1; }
        if (i == 1) { fail_size = strlen(domain) + 47; fail_after = 1; }
        if (i == 2) fail_domain_after = 1;
        if (i == 3) { fail_size = sizeof("https://") - 1 + strlen(domain) + sizeof("/api/access-control/user/permissions"); fail_after = 1; }
        char *error = NULL; CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_domain_after && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); free(error);
    }
    br_results_clear(&out);
}
int main(void)
{
    memcpy(a, "glsa_", 5); test_secret(a + 5, 41, 0); a[9] = 'Z'; a[16] = '_';
    memcpy(b, "glsa_", 5); test_secret(b + 5, 41, 11); b[20] = 'Q';
    const br_detector *d = descriptor(); grammar(d); products_and_long(d); statuses_and_setup(d); resources(d);
    CHECK(!fail_after && !fail_domain_after && !fail_status && !fail_agent && !borrowed_url);
    return test_finish("GrafanaServiceAccount");
}
