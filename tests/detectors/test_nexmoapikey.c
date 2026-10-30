/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_nexmoapikey_init(const br_detector **out, char **error);

#define br_result_set_verification_error nexmo_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *, br_slice, const char *, br_slice);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_pair_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_nexmoapikey_init observed_init
#include "../../src/detectors/nexmoapikey.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_pair_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_nexmoapikey_init

static const char key_a[] = "KULOcaja";
static const char key_b[] = "KEYBBBBB";
static const char secret_a[] = "gngKGCWbmK0COTtS";
static const char secret_b[] = "SECRETsecret2222";
static const char hyphen_key[] = "ku-ocaja";
static const char hyphen_secret[] = "gngK-GCWbmK0COTt";
static const char url_prefix[] = "https://rest.nexmo.com/account/get-balance?api_key=";
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, captures, findings, urls, url_frees, pushes, setter_calls, held_n, release_n;
static bool fault_hit, release_before_push;
static br_result *candidate;
static const br_http_request *live_request;
static char *live_url, *held_urls[8];
static br_results *watch_out;
static size_t rows_at[8];
static int order_at[8];

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return nexmo_real_setter(result, cause, secrets, count);
}

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE;
    fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!live_request && !live_url);
    for (size_t i = 0; i < held_n; ++i) CHECK(!held_urls[i]);
    captures = findings = urls = url_frees = pushes = setter_calls = held_n = release_n = 0;
    candidate = NULL;
    watch_out = NULL;
    fault = NONE;
    nth = 0;
    fault_hit = release_before_push = false;
}

static void expect_pair(const br_result *result, const char *key, const char *secret, bool verified)
{
    CHECK(result->detector_type == 121 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 8 && !memcmp(result->raw.data, key, 8));
    CHECK(result->raw_v2.len == 24 && !memcmp(result->raw_v2.data, key, 8));
    CHECK(!memcmp(result->raw_v2.data + 8, secret, 16));
    CHECK(!result->extra_data && !result->redacted && !result->detector_name);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), secret));
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid NexmoApiKey detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 121 && !detector->version && !strcmp(detector->name, "NexmoApiKey"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Nexmo provides APIs for SMS, voice, phone verifications, and more. Nexmo API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "nexmo") && strcmp(detector->keywords[0], "nexmoapikey"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->cloud_endpoint);
    return detector;
}

static void scan_none(const br_detector *detector, const char *input)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
}

static void grammar(const br_detector *detector)
{
    char input[180];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "nexmoapikey token - '%s'\nnexmoapikey token - '%s'\n", key_a, secret_a);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmoapikey token - '%s'\nnexmoapikey token - '%s'\n", "KULO?aja", "gngKGCWb?K0COTtS");
    scan_none(detector, input);
    snprintf(input, sizeof(input), "NEXMO %s\nnexmo %s", key_b, secret_b);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key_b, secret_b, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s\nnexmo %s\nnexmo %s", key_a, key_b, secret_a, secret_b);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 4);
    expect_pair(&out.items[0], key_a, secret_a, false);
    expect_pair(&out.items[1], key_a, secret_b, false);
    expect_pair(&out.items[2], key_b, secret_a, false);
    expect_pair(&out.items[3], key_b, secret_b, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s nexmo %s\nnexmo %s", key_a, key_a, secret_a);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].raw.data != out.items[1].raw.data);
    expect_pair(&out.items[0], key_a, secret_a, false);
    expect_pair(&out.items[1], key_a, secret_a, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", secret_a, key_a);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    char *distant = malloc(1300);
    CHECK(distant);
    int used = snprintf(distant, 1300, "nexmo %s\n", secret_a);
    CHECK(used > 0 && used + 1120 < 1300);
    memset(distant + used, 'z', 1100);
    CHECK(snprintf(distant + used + 1100, 80, "\nnexmo %s", key_a) > 0);
    out = test_scan(detector, &ctx, false, distant, strlen(distant));
    CHECK(out.len == 1 && detector->max_credential_span == 1024);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    free(distant);
    snprintf(input, sizeof(input), "nexmo %s-%s", key_a, secret_a);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s_%s", key_a, secret_a);
    scan_none(detector, input);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", hyphen_key, hyphen_secret);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], hyphen_key, hyphen_secret, false);
    br_results_clear(&out);
    scan_none(detector, "nexmo -KULOcaj\nnexmo gngKGCWbmK0COTtS");
    scan_none(detector, "nexmoKULOcaja\nnexmo gngKGCWbmK0COTtS");
    scan_none(detector, "nexmo gngKGCWbmK0COTtS");
    scan_none(detector, "nexmo KULOcaja");
    scan_none(detector, "nexmo KULOcaj\nnexmo gngKGCWbmK0COTtS");
    scan_none(detector, "nexmo KULOcajaX\nnexmo gngKGCWbmK0COTtS");
    scan_none(detector, "nexmo KULOcaja\nnexmo gngKGCWbmK0COTt");
    scan_none(detector, "nexmo KULOcaja\nnexmo gngKGCWbmK0COTtSX");
    char gap[80];
    memset(gap, 'x', 39);
    gap[39] = '\0';
    snprintf(input, sizeof(input), "nexmo%s %s\nnexmo %s", gap, key_a, secret_a);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    memset(gap, 'x', 40);
    gap[40] = '\0';
    snprintf(input, sizeof(input), "nexmo%s %s\nnexmo %s", gap, key_a, secret_a);
    scan_none(detector, input);
}

static void hyphen_inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->url, http->user) && !strstr(request->url, "%"));
    CHECK(!request->body.data && request->nheaders == 1);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char expected[96];
    snprintf(expected, sizeof(expected), "%s%s&api_secret=%s", url_prefix, key_a, secret_a);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 121);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
}

static void verify_policy(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", key_a, secret_a);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; const char *body; const char *read_error; bool verified; } cases[] = {
        {199, "balance", "ignored", false},
        {200, NULL, NULL, true},
        {204, "not read", "read failed", true},
        {299, "", "", true},
        {300, "redirect", NULL, false},
        {401, "denied", "ignored", false},
        {500, NULL, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, cases[i].body ? strlen(cases[i].body) : 0},
            .body_error = cases[i].read_error,
        };
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        expect_pair(&out.items[0], key_a, secret_a, cases[i].verified);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.response = (br_http_response){.status = 200, .body_error = "ignored after Do"};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    br_transport missing = {&http, NULL, test_http_release};
    br_scan_ctx bare = {.transport = &missing};
    http.calls = http.releases = 0;
    out = test_scan(detector, &bare, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !setter_calls);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", hyphen_key, hyphen_secret);
    http.calls = http.releases = 0;
    http.send_rc = 0;
    http.send_error = NULL;
    http.inspect = NULL;
    http.response = (br_http_response){.status = 200};
    http.user = (void *)"https://rest.nexmo.com/account/get-balance?api_key=ku-ocaja&api_secret=gngK-GCWbmK0COTt";
    http.inspect = hyphen_inspect;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_pair(&out.items[0], hyphen_key, hyphen_secret, true);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", key_a, secret_a);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
}

static void keep_caller(br_results *out, br_result *saved)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
    *saved = out->items[0];
}

static void *checked_malloc(size_t size)
{
    CHECK(candidate && candidate->raw.len == 8 && candidate->raw_v2.len == 24 && held_n < 8);
    CHECK(size == sizeof(url_prefix) + sizeof("&api_secret=") - 1 + 8 + 16);
    ++urls;
    if (hit(URL)) return NULL;
    char *url = malloc(size);
    CHECK(url);
    held_urls[held_n++] = url;
    live_url = url;
    return url;
}

static void checked_free(void *value)
{
    CHECK(!live_request);
    if (value) {
        for (size_t i = 0; i < held_n; ++i) {
            if (held_urls[i] != value) continue;
            held_urls[i] = NULL;
            ++url_frees;
            if (live_url == value) live_url = NULL;
            break;
        }
    }
    free(value);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    CHECK(regex == ((captures++ % 2) ? nexmo_compiled.secret : nexmo_compiled.key));
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure");
        CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *key_name,
                           br_slice secondary, const char *secondary_name, br_slice separator)
{
    ++findings;
    candidate = result;
    CHECK(!separator.data && !separator.len && !strcmp(key_name, "key") && !strcmp(secondary_name, "secret"));
    int rc = br_finding_pair_bytes(result, type, key, key_name, secondary, secondary_name, separator);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void check_url(const char *url, const br_result *result)
{
    char expected[96];
    snprintf(expected, sizeof(expected), "%s%.*s&api_secret=%.*s", url_prefix, 8, result->raw.data, 16, result->raw_v2.data + 8);
    CHECK(url && !strcmp(url, expected));
    CHECK(!strstr(url, "%"));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    live_request = request;
    CHECK(request->url == live_url && !request->nheaders && !request->headers && !request->timeout_ms);
    check_url(request->url, candidate);
    int rc = br_http_send(ctx, request, response, error);
    /* Send frees its synthesized User-Agent array. The provider request stays headerless. */
    CHECK(request->nheaders == 0 && !request->headers && request->url == live_url);
    check_url(request->url, candidate);
    live_request = NULL;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t alive = 0;
    for (size_t i = 0; i < held_n; ++i) {
        if (!held_urls[i]) continue;
        ++alive;
        CHECK(!strncmp(held_urls[i], url_prefix, sizeof(url_prefix) - 1));
        CHECK(!strstr(held_urls[i], "%"));
    }
    CHECK(alive && alive == held_n - url_frees);
    if (watch_out && release_n < 8) {
        rows_at[release_n] = watch_out->len;
        order_at[release_n] = response && response->status >= 200 ? response->status - 200 : 0;
    }
    ++release_n;
    br_http_release(ctx, response);
}

static int checked_push(br_results *out, br_result *result)
{
    if (!urls) CHECK(!live_url && !release_n);
    else if (release_before_push) CHECK(release_n == urls && !live_url);
    else CHECK(!release_n && live_url);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static void seam(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", key_a, secret_a);
    test_http http = {.response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    br_results out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && findings == 1 && urls == 1 && url_frees == 1 && !pushes && !http.calls && !setter_calls);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && findings == 1 && !urls && pushes == 1 && !http.calls);
    expect_pair(&out.items[0], key_a, secret_a, false);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && urls == 1 && url_frees == 1 && release_n == 1 && !release_before_push);
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls);
    expect_pair(&out.items[0], key_a, secret_a, true);
    br_results_clear(&out);
    reset_observation();
    release_before_push = true;
    http.send_rc = 1;
    http.send_error = "timeout";
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && release_n == 1 && url_frees == 1);
    CHECK(http.calls == 1 && http.releases == 1 && pushes == 1 && !setter_calls);
    br_results_clear(&out);
    http.send_rc = 0;
    http.send_error = NULL;
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    reset_observation();
    fault = URL;
    nth = 1;
    http.calls = http.releases = 0;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot allocate NexmoApiKey URL"));
    free(error);
    CHECK(fault_hit && urls == 1 && !url_frees && !http.calls && !http.releases && !pushes && !setter_calls);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fault = PUSH;
    nth = 1;
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append NexmoApiKey result"));
    free(error);
    CHECK(fault_hit && http.calls == 1 && http.releases == 1 && urls == 1 && url_frees == 1 && !setter_calls);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fault = FINDING;
    nth = 1;
    http.calls = http.releases = 0;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create NexmoApiKey result"));
    free(error);
    CHECK(fault_hit && !urls && !http.calls && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    reset_observation();
    fault = CAPTURE;
    nth = 1;
    error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "synthetic capture failure"));
    free(error);
    CHECK(fault_hit && !findings && !urls && !pushes && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
}

typedef struct {
    br_results *out;
    size_t calls, releases, rows[4];
    int order[4], send_rc;
    const char *send_error;
} nexmo_script;

static int nexmo_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    (void)ctx;
    nexmo_script *script = user;
    CHECK(request && request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog") && request->url);
    CHECK(!strncmp(request->url, url_prefix, sizeof(url_prefix) - 1) && !strstr(request->url, "%"));
    ++script->calls;
    if (script->send_rc) {
        *error = script->send_error ? strdup(script->send_error) : NULL;
        CHECK(!script->send_error || *error);
        return script->send_rc;
    }
    *response = (br_http_response){.status = 200 + (int)script->calls};
    *error = NULL;
    return 0;
}

static void nexmo_release(void *user, br_http_response *response)
{
    nexmo_script *script = user;
    CHECK(script->releases < 4 && script->out);
    script->rows[script->releases] = script->out->len;
    script->order[script->releases] = response && response->status >= 200 ? response->status - 200 : 0;
    ++script->releases;
}

static void lifo_and_failed_send(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s\nnexmo %s", key_a, secret_a, secret_b);
    br_results out = {0};
    br_result prior = {0};
    keep_caller(&out, &prior);
    nexmo_script script = {.out = &out};
    br_transport transport = {&script, nexmo_send, nexmo_release};
    br_scan_ctx ctx = {.transport = &transport};
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && script.calls == 2 && script.releases == 2 && !setter_calls);
    CHECK(script.order[0] == 2 && script.order[1] == 1);
    CHECK(script.rows[0] == 3 && script.rows[1] == 3);
    expect_pair(&out.items[1], key_a, secret_a, true);
    expect_pair(&out.items[2], key_a, secret_b, true);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", key_a, secret_a);
    script = (nexmo_script){.out = &out, .send_rc = 1, .send_error = "timeout"};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && script.calls == 1 && script.releases == 1 && script.rows[0] == 1);
    expect_pair(&out.items[1], key_a, secret_a, false);
    CHECK(out.items[0].raw.data == prior.raw.data && !strcmp(prior.verification_error, "caller-owned"));
    br_results_clear(&out);
    keep_caller(&out, &prior);
    br_transport missing = {&script, NULL, nexmo_release};
    br_scan_ctx bare = {.transport = &missing};
    script = (nexmo_script){.out = &out};
    error = NULL;
    CHECK(detector->scan(detector, &bare, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 2 && !script.calls && script.releases == 1 && script.rows[0] == 1);
    expect_pair(&out.items[1], key_a, secret_a, false);
    CHECK(out.items[0].verification_error == prior.verification_error);
    br_results_clear(&out);
}

static void later_fatal_drain(const br_detector *detector)
{
    char input[220];
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s\nnexmo %s\nnexmo %s",
             key_a, secret_a, secret_b, hyphen_secret);
    br_results kept = {0};
    br_result prior = {0};
    keep_caller(&kept, &prior);
    nexmo_script script = {.out = &kept};
    br_transport transport = {&script, nexmo_send, nexmo_release};
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    watch_out = &kept;
    fault = PUSH;
    nth = 3;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append NexmoApiKey result"));
    free(error);
    CHECK(fault_hit && script.calls == 3 && script.releases == 3 && release_n == 3 && url_frees == 3);
    CHECK(script.order[0] == 3 && script.order[1] == 2 && script.order[2] == 1);
    CHECK(script.rows[0] == 3 && script.rows[1] == 3 && script.rows[2] == 3);
    CHECK(rows_at[0] == 3 && order_at[0] == 3 && rows_at[2] == 3 && order_at[2] == 1);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    CHECK(!strcmp(prior.verification_error, "caller-owned") && !setter_calls);
    br_results_clear(&kept);
    reset_observation();
    keep_caller(&kept, &prior);
    snprintf(input, sizeof(input), "nexmo %s\nnexmo %s\nnexmo %s", key_a, secret_a, secret_b);
    script = (nexmo_script){.out = &kept};
    watch_out = &kept;
    fault = URL;
    nth = 2;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot allocate NexmoApiKey URL"));
    free(error);
    CHECK(fault_hit && urls == 2 && url_frees == 1 && script.calls == 1 && script.releases == 1);
    CHECK(script.rows[0] == 2 && kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)));
    br_results_clear(&kept);
    reset_observation();
}

int main(void)
{
    CHECK(strlen(key_a) == 8 && strlen(key_b) == 8 && strlen(hyphen_key) == 8);
    CHECK(strlen(secret_a) == 16 && strlen(secret_b) == 16 && strlen(hyphen_secret) == 16);
    const br_detector *detector = open_detector(br_nexmoapikey_init);
    grammar(detector);
    verify_policy(detector);
    lifo_and_failed_send(detector);
    const br_detector *observed = open_detector(observed_init);
    grammar(observed);
    seam(observed);
    later_fatal_drain(observed);
    CHECK(!live_request && !live_url && fault == NONE && !setter_calls);
    return test_finish("NexmoApiKey");
}
