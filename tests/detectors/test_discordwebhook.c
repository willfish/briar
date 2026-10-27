/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char prefix[] = "https://discord.com/api/webhooks/";
static char secret[69], url18[121], url19[122];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Fail actual shared resources, never an invented URL-copy allocation. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++allocation_failures; return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(secret) == 68 && strlen(url18) == 120 && strlen(url19) == 121);
    CHECK(br_discordwebhook_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_discordwebhook_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_discordwebhook_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 66 && detector->version == 0 && !strcmp(detector->name, "DiscordWebhook"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Discord webhooks are used to send messages to a Discord channel. They can be used to automate messages and send data updates."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], prefix));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 66, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], changed[122];
    extraction_case(detector, url18, strlen(url18), url18); /* Leading-zero ID is not validated. */
    extraction_case(detector, url19, strlen(url19), url19);
    const char *accepted[] = {"prefix%sSuffix", "'%s'", "%sA", "%s_", "%s?wait=true", "%s/messages"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], url18); extraction_case(detector, input, strlen(input), url18);
    }
    snprintf(input, sizeof(input), "%.*s", (int)strlen(url18) - 1, url18);
    extraction_case(detector, input, strlen(input), NULL);
    const char *bad_prefixes[] = {"http://discord.com/api/webhooks/", "HTTPS://discord.com/api/webhooks/",
        "https://Discord.com/api/webhooks/", "https://discord.com/api/Webhooks/", "https://discordapp.com/api/webhooks/",
        "https://discordXcom/api/webhooks/", "https://discord.com.evil/api/webhooks/", "https://discord.com//api/webhooks/"};
    for (size_t i = 0; i < sizeof(bad_prefixes) / sizeof(bad_prefixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s000000000000000000/%s", bad_prefixes[i], secret);
        extraction_case(detector, input, strlen(input), NULL);
    }
    const char *bad_ids[] = {"12345678901234567", "12345678901234567890", "12345678901234567x"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s/%s", prefix, bad_ids[i], secret); extraction_case(detector, input, strlen(input), NULL);
    }
    const char invalid[] = "_./+=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, url18, sizeof(url18)); changed[sizeof(prefix) - 1 + 18 + 1 + 20] = invalid[i];
        extraction_case(detector, changed, strlen(changed), NULL);
    }
    char hyphens[69]; memset(hyphens, '-', 68); hyphens[68] = '\0';
    snprintf(input, sizeof(input), "%s000000000000000000/%s", prefix, hyphens);
    extraction_case(detector, input, strlen(input), input); /* No boundary, ID, entropy or URL parser filter. */
    int n = snprintf(input, sizeof(input), "%c%s%c", 0, url18, 0xff);
    CHECK(n == 122); extraction_case(detector, input, (size_t)n, url18);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *url, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *step = &steps->rows[at];
    CHECK(request->detector_type == 66 && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, step->url)); /* Never message-creating POST or DELETE. */
    CHECK(strlen(request->url) == 120 || strlen(request->url) == 121);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog discordwebhook-offline" : "TruffleHog"));
    /* No Auth, Type, Accept or invented logical Content-Length. */
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->nil_body ? "" : "synthetic ignored read error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; const char *expected = steps->rows[http->calls - 1].url;
    CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, expected, strlen(expected) + 1));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void verification_and_occurrences(const br_detector *detector)
{
    char input[384]; snprintf(input, sizeof(input), "%s\n%s\n%s", url18, url19, url18);
    reply rows[] = {{.url = url18, .status = 200, .send_rc = 1, .send_error = "unsupported: native curl HTTP client profile"},
                    {.url = url19, .status = 204, .nil_body = true},
                    {.url = url18, .status = 299, .send_rc = -7, .send_error = "cannot create DiscordWebhook result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u, .agent_suffix = "discordwebhook-offline"};
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], url18, false); check_result(&results.items[1], url19, verify); check_result(&results.items[2], url18, false);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap); /* No artificial append/clear on constructor skip. */
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? url19 : url18, false);
        br_results_clear(&results);
    }
    /* Verification uses the captured prefix, not the longer input URL. */
    snprintf(input, sizeof(input), "%sA_extra?wait=true", url18);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 403, 429, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.url = url18, .status = statuses[i], .nil_body = i % 2 == 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], url18, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, url18, strlen(url18));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], url18, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
}

static void resource_failures(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\n%s", url18, url19); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.url = url18, .status = 200}, {.url = url19, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First finding already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot create DiscordWebhook result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual +1 capture/regexp resource failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DiscordWebhook result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(secret, 68, 0); secret[0] = 'G'; secret[31] = '-'; secret[43] = 'Y'; secret[67] = 'Z';
    CHECK(snprintf(url18, sizeof(url18), "%s000000000000000000/%s", prefix, secret) == 120);
    CHECK(snprintf(url19, sizeof(url19), "%s9999999999999999999/%s", prefix, secret) == 121);
    const br_detector *detector = descriptor(); extraction(detector); verification_and_occurrences(detector);
    shared_setup_errors(detector); resource_failures(detector);
    return test_finish("DiscordWebhook");
}
