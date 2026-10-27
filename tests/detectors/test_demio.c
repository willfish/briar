/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[33], other[33], short_secret[11], long_secret[21];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Exercise actual shared resources, not invented URL formatting seams. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(strlen(short_secret) == 10 && strlen(long_secret) == 20);
    CHECK(br_demio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:demio)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_demio_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_demio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_demio_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 863 && detector->version == 0 && !strcmp(detector->name, "Demio"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Demio is a webinar platform that allows users to host, promote, and analyze webinars. Demio API keys can be used to access and manage webinar data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "demio"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    /* Only the key is exposed, including for verified hidden-secret products. */
    test_key_result(result, 863, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, bool paired)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (paired ? 1u : 0u) && !http.calls && !http.releases);
    if (paired) check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[34];
    snprintf(input, sizeof(input), "DeMiO = '%s'\r\nDEMIO = '%s'", key, short_secret); extraction_case(detector, input, true);
    snprintf(input, sizeof(input), "predemiosuffix:%s\ndemio-%s-", key, long_secret); extraction_case(detector, input, true);
    snprintf(input, sizeof(input), "demio %s %s", key, short_secret); extraction_case(detector, input, true);
    snprintf(input, sizeof(input), "demio %s", key); extraction_case(detector, input, false); /* Cannot truncate a 32-byte word into a secret. */
    snprintf(input, sizeof(input), "demio %s", short_secret); extraction_case(detector, input, false);
    snprintf(input, sizeof(input), "dem io %s\ndem io %s", key, short_secret); extraction_case(detector, input, false);
    const char *bad_keys[] = {"demio%s\ndemio %s", "demio _%s\ndemio %s", "demio %s_\ndemio %s"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        snprintf(input, sizeof(input), bad_keys[i], key, short_secret); extraction_case(detector, input, false);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "demio %s\ndemio %s", changed, short_secret); extraction_case(detector, input, false);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0';
    snprintf(input, sizeof(input), "demio %s\ndemio %s", changed, short_secret); extraction_case(detector, input, false);
    char secret[22]; memcpy(secret, short_secret, sizeof(short_secret)); secret[9] = '\0';
    snprintf(input, sizeof(input), "demio %s\ndemio %s", key, secret); extraction_case(detector, input, false);
    memcpy(secret, long_secret, sizeof(long_secret)); secret[20] = 'a'; secret[21] = '\0';
    snprintf(input, sizeof(input), "demio %s\ndemio %s", key, secret); extraction_case(detector, input, false);
    snprintf(input, sizeof(input), "demio %s\ndemio _%s_", key, short_secret); extraction_case(detector, input, false);
    memcpy(secret, long_secret, sizeof(long_secret)); secret[10] = '_';
    snprintf(input, sizeof(input), "demio %s\ndemio %s", key, secret); extraction_case(detector, input, false);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "demio%*s%s\ndemio %s", (int)gap, "", key, short_secret);
        extraction_case(detector, input, gap == 40);
        snprintf(input, sizeof(input), "demio %s\ndemio%*s%s", key, (int)gap, "", long_secret);
        extraction_case(detector, input, gap == 40);
    }
    char far[1400]; int n = snprintf(far, sizeof(far), "demio %s", key); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "\ndemio %s", short_secret);
    extraction_case(detector, far, true); /* No local 1024-byte span constraint on products. */
    extraction_case(detector, "", false);
}

typedef struct { const char *key, *secret, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[112];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *step = &steps->rows[at];
    CHECK(request->detector_type == 863 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    int n = snprintf(steps->expected_url, sizeof(steps->expected_url), "https://my.demio.com/api/v1/ping/query?api_key=%s&api_secret=%s", step->key, step->secret);
    CHECK(n >= 101 && n <= 111 && n == 91 + (int)strlen(step->secret));
    CHECK(strlen(request->url) == (size_t)n && !memcmp(request->url, steps->expected_url, (size_t)n + 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog demio-offline" : "TruffleHog"));
    /* Exact count excludes Type/Accept/Auth/secret headers and invented CL. */
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->nil_body ? "" : "synthetic ignored read error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && !strcmp(steps->borrowed_url, steps->expected_url));
    CHECK(steps->borrowed_url[strlen(steps->expected_url)] == '\0');
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void products_and_verification(const br_detector *detector)
{
    char input[384]; snprintf(input, sizeof(input), "demio %s\nDEMIO %s\ndemio %s\ndemio %s\nDEMIO %s\ndemio %s", key, other, key, short_secret, long_secret, short_secret);
    const char *keys[] = {key, other, key}, *secrets[] = {short_secret, long_secret, short_secret};
    const int statuses[] = {200, 204, 299, 199, 300, 401, 429, 503, 201}; reply rows[9];
    for (size_t k = 0; k < 3; ++k) for (size_t s = 0; s < 3; ++s) {
        size_t i = k * 3 + s;
        rows[i] = (reply){.key = keys[k], .secret = secrets[s], .status = statuses[i], .nil_body = i % 2 != 0};
    }
    rows[0].send_rc = 1; rows[0].send_error = "cannot format Demio URL";
    rows[8].send_rc = -7; rows[8].send_error = "cannot create Demio result";
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 9u : 0u, .agent_suffix = "demio-offline"};
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 9);
        for (size_t i = 0; i < 9; ++i)
            check_result(&results.items[i], keys[i / 3], verify && rows[i].send_rc == 0 && statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], false);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "demio %s\ndemio %s", key, short_secret);
    const int bounds[] = {200, 299, 300};
    for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); ++i) {
        reply row = {.key = key, .secret = short_secret, .status = bounds[i], .nil_body = true}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, bounds[i] < 300); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "demio %s\ndemio %s", key, short_secret);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
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
    char input[160]; snprintf(input, sizeof(input), "demio %s\ndemio %s\ndemio %s", key, short_secret, long_secret);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .secret = short_secret, .status = 200}, {.key = key, .secret = long_secret, .status = 200}};
        script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First native product was already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot create Demio result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        /* The second regex scratch allocation belongs to the secret list and
         * genuinely returns +1; no products may escape that capture failure. */
        fail_size = 2 * sizeof(br_span); fail_after = 2;
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t capacity = results.cap; results.cap = 0; /* Genuine +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Demio result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 32, 0); test_secret(other, 32, 11); test_secret(short_secret, 10, 7); test_secret(long_secret, 20, 19);
    key[0] = 'G'; key[21] = 'Z'; other[13] = 'H'; short_secret[0] = 'Q'; long_secret[17] = 'W';
    const br_detector *detector = descriptor(); extraction(detector); products_and_verification(detector);
    shared_setup_errors(detector); resource_failures(detector);
    return test_finish("Demio");
}
