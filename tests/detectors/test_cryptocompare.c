/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[65], other[65];
static const char url_prefix[] = "https://min-api.cryptocompare.com/data/blockchain/list?api_key=";
static const unsigned char success[] = "\"Response\":\"Success\"";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Target real shared-resource boundaries, never an invented URL allocation. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
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
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64);
    CHECK(br_cryptocompare_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    /* The prefix helper's genuine positive failure is normalized by the factory. */
    fail_alloc_size = sizeof("(?i:cryptocompare)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_cryptocompare_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_cryptocompare_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_cryptocompare_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 393 && detector->version == 0 && !strcmp(detector->name, "CryptoCompare"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "CryptoCompare is a cryptocurrency market data provider. CryptoCompare API keys can be used to access and retrieve market data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cryptocompare"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 393, expected, "key");
    CHECK(result->raw.len == 64 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 64 && !memcmp(json_object_get_string(part), expected, 64));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[66];
    const char *accepted[] = {"cryptocompare = '%s'", "CrYpToCoMpArE\r\n%s", "preCRYPTOCOMPAREsuffix:%s", "cryptocompare\r%s", "cryptocompare\n%s", "cryptocompare-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s cryptocompare", "crypto compare %s", "cryptocompare%s", "cryptocompare _%s", "cryptocompare %s_", "cryptocompare X%s", "cryptocompare %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "cryptocompare%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
        memcpy(input, "cryptocompare", 13);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 13 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 13 + 2 * gap, key, sizeof(key));
        extraction_case(detector, input, 13 + 2 * gap + 64, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[63] = '\0';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[64] = 'a'; changed[65] = '\0';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "_.:/AZ";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[20] = disallowed[i];
        snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    /* Literal hyphens are allowed, including at an endpoint when its outside
     * neighbor is a word byte; standalone endpoint hyphens lack that boundary. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "cryptocompareX%s", changed); extraction_case(detector, input, strlen(input), changed);
    snprintf(input, sizeof(input), "cryptocompare%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[63] = '-';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "cryptocompare %sX", changed); extraction_case(detector, input, strlen(input), changed);
    changed[0] = '-';
    snprintf(input, sizeof(input), "cryptocompareX%sY", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, 'a', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), changed); /* No local entropy/FP filter. */
    changed[31] = 'z'; changed[32] = '-';
    snprintf(input, sizeof(input), "cryptocompare %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not a hex-only capture. */
    snprintf(input, sizeof(input), "cryptocompare %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches. */
    int n = snprintf(input, sizeof(input), "cryptocompare%c%s", 0, key);
    CHECK(n == 78); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%ccryptocompare %s%c", 0xff, key, 0xff);
    CHECK(n == 80); extraction_case(detector, input, (size_t)n, key); /* No global UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *key, *send_error, *body_error;
    int status, send_rc;
    br_slice body;
} reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[sizeof(url_prefix) + 64];
} script;

static reply success_reply(const char *candidate, int status)
{
    return (reply){.key = candidate, .status = status, .body = {success, sizeof(success) - 1}};
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 393 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "%s%s", url_prefix, step->key) == (int)sizeof(steps->expected_url) - 1);
    CHECK(strlen(request->url) == sizeof(steps->expected_url) - 1 && !memcmp(request->url, steps->expected_url, sizeof(steps->expected_url)));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    /* Common UA only: no Type, Accept, Authorization or invented logical CL. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog cryptocompare-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->body_error};
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == sizeof(steps->expected_url) - 1);
    CHECK(!memcmp(steps->borrowed_url, steps->expected_url, sizeof(steps->expected_url)));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "cryptocompare %s\nCRYPTOCOMPARE %s\ncryptocompare %s", key, other, key);
    const char *keys[] = {key, other, key};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "cryptocompare-offline"};
        steps.rows[0] = success_reply(key, 200); steps.rows[0].send_rc = 1;
        steps.rows[0].send_error = "synthetic timeout"; steps.rows[0].body_error = "ignored after failed send";
        steps.rows[1] = success_reply(other, 204);
        steps.rows[2] = success_reply(key, 299); steps.rows[2].send_rc = -7;
        steps.rows[2].send_error = "context canceled"; steps.rows[2].body_error = "";
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i == 1);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
    /* A read failure drops only its occurrence; later duplicates still verify. */
    for (int drop = 0; drop < 2; ++drop) {
        script steps = {.count = 3};
        steps.rows[0] = success_reply(key, 200); steps.rows[1] = success_reply(other, 403);
        steps.rows[2] = success_reply(key, 299); steps.rows[drop].body_error = drop ? "" : "synthetic read failure";
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 2);
        check_result(&results.items[0], drop ? key : other, drop != 0);
        check_result(&results.items[1], key, true); br_results_clear(&results);
    }
}

static void statuses_bodies_and_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "cryptocompare %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = success_reply(key, status);
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = success_reply(key, rejected[i]);
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    static const unsigned char binary[] = "\0\xff junk \"Response\":\"Success\"\0tail";
    static const unsigned char split[] = "\"Response\":\"Succ\0ess\"";
    const struct { br_slice body; bool verified; } bodies[] = {
        {{(const unsigned char *)"{\"Response\":\"Success\"}", sizeof("{\"Response\":\"Success\"}") - 1}, true},
        {{binary, sizeof(binary) - 1}, true},
        {{(const unsigned char *)"junk\"Response\":\"Success\"malformed", sizeof("junk\"Response\":\"Success\"malformed") - 1}, true},
        {{(const unsigned char *)"{\"Response\": \"Success\"}", sizeof("{\"Response\": \"Success\"}") - 1}, false},
        {{(const unsigned char *)"{\"Response\" :\"Success\"}", sizeof("{\"Response\" :\"Success\"}") - 1}, false},
        {{(const unsigned char *)"\"response\":\"Success\"", sizeof("\"response\":\"Success\"") - 1}, false},
        {{(const unsigned char *)"\"Response\":\"success\"", sizeof("\"Response\":\"success\"") - 1}, false},
        {{(const unsigned char *)"\"Response\":\"Successful\"", sizeof("\"Response\":\"Successful\"") - 1}, false},
        {{(const unsigned char *)"Response:Success", sizeof("Response:Success") - 1}, false},
        {{split, sizeof(split) - 1}, false},
        {{(const unsigned char *)"", 0}, false},
        {{0}, false},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = success_reply(key, 200); steps.rows[0].body = bodies[i].body;
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, bodies[i].verified); br_results_clear(&results);
    }
    const int read_statuses[] = {0, 199, 200, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(read_statuses) / sizeof(read_statuses[0]); ++i) {
        for (int empty = 0; empty < 2; ++empty) {
            script steps = {.count = 1}; steps.rows[0] = success_reply(key, read_statuses[i]);
            steps.rows[0].body_error = empty ? "" : "synthetic read failure";
            br_results results = run(detector, input, true, &steps);
            CHECK(!results.len); br_results_clear(&results);
        }
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create CryptoCompare result", "synthetic secret-bearing Do error", "unsupported native client configuration", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = success_reply(key, 200);
        steps.rows[0].send_rc = i % 2 ? -1 : 1; steps.rows[0].send_error = causes[i];
        steps.rows[0].body_error = i % 2 ? "" : "must not turn a send failure into a drop";
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "cryptocompare %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t before = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
    CHECK(results->items[0].secret_parts == parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "cryptocompare %s\ncryptocompare %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 4; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = success_reply(key, 200); steps.rows[1] = success_reply(other, 200);
        if (mode == 3) steps.rows[0].body_error = steps.rows[1].body_error = "";
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) fail_part_after = 2; /* First finding appended, nil-ctx skipped or read-error dropped. */
            else {
                fail_alloc_size = failure == 1 ? 64 : failure == 2 ? 65 : failure == 3 ? 2 * sizeof(br_span) : 8 * sizeof(char *);
                /* Two capture-vector allocations precede both 64-byte Raw allocations. */
                fail_alloc_after = failure == 1 ? 4 : failure == 2 ? 2 : 1;
            }
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_part_after && !fail_alloc_after);
            const char *expected = failure < 2 ? "cannot create CryptoCompare result" : failure == 2 ? "out of memory copying detector capture" : failure == 3 ? "out of memory iterating regex" : "out of memory collecting detector captures";
            CHECK(!strcmp(error, expected));
            CHECK(http.calls == ((mode == 1 || mode == 3) && failure < 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* The actual append guard returns +1, which must be fatal, not a skip. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append CryptoCompare result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts);
        if (mode == 3) {
            CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == 0 && !error);
            CHECK(http.calls == 2 && http.releases == 2); check_prior(&results, raw, prior_error, parts);
        }
        br_results_clear(&results);
    }
    script steps = {.count = 2}; steps.rows[0] = success_reply(key, 200); steps.rows[1] = success_reply(other, 299);
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 64, 0); test_secret(other, 64, 11);
    key[9] = key[31] = key[53] = '-'; other[17] = '-';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_bodies_and_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("CryptoCompare");
}
