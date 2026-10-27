/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33], id1[37], id2[37];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Target actual resources/positive helper returns, without URL/auth seams. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static void make_id(char out[37], size_t shift)
{
    test_secret(out, 36, shift);
    out[0] = shift ? 'Q' : 'G'; out[8] = '-'; out[9] = '-'; out[16] = 'Z'; out[23] = '-'; out[30] = '-'; out[35] = 'W';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 32 && strlen(key2) == 32 && strlen(id1) == 36 && strlen(id2) == 36);
    CHECK(br_dnscheck_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Dnscheck detector output"));
    free(error); error = NULL;
    CHECK(br_dnscheck_init(NULL, NULL) == -1);
    CHECK(br_dnscheck_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dnscheck_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 281 && detector->version == 0 && !strcmp(detector->name, "Dnscheck"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Dnscheck is a service used to monitor DNS records. The API keys can be used to access and manage DNS monitoring configurations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "dnscheck"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, const char *id, bool verified)
{
    CHECK(result->detector_type == 281 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, key, 32));
    CHECK(result->raw_v2.len == 68 && !memcmp(result->raw_v2.data, key, 32) && !memcmp(result->raw_v2.data + 32, id, 36));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->verified == verified && !result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), key, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 36 && !memcmp(json_object_get_string(part), id, 36));
}

static void extraction_case(const br_detector *detector, br_slice input, const char *key, const char *id)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    if (results.len != (key && id ? 1u : 0u))
        fprintf(stderr, "extraction count=%zu expected=%u input=%.*s\n", results.len, key && id ? 1u : 0u, (int)input.len, input.data ? (const char *)input.data : "");
    CHECK(results.len == (key && id ? 1u : 0u) && !http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], key, id, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[768], changed[39];
    const struct { const char *format; bool match; } keys[] = {
        {"dnscheck %s", true}, {"DnScHeCk:'%s'", true}, {"preDNSCHECKsuffix\r\n%s", true},
        {"%s dnscheck", false}, {"%s", false}, {"dnscheck%s", false},
        {"dnscheck x%s", false}, {"dnscheck _%s", false}, {"dnscheck %sx", false}, {"dnscheck %s_", false},
        {"dnscheck .%s!", true}, {"dnscheck \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), keys[i].format, key1);
        snprintf(input + at, sizeof(input) - at, "\ndnscheck %s", id1);
        extraction_case(detector, text(input), keys[i].match ? key1 : NULL, id1);
    }
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, key1, sizeof(key1)); changed[7] = "_+-"[i];
        snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", changed, id1);
        extraction_case(detector, text(input), NULL, id1);
    }
    snprintf(input, sizeof(input), "dnscheck %.31s\ndnscheck %s", key1, id1); extraction_case(detector, text(input), NULL, id1);
    snprintf(input, sizeof(input), "dnscheck %sa\ndnscheck %s", key1, id1); extraction_case(detector, text(input), NULL, id1);
    memset(changed, 'Z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", changed, id1); extraction_case(detector, text(input), changed, id1); /* Not hex or entropy-filtered. */
    const struct { const char *format; bool match; } ids[] = {
        {"dnscheck %s", true}, {"DNSCHECK id=%s", true}, {"%s", true}, {"dnscheck%s", false}, /* Bare ID shares the earlier key field's prefix, 34 runes away. */
        {"dnscheck x%s", false}, {"dnscheck _%s", false}, {"dnscheck %sx", false}, {"dnscheck %s_", false},
        {"dnscheck %s!", true}, {"dnscheck %sa", false}, {"dnscheck %.35s", false},
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), "dnscheck %s\n", key1);
        snprintf(input + at, sizeof(input) - at, ids[i].format, id1);
        extraction_case(detector, text(input), key1, ids[i].match ? id1 : NULL);
    }
    memcpy(changed, id1, sizeof(id1)); changed[12] = '_';
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", key1, changed); extraction_case(detector, text(input), key1, NULL);
    memcpy(changed, id1, sizeof(id1)); changed[0] = '-';
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck%s", key1, changed); extraction_case(detector, text(input), key1, changed);
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", key1, changed); extraction_case(detector, text(input), key1, NULL);
    memcpy(changed, id1, sizeof(id1)); changed[35] = '-';
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %sX", key1, changed); extraction_case(detector, text(input), key1, changed);
    snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", key1, changed); extraction_case(detector, text(input), key1, NULL); /* Source ASCII word boundary, not a UUID rule. */
    snprintf(input, sizeof(input), "dnscheck %s", key1); extraction_case(detector, text(input), key1, NULL);
    snprintf(input, sizeof(input), "dnscheck %s", id1); extraction_case(detector, text(input), NULL, id1);
    extraction_case(detector, (br_slice){0}, NULL, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int kind = 0; kind < 2; ++kind) {
            size_t at = (size_t)snprintf(input, sizeof(input), "dnscheck %s\ndnscheck", kind ? key1 : id1);
            for (size_t r = 0; r < gap; ++r) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
            at += (size_t)snprintf(input + at, sizeof(input) - at, "%s", kind ? id1 : key1);
            extraction_case(detector, (br_slice){(const unsigned char *)input, at}, gap == 40 ? key1 : NULL, id1);
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\ndnscheck %s\ndnscheck %s\n\xff", key1, id1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key1, id1);
}

typedef struct {
    const char *const *keys, *const *ids; size_t nkeys, nids;
    const char *agent, *borrowed_url, *current_key, *current_id;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t pair = http->calls - 1;
    CHECK(ctx && ctx == expected->original && pair < expected->nkeys * expected->nids);
    const char *key = expected->keys[pair / expected->nids], *id = expected->ids[pair % expected->nids];
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && request->detector_type == 281);
    CHECK(strlen(request->url) == 115 && request->url[115] == '\0');
    CHECK(!memcmp(request->url, "https://www.dnscheck.co/api/v1/groups/", 38));
    CHECK(!memcmp(request->url + 38, id, 36) && !memcmp(request->url + 74, "?api_key=", 9) && !memcmp(request->url + 83, key, 32));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, expected->agent)); /* No Auth, Type, Accept or dedup header. */
    expected->borrowed_url = request->url; expected->current_key = key; expected->current_id = id;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(expected->borrowed_url[115] == '\0');
        CHECK(!memcmp(expected->borrowed_url + 38, expected->current_id, 36) && !memcmp(expected->borrowed_url + 83, expected->current_key, 32));
        expected->borrowed_url = NULL; /* Complete stack URL survives send AND release. */
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products(const br_detector *detector)
{
    char input[4096]; size_t at = (size_t)snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s\ndnscheck %s\n", key1, key2, key1);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\ndnscheck %s\ndnscheck %s\ndnscheck %s", id1, id2, id1);
    const char *keys[] = {key1, key2, key1}, *ids[] = {id1, id2, id1};
    expected_http expected = {.keys = keys, .ids = ids, .nkeys = 3, .nids = 3, .agent = "TruffleHog dnscheck-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "dnscheck-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == 9 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], ids[i % 3], false);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], ids[i % 3], true);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, at);
    CHECK(!results.len && http.calls == 9 && http.releases == 9); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 9); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", key1, id1);
    const char *keys[] = {key1}, *ids[] = {id1};
    expected_http expected = {.keys = keys, .ids = ids, .nkeys = 1, .nids = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, "ignored", true},
        {204, 0, NULL, "", true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, "ignored", false}, {403, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, -1, "synthetic timeout", "ignored", false}, {200, 1, "net/http: nil Context", NULL, false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false}, {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key1, id1, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s", key1, id1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, id1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "dnscheck %s\ndnscheck %s\ndnscheck %s", key1, id1, id2);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Dnscheck result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Dnscheck result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 33; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 37; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL; /* ID capture resources fail before constructor skip as well. */
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Skips never append. */
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Dnscheck result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, id1, true); check_result(&results.items[1], key1, id2, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 7); key1[0] = 'Z'; key1[8] = 'Q'; key2[5] = 'G';
    make_id(id1, 0); make_id(id2, 9);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); verification(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("Dnscheck");
}
