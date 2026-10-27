/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[60], key2[60];
static const char id1[] = "00000000000000000", id2[] = "12345678901234567";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Target actual owned resources and positive helper failures; no auth heap seam. */
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

static void make_key(char out[60], size_t shift)
{
    test_secret(out, 24, shift); out[24] = '.';
    test_secret(out + 25, 6, shift + 9); out[31] = '.';
    test_secret(out + 32, 27, shift + 17);
    out[0] = shift ? 'Q' : 'A'; out[8] = '_'; out[13] = '-'; out[27] = 'B'; out[45] = '_'; out[48] = '-'; out[58] = 'Z';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 59 && strlen(key2) == 59 && strlen(id1) == 17 && strlen(id2) == 17);
    CHECK(br_discordbottoken_init(NULL, &error) == -1 && error && !strcmp(error, "invalid DiscordBotToken detector output"));
    free(error); error = NULL;
    CHECK(br_discordbottoken_init(NULL, NULL) == -1);
    CHECK(br_discordbottoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_discordbottoken_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 65 && detector->version == 0 && !strcmp(detector->name, "DiscordBotToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Discord bot tokens are used to authenticate and control Discord bots. These tokens can be used to interact with the Discord API to perform various bot-related operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "discord"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, const char *id, bool verified)
{
    CHECK(result->detector_type == 65 && !result->detector_name);
    CHECK(result->raw.len == 59 && !memcmp(result->raw.data, key, 59));
    CHECK(result->raw_v2.len == 76 && !memcmp(result->raw_v2.data, key, 59) && !memcmp(result->raw_v2.data + 59, id, 17));
    CHECK(result->redacted && strlen(result->redacted) == 17 && !memcmp(result->redacted, id, 17));
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->verified == verified && !result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 59 && !memcmp(json_object_get_string(part), key, 59));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 17 && !memcmp(json_object_get_string(part), id, 17));
    CHECK(result->redacted != json_object_get_string(part)); /* Separate owned allocation, not a JSON alias. */
}

static void extraction_case(const br_detector *detector, br_slice input, const char *key, const char *id)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (key && id ? 1u : 0u) && !http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], key, id, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[768], changed[62];
    const struct { const char *format; bool match; } keys[] = {
        {"discord %s", true}, {"DiScOrD:'%s'", true}, {"preDISCORDsuffix\r\n%s", true},
        {"%s discord", false}, {"%s", false}, {"discord%s", false},
        {"discord x%s", false}, {"discord _%s", false}, {"discord %sx", false}, {"discord %s_", false},
        {"discord .%s!", true}, {"discord \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), keys[i].format, key1);
        snprintf(input + at, sizeof(input) - at, "\ndiscord %s", id1);
        extraction_case(detector, text(input), keys[i].match ? key1 : NULL, id1);
    }
    memcpy(changed, key1, sizeof(key1)); changed[9] = '+';
    snprintf(input, sizeof(input), "discord %s\ndiscord %s", changed, id1); extraction_case(detector, text(input), NULL, id1);
    snprintf(input, sizeof(input), "discord %.23s%s\ndiscord %s", key1, key1 + 24, id1);
    extraction_case(detector, text(input), NULL, id1);
    snprintf(input, sizeof(input), "discord %.30s%s\ndiscord %s", key1, key1 + 31, id1);
    extraction_case(detector, text(input), NULL, id1);
    snprintf(input, sizeof(input), "discord %.58s\ndiscord %s", key1, id1);
    extraction_case(detector, text(input), NULL, id1);
    memcpy(changed, key1, sizeof(key1)); changed[0] = '-';
    snprintf(input, sizeof(input), "discord%s\ndiscord %s", changed, id1); extraction_case(detector, text(input), changed, id1);
    snprintf(input, sizeof(input), "discord %s\ndiscord %s", changed, id1); extraction_case(detector, text(input), NULL, id1);
    memcpy(changed, key1, sizeof(key1)); changed[58] = '-';
    snprintf(input, sizeof(input), "discord %sX\ndiscord %s", changed, id1); extraction_case(detector, text(input), changed, id1);
    snprintf(input, sizeof(input), "discord %s\ndiscord %s", changed, id1); extraction_case(detector, text(input), NULL, id1); /* ASCII word boundary, not a Base64 semantic rule. */

    const struct { const char *format; bool match; } ids[] = {
        {"discord %s", true}, {"DISCORD id=%s", true}, {"%s", false}, {"discord%s", false},
        {"discord x%s", false}, {"discord _%s", false}, {"discord %sx", false}, {"discord %s_", false},
        {"discord %s-", true}, {"discord %s0", false}, {"discord %.16s", false},
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), "discord %s\n", key1);
        snprintf(input + at, sizeof(input) - at, ids[i].format, id1);
        extraction_case(detector, text(input), key1, ids[i].match ? id1 : NULL);
    }
    snprintf(input, sizeof(input), "discord %s", key1); extraction_case(detector, text(input), key1, NULL);
    snprintf(input, sizeof(input), "discord %s", id1); extraction_case(detector, text(input), NULL, id1);
    extraction_case(detector, (br_slice){0}, NULL, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int kind = 0; kind < 2; ++kind) {
            size_t at = (size_t)snprintf(input, sizeof(input), "%s", kind ? "" : "discord 00000000000000000\n");
            if (kind) at += (size_t)snprintf(input + at, sizeof(input) - at, "discord %s\n", key1);
            memcpy(input + at, "discord", 7); at += 7;
            for (size_t r = 0; r < gap; ++r) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
            at += (size_t)snprintf(input + at, sizeof(input) - at, "%s", kind ? id1 : key1);
            extraction_case(detector, (br_slice){(const unsigned char *)input, at}, gap == 40 ? key1 : NULL, id1);
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\ndiscord %s\ndiscord %s\n\xff", key1, id1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key1, id1);
}

typedef struct {
    const char *const *keys, *const *ids; size_t nkeys, nids;
    const char *agent, *borrowed_url, *borrowed_auth, *current_key, *current_id;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t pair = http->calls - 1;
    CHECK(ctx && ctx == expected->original && pair < expected->nkeys * expected->nids);
    const char *key = expected->keys[pair / expected->nids], *id = expected->ids[pair % expected->nids];
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && request->detector_type == 65);
    CHECK(strlen(request->url) == 50 && request->url[50] == '\0');
    CHECK(!memcmp(request->url, "https://discord.com/api/v8/users/", 33) && !memcmp(request->url + 33, id, 17));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 63 && auth[63] == '\0' && !memcmp(auth, "Bot ", 4) && !memcmp(auth + 4, key, 59));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    expected->borrowed_url = request->url; expected->borrowed_auth = auth;
    expected->current_key = key; expected->current_id = id;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(expected->borrowed_url[50] == '\0' && !memcmp(expected->borrowed_url + 33, expected->current_id, 17));
        CHECK(expected->borrowed_auth[63] == '\0' && !memcmp(expected->borrowed_auth + 4, expected->current_key, 59));
        expected->borrowed_url = expected->borrowed_auth = NULL; /* Both complete stack buffers survive release. */
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products_and_ownership(const br_detector *detector)
{
    char input[4096]; size_t at = (size_t)snprintf(input, sizeof(input), "discord %s\ndiscord %s\ndiscord %s\n", key1, key2, key1);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\ndiscord %s\ndiscord %s\ndiscord %s", id1, id2, id1);
    const char *keys[] = {key1, key2, key1}, *ids[] = {id1, id2, id1};
    expected_http expected = {.keys = keys, .ids = ids, .nkeys = 3, .nids = 3, .agent = "TruffleHog discord-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "discord-offline"}; expected.original = &ctx;
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
    at = (size_t)snprintf(input, sizeof(input), "discord %s\ndiscord %s", key1, id1);
    results = test_scan(detector, NULL, false, input, at);
    memset(input, 'x', at);
    CHECK(results.len == 1); check_result(&results.items[0], key1, id1, false); br_results_clear(&results); /* Every visible field owns its bytes. */
}

static void verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "discord %s\ndiscord %s", key1, id1);
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
    char input[256]; snprintf(input, sizeof(input), "discord %s\ndiscord %s", key1, id1);
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
    char input[256], single[256]; snprintf(input, sizeof(input), "discord %s\ndiscord %s\ndiscord %s", key1, id1, id2);
    snprintf(single, sizeof(single), "discord %s\ndiscord %s", key1, id1);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create DiscordBotToken result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    /* One ID capture copy then its separate Redacted copy: fail BEFORE skip. */
    fail_alloc_size = 18; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, text(single), &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate DiscordBotToken redaction") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create DiscordBotToken result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0;
    /* Two ID capture copies, then two owned redactions: fail on pair two. */
    fail_alloc_size = 18; fail_alloc_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate DiscordBotToken redaction") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 60; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Constructor skips do not push. */
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append DiscordBotToken result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, id1, true); check_result(&results.items[1], key1, id2, true);
    br_results_clear(&results);
}

int main(void)
{
    make_key(key1, 0); make_key(key2, 7);
    const br_detector *detector = descriptor();
    extraction(detector); products_and_ownership(detector); verification(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("DiscordBotToken occurrence products + visible ID + v8 user URL + literal Bot + pre-skip redaction + rollback");
}
