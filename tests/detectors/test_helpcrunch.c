/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[329], other[329];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_agent;

/* Focused seams already used by the named detector tests: actual capture/Raw
 * allocations and positive JSON insertion failures, not synthetic Do errors. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_helpcrunch_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_helpcrunch_init(NULL, NULL) != 0);
    CHECK(br_helpcrunch_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_helpcrunch_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 164 && detector->version == 0);
    CHECK(!strcmp(detector->name, "HelpCrunch") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "HelpCrunch is a customer communication platform offering live chat, email automation, and more. HelpCrunch API keys can be used to access and manage customer interactions and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "helpcrunch"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(key, 328, 0);
    test_secret(other, 328, 9);
    key[2] = 'Z'; key[5] = '-'; key[8] = '+'; key[11] = '/'; key[14] = '=';
    other[0] = 'Q'; other[327] = '=';
    return detector;
}

static void result(const br_result *finding, const char *expected, bool verified)
{
    test_key_result(finding, 164, expected, "key");
    CHECK(finding->raw.len == 328 && finding->verified == verified && !finding->verification_error);
}

static void extract_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction_and_boundaries(const br_detector *detector)
{
    char input[1200], changed[329], shifted[329];
    const char *prefixes[] = {"helpcrunch ", "HeLpCrUnCh:", "prefixHELPCRUNCHsuffix\r\n"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        int len = snprintf(input, sizeof(input), "%s%s", prefixes[i], key);
        extract_case(detector, input, (size_t)len, key);
    }
    /* Adjacent '=' and a leading word after a space both start their own
     * 328-byte capture; neither can be excluded as an assignment/token prefix. */
    shifted[0] = '='; memcpy(shifted + 1, key, 327); shifted[328] = '\0';
    int len = snprintf(input, sizeof(input), "HeLpCrUnCh=%s", key);
    extract_case(detector, input, (size_t)len, shifted);
    shifted[0] = 'A';
    len = snprintf(input, sizeof(input), "helpcrunch A%s", key);
    extract_case(detector, input, (size_t)len, shifted);
    const char *bad_prefixes[] = {"", "help crunch ", "helpcrunch _"};
    for (size_t i = 0; i < sizeof(bad_prefixes) / sizeof(bad_prefixes[0]); ++i) {
        int len = snprintf(input, sizeof(input), "%s%s", bad_prefixes[i], key);
        extract_case(detector, input, (size_t)len, NULL);
    }
    len = snprintf(input, sizeof(input), "%s helpcrunch", key);
    extract_case(detector, input, (size_t)len, NULL);
    memcpy(changed, key, sizeof(key)); changed[327] = '\0';
    len = snprintf(input, sizeof(input), "helpcrunch %s", changed);
    extract_case(detector, input, (size_t)len, NULL);
    const char invalid[] = {'_', '.', ':', ' ', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[100] = invalid[i];
        len = snprintf(input, sizeof(input), "helpcrunch %s", changed);
        extract_case(detector, input, (size_t)len, NULL);
    }
    /* There is no ending boundary: longer alphabet strings and a following
     * underscore retain exactly their first 328 bytes, never a second key. */
    const char *tails[] = {"Z", "_", "+/=", key};
    for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i) {
        len = snprintf(input, sizeof(input), "helpcrunch %s%s", key, tails[i]);
        extract_case(detector, input, (size_t)len, key);
    }
    len = snprintf(input, sizeof(input), "helpcrunch %s %s", key, other);
    extract_case(detector, input, (size_t)len, key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "helpcrunch", 10); memset(input + 10, ':', gap);
        memcpy(input + 10 + gap, key, 328);
        extract_case(detector, input, 10 + gap + 328, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 10 + 4 * i, "💡", 4);
        memcpy(input + 10 + 4 * gap, key, 328);
        extract_case(detector, input, 10 + 4 * gap + 328, gap == 40 ? key : NULL);
    }
    memcpy(input, "helpcrunch\0", 11); memcpy(input + 11, key, 328);
    extract_case(detector, input, 339, key);
    /* A leading nonword is captured only across a word/nonword boundary.
     * The following word can instead become the start of a shifted capture. */
    const char leading[] = {'-', '+', '/', '='};
    for (size_t i = 0; i < sizeof(leading); ++i) {
        memcpy(changed, key, sizeof(key)); changed[0] = leading[i];
        len = snprintf(input, sizeof(input), "helpcrunch%s", changed);
        extract_case(detector, input, (size_t)len, changed);
        len = snprintf(input, sizeof(input), "helpcrunchX%s", changed);
        extract_case(detector, input, (size_t)len, changed);
        len = snprintf(input, sizeof(input), "helpcrunch %s", changed);
        extract_case(detector, input, (size_t)len, NULL);
        memcpy(shifted, changed + 1, 327); shifted[327] = 'Z'; shifted[328] = '\0';
        len = snprintf(input, sizeof(input), "helpcrunch %sZ", changed);
        extract_case(detector, input, (size_t)len, shifted);
    }
    memset(changed, 'z', 328); changed[328] = '\0';
    len = snprintf(input, sizeof(input), "helpcrunch %s", changed);
    extract_case(detector, input, (size_t)len, changed); /* No entropy/JWT check. */
    memset(changed, '=', 328);
    len = snprintf(input, sizeof(input), "helpcrunch%s", changed);
    extract_case(detector, input, (size_t)len, changed); /* Not valid Base64. */
    extract_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_auth, *borrowed_url, *expected_key;
} expected_request;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_request *expected = http->user;
    size_t at = http->calls - 1;
    CHECK(at < expected->count && ctx == expected->ctx && http->releases == at && !expected->borrowed_auth);
    CHECK(request->detector_type == 164 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.helpcrunch.com/v1/departments"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 335 && !memcmp(auth, "Bearer ", 7));
    CHECK(!memcmp(auth + 7, expected->keys[at], 328) && auth[335] == '\0');
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    /* Effective header array/UA are borrowed only during send. These two
     * values are provider originals and must remain valid through release. */
    expected->borrowed_auth = auth;
    expected->borrowed_url = request->url;
    expected->expected_key = expected->keys[at];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected_request *expected = http->user;
    if (expected->borrowed_auth) {
        CHECK(strlen(expected->borrowed_auth) == 335 && !memcmp(expected->borrowed_auth, "Bearer ", 7));
        CHECK(!memcmp(expected->borrowed_auth + 7, expected->expected_key, 328));
        CHECK(!strcmp(expected->borrowed_url, "https://api.helpcrunch.com/v1/departments"));
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    expected->borrowed_auth = expected->borrowed_url = expected->expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[1100];
    int len = snprintf(input, sizeof(input), "helpcrunch %s\nHELPCRUNCH %s\nhelpcrunch %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_request expected = {.keys = keys, .count = 3, .agent = "TruffleHog helpcrunch-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected, .response = {.status = 204}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "helpcrunch-offline"}; expected.ctx = &ctx;
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(detector, &ctx, verify != 0, input, (size_t)len);
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], verify != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(detector, NULL, true, input, (size_t)len);
    CHECK(!out.len && http.calls == 3 && http.releases == 3);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, (size_t)len);
    CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool arm_headers_failure(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static bool arm_agent_failure(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void status_body_send_and_setup(const br_detector *detector)
{
    char input[350]; int len = snprintf(input, sizeof(input), "helpcrunch %s", key);
    const char *keys[] = {key};
    expected_request expected = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
    static const unsigned char body[] = {0, 0xff, '{'};
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "ignored body read error" : ""};
        br_results out = test_scan(detector, &ctx, true, input, (size_t)len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const struct { int rc; const char *error; } failures[] = {
        {1, "timeout"}, {-7, "cannot create HelpCrunch result"},
        {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].error;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(detector, &ctx, true, input, (size_t)len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {.transport = &transport, .cancelled = arm_headers_failure},
        {.transport = &transport, .cancelled = arm_agent_failure},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
        {0},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(detector, &contexts[i], true, input, (size_t)len);
        CHECK(out.len == 1 && !http.calls && http.releases == (i == 5 ? 0u : 1u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i < 2 ? 1u : 0u));
        result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !expected.borrowed_auth && !expected.borrowed_url);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void own_failures_and_rollback(const br_detector *detector)
{
    char input[750]; int len = snprintf(input, sizeof(input), "helpcrunch %s\nhelpcrunch %s", key, other);
    const char *keys[] = {key, other};
    expected_request expected = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Regex returns +1. */
        if (failure == 1) { fail_size = 329; fail_after = 2; } /* All captures precede findings. */
        if (failure == 2) { fail_size = 328; fail_after = 2; http.send_rc = 1; http.send_error = "suppressed Do error"; }
        if (failure == 3) { fail_part_after = 2; http.send_rc = 0; http.send_error = NULL; } /* Insertion returns +7. */
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)len}, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Own finding failure wins before nil-context skip, and also in NoV. */
    fail_size = 328; fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)len}, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    fail_after = 2;
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)input, (size_t)len}, &out, &error) != 0 && error && !fail_after);
    CHECK(!http.calls && !http.releases); check_prior(&out, &prior); free(error); error = NULL;
    /* Existing collection-invariant seam makes push return +1 after a verified
     * send. Restore capacity before clearing the unchanged caller finding. */
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)len}, &out, &error) != 0 && error);
    CHECK(!strcmp(error, "cannot append HelpCrunch result")); out.cap = cap;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error);
    br_results_clear(&out);
    CHECK(!expected.borrowed_auth && !expected.borrowed_url);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction_and_boundaries(detector);
    occurrences_and_nil_context(detector);
    status_body_send_and_setup(detector);
    own_failures_and_rollback(detector);
    CHECK(!fail_after && !fail_part_after && !fail_agent);
    return test_finish("HelpCrunch");
}
