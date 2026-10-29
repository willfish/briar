/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <openssl/evp.h>

static char account[28], account2[28], key[55], key2[55];
static size_t fail_size, fail_after, failed_allocations, fail_part_after, arm_auth_after;

/* Reuse the named native tests' narrow allocation/map failure technique. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && arm_auth_after && !strcmp(name, "key") && --arm_auth_after == 0) {
        fail_size = 119; fail_after = 1;
    }
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(account) == 27 && strlen(key) == 54);
    CHECK(br_hypertrack_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:hypertrack)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_hypertrack_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_hypertrack_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_hypertrack_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 459 && detector->version == 0 && !strcmp(detector->name, "Hypertrack"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Hypertrack is a service that provides live location tracking for fleets and other mobile workforce management. Hypertrack keys can be used to access and manage these tracking services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "hypertrack"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 459, expected, "key");
    CHECK(result->raw.len == 54 && result->verified == verified && !result->verification_error);
}

static void pair_input(char *out, size_t size, const char *a, const char *k)
{
    int n = snprintf(out, size, "hypertrack %s%50shypertrack %s", a, "", k);
    CHECK(n > 0 && (size_t)n < size);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[360], changed[56];
    pair_input(input, sizeof(input), account, key); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "preHyPeRtRaCksuffix:\r\n%s%50sHYPERTRACK\n%s", account, "", key);
    extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "%s%50shypertrack %s", account, "", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "hypertrack %s%50s%s", account, "", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "hypertrack %s", account); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "hypertrack %s", key); extraction_case(detector, input, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "hypertrack%*s%s%50shypertrack %s", (int)gap, "", account, "", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
        snprintf(input, sizeof(input), "hypertrack %s%50shypertrack%*s%s", account, "", (int)gap, "", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, account, sizeof(account)); changed[26] = '\0';
    pair_input(input, sizeof(input), changed, key); extraction_case(detector, input, NULL);
    memcpy(changed, account, sizeof(account)); changed[27] = 'X'; changed[28] = '\0';
    pair_input(input, sizeof(input), changed, key); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[53] = '\0';
    pair_input(input, sizeof(input), account, changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[54] = 'X'; changed[55] = '\0';
    pair_input(input, sizeof(input), account, changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[30] = '!';
    pair_input(input, sizeof(input), account, changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "hypertrack _%s%50shypertrack %s", account, "", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "hypertrack %s%50shypertrack %s_", account, "", key); extraction_case(detector, input, NULL);
    char repeated_account[28], repeated_key[55];
    memset(repeated_account, 'Z', 27); repeated_account[27] = '\0';
    memset(repeated_key, 'Z', 54); repeated_key[54] = '\0';
    pair_input(input, sizeof(input), repeated_account, repeated_key); extraction_case(detector, input, repeated_key);
    char far[1400]; int n = snprintf(far, sizeof(far), "hypertrack %s", account); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "hypertrack %s", key);
    extraction_case(detector, far, key); /* The multipart hint is not a direct-scanner cap. */
    br_results out = test_scan(detector, NULL, false, NULL, 0); CHECK(!out.len); br_results_clear(&out);
}

typedef struct { const char *account, *key, *error; int status, rc; bool empty; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth;
    char saved_auth[119];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t i = http->calls - 1;
    CHECK(i < steps->count && ctx == steps->ctx && http->releases == i && !steps->borrowed_auth);
    const reply *row = &steps->rows[i];
    CHECK(request->detector_type == 459 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://v3.api.hypertrack.com/trips/"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 118 && !memcmp(auth, "Basic ", 6) && auth[116] == '=' && auth[117] == '=');
    unsigned char decoded[84];
    CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 112) == 84);
    CHECK(!memcmp(decoded, row->account, 27) && decoded[27] == ':' && !memcmp(decoded + 28, row->key, 54));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog hypertrack-offline" : "TruffleHog"));
    /* Retain only the provider-owned value, never synthesized headers/UA/request. */
    steps->borrowed_auth = auth; memcpy(steps->saved_auth, auth, sizeof(steps->saved_auth));
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->empty ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = row->empty ? NULL : "synthetic ignored read error"};
    http->send_rc = row->rc; http->send_error = row->error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->saved_auth, sizeof(steps->saved_auth)));
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "hypertrack-offline"}; steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    return out;
}

static void boundaries_and_overlap(const br_detector *detector)
{
    char a[28], k[55], input[360];
    memset(a, 'A', 27); a[27] = '\0';
    memset(k, 'K', 54); k[54] = '\0';
    a[0] = '-';
    snprintf(input, sizeof(input), "hypertrackx%s%50shypertrack %s", a, "", k); extraction_case(detector, input, k);
    pair_input(input, sizeof(input), a, k); extraction_case(detector, input, NULL); /* Nonword before leading hyphen. */
    a[0] = 'A'; a[26] = '-';
    snprintf(input, sizeof(input), "hypertrack %sx%50shypertrack %s", a, "", k); extraction_case(detector, input, k);
    pair_input(input, sizeof(input), a, k); extraction_case(detector, input, NULL); /* Nonword after trailing hyphen. */
    a[26] = 'A'; k[0] = '-';
    snprintf(input, sizeof(input), "hypertrack %s%50shypertrackx%s", a, "", k); extraction_case(detector, input, k);
    pair_input(input, sizeof(input), a, k); extraction_case(detector, input, NULL);
    k[0] = 'K'; k[53] = '-';
    snprintf(input, sizeof(input), "hypertrack %s%50shypertrack %sx", a, "", k); extraction_case(detector, input, k);
    pair_input(input, sizeof(input), a, k); extraction_case(detector, input, NULL);
    /* One independent match per regex: ACCOUNT is the first 27 bytes of KEY,
     * ending at an internal hyphen boundary, not a separately validated role. */
    memset(k, 'Z', 54); k[26] = '-'; memcpy(a, k, 27); a[27] = '\0';
    snprintf(input, sizeof(input), "hypertrack %s", k);
    reply row = {.account = a, .key = k, .status = 200}; script steps = {.rows = &row, .count = 1};
    br_results out = run(detector, input, true, &steps);
    CHECK(out.len == 1); result_is(&out.items[0], k, true); br_results_clear(&out);
}

static void products_and_verification(const br_detector *detector)
{
    const char *accounts[] = {account, account2, account}, *keys[] = {key, key2, key};
    char input[900];
    snprintf(input, sizeof(input), "hypertrack %s%50sHYPERTRACK %s%50shypertrack %s%50shypertrack %s%50sHyPeRtRaCk %s%50shypertrack %s",
        key, "", account, "", key2, "", account2, "", key, "", account);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 500, 201}; reply rows[9];
    for (size_t i = 0; i < 9; ++i)
        rows[i] = (reply){.account = accounts[i / 3], .key = keys[i % 3], .status = statuses[i], .empty = i % 2 != 0};
    rows[0].rc = 1; rows[0].error = "cannot create Hypertrack result";
    rows[8].rc = -7; rows[8].error = "out of memory constructing Basic authentication";
    script steps = {.rows = rows, .count = 0};
    br_results out = run(detector, input, false, &steps); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i) result_is(&out.items[i], keys[i % 3], false);
    br_results_clear(&out);
    steps.count = 9; out = run(detector, input, true, &steps); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i)
        result_is(&out.items[i], keys[i % 3], !rows[i].rc && statuses[i] >= 200 && statuses[i] < 300);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, strlen(input)); CHECK(out.len == 9); br_results_clear(&out);
    out = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!out.len && !out.items && !out.cap); br_results_clear(&out);
    pair_input(input, sizeof(input), account, key);
    const int edge_statuses[] = {0, 200, 201, 204, 299, 429};
    for (size_t i = 0; i < sizeof(edge_statuses) / sizeof(*edge_statuses); ++i) {
        reply row = {.account = account, .key = key, .status = edge_statuses[i], .empty = i % 2 == 0};
        steps = (script){.rows = &row, .count = 1}; out = run(detector, input, true, &steps); CHECK(out.len == 1);
        result_is(&out.items[0], key, edge_statuses[i] >= 200 && edge_statuses[i] < 300); br_results_clear(&out);
    }
    reply row = {.account = account, .key = key, .status = 200, .rc = 7, .error = key};
    steps = (script){.rows = &row, .count = 1}; out = run(detector, input, true, &steps); CHECK(out.len == 1);
    result_is(&out.items[0], key, false); br_results_clear(&out); /* No diagnostic, not even a sanitized setter. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user)
{
    ++*(size_t *)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[180]; pair_input(input, sizeof(input), account, key);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "invalid\r\nagent"},
        {.transport = &transport, .cancelled = fail_headers, .cancel_user = &cancellations},
    };
    size_t before = failed_allocations;
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        br_results out = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 2 && !fail_after && failed_allocations == before + 1);
    http.calls = http.releases = 0;
    br_results out = test_scan(detector, &contexts[1], false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases && cancellations == 2); br_results_clear(&out);
    transport.send = NULL; contexts[0].transport = &transport;
    out = test_scan(detector, &contexts[0], true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && http.releases == 1); result_is(&out.items[0], key, false); br_results_clear(&out);
}

static void prior_is(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void own_resources(const br_detector *detector)
{
    char input[360]; snprintf(input, sizeof(input), "hypertrack %s%50shypertrack %s%50shypertrack %s", account, "", key, "", key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_result prior = {0}; br_results out = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    fail_size = 2 * sizeof(br_span); fail_after = 2; /* Positive regex failure in the independent KEY search. */
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory iterating regex")); prior_is(&out, &prior); free(error); error = NULL;
    fail_size = 55; fail_after = 2; /* Capture storage failure, never a nil-context drop. */
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == -1 && error && !fail_after);
    prior_is(&out, &prior); free(error); error = NULL;
    fail_part_after = 2; /* A first appended finding is rolled back by the second owned finding failure. */
    CHECK(detector->scan(detector, NULL, false, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create Hypertrack result")); prior_is(&out, &prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == -1 && error && !fail_part_after);
    prior_is(&out, &prior); free(error); error = NULL;

    reply rows[] = {{.account = account, .key = key, .status = 200}, {.account = account, .key = key2, .status = 200}};
    script steps = {.rows = rows, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; steps.ctx = &ctx;
    arm_auth_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error && !arm_auth_after && fail_after == 1);
    CHECK(!http.calls && !http.releases); fail_after = 0; prior_is(&out, &prior); /* Constructor precedes encoding. */
    arm_auth_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error && !fail_after && !arm_auth_after);
    CHECK(!strcmp(error, "out of memory constructing Basic authentication"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_auth); prior_is(&out, &prior); free(error); error = NULL;
    /* A positive shared Do error is ordinarily suppressed, but a following
     * positive append guard failure must still fail and preserve caller rows. */
    http.calls = http.releases = 0; rows[0].rc = 7; rows[0].error = "cannot append Hypertrack result";
    size_t cap = out.cap; out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    out.cap = cap; CHECK(!strcmp(error, "cannot append Hypertrack result"));
    CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_auth); prior_is(&out, &prior); free(error);
    br_results_clear(&out);
    CHECK(detector->scan(NULL, NULL, false, data, NULL, NULL) == -1);
    CHECK(!fail_after && !fail_part_after && !arm_auth_after);
}

int main(void)
{
    test_secret(account, 27, 0); test_secret(account2, 27, 11); test_secret(key, 54, 7); test_secret(key2, 54, 19);
    account[3] = 'Z'; account[9] = '-'; account[17] = '_'; account[26] = 'Q'; account2[4] = 'G';
    key[4] = 'H'; key[11] = '-'; key[20] = '_'; key[53] = 'R'; key2[7] = 'U';
    const br_detector *detector = descriptor(); extraction(detector); boundaries_and_overlap(detector);
    products_and_verification(detector); shared_setup_errors(detector); own_resources(detector);
    return test_finish("Hypertrack grammar/independent-occurrences/account-major-products/metadata/Basic/status/errors/release/rollback");
}
