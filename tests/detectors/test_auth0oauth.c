/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char client_id[33], other_id[33], secret[65], other_secret[65];
static const char domain[] = "briar-fixture.auth0.com";

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_auth0oauth_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_auth0oauth_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 55 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Auth0oauth") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Auth0 is a service designed to handle authentication and authorization for users. "
        "Oauth API keys can be used to impersonate applications and other things related to Auth0's API"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "auth0"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *id, const char *key)
{
    size_t id_len = strlen(id), key_len = strlen(key);
    CHECK(result->detector_type == 55 && !result->detector_name);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, key, key_len));
    CHECK(result->raw_v2.data && result->raw_v2.len == id_len + key_len);
    CHECK(!memcmp(result->raw_v2.data, id, id_len) && !memcmp(result->raw_v2.data + id_len, key, key_len));
    CHECK(result->redacted && !strcmp(result->redacted, id));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), id));
    CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), key));
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const char *input, const char *id, const char *key)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (id ? 1u : 0u) && !http.calls && !http.releases);
    if (id) {
        check_result(&results.items[0], id, key);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed_id[65], changed_secret[129], padding[42];
    snprintf(input, sizeof(input), "preAuTh0suffix '%s'\n%s\n%s", client_id, secret, domain);
    expect_one(detector, input, client_id, secret);
    expect_one(detector, "", NULL, NULL);
    snprintf(input, sizeof(input), "%s\n%s\n%s", client_id, secret, domain);
    expect_one(detector, input, NULL, NULL); /* Only the ID requires a preceding keyword. */
    snprintf(input, sizeof(input), "auth0 %s\n%s", client_id, secret);
    expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "auth0 %s\n%s", client_id, domain);
    expect_one(detector, input, NULL, NULL);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "auth0%.*s%s\n%s\n%s", gap, padding, client_id, secret, domain);
        expect_one(detector, input, gap == 40 ? client_id : NULL, secret);
    }
    snprintf(input, sizeof(input), "auth0\r\n%s\n%s\n%s", client_id, secret, domain);
    expect_one(detector, input, client_id, secret);
    const size_t lengths[] = {31, 32, 60, 61};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        test_secret(changed_id, lengths[i], 3);
        snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", changed_id, secret, domain);
        expect_one(detector, input, lengths[i] == 32 || lengths[i] == 60 ? changed_id : NULL, secret);
    }
    memcpy(changed_id, client_id, sizeof(client_id));
    changed_id[16] = '+';
    snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", changed_id, secret, domain);
    expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "auth0 %s-\n%s\n%s", client_id, secret, domain);
    expect_one(detector, input, client_id, secret); /* The source word boundary excludes a trailing hyphen. */
    const size_t secret_lengths[] = {63, 64, 65, 128};
    for (size_t i = 0; i < sizeof(secret_lengths) / sizeof(secret_lengths[0]); ++i) {
        test_secret(changed_secret, secret_lengths[i], 7);
        snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", client_id, changed_secret, domain);
        expect_one(detector, input, secret_lengths[i] >= 64 ? client_id : NULL, changed_secret);
    }
    const char *domains[] = {"auth0.com", "briar.auth0.COM", "xauth0.com", "https://briar.auth0.com/path", "briar.auth0.com.evil"};
    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); ++i) {
        snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", client_id, secret, domains[i]);
        expect_one(detector, input, i >= 2 ? client_id : NULL, secret);
    }
    snprintf(input, sizeof(input), "auth0 %s\n%s\n%s\nauth0 %s\n%s\n%s", client_id, secret, domain, client_id, secret, domain);
    expect_one(detector, input, client_id, secret); /* Each set is independently unique. */
}

typedef struct {
    const char *ids[2], *secrets[2], *domains[2];
    size_t nids, nsecrets, ndomains, seen[2][2][2];
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(request->detector_type == 55 && request->body.data && request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog auth0-test"));
    size_t found_id = SIZE_MAX, found_secret = SIZE_MAX, found_domain = SIZE_MAX;
    for (size_t i = 0; i < expected->nids; ++i) {
        for (size_t s = 0; s < expected->nsecrets; ++s) {
            size_t size = strlen(expected->ids[i]) + strlen(expected->secrets[s]) +
                sizeof("client_id=&client_secret=&code=AUTHORIZATION_CODE&grant_type=authorization_code&redirect_uri=undefined");
            char *body = malloc(size);
            CHECK(body);
            int len = snprintf(body, size,
                "client_id=%s&client_secret=%s&code=AUTHORIZATION_CODE&grant_type=authorization_code&redirect_uri=undefined",
                expected->ids[i], expected->secrets[s]);
            CHECK(len >= 0 && (size_t)len < size);
            if (request->body.len == (size_t)len && !memcmp(request->body.data, body, (size_t)len)) {
                found_id = i;
                found_secret = s;
            }
            free(body);
        }
    }
    for (size_t d = 0; d < expected->ndomains; ++d) {
        size_t size = strlen(expected->domains[d]) + sizeof("https:///oauth/token");
        char *url = malloc(size);
        CHECK(url);
        snprintf(url, size, "https://%s/oauth/token", expected->domains[d]);
        if (!strcmp(request->url, url)) found_domain = d;
        free(url);
    }
    CHECK(found_id < expected->nids && found_secret < expected->nsecrets && found_domain < expected->ndomains);
    ++expected->seen[found_id][found_secret][found_domain];
}

#define BODY(text) {(const unsigned char *)(text), sizeof(text) - 1}

typedef struct {
    int status, send_rc;
    br_slice body;
    const char *body_error, *send_error, *error;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[256];
    snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", client_id, secret, domain);
    requests expected = {.ids = {client_id}, .secrets = {secret}, .domains = {domain}, .nids = 1, .nsecrets = 1, .ndomains = 1};
    test_http http = {.response = {.status = fixture.status, .body = fixture.body, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "auth0-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen[0][0][0] == 1);
    check_result(&results.items[0], client_id, secret);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.status = 200, .body_error = "ignored drain failure", .verified = true},
        {.status = 401, .body = BODY("invalid_grant"), .body_error = "ignored"},
        {.status = 404, .body = BODY("unauthorized_client"), .body_error = "ignored"},
        {.status = 403, .body = BODY("{\"error\":\"invalid_grant\"}"), .verified = true},
        {.status = 403, .body = BODY("not JSON: unauthorized_client suffix"), .verified = true},
        {.status = 403, .body = BODY("\0invalid_grant\xff"), .verified = true},
        {.status = 403, .body = BODY("\0unauthorized_client"), .verified = true},
        {.status = 403, .body = BODY("Invalid_Grant UNAUTHORIZED_CLIENT")},
        {.status = 403, .body = BODY("access_denied")}, {.status = 403},
        {.status = 403, .body = BODY("invalid_grant"), .body_error = "read failed", .error = "read failed"},
        {.status = 201, .body_error = "ignored", .error = "unexpected HTTP response status 201"},
        {.status = 302, .error = "unexpected HTTP response status 302"},
        {.status = 500, .body_error = "ignored", .error = "unexpected HTTP response status 500"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .send_error = "lookup synthetic: no such host", .error = "lookup synthetic: no such host"},
        {.send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "id=%s secret=%s domain=%s again=%s other_id=%s", client_id, secret, domain, client_id, other_id);
    snprintf(redacted, sizeof(redacted), "id=[REDACTED] secret=%s domain=%s again=[REDACTED] other_id=%s", secret, domain, other_id);
    verify_case(detector, (verification_case){.send_rc = -1, .send_error = cause, .error = redacted});
    verify_case(detector, (verification_case){.status = 403, .body = BODY("unauthorized_client"), .body_error = cause, .error = redacted});
    char input[256];
    snprintf(input, sizeof(input), "auth0 %s\n%s\n%s", client_id, secret, domain);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], client_id, secret);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void unique_triples(const br_detector *detector)
{
    const char *domains[] = {"briar-pair.auth0.com", "BRIAR-pair.auth0.com"};
    char input[512];
    snprintf(input, sizeof(input), "auth0 %s\nauth0 %s\nauth0 %s\n%s\n%s\n%s\n%s\nhttps://%s/path\n%s",
        client_id, other_id, client_id, secret, other_secret, secret, domains[0], domains[0], domains[1]);
    requests expected = {.ids = {client_id, other_id}, .secrets = {secret, other_secret}, .domains = {domains[0], domains[1]},
                          .nids = 2, .nsecrets = 2, .ndomains = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "auth0-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 8 && !http.calls && !http.releases);
    size_t copies[2][2] = {{0}};
    for (size_t r = 0; r < results.len; ++r) {
        size_t i = !strcmp(results.items[r].redacted, client_id) ? 0 : 1;
        size_t s = !memcmp(results.items[r].raw.data, secret, 64) ? 0 : 1;
        check_result(&results.items[r], expected.ids[i], expected.secrets[s]);
        ++copies[i][s];
        CHECK(!results.items[r].verified && !results.items[r].verification_error);
    }
    for (size_t i = 0; i < 2; ++i)
        for (size_t s = 0; s < 2; ++s) CHECK(copies[i][s] == 2); /* Domain deliberately does not distinguish findings. */
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 8 && http.calls == 8 && http.releases == 8);
    for (size_t i = 0; i < 2; ++i)
        for (size_t s = 0; s < 2; ++s)
            for (size_t d = 0; d < 2; ++d) CHECK(expected.seen[i][s][d] == 1); /* No success short circuit. */
    for (size_t r = 0; r < results.len; ++r) CHECK(results.items[r].verified && !results.items[r].verification_error);
    br_results_clear(&results);
}

static void unbounded_captures(const br_detector *detector)
{
    size_t secret_len = 8192, labels = 300;
    char *long_secret = malloc(secret_len + 1), *long_domain = malloc(labels * 4 + sizeof("auth0.com"));
    CHECK(long_secret && long_domain);
    test_secret(long_secret, secret_len, 5);
    for (size_t i = 0; i < labels; ++i) memcpy(long_domain + i * 4, "sub.", 4);
    memcpy(long_domain + labels * 4, "auth0.com", sizeof("auth0.com"));
    /* Dotted labels keep the domain from incidentally becoming a secret capture. */
    size_t size = secret_len + strlen(long_domain) + strlen(client_id) + sizeof("auth0 \n\n");
    char *input = malloc(size);
    CHECK(input);
    snprintf(input, size, "auth0 %s\n%s\n%s", client_id, long_secret, long_domain);
    requests expected = {.ids = {client_id}, .secrets = {long_secret}, .domains = {long_domain},
                          .nids = 1, .nsecrets = 1, .ndomains = 1};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "auth0-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], client_id, long_secret);
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
    free(long_domain);
    free(long_secret);
}

int main(void)
{
    test_secret(client_id, 32, 0);
    client_id[0] = 'B';
    client_id[8] = '_';
    client_id[16] = '-';
    memcpy(other_id, client_id, sizeof(client_id));
    other_id[0] = 'b';
    test_secret(secret, 64, 9);
    secret[0] = 'S';
    secret[12] = '_';
    secret[20] = '-';
    memcpy(other_secret, secret, sizeof(secret));
    other_secret[0] = 's';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unique_triples(detector);
    unbounded_captures(detector);
    return test_finish("Auth0oauth");
}
