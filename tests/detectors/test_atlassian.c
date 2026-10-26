/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key1[25], other1[25], third1[25];
static const char key2[] = "ATCTT3xFfGQ=1b3D5f7H";
static const char other2[] = "ATCTT3xFfG9+/=_-Ab=Z9y8X7w6";
static const char id1[] = "zzzzzzzz-qrst-uvwx-yz12-zzzzzzzzzzzz";
static const char id2[] = "01234567-89ab-cdef-ghij-klmnopqrstuv";
static const char unsupported[] = "unsupported upstream panic: Atlassian v1 indexes empty OrgRes.Data";

typedef struct { const char *key, *id; } expected_result;

static const br_detector *detector_init(int version)
{
    int (*init)(const br_detector **, char **) = version == 1 ? br_atlassian_v1_init : br_atlassian_v2_init;
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(init(&detector, &error) == 0 && !error && detector);
    CHECK(init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 190 && detector->version == version);
    CHECK(!strcmp(detector->name, "Atlassian") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, version == 1 ?
        "Atlassian provides tools for software development, project management, and content management. "
        "Atlassian API keys can be used to access and manage these tools and services." :
        "Atlassian is a software company that provides tools for project management, software development, and collaboration. "
        "Atlassian tokens can be used to access and manage these tools and services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], version == 1 ? "atlassian" : "ATCTT3xFfG"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const br_detector *detector, expected_result expected)
{
    CHECK(result->detector_type == 190 && !result->detector_name);
    CHECK(result->raw.len == strlen(expected.key) && !memcmp(result->raw.data, expected.key, result->raw.len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted);
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (expected.id ? 2 : 1));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), expected.key));
    if (expected.id) {
        CHECK(json_object_object_get_ex(result->secret_parts, "organization_id", &part));
        CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), expected.id));
    } else CHECK(!json_object_object_get_ex(result->secret_parts, "organization_id", &part));
    CHECK(result->extra_data);
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
    CHECK(json_object_is_type(part, json_type_string) &&
          !strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/atlassian/"));
    CHECK(json_object_object_get_ex(result->extra_data, "version", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), detector->version == 1 ? "1" : "2"));
}

static void check_organization(const br_result *result, const char *name, size_t len)
{
    br_json *value = NULL;
    CHECK(json_object_object_length(result->extra_data) == (name ? 3 : 2));
    if (!name) CHECK(!json_object_object_get_ex(result->extra_data, "Organization", &value));
    else {
        CHECK(json_object_object_get_ex(result->extra_data, "Organization", &value));
        CHECK(json_object_is_type(value, json_type_string) && (size_t)json_object_get_string_len(value) == len);
        CHECK(!len || !memcmp(json_object_get_string(value), name, len));
    }
}

/* The source uses maps: compare unique key/ID sets rather than their order. */
static void check_set(const br_results *results, const br_detector *detector,
                      const expected_result *expected, size_t count, bool verified, const char *organization)
{
    CHECK(results->len == count);
    bool *seen = calloc(count ? count : 1, sizeof(*seen));
    CHECK(seen);
    for (size_t r = 0; r < results->len; ++r) {
        size_t found = count;
        for (size_t e = 0; e < count; ++e) {
            if (seen[e] || results->items[r].raw.len != strlen(expected[e].key) ||
                memcmp(results->items[r].raw.data, expected[e].key, results->items[r].raw.len)) continue;
            br_json *id = NULL;
            bool has_id = json_object_object_get_ex(results->items[r].secret_parts, "organization_id", &id);
            if ((expected[e].id && has_id && !strcmp(json_object_get_string(id), expected[e].id)) ||
                (!expected[e].id && !has_id)) { found = e; break; }
        }
        CHECK(found < count);
        seen[found] = true;
        check_result(&results->items[r], detector, expected[found]);
        CHECK(results->items[r].verified == verified && !results->items[r].verification_error);
        check_organization(&results->items[r], organization, organization ? strlen(organization) : 0);
    }
    free(seen);
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const expected_result *expected, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(!http.calls && !http.releases);
    check_set(&results, detector, expected, count, false, NULL);
    br_results_clear(&results);
}

static void extraction_v1(const br_detector *detector)
{
    char input[512], changed[25];
    const expected_result one[] = {{key1, NULL}}, two[] = {{key1, NULL}, {other1, NULL}};
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key1, NULL, 0);
    snprintf(input, sizeof(input), "atlassian %s", key1);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "preATLASSIANsuffix:%s\natlassian %s\natlassian %s", key1, key1, other1);
    expect_extraction(detector, input, two, 2);
    snprintf(input, sizeof(input), "atlassian \xc3\xa9%s\xc3\xa9", key1);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "atlassian");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key1);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "atlassian %.23s", key1);
    expect_extraction(detector, input, NULL, 0);
    const char *const wrappers[] = {"atlassian _%s", "atlassian %s_", "atlassian %sQ"};
    for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        snprintf(input, sizeof(input), wrappers[i], key1);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key1, sizeof(changed));
    changed[7] = '-';
    snprintf(input, sizeof(input), "atlassian %s", changed);
    expect_extraction(detector, input, NULL, 0);
    memset(changed, 'a', 24);
    changed[24] = '\0';
    const expected_result low[] = {{changed, NULL}};
    snprintf(input, sizeof(input), "atlassian %s", changed);
    expect_extraction(detector, input, low, 1); /* No detector-local placeholder filter. */
}

static void extraction_v2(const br_detector *detector)
{
    char input[1024], changed_id[37];
    const expected_result bare[] = {{key2, NULL}}, with_id[] = {{key2, id1}};
    const expected_result product[] = {{key2, id1}, {key2, id2}, {other2, id1}, {other2, id2}};
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key2, bare, 1);
    snprintf(input, sizeof(input), "-%s\n%s", key2, id1);
    expect_extraction(detector, input, bare, 1); /* An unprefixed ID is not a hint. */
    snprintf(input, sizeof(input), "%s\nORG=%s\nid=%s\nid=%s\n%s\n%s\n%s", key2, id1, id2, id1, key2, other2, other2);
    expect_extraction(detector, input, product, 4);
    snprintf(input, sizeof(input), "%s\npreIDstuff:%s", key2, id1);
    expect_extraction(detector, input, with_id, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "%s\norg", key2);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id1);
        expect_extraction(detector, input, gap == 40 ? with_id : bare, 1);
    }
    memcpy(changed_id, id1, sizeof(changed_id));
    changed_id[0] = 'Z';
    snprintf(input, sizeof(input), "%s\norg %s", key2, changed_id);
    expect_extraction(detector, input, bare, 1);
    snprintf(input, sizeof(input), "%s\norg _%s_", key2, id1);
    expect_extraction(detector, input, bare, 1);
    const char *const invalid[] = {
        "atctt3xFfGQ=1b3D5f7H", "ATCTT3xFfG=1b3D5f7H", "ATCTT3xFfGQ=1234567",
        "ATCTT3xFfGQ=123456789", "ATCTT3xFfGQ=1234567_", "ATCTT3xFfG!=1b3D5f7H",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        expect_extraction(detector, invalid[i], NULL, 0);
    const char *const wrappers[] = {"_%s", "Q%s", "%s_", "%sQ"};
    for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        snprintf(input, sizeof(input), wrappers[i], key2);
        expect_extraction(detector, input, NULL, 0);
    }
}

typedef struct {
    const char *keys[3];
    size_t nkeys, seen[3], empty_on_call;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.atlassian.com/admin/v1/orgs"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 190);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Bearer ", 7));
    bool found = false;
    for (size_t k = 0; k < expected->nkeys; ++k) {
        if (!strcmp(request->headers[1].value + 7, expected->keys[k])) { ++expected->seen[k]; found = true; break; }
    }
    CHECK(found);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog atlassian-test"));
    if (expected->empty_on_call == http->calls) {
        static const unsigned char empty[] = "{\"data\":[]}";
        http->response.body = (br_slice){empty, sizeof(empty) - 1};
    }
}

typedef struct {
    const char *body, *body_error, *error, *organization;
    int status, send_rc;
    const char *send_error;
} verification_case;

static void verify_case(const br_detector *detector, const char *key, const char *id, verification_case fixture)
{
    size_t size = strlen(key) + 128;
    char *input = malloc(size);
    CHECK(input);
    if (detector->version == 1) snprintf(input, size, "atlassian %s", key);
    else snprintf(input, size, "%s\norg %s", key, id ? id : "");
    requests expected = {.keys = {key}, .nkeys = 1};
    test_http http = {
        .response = {.status = fixture.status ? fixture.status : 200,
            .body = {(const unsigned char *)fixture.body, fixture.body ? strlen(fixture.body) : 0}, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error, .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "atlassian-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen[0] == 1);
    check_result(&results.items[0], detector, (expected_result){key, id});
    CHECK(results.items[0].verified == (!fixture.error && (!fixture.status || fixture.status == 200)));
    check_organization(&results.items[0], fixture.organization, fixture.organization ? strlen(fixture.organization) : 0);
    if (fixture.error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
}

static void decoding(const br_detector *detector)
{
    const char *key = detector->version == 1 ? key1 : key2;
    const char *id = detector->version == 1 ? NULL : id1;
    const verification_case fixtures[] = {
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}]}", .organization = "A"},
        {.body = "{\"data\":[null]}", .organization = ""},
        {.body = "{\"data\":[{}, {\"attributes\":{\"name\":\"B\"}}]}", .organization = ""},
        {.body = "{\"data\":[{\"attributes\":null}]}", .organization = ""},
        {.body = "{\"data\":[{\"attributes\":{\"name\":null}}]}", .organization = ""},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\",\"name\":null}}]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\",\"name\":\"B\"}}]}", .organization = "B"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"},\"attributes\":null}]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"},\"attributes\":{}}]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[{}]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}},{\"attributes\":{\"name\":\"B\"}}],\"data\":[null]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[{\"attributes\":{\"name\":null}}]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[],\"data\":[null]}", .organization = ""},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":null,\"data\":[{}]}", .organization = ""},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[{\"attributes\":{\"name\":\"\"}}]}", .organization = ""},
        {.body = "{\"DATA\":[{\"ATTRIBUTES\":{\"NAME\":\"A\"}}],\"ignored\":[123,null]}", .organization = "A"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"} \n } \t ] \n } junk", .organization = "A", .body_error = "ignored after first document"},
        {.body = "{\"data\":[null]} {broken trailing document", .organization = ""},
        {.body = "", .error = "EOF"},
        {.body = "{\"data\":[", .error = "unexpected EOF"},
        {.body = "{\"data\":[", .body_error = "synthetic read failure", .error = "synthetic read failure"},
        {.body = "\"x\"", .body_error = "synthetic read failure", .error = "synthetic read failure"},
        {.body = "\"x\" ", .body_error = "ignored after scalar delimiter", .error = "json: cannot unmarshal string into Go value of type atlassian.OrgRes"},
        {.body = "[]", .error = "json: cannot unmarshal array into Go value of type atlassian.OrgRes"},
        {.body = "{\"data\":{}}", .error = "json: cannot unmarshal object into Go struct field OrgRes.data of type []struct { Attributes struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"attributes\\\"\" }"},
        {.body = "{\"data\":[true]}", .error = "json: cannot unmarshal bool into Go struct field OrgRes.data of type struct { Attributes struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"attributes\\\"\" }"},
        {.body = "{\"data\":[{\"attributes\":[]}]}", .error = "json: cannot unmarshal array into Go struct field .data.attributes of type struct { Name string \"json:\\\"name\\\"\" }"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":true}}]}", .error = "json: cannot unmarshal bool into Go struct field .data.attributes.name of type string"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":\"A\"}},{\"attributes\":{\"name\":7}}]}", .error = "json: cannot unmarshal number into Go struct field .data.attributes.name of type string"},
        {.body = "{\"data\":[{\"attributes\":{\"name\":7,\"name\":\"A\"}}]}", .error = "json: cannot unmarshal number into Go struct field .data.attributes.name of type string"},
        {.body = "{\"data\":false,\"data\":[null]}", .error = "json: cannot unmarshal bool into Go struct field OrgRes.data of type []struct { Attributes struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"attributes\\\"\" }"},
        {.status = 401, .body = "not JSON", .body_error = "ignored"},
        {.status = 403, .body_error = "ignored", .error = "unexpected HTTP response status 403"},
        {.status = 500, .error = "unexpected HTTP response status 500"},
        {.status = 201, .error = "unexpected HTTP response status 201"},
        {.send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) verify_case(detector, key, id, fixtures[i]);
    if (detector->version == 2) {
        const char *const empty[] = {"null", "{}", "{\"data\":null}", "{\"data\":[]}",
            "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[]}"};
        for (size_t i = 0; i < sizeof(empty) / sizeof(empty[0]); ++i)
            verify_case(detector, key, id, (verification_case){.body = empty[i]});
        verify_case(detector, key, NULL, (verification_case){.body = "{\"data\":[null]}", .organization = ""});
    }
    char input[160];
    if (detector->version == 1) snprintf(input, sizeof(input), "atlassian %s", key);
    else snprintf(input, sizeof(input), "%s\norg %s", key, id);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], detector, (expected_result){key, id});
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_organization(&results.items[0], NULL, 0);
    br_results_clear(&results);

    requests expected = {.keys = {key}, .nkeys = 1};
    static const unsigned char body[] = "{\"data\":[{\"attributes\":{\"name\":\"A\\u0000B\"}}]}";
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "atlassian-test"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], detector, (expected_result){key, id});
    check_organization(&results.items[0], "A\0B", 3);
    br_results_clear(&results);
}

static void redaction(const br_detector *detector)
{
    const char *key = detector->version == 1 ? key1 : key2;
    const char *other = detector->version == 1 ? other1 : other2;
    const char *id = detector->version == 1 ? NULL : id1;
    char cause[320], sanitized[320];
    snprintf(cause, sizeof(cause), "key=%s repeated=%s organization_id=%s other=%s", key, key, id1, other);
    snprintf(sanitized, sizeof(sanitized), "key=[REDACTED] repeated=[REDACTED] organization_id=%s other=%s", id1, other);
    verify_case(detector, key, id, (verification_case){.send_rc = -1, .send_error = cause, .error = sanitized});
    verify_case(detector, key, id, (verification_case){.body = "{\"data\":[", .body_error = cause, .error = sanitized});
}

static void rollback_v1(const br_detector *detector)
{
    const char *const empty[] = {"null", "{}", "{\"data\":null}", "{\"data\":[]}",
        "{\"data\":[{\"attributes\":{\"name\":\"A\"}}],\"data\":[]}"};
    for (size_t i = 0; i <= sizeof(empty) / sizeof(empty[0]); ++i) {
        br_result prior = {0};
        CHECK(br_finding_pair(&prior, 777, "prior caller key", "key", "prior secondary", "id") == 0);
        prior.verified = true;
        prior.verification_error = strdup("prior caller error");
        CHECK(prior.verification_error);
        br_result saved = prior;
        br_results results = {0};
        CHECK(br_results_push(&results, &prior) == 0);
        bool after_good = i == sizeof(empty) / sizeof(empty[0]);
        const char *body = after_good ? "{\"data\":[{\"attributes\":{\"name\":\"A\"}}]}" : empty[i];
        requests expected = {.keys = {key1, other1, third1}, .nkeys = 3, .empty_on_call = after_good ? 2 : 0};
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}},
            .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "atlassian-test"};
        char input[160], *error = NULL;
        snprintf(input, sizeof(input), "atlassian %s\natlassian %s\natlassian %s", key1, other1, third1);
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && !strcmp(error, unsupported));
        CHECK(http.calls == (after_good ? 2 : 1) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].verified);
        CHECK(results.items[0].raw.data == saved.raw.data && results.items[0].raw.len == saved.raw.len);
        CHECK(!memcmp(results.items[0].raw.data, "prior caller key", saved.raw.len));
        CHECK(results.items[0].raw_v2.data == saved.raw_v2.data && results.items[0].raw_v2.len == saved.raw_v2.len);
        CHECK(!memcmp(results.items[0].raw_v2.data, "prior caller keyprior secondary", saved.raw_v2.len));
        CHECK(results.items[0].secret_parts == saved.secret_parts && json_object_object_length(results.items[0].secret_parts) == 2);
        CHECK(results.items[0].verification_error == saved.verification_error && !strcmp(results.items[0].verification_error, "prior caller error"));
        free(error);
        br_results_clear(&results);
    }
}

static void v2_products_and_long_key(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s\n%s\n%s\norg %s\nid %s\nid %s", key2, other2, key2, id1, id2, id1);
    const expected_result product[] = {{key2, id1}, {key2, id2}, {other2, id1}, {other2, id2}};
    requests expected = {.keys = {key2, other2}, .nkeys = 2};
    static const unsigned char body[] = "{\"data\":[null]}";
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "atlassian-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 4 && http.releases == 4 && expected.seen[0] == 2 && expected.seen[1] == 2);
    check_set(&results, detector, product, 4, true, "");
    br_results_clear(&results);

    size_t payload_len = 4096;
    char *long_key = malloc(10 + payload_len + 1 + 8 + 1);
    CHECK(long_key);
    memcpy(long_key, "ATCTT3xFfG", 10);
    memset(long_key + 10, 'Q', payload_len);
    memcpy(long_key + 10 + payload_len, "=12Ab34Cd", 10);
    const expected_result long_result[] = {{long_key, NULL}};
    expect_extraction(detector, long_key, long_result, 1);
    verify_case(detector, long_key, NULL, (verification_case){.status = 401});
    free(long_key);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    test_secret(key1, 24, 0);
    test_secret(other1, 24, 9);
    test_secret(third1, 24, 17);
    key1[0] = 'B';
    other1[0] = 'M';
    third1[0] = 'T';
    const br_detector *v1 = detector_init(1), *v2 = detector_init(2);
    CHECK(v1 != v2 && v1->scan != v2->scan);
    extraction_v1(v1);
    extraction_v2(v2);
    decoding(v1);
    decoding(v2);
    redaction(v1);
    redaction(v2);
    rollback_v1(v1);
    v2_products_and_long_key(v2);
    return test_finish("Atlassian v1+v2");
}
