/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_onelogin_init(const br_detector **out, char **error);

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_onelogin_init(NULL, &error) != 0 && error && !strcmp(error, "invalid OneLogin detector output"));
    free(error);
    CHECK(br_onelogin_init(NULL, NULL) != 0);
    CHECK(br_onelogin_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_onelogin_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 22 && detector->version == 0 && !strcmp(detector->name, "OneLogin"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
                  "OneLogin is an identity and access management provider. OneLogin OAuth "
                  "client IDs and secrets can be used to authenticate and authorize API requests."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "onelogin"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, const char *id, const char *secret, bool verified)
{
    char raw_v2[130];
    CHECK(result->detector_type == 22 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 64 && !memcmp(result->raw.data, id, 64));
    snprintf(raw_v2, sizeof(raw_v2), "%s:%s", id, secret);
    CHECK(result->raw_v2.len == 129 && !memcmp(result->raw_v2.data, raw_v2, 129));
    CHECK(result->redacted && !strcmp(result->redacted, id));
    CHECK(!result->detector_name && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &part));
    CHECK(!strcmp(json_object_get_string(part), id));
    CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_pairs(const br_detector *detector, const char *input,
                          const char *const *ids, const char *const *secrets, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_pair(&results.items[i], ids[i], secrets[i], false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char id[65], id2[65], secret[65], secret2[65], input[512];
    test_secret(id, 64, 0);
    test_secret(id2, 64, 3);
    test_secret(secret, 64, 7);
    test_secret(secret2, 64, 11);
    const char *ids[] = {id, id};
    const char *secrets[] = {secret, secret};
    snprintf(input, sizeof(input), "onelogin token - 'idr_%s'\nonelogin token - 'secret_%s'\n", id, secret);
    expect_pairs(detector, input, ids, secrets, 1);
    snprintf(input, sizeof(input), "ID='%s' SeCrEt=\"%s\"", id, secret);
    expect_pairs(detector, input, ids, secrets, 1); /* Unprefixed; keyword is engine-only. */
    snprintf(input, sizeof(input), "id%*s%s\nsecret%*s%s", 20, "", id, 20, "", secret);
    expect_pairs(detector, input, ids, secrets, 1);
    snprintf(input, sizeof(input), "id%*s%s\nsecret %s", 21, "", id, secret);
    expect_pairs(detector, input, NULL, NULL, 0);
    snprintf(input, sizeof(input), "id-%s\nsecret_%s", id, secret);
    expect_pairs(detector, input, NULL, NULL, 0);
    id[10] = '?'; /* (?i) makes the capture class case-insensitive; '?' is the real break. */
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, secret);
    expect_pairs(detector, input, NULL, NULL, 0);
    id[10] = 'b';
    snprintf(input, sizeof(input), "id %s\nsecret %s\nid %s\nsecret %s", id, secret, id2, secret2);
    const char *cart_ids[] = {id, id, id2, id2};
    const char *cart_secrets[] = {secret, secret2, secret, secret2};
    expect_pairs(detector, input, cart_ids, cart_secrets, 4);
    snprintf(input, sizeof(input), "id %s\nid %s\nsecret %s", id, id, secret);
    const char *dup_ids[] = {id, id};
    const char *dup_secrets[] = {secret, secret};
    expect_pairs(detector, input, dup_ids, dup_secrets, 2);
    expect_pairs(detector, "", NULL, NULL, 0);
}

typedef struct { const char *id, *secret; int statuses[2]; int send_rc; const char *send_error; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *step = http->user;
    size_t at = http->calls - 1;
    CHECK(ctx && ctx->transport && at < 2);
    CHECK(!strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && request->detector_type == 22);
    CHECK(!strcmp(request->url, at == 0 ? "https://api.us.onelogin.com/auth/oauth2/v2/token"
                                        : "https://api.eu.onelogin.com/auth/oauth2/v2/token"));
    CHECK(request->body.len == 35 && !memcmp(request->body.data, "{\"grant_type\":\"client_credentials\"}", 35));
    CHECK(!request->dedup_key.len && request->nheaders == 3);
    char authorization[155];
    snprintf(authorization, sizeof(authorization), "client_id:%s, client_secret:%s", step->id, step->secret);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") &&
          !strcmp(request->headers[1].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    http->response.status = step->statuses[at];
    http->send_rc = step->send_rc;
    http->send_error = step->send_error;
}

static void verification(const br_detector *detector)
{
    char id[65], secret[65], input[180];
    test_secret(id, 64, 1);
    test_secret(secret, 64, 2);
    snprintf(input, sizeof(input), "id %s\nsecret %s", id, secret);
    const struct { int us, eu, send_rc; const char *send_error; bool verified; } cases[] = {
        {200, 401, 0, NULL, true}, {500, 204, 0, NULL, true}, {199, 300, 0, NULL, false},
        {401, 403, 0, NULL, false}, {200, 200, 1, "context canceled", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script step = {.id = id, .secret = secret, .statuses = {cases[i].us, cases[i].eu},
                       .send_rc = cases[i].send_rc, .send_error = cases[i].send_error};
        test_http http = {.inspect = inspect, .user = &step};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 2 && http.releases == 2);
        check_pair(&results.items[0], id, secret, cases[i].verified);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_pair(&results.items[0], id, secret, false);
    br_results_clear(&results);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && !http.releases);
    check_pair(&results.items[0], id, secret, false);
    br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1);
    check_pair(&results.items[0], id, secret, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("OneLogin");
}
