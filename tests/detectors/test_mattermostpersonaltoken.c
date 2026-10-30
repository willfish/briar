/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_mattermostpersonaltoken_init(const br_detector **out, char **error);

static const char key[] = "e2rgfqdg7xpzbq0nmj8l68gmuz";
static const char other[] = "a1b2c3d4e5f6g7h8i9j0k1l2m3";
static const char server[] = "example.cloud.mattermost.com";
static const char dotted[] = "xXcloudYmattermostZcom";
static char seen_url[160], seen_auth[64];
static int seen_status_profile;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->url);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 174 && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data);
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
    seen_status_profile = (int)request->profile;
}

static void expect_pair(const br_result *result, const char *token, const char *host, bool verified)
{
    char raw_v2[160];
    snprintf(raw_v2, sizeof(raw_v2), "%s%s", token, host);
    CHECK(result->detector_type == 174 && !result->detector_name);
    CHECK(result->verified == verified && !result->verification_error && !result->extra_data);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), token));
    CHECK(json_object_object_get_ex(result->secret_parts, "url", &part));
    CHECK(!strcmp(json_object_get_string(part), host));
}

static const br_detector *open_detector(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_mattermostpersonaltoken_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid MattermostPersonalToken detector output"));
    free(error);
    error = NULL;
    CHECK(br_mattermostpersonaltoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 174 && detector->version == 0);
    CHECK(!strcmp(detector->name, "MattermostPersonalToken"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
                  "Mattermost is an open-source, self-hostable online chat service with file sharing, search, and integrations. Mattermost Personal Tokens can be used to authenticate API requests to a Mattermost server."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mattermost"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == 1024 && detector->scan && detector->state);
    return detector;
}

static void grammar(const br_detector *detector)
{
    char input[512], gap[48];
    snprintf(input, sizeof(input), "mattermost '%s' mattermost '%s'", key, server);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, server, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "MATTERMOST %s\nMattermost %s", key, server);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, server, false);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mattermost %s mattermost %s mattermost %s mattermost %s",
             key, other, server, dotted);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    expect_pair(&out.items[0], key, server, false);
    expect_pair(&out.items[1], key, dotted, false);
    expect_pair(&out.items[2], other, server, false);
    expect_pair(&out.items[3], other, dotted, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mattermost %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "mattermost %s", server);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    memset(gap, '.', 40);
    gap[40] = '\0';
    snprintf(input, sizeof(input), "mattermost%s%s mattermost %s", gap, key, server);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    gap[40] = '.';
    gap[41] = '\0';
    snprintf(input, sizeof(input), "mattermost%s%s mattermost %s", gap, key, server);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "mattermost %s mattermost%s%s", key, gap, server);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    /* The unescaped dot and word boundary accept xample after a non-word. */
    snprintf(input, sizeof(input), "mattermost %s mattermost ?xample.cloud.mattermost.com", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_pair(&out.items[0], key, "xample.cloud.mattermost.com", false);
    br_results_clear(&out);

    const char *rejected[] = {
        "mattermost E2rgfqdg7xpzbq0nmj8l68gmuz mattermost example.cloud.mattermost.com",
        "mattermost e2rgfqdg7xpzbq0nmj8l68gmu mattermost example.cloud.mattermost.com",
        "mattermost =2rgfqdg7xpzbq0nmj8l68gmuz mattermost example.cloud.mattermost.com",
        "e2rgfqdg7xpzbq0nmj8l68gmuz example.cloud.mattermost.com",
        "mattermost key = '=2rgfqdg7xpzbq0nmj8l68gmuz' url = '?xample.cloud.mattermost.com'",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        out = test_scan(detector, NULL, false, rejected[i], strlen(rejected[i]));
        CHECK(!out.len);
        br_results_clear(&out);
    }
    out = test_scan(detector, NULL, false, "", 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "mattermost %s mattermost %s", key, server);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    br_results_clear(&out);

    const struct { int status; bool verified; } cases[] = {
        {200, true}, {201, true}, {299, true}, {199, false}, {300, false}, {401, false}, {500, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){
            .status = cases[i].status,
            .body = {(const unsigned char *)"ignored", 7},
            .body_error = "read failed",
        };
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        expect_pair(&out.items[0], key, server, cases[i].verified);
        CHECK(!strcmp(seen_url, "https://example.cloud.mattermost.com/api/v4/users/stats"));
        CHECK(!strcmp(seen_auth, "Bearer e2rgfqdg7xpzbq0nmj8l68gmuz"));
        br_results_clear(&out);
    }

    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    expect_pair(&out.items[0], key, server, false);
    br_results_clear(&out);

    http.calls = http.releases = 0;
    http.send_rc = 0;
    http.send_error = NULL;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mattermost %s mattermost %s mattermost %s", key, server, dotted);
    http.response.status = 204;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    expect_pair(&out.items[0], key, server, true);
    expect_pair(&out.items[1], key, dotted, true);
    CHECK(!strcmp(seen_url, "https://xXcloudYmattermostZcom/api/v4/users/stats"));
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 7, "prior", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    char *error = NULL;
    snprintf(input, sizeof(input), "mattermost %s mattermost %s", key, server);
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) == 0 && !error);
    CHECK(kept.len == 2 && kept.items[0].detector_type == 7);
    expect_pair(&kept.items[1], key, server, false);
    br_results_clear(&kept);
}

int main(void)
{
    const br_detector *detector = open_detector();
    grammar(detector);
    verification(detector);
    return test_finish("MattermostPersonalToken");
}
