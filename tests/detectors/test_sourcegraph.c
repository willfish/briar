/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sourcegraph_init(const br_detector **out, char **error);

static void hex40(char *out, char fill)
{
    memset(out, fill, 40);
    out[40] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    static const char payload[] = "{\"query\": \"query { currentUser { username } }\"}";
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "token %s", (char *)http->user);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://sourcegraph.com/.api/graphql"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, request->body.len));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 928);
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sourcegraph_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 928 && !strcmp(detector->keywords[0], "sgp_"));
    char hex[41], local[64], dotted[80], plain[48], input[256];
    hex40(hex, 'a');
    snprintf(plain, sizeof(plain), "sgp_%s", hex);
    snprintf(local, sizeof(local), "sgp_local_%s", hex);
    snprintf(dotted, sizeof(dotted), "sgp_%s_%s", "0123456789abcdef", hex);
    snprintf(input, sizeof(input), "%s %s %s", plain, local, dotted);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 3);
    CHECK(!strcmp(extra(&found.items[0], "rotation_guide"), "https://howtorotate.com/docs/tutorials/sourcegraph/"));
    br_results_clear(&found);
    br_results bare = test_scan(detector, NULL, false, hex, 40);
    CHECK(bare.len == 1 && bare.items[0].raw.len == 40 && !memcmp(bare.items[0].raw.data, hex, 40));
    CHECK(!strcmp(extra(&bare.items[0], "rotation_guide"), "https://howtorotate.com/docs/tutorials/sourcegraph/"));
    br_results_clear(&bare);
    snprintf(input, sizeof(input), "%s %s", plain, plain);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = plain};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, plain, strlen(plain));
    CHECK(verified.len == 1 && verified.items[0].verified && !verified.items[0].verification_error);
    br_results_clear(&verified);
    http.response.status = 401;
    http.calls = http.releases = 0;
    br_results denied = test_scan(detector, &ctx, true, plain, strlen(plain));
    CHECK(denied.len == 1 && !denied.items[0].verified && !denied.items[0].verification_error);
    br_results_clear(&denied);
    http.response.status = 500;
    http.calls = http.releases = 0;
    br_results unexpected = test_scan(detector, &ctx, true, plain, strlen(plain));
    CHECK(!unexpected.items[0].verified);
    CHECK(!strcmp(unexpected.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&unexpected);
    br_results out = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)plain, strlen(plain)},
                         &out, &scan_error) != 0);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, plain, strlen(plain));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(scan_error && out.len == 0);
    free(scan_error);
    br_results_clear(&out);
    return test_finish("Sourcegraph");
}
