/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_twitch_init(const br_detector **out, char **error);

static const char id[] = "kn64qw9jt39bhni04h2k5jc7ebefyn";
static const char secret[] = "k0lj2mwl8n3ztmrivlpbc7obk914sj";
static char seen_body[160], seen_length[16];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://id.twitch.tv/oauth2/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 310);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Content-Length"));
    snprintf(seen_length, sizeof(seen_length), "%s", request->headers[1].value);
    snprintf(seen_body, sizeof(seen_body), "%.*s", (int)request->body.len, (const char *)request->body.data);
    CHECK(request->body.len == (size_t)atoi(seen_length));
}

static int has_raw(const br_results *out, const char *raw)
{
    for (size_t i = 0; i < out->len; ++i)
        if (out->items[i].raw_v2.len == strlen(raw) && !memcmp(out->items[i].raw_v2.data, raw, strlen(raw)))
            return 1;
    return 0;
}

int main(void)
{
    CHECK(strlen(id) == 30 && strlen(secret) == 30);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_twitch_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 310 && !strcmp(detector->name, "Twitch") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "twitch"));
    CHECK(!strcmp(detector->description, "Twitch is a live streaming service. Twitch client credentials can be used to access and modify data on the Twitch platform."));
    char input[160];
    snprintf(input, sizeof(input), "twitch token - '%s'\ntwitch token - '%s'\ntwitch token - '%s'\n", secret, id, secret);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && has_raw(&out, "kn64qw9jt39bhni04h2k5jc7ebefyn:k0lj2mwl8n3ztmrivlpbc7obk914sj"));
    CHECK(has_raw(&out, "k0lj2mwl8n3ztmrivlpbc7obk914sj:kn64qw9jt39bhni04h2k5jc7ebefyn"));
    br_results_clear(&out);
    snprintf(input, sizeof(input), "twitch %s twitch %s", secret, secret);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "twitch %s twitch %s", id, secret);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].verified && out.items[1].verified && http.calls == 2);
    CHECK(strstr(seen_body, "grant_type=client_credentials") && strstr(seen_body, "client_id="));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 400;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 201;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && !strcmp(out.items[0].verification_error, "unexpected http response status 201"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "bad kn64qw9jt39bhni04h2k5jc7ebefyn and k0lj2mwl8n3ztmrivlpbc7obk914sj";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].verification_error && out.items[1].verification_error);
    CHECK(strstr(out.items[0].verification_error, "[REDACTED]") || strstr(out.items[1].verification_error, "[REDACTED]"));
    CHECK(strstr(out.items[0].verification_error, secret) || strstr(out.items[1].verification_error, secret));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 2 && !http.calls && !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    return test_finish("Twitch");
}
