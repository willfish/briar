/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <json-c/json.h>
#include <string.h>

int br_tru_init(const br_detector **, char **);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char secret[] = "abcdefghijklmnopqrstuvwxyz";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://eu.api.tru.id/oauth2/v1/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 605);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Basic ", 6));
    CHECK(request->body.len == strlen("grant_type=client_credentials"));
    CHECK(!memcmp(request->body.data, "grant_type=client_credentials", request->body.len));
}

static void exercise(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "tru %s %s", key, secret);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    CHECK(out.items[0].raw.len == strlen(key) && !memcmp(out.items[0].raw.data, key, strlen(key)));
    CHECK(out.items[0].raw_v2.len == strlen(key) + strlen(secret));
    CHECK(!memcmp(out.items[0].raw_v2.data, key, strlen(key)));
    CHECK(!memcmp(out.items[0].raw_v2.data + strlen(key), secret, strlen(secret)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(out.items[0].secret_parts, "secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    br_results_clear(&out);
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tru_init(&detector, &error) == 0 && detector->type == 605 && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "tru"));
    exercise(detector);
    return test_finish("Tru");
}
