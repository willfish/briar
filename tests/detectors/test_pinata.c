/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_pinata_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *const *parts = http->user;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.pinata.cloud/pinning/pinJSONToIPFS"));
    CHECK(request->timeout_ms == 10000 && request->detector_type == 755);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[1].name, "pinata_api_key"));
    CHECK(!strcmp(request->headers[1].value, parts[1]));
    CHECK(!strcmp(request->headers[2].name, "pinata_secret_api_key"));
    CHECK(!strcmp(request->headers[2].value, parts[0]));
    CHECK(request->body.len > 0 && request->body.data[0] == '{');
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_pinata_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 755 && !strcmp(detector->keywords[0], "pinata"));
    CHECK(detector->max_credential_span == 1024);
    char secret[65], id[21], input[256];
    test_secret(secret, 64, 1);
    test_secret(id, 20, 2);
    snprintf(input, sizeof(input), "pinata %s pinata %s", secret, id);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 755, secret, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "pinata %s", secret);
    br_results alone = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(alone.len == 0);
    br_results_clear(&alone);
    char secret2[65], id2[21];
    test_secret(secret2, 64, 3);
    test_secret(id2, 20, 4);
    snprintf(input, sizeof(input), "pinata %s pinata %s pinata %s pinata %s", secret, secret2, id, id2);
    br_results pairs = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(pairs.len == 4);
    br_results_clear(&pairs);
    snprintf(input, sizeof(input), "pinata %s pinata %s pinata %s pinata %s", secret, secret, id, id);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 4);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "pinata %s pinata %s", secret, id);
    const char *parts[] = {secret, id};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = parts};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&verified);
    http.response.status = 401;
    http.calls = http.releases = 0;
    br_results denied = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(denied.len == 1 && !denied.items[0].verified && !denied.items[0].verification_error);
    br_results_clear(&denied);
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    return test_finish("Pinata");
}
