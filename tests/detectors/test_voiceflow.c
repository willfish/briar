/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_voiceflow_init(const br_detector **out, char **error);

static void fill_key(char *out, const char *prefix)
{
    size_t n = strlen(prefix);
    memcpy(out, prefix, n);
    memset(out + n, 'a', 24);
    out[n + 24] = '.';
    memset(out + n + 25, 'b', 16);
    out[n + 41] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    static const char payload[] = "{\"question\": \"why is the sky blue?\"}";
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://general-runtime.voiceflow.com/knowledge-base/query"));
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, http->user));
    CHECK(!strcmp(request->headers[2].value, "application/json"));
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 937);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_voiceflow_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 937 && detector->nkeywords == 2);
    CHECK(!strcmp(detector->keywords[0], "vf") && !strcmp(detector->keywords[1], "dm"));
    char key[64], dm[64], ws[64], input[192];
    fill_key(key, "VF.");
    fill_key(dm, "VF.DM.");
    fill_key(ws, "VF.WS.");
    snprintf(input, sizeof(input), "token %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 937, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "%s %s", dm, ws);
    br_results both = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(both.len == 2);
    br_results_clear(&both);
    snprintf(input, sizeof(input), "vf.%s", key + 3);
    br_results lower = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(lower.len == 0);
    br_results_clear(&lower);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "%s", key);
    test_http ok = {.response = {.status = 200}, .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&ok);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified && !verified.items[0].verification_error);
    br_results_clear(&verified);
    test_http denied = {.response = {.status = 401}, .inspect = inspect_request, .user = key};
    br_transport denied_transport = test_transport(&denied);
    br_scan_ctx denied_ctx = {.transport = &denied_transport};
    br_results no = test_scan(detector, &denied_ctx, true, input, strlen(input));
    CHECK(no.len == 1 && !no.items[0].verified && !no.items[0].verification_error);
    br_results_clear(&no);
    const char body[] = "nope";
    test_http other = {.response = {.status = 500, .body = {(const unsigned char *)body, sizeof(body) - 1}},
                       .inspect = inspect_request, .user = key};
    br_transport other_transport = test_transport(&other);
    br_scan_ctx other_ctx = {.transport = &other_transport};
    br_results unexpected = test_scan(detector, &other_ctx, true, input, strlen(input));
    CHECK(unexpected.len == 1 && !unexpected.items[0].verified);
    CHECK(!strcmp(unexpected.items[0].verification_error, "unexpected HTTP response [status=500, body=nope]"));
    br_results_clear(&unexpected);
    test_http unread = {.response = {.status = 502, .body_error = "read failed",
                                     .body = {(const unsigned char *)body, sizeof(body) - 1}},
                        .inspect = inspect_request, .user = key};
    br_transport unread_transport = test_transport(&unread);
    br_scan_ctx unread_ctx = {.transport = &unread_transport};
    br_results empty_body = test_scan(detector, &unread_ctx, true, input, strlen(input));
    CHECK(!strcmp(empty_body.items[0].verification_error, "unexpected HTTP response [status=502, body=]"));
    br_results_clear(&empty_body);
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    return test_finish("Voiceflow");
}
