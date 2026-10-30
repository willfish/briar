/* SPDX-License-Identifier: AGPL-3.0-only */
/* Salescookie, from pinned TruffleHog pkg/detectors/salescookie/salescookie.go. */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char url[] = "https://salescookie.com/app/Api/CreateTransaction";
static const char body[] =
    "{\"date\":\"2021-07-04T02:47:42.1442597Z\",\"uniqueId\":\"id-123\",\"revenue\":1.3,\"profit\":-2.5,"
    "\"currency\":\"USD\",\"transactionStatus\":\"closed won\",\"customer\":\"Candy By Mail\","
    "\"product\":\"Lemon Cake\",\"owner1\":\"John Doe\",\"owner2\":\"Jane Doe\",\"owner3\":\"Bob Smith\","
    "\"team1\":\"USA\",\"team2\":\"Washington\",\"team3\":\"98004\",\"quantity\":3,\"costPerUnit\":3.14,"
    "\"taxes\":6.54,\"otherText1\":\"additional data\",\"otherText2\":\"more data\","
    "\"otherText3\":\"even more data\",\"otherNumeric1\":123.45,\"otherNumeric2\":54.321,"
    "\"otherNumeric3\":-98.76,\"otherDate1\":\"2019-01-03T06:03:01Z\","
    "\"otherDate2\":\"2019-05-10T08:05:09Z\",\"otherDate3\":\"2019-09-04T12:17:33Z\"}";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    (void)error;
    br_slice payload = {(const unsigned char *)body, sizeof(body) - 1};
    if (!ctx) return 1;
    const br_header headers[] = {{"X-Apikey", key}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2, .body = payload,
        .timeout_ms = 5000, .detector_type = 300, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Salescookie scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key(&result, detector->type, found.items[i], "key") != 0)
            rc = fail(&owned, "cannot create Salescookie finding");
        else if (verify_requested && (outcome = verify(ctx, found.items[i], &result, &owned)) < 0)
            rc = -1;
        else if (!outcome && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Salescookie finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Salescookie", .type = 300, .description =
        "Salescookie is a sales performance management tool. Salescookie API keys can be used to create and manage transactions within the platform.",
    .keywords = (const char *[]){"salescookie", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_salescookie_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Salescookie detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([a-zA-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
