/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/boostnote/boostnote.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_boostnote(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Source retains creation errors and ALL Client.Do errors. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0 ? -1 : 0;
    char authorization[72]; /* Bearer + SPACE + exactly 64 captured ASCII bytes + NUL. */
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = "https://boostnote.io/api/docs",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 707};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Ignore body/read/drain errors. Upstream supplies ZERO redaction secrets,
     * so even an echoed key in a transport error must remain UNREDACTED. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0; /* Core setter allocation failures may be positive. */
}

static int scan_boostnote(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_boostnote, error);
}

static const char *const keywords[] = {"boostnote"};
static br_detector boostnote = {
    .type = 707, .version = 0, .name = "BoostNote", .custom_name = "",
    .description = "BoostNote is a note-taking application. The secret detected here is likely an API key or token used to access BoostNote services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_boostnote,
};

int br_boostnote_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BoostNote detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&boostnote, "\\b([0-9a-f]{64})\\b", error) != 0) return -1;
    *out = &boostnote;
    return 0;
}
