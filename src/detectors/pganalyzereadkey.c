/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pganalyzereadkey/pganalyzereadkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pganalyze_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pganalyze_verify(const br_scan_ctx *ctx, const char *token, br_slice secret,
                            br_result *result, char **error)
{
    char authorization[40];
    const char *cause = NULL;
    char status_error[80];
    bool verified = false;
    /* Constant URL needs no pre-construction. Nil context is the constructor error. */
    if (!ctx) cause = "net/http: nil Context";
    else {
        memcpy(authorization, "Token ", 6);
        memcpy(authorization + 6, token, 32);
        authorization[38] = '\0';
        const br_header header = {"Authorization", authorization};
        const br_http_request request = {
            .method = "POST", .url = "https://app.pganalyze.com/graphql",
            .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error;
        else if (response.status == 200) verified = true;
        else if (response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error),
                             "unexpected HTTP response status %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error)) {
                br_http_release(ctx, &response);
                free(transport_error);
                return pganalyze_fail(error, "cannot format PgAnalyzeReadKey status cause");
            }
            cause = status_error;
        }
        /* Copy/discard errors are ignored. Setter runs before Verified. */
        int set = br_result_set_verification_error(result, cause, &secret, 1);
        br_http_release(ctx, &response);
        free(transport_error);
        if (set != 0) return pganalyze_fail(error, "cannot set PgAnalyzeReadKey verification error");
        result->verified = verified;
        return 0;
    }
    if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
        return pganalyze_fail(error, "cannot set PgAnalyzeReadKey verification error");
    result->verified = verified;
    return 0;
}

static int pganalyze_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pganalyze_fail(error, "invalid or uninitialized PgAnalyzeReadKey scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (token.len != 32) rc = pganalyze_fail(&owned_error, "invalid PgAnalyzeReadKey capture");
        else if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = pganalyze_fail(&owned_error, "cannot create PgAnalyzeReadKey result");
        else {
            br_json *access = json_object_new_string("read");
            if (!access || json_object_object_add(result.secret_parts, "access_type", access) != 0) {
                json_object_put(access);
                rc = pganalyze_fail(&owned_error, "cannot store PgAnalyzeReadKey access type");
            }
        }
        if (rc == 0 && verify &&
            pganalyze_verify(ctx, tokens.items[i], token, &result, &owned_error) != 0)
            rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pganalyze_fail(&owned_error, "cannot append PgAnalyzeReadKey result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pganalyze_keywords[] = {"pgar_"};
static br_regex *pganalyze_regex;
static br_detector pganalyze_detector = {
    .type = 1054, .version = 0, .name = "PgAnalyzeReadKey", .custom_name = "",
    .description = "pganalyze is a PostgreSQL monitoring and performance analysis platform. pganalyze Read API keys can be used to access read-only monitoring and query performance data.",
    .keywords = pganalyze_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pganalyze_scan,
};

int br_pganalyzereadkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pganalyze_fail(error, "invalid PgAnalyzeReadKey detector output");
    *out = NULL;
    if (!pganalyze_regex &&
        br_regex_compile("\\b(pgar_[A-Za-z0-9]{27})\\b", &pganalyze_regex, error) != 0)
        return -1;
    pganalyze_detector.state = pganalyze_regex;
    *out = &pganalyze_detector;
    return 0;
}
