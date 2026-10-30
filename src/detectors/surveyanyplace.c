/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/surveyanyplace/surveyanyplace.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

enum { SURVEY_KEEP = 0, SURVEY_DROP = 1, SURVEY_FATAL = -1 };

static const char survey_body[] =
    "{\n\t\t\t\t\t\"codes\": [\n\t\t\t\t\t\"code1\",\n\t\t\t\t\t\"code2\"\n\t\t\t\t\t]\n\t\t\t\t\t}";

static int survey_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return SURVEY_FATAL;
}

static int survey_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result,
                         char **error)
{
    _Static_assert(sizeof(survey_body) - 1 == 58, "SurveyAnyplace payload is 58 bytes");
    static const char prefix[] = "https://api.surveyanyplace.com/v1/surveys/";
    static const char suffix[] = "/accesscodes";
    if (id.len > SIZE_MAX - (sizeof(prefix) - 1 + sizeof(suffix) - 1))
        return survey_fail(error, "SurveyAnyplace URL size overflow");
    size_t size = sizeof(prefix) - 1 + id.len + sizeof(suffix) - 1;
    char *url = malloc(size + 1);
    if (!url) return survey_fail(error, "cannot allocate SurveyAnyplace URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, id.data, id.len);
    memcpy(url + sizeof(prefix) - 1 + id.len, suffix, sizeof(suffix));
    /* Payload and URL exist before the nil-context constructor skip. */
    int outcome = ctx ? SURVEY_KEEP : SURVEY_DROP;
    if (outcome == SURVEY_KEEP && (memchr(url, '\0', size) || memchr(key.data, '\0', key.len)))
        outcome = survey_fail(error, "unsupported: SurveyAnyplace embedded NUL");
    if (outcome == SURVEY_KEEP) {
        char *authorization = malloc(4 + key.len + 1);
        if (!authorization) outcome = survey_fail(error, "cannot allocate SurveyAnyplace Authorization");
        else {
            memcpy(authorization, "API ", 4);
            memcpy(authorization + 4, key.data, key.len);
            authorization[4 + key.len] = '\0';
            const br_header headers[] = {
                {"Authorization", authorization},
                {"Content-Type", "application/json"},
            };
            const br_http_request request = {
                .method = "POST", .url = url, .headers = headers, .nheaders = 2,
                .body = {(const unsigned char *)survey_body, sizeof(survey_body) - 1},
                .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0)
                result->verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(send_error);
            free(authorization);
        }
    }
    free(url);
    return outcome;
}

static int survey_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !out || (!input.data && input.len))
        return survey_fail(error, "invalid or uninitialized SurveyAnyplace scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            int outcome = SURVEY_KEEP;
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, k), "key") != 0)
                outcome = survey_fail(&owned_error, "cannot create SurveyAnyplace result");
            else if (verify)
                outcome = survey_verify(ctx, br_captures_at(&keys, k), br_captures_at(&ids, i),
                                        &result, &owned_error);
            if (outcome == SURVEY_FATAL) rc = -1;
            if (outcome == SURVEY_DROP) {
                br_result_clear(&result);
                continue;
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = survey_fail(&owned_error, "cannot append SurveyAnyplace result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const survey_keywords[] = {"surveyanyplace"};
static const char *const survey_prefix[] = {"survey"};
static br_regex *survey_patterns[2];
static br_detector survey_detector = {
    .type = 233, .version = 0, .name = "SurveyAnyplace", .custom_name = "",
    .description = "SurveyAnyplace is a platform for creating surveys and quizzes. The detected credential can be used to access and manage surveys on this platform.",
    .keywords = survey_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = survey_scan,
};

int br_surveyanyplace_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return survey_fail(error, "invalid SurveyAnyplace detector output");
    *out = NULL;
    if (!survey_patterns[0] &&
        br_regex_compile_prefixed(survey_prefix, 1, "\\b([a-z0-9A-Z]{32})\\b",
                                  &survey_patterns[0], error) != 0)
        return -1;
    if (!survey_patterns[1] &&
        br_regex_compile_prefixed(survey_prefix, 1, "\\b([a-z0-9A-Z-]{36})\\b",
                                  &survey_patterns[1], error) != 0)
        return -1;
    survey_detector.state = survey_patterns;
    *out = &survey_detector;
    return 0;
}
