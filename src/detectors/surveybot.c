/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/surveybot/surveybot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static int surveybot_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

typedef struct {
    bool present, failed;
    char *cause;
} survey_fields;

static int surveybot_keep(survey_fields *fields, char *next)
{
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = next;
    } else free(next);
    return 0;
}

static int surveybot_surveys(void *user, br_slice name, br_json *value, br_slice encoded)
{
    survey_fields *fields = user;
    if (!br_json_field_name(name, "surveys")) return 0;
    /* Null replaces the slice. It does not clear an earlier type error. */
    if (!value || json_object_is_type(value, json_type_null)) {
        fields->present = false;
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) {
        char *next = NULL;
        if (br_json_type_cause(value, "response.surveys", "[]interface {}", &next) != 0) return -1;
        return surveybot_keep(fields, next);
    }
    char *cause = NULL;
    /* []interface{} stores numbers as float64, including nested values. */
    int checked = br_json_check_float64_numbers(encoded, &cause);
    if (checked == 1) return surveybot_keep(fields, cause);
    free(cause);
    if (checked != 0) return -1;
    fields->present = json_object_array_length(value) > 0;
    return 0;
}

static int surveybot_decode(const br_http_response *response, char **cause_out, bool *has_surveys)
{
    *has_surveys = false;
    *cause_out = NULL;
    br_json *root = NULL;
    char *cause = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &cause);
    /* Exact document +1 is ordinary even when the diagnostic was not stored. */
    if (rc == 1) {
        json_object_put(root);
        *cause_out = cause;
        return 1;
    }
    if (rc != 0) {
        free(cause);
        json_object_put(root);
        return -1;
    }
    free(cause);
    /* json-c represents JSON null as a NULL object. That is a zero struct. */
    if (!root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        return 0;
    }
    if (!json_object_is_type(root, json_type_object)) {
        char *next = NULL;
        int typed = br_json_type_cause(root, NULL, "surveybot.response", &next);
        json_object_put(root);
        if (typed != 0) return -1;
        *cause_out = next;
        return 1;
    }
    survey_fields fields = {0};
    int visit = br_json_each_member((br_slice){response->body.data, end}, surveybot_surveys, &fields);
    json_object_put(root);
    if (visit != 0) {
        free(fields.cause);
        return -1;
    }
    if (fields.failed) {
        *cause_out = fields.cause;
        return 1;
    }
    *has_surveys = fields.present;
    return 0;
}

static int surveybot_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (!ctx) return 1;
    char api_key[81];
    memcpy(api_key, key, 80);
    api_key[80] = '\0';
    const br_header headers[] = {{"Accept", "application/json"}, {"X-Api-Key", api_key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://app.surveybot.io/api/v1/surveys?page=1&per_page=20&offset=0",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int outcome = 0;
    if (sent == 0 && response.status >= 200 && response.status < 300) {
        bool has_surveys = false;
        char *cause = NULL;
        int decoded = surveybot_decode(&response, &cause, &has_surveys);
        if (decoded < 0) outcome = surveybot_fail(error, "cannot decode SurveyBot response");
        else if (decoded == 1) {
            /* SetVerificationError runs before the candidate is dropped. */
            br_slice secret = {(const unsigned char *)key, 80};
            if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
                outcome = surveybot_fail(error, "cannot set SurveyBot verification error");
            else outcome = 1;
        } else if (has_surveys) result->verified = true;
        free(cause);
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int surveybot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return surveybot_fail(error, "invalid or uninitialized SurveyBot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        int outcome = 0;
        if (key.len != 80) rc = surveybot_fail(&owned_error, "invalid SurveyBot capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = surveybot_fail(&owned_error, "cannot create SurveyBot result");
        else if (verify) outcome = surveybot_verify(ctx, keys.items[i], &result, &owned_error);
        if (outcome < 0) rc = -1;
        if (rc == 0 && outcome == 0 && br_results_push(out, &result) != 0)
            rc = surveybot_fail(&owned_error, "cannot append SurveyBot result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const surveybot_keywords[] = {"surveybot"};
static br_detector surveybot_detector = {
    .type = 234, .version = 0, .name = "SurveyBot", .custom_name = "",
    .description = "SurveyBot is a service used for conducting surveys. SurveyBot API keys can be used to access and manage surveys.",
    .keywords = surveybot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = surveybot_scan,
};

int br_surveybot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return surveybot_fail(error, "invalid SurveyBot detector output");
    *out = NULL;
    if (br_key_pattern_init(&surveybot_detector, "\\b([A-Za-z0-9-]{80})\\b", error) != 0) return -1;
    *out = &surveybot_detector;
    return 0;
}
