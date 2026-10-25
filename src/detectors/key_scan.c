/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared single-key extraction, derived from TruffleHog v3.97.2 detectors. */
#include "key_scan.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    const char *secret_part;
    br_key_verifier verifier;
    bool verify;
    char *error;
} key_matches;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int emit_key(void *user, const br_span *groups, size_t ngroups)
{
    key_matches *matches = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > matches->input.len)
        return fail(&matches->error, "invalid detector capture");
    size_t len = groups[1].end - groups[1].begin;
    char *key = malloc(len + 1);
    if (!key) return fail(&matches->error, "out of memory copying detector key");
    memcpy(key, matches->input.data + groups[1].begin, len);
    key[len] = '\0';

    br_result result = {.detector_type = matches->detector->type};
    result.raw.data = malloc(len);
    result.secret_parts = json_object_new_object();
    br_json *value = json_object_new_string_len(key, (int)len);
    if (!result.raw.data || !result.secret_parts || !value) {
        if (value) json_object_put(value);
        free(key);
        br_result_clear(&result);
        return fail(&matches->error, "out of memory creating detector result");
    }
    memcpy(result.raw.data, key, len);
    result.raw.len = len;
    if (json_object_object_add(result.secret_parts, matches->secret_part, value) != 0) {
        json_object_put(value);
        free(key);
        br_result_clear(&result);
        return fail(&matches->error, "out of memory creating secret parts");
    }
    int rc = 0;
    if (matches->verify && matches->verifier(matches->ctx, key, &result) != 0)
        rc = fail(&matches->error, "out of memory sanitizing verification error");
    free(key);
    if (!rc && br_results_push(matches->out, &result) != 0)
        rc = fail(&matches->error, "out of memory appending detector result");
    if (rc) br_result_clear(&result);
    return rc;
}

int br_scan_key(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, const char *secret_part,
                br_key_verifier verifier, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || !secret_part || !verifier ||
        (!input.data && input.len))
        return fail(error, "invalid or uninitialized detector scan");
    key_matches matches = {detector, ctx, input, out, secret_part, verifier, verify, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(detector->state, input, emit_key, &matches, &regex_error);
    if (matches.error) {
        free(regex_error);
        regex_error = matches.error;
    }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

int br_key_pattern_init(br_detector *detector, const char *capture, char **error)
{
    if (detector->state) return 0;
    char *prefix = NULL;
    if (br_prefix_regex(detector->keywords, detector->nkeywords, &prefix) != 0)
        return fail(error, "cannot allocate detector prefix pattern");
    size_t len = strlen(prefix) + strlen(capture) + 1;
    char *pattern = malloc(len);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate detector pattern");
    }
    snprintf(pattern, len, "%s%s", prefix, capture);
    br_regex *regex = NULL;
    int rc = br_regex_compile(pattern, &regex, error);
    free(pattern);
    free(prefix);
    if (!rc) detector->state = regex;
    return rc;
}
