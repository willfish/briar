/* SPDX-License-Identifier: AGPL-3.0-only */
/* Shared single-key extraction, derived from TruffleHog v3.97.2 detectors. */
#include "key_scan.h"
#include "findings.h"
#include "captures.h"

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

static int append_key(key_matches *matches, br_slice captured)
{
    size_t len = captured.len;
    if (len == SIZE_MAX) return fail(&matches->error, "detector key too large");
    char *key = malloc(len + 1);
    if (!key) return fail(&matches->error, "out of memory copying detector key");
    memcpy(key, captured.data, len);
    key[len] = '\0';

    br_result result = {0};
    if (br_finding_key_bytes(&result, matches->detector->type,
                            (br_slice){(const unsigned char *)key, len}, matches->secret_part) != 0) {
        free(key);
        return fail(&matches->error, "out of memory creating detector result");
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

static int emit_key(void *user, const br_span *groups, size_t ngroups)
{
    key_matches *matches = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > matches->input.len)
        return fail(&matches->error, "invalid detector capture");
    return append_key(matches, (br_slice){matches->input.data + groups[1].begin,
                                         groups[1].end - groups[1].begin});
}

static int scan_keys(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, const char *secret_part,
                      br_key_verifier verifier, bool unique, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || !secret_part || !verifier ||
        (!input.data && input.len))
        return fail(error, "invalid or uninitialized detector scan");
    size_t original_len = out->len;
    key_matches matches = {detector, ctx, input, out, secret_part, verifier, verify, NULL};
    char *regex_error = NULL;
    int rc;
    if (unique) {
        br_captures keys = {0};
        rc = br_captures_find(detector->state, input, &keys, true, &regex_error);
        for (size_t i = 0; !rc && i < keys.len; ++i)
            rc = append_key(&matches, br_captures_at(&keys, i));
        br_captures_clear(&keys);
    } else {
        rc = br_regex_each(detector->state, input, emit_key, &matches, &regex_error);
    }
    if (matches.error) {
        free(regex_error);
        regex_error = matches.error;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

int br_scan_key(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, const char *secret_part,
                br_key_verifier verifier, char **error)
{
    return scan_keys(detector, ctx, verify, input, out, secret_part, verifier, false, error);
}

int br_scan_unique_key(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, const char *secret_part,
                       br_key_verifier verifier, char **error)
{
    return scan_keys(detector, ctx, verify, input, out, secret_part, verifier, true, error);
}

int br_key_pattern_init(br_detector *detector, const char *capture, char **error)
{
    if (detector->state) return 0;
    br_regex *regex = NULL;
    int rc = br_regex_compile_prefixed(detector->keywords, detector->nkeywords,
                                      capture, &regex, error);
    if (!rc) detector->state = regex;
    return rc;
}
