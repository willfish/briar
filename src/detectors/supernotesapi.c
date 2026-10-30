/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/supernotesapi/supernotesapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef enum { NOTE_ABORT = -1, NOTE_KEEP = 0, NOTE_SKIP = 1 } note_outcome;

static int note_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static br_slice note_trim(br_slice value)
{
    while (value.len && isspace(value.data[0])) {
        value.data++;
        value.len--;
    }
    while (value.len && isspace(value.data[value.len - 1])) value.len--;
    return value;
}

static note_outcome note_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return NOTE_SKIP;
    char token[43 + 1];
    memcpy(token, key.data, key.len);
    token[key.len] = '\0';
    /* Header.Add canonicalizes Api-Key before Do. Briar does not. */
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Api-Key", token},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.supernotes.app/v1/user/",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do failures stay unverified with no setter. Body and read errors are
     * ignored. Only 2xx verifies. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return NOTE_KEEP;
}

static int note_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return note_fail(error, "invalid or uninitialized SuperNotesAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Ordered duplicates stay. The capture includes required trailing space. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = note_trim(br_captures_at(&keys, i));
        br_result result = {0};
        note_outcome outcome = NOTE_KEEP;
        if (key.len != 43) {
            note_fail(&owned_error, "invalid SuperNotesAPI capture");
            outcome = NOTE_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            note_fail(&owned_error, "cannot create SuperNotesAPI result");
            outcome = NOTE_ABORT;
        } else if (verify) {
            outcome = note_verify(ctx, key, &result);
        }
        if (outcome == NOTE_KEEP && br_results_push(out, &result) != 0) {
            note_fail(&owned_error, "cannot append SuperNotesAPI result");
            outcome = NOTE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == NOTE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const note_keywords[] = {"supernotes"};
static br_detector note_detector = {
    .type = 718, .version = 0, .name = "SuperNotesAPI", .custom_name = "",
    .description = "SuperNotes is a note-taking application. SuperNotes API keys can be used to access and manage user notes and other data within the application.",
    .keywords = note_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = note_scan,
};

int br_supernotesapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return note_fail(error, "invalid SuperNotesAPI detector output");
    *out = NULL;
    if (!note_detector.state) {
        const char *const prefix[] = {"supernotes"};
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(prefix, 1,
                                      "([ \\r\\n]{0,1}[0-9A-Za-z\\-_]{43}[ \\r\\n]{1})",
                                      &pattern, error) != 0)
            return -1;
        note_detector.state = pattern;
    }
    *out = &note_detector;
    return 0;
}
