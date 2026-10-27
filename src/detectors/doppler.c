/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/doppler/doppler.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>

typedef enum { DOPPLER_ABORT = -1, DOPPLER_KEEP = 0, DOPPLER_DROP = 1 } doppler_outcome;
typedef struct { br_json *type, *workplace; char *cause; } doppler_response;

static int doppler_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int doppler_type(br_json *value, const char *field, const char *expected, doppler_response *response)
{
    /* The first ordinary type error survives later valid duplicates. Continue
     * projecting other known fields, without hiding subsequent resource errors. */
    if (response->cause) return 0;
    return br_json_type_cause(value, field, expected, &response->cause) == 0 ? 0 : -1;
}

static int doppler_string(br_json *value, br_json **field, const char *path, doppler_response *response)
{
    if (!value) return 0; /* null primitive strings are no-ops. */
    if (!json_object_is_type(value, json_type_string)) return doppler_type(value, path, "string", response);
    if (field) { json_object_put(*field); *field = json_object_get(value); }
    return 0;
}

static int doppler_workplace(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    doppler_response *response = user;
    /* The source nested struct is anonymous: its error Struct name is empty. */
    return br_json_field_name(name, "name") ? doppler_string(value, &response->workplace, ".workplace.name", response) : 0;
}

static int doppler_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    doppler_response *response = user;
    if (br_json_field_name(name, "name")) return doppler_string(value, NULL, "response.name", response); /* Unused, but typed. */
    if (br_json_field_name(name, "type")) return doppler_string(value, &response->type, "response.type", response);
    if (br_json_field_name(name, "workplace") && value) {
        if (!json_object_is_type(value, json_type_object))
            return doppler_type(value, "response.workplace", "struct { Name string \"json:\\\"name\\\"\" }", response);
        return br_json_each_member(encoded, doppler_workplace, response);
    }
    return 0; /* Unknown fields/numbers are skipped, not float64-map converted. */
}

static void doppler_response_clear(doppler_response *response)
{
    json_object_put(response->type); json_object_put(response->workplace); free(response->cause);
    *response = (doppler_response){0};
}

/* Exactly one typed Decoder.Decode: 0 success (including JSON null), +1 an
 * owned ordinary decode/read cause, -1 a fatal native resource/unsupported
 * failure. An ordinary error will be SANITIZED, then its finding DROPPED. */
static int doppler_decode(br_slice body, const char *read_error, doppler_response *response, char **error)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &response->cause);
    if (rc < 0) {
        json_object_put(root);
        return doppler_fail(error, "cannot decode Doppler response");
    }
    if (rc) { json_object_put(root); return 1; }
    br_slice document = {body.data, end};
    /* Only the ORIGINAL consumed document is guarded. Do not reject extraction,
     * ignored statuses, trailing documents/bytes or an unconsumed Reader tail.
     * Go invalid-UTF-8 replacement/full unquoting is not json-c parity. */
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return doppler_fail(error, "unsupported: Doppler invalid UTF-8 in consumed JSON document");
    }
    if (root && !json_object_is_type(root, json_type_object)) rc = doppler_type(root, NULL, "doppler.response", response);
    else if (root) rc = br_json_each_member(document, doppler_member, response);
    json_object_put(root);
    if (rc != 0) return doppler_fail(error, "cannot project Doppler response");
    return response->cause ? 1 : 0;
}

static int doppler_metadata(br_json *extra, const char *key, br_json *value)
{
    if (!br_json_text(value).len) return 0; /* Go byte length, not strlen: NUL is nonempty. */
    br_json *owned = json_object_get(value);
    if (json_object_object_add(extra, key, owned) == 0) return 0;
    json_object_put(owned); return -1;
}

static doppler_outcome doppler_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (!ctx) return DOPPLER_DROP; /* Constructor skip AFTER finding/empty ExtraData allocation. */
    /* These headers are constructed only after the successful source ctor.
     * Compiled captures are at most 86 ASCII bytes; no heap/cap/truncation seam. */
    char authorization[94];
    _Static_assert(7 + 86 + 1 == sizeof(authorization), "Doppler auth must fit 93 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.doppler.com/v3/me", .profile = BR_HTTP_SANE,
        .headers = headers, .nheaders = 2, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; doppler_response decoded = {0};
    char *transport_error = NULL; doppler_outcome outcome = DOPPLER_KEEP;
    /* Suppress the WHOLE shared setup/allocation/Do error domain, without
     * diagnostic classifiers, verification-error setters or result skipping. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.status >= 200 && response.status < 300) {
        result->verified = true;
        int rc = doppler_decode(response.body, response.body_error, &decoded, error);
        if (rc < 0) outcome = DOPPLER_ABORT;
        else if (rc != 0) {
            /* Source SetVerificationError runs BEFORE continue, even though the
             * finding will never be appended. Its +1 allocation failure is fatal.
             * Never turn this into Deno's retained verified-with-error result. */
            if (br_result_set_verification_error(result, decoded.cause, &key, 1) != 0) {
                doppler_fail(error, "cannot sanitize dropped Doppler verification error");
                outcome = DOPPLER_ABORT;
            } else outcome = DOPPLER_DROP;
        } else if (doppler_metadata(result->extra_data, "key type", decoded.type) != 0 ||
                   doppler_metadata(result->extra_data, "workplace", decoded.workplace) != 0) {
            doppler_fail(error, "cannot store Doppler metadata");
            outcome = DOPPLER_ABORT;
        }
    }
    /* Keep stack auth/borrowed diagnostics valid through release. Source scan-
     * deferred Close-only timing, streaming Reader/private-client/native HTTP
     * policies, complete JSON unquoting and global engine/output remain partial.
     * Release every ABI response, including failed sends and dropped findings. */
    br_http_release(ctx, &response);
    doppler_response_clear(&decoded); free(transport_error);
    return outcome;
}

static int doppler_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return doppler_fail(error, "invalid or uninitialized Doppler scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0}; doppler_outcome outcome = DOPPLER_KEEP;
        /* ASCII capture makes TrimSpace a no-op. Preserve EVERY occurrence and
         * always allocate empty ExtraData, including NoV and constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) rc = doppler_fail(&owned_error, "cannot create Doppler finding");
        if (!rc && !(result.extra_data = json_object_new_object())) rc = doppler_fail(&owned_error, "cannot create Doppler empty metadata");
        if (!rc && verify) {
            outcome = doppler_verify(ctx, key, &result, &owned_error);
            if (outcome == DOPPLER_ABORT) rc = -1;
        }
        if (!rc && outcome == DOPPLER_KEEP && br_results_push(out, &result) != 0) rc = doppler_fail(&owned_error, "cannot append Doppler finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const doppler_keywords[] = {"dp.ct.", "dp.pt.", "dp.st", "dp.sa.", "dp.scim.", "dp.audit."};
static br_detector doppler_detector = {
    .type = 196, .version = 0, .name = "Doppler", .custom_name = "",
    .description = "Doppler is a secrets management platform that allows teams to manage and secure environment variables and secrets. Doppler tokens can be used to access and manage these secrets.",
    .keywords = doppler_keywords, .nkeywords = 6, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = doppler_scan,
};

int br_doppler_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return doppler_fail(error, "invalid Doppler detector output");
    *out = NULL;
    if (!doppler_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(dp\\.(?:ct|pt|st(?:\\.[a-z0-9\\-_]{2,35})?|sa|scim|audit)\\.[a-zA-Z0-9]{40,44})\\b", &pattern, error) != 0) return -1;
        doppler_detector.state = pattern;
    }
    *out = &doppler_detector;
    return 0;
}
