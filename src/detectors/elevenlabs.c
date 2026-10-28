/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/elevenlabs/{v1,v2}/elevenlabs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *name, *tier; char *cause; } eleven_user;
static const char rotation_guide[] = "https://howtorotate.com/docs/tutorials/elevenlabs/";

static int eleven_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int eleven_type(br_json *value, const char *field, const char *expected, eleven_user *user)
{
    if (user->cause) return 0; /* First ordinary type error sticks across duplicates. */
    return br_json_type_cause(value, field, expected, &user->cause) == 0 ? 0 : -1;
}

static int eleven_string(br_json *value, br_json **slot, const char *field, eleven_user *user)
{
    if (!value) return 0; /* null string is a no-op, not an empty assignment. */
    if (!json_object_is_type(value, json_type_string)) return eleven_type(value, field, "string", user);
    json_object_put(*slot); *slot = json_object_get(value); /* Ordered callbacks lend values. */
    return 0;
}

static int eleven_subscription(void *state, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded; eleven_user *user = state;
    /* Source Subscription is anonymous, so its type-error Struct name is empty. */
    return br_json_field_name(name, "tier") ? eleven_string(value, &user->tier, ".subscription.tier", user) : 0;
}

static int eleven_member(void *state, br_slice name, br_json *value, br_slice encoded)
{
    eleven_user *user = state;
    if (br_json_field_name(name, "first_name")) return eleven_string(value, &user->name, "UserRes.first_name", user);
    if (br_json_field_name(name, "subscription") && value) {
        if (!json_object_is_type(value, json_type_object))
            return eleven_type(value, "UserRes.subscription", "struct { Tier string \"json:\\\"tier\\\"\" }", user);
        /* Duplicate value-struct objects merge; whole-struct null is a no-op. */
        return br_json_each_member(encoded, eleven_subscription, user);
    }
    return 0; /* Typed unknown fields, including huge numbers, are ignored. */
}

static void eleven_user_clear(eleven_user *user)
{
    json_object_put(user->name); json_object_put(user->tier); free(user->cause);
    *user = (eleven_user){0};
}

/* 0 typed success (root null included), +1 owned ordinary decode/read cause,
 * -1 fatal owned resource/unsupported failure. Never collapse these domains. */
static int eleven_decode(br_slice body, const char *read_error, eleven_user *user, char **error)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &user->cause);
    if (rc < 0) { json_object_put(root); return eleven_fail(error, "cannot decode ElevenLabs response"); }
    if (rc) { json_object_put(root); return 1; }
    br_slice document = {body.data, end};
    /* Guard ONLY the original consumed document, not the input chunk, ignored
     * status bodies or unconsumed Reader tail. Go replacement/full unquoting
     * semantics are not supplied by json-c; don't broadly normalize bytes. */
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return eleven_fail(error, "unsupported: ElevenLabs invalid UTF-8 in consumed JSON document");
    }
    if (root && !json_object_is_type(root, json_type_object)) rc = eleven_type(root, NULL, "elevenlabs.UserRes", user);
    else if (root) rc = br_json_each_member(document, eleven_member, user);
    json_object_put(root);
    /* Every nonzero visitor/helper failure is owned/fatal. The saved ordinary
     * error is reported ONLY after ordered projection completed successfully. */
    if (rc != 0) return eleven_fail(error, "cannot project ElevenLabs response");
    return user->cause ? 1 : 0;
}

static int eleven_add(br_json *object, const char *key, br_json *owned)
{
    if (!owned) return -1;
    if (json_object_object_add(object, key, owned) == 0) return 0;
    json_object_put(owned); return -1;
}

static int eleven_metadata(br_result *result, const eleven_user *user)
{
    /* Successful Decode always returns &UserRes, even for null/{}. Both output
     * fields are present, including zero strings and Unicode/embedded NUL bytes.
     * Retain complete decoded strings; never strlen/filter their contents. */
    if (eleven_add(result->extra_data, "Name", user->name ? json_object_get(user->name) : json_object_new_string("")) != 0) return -1;
    return eleven_add(result->extra_data, "Tier", user->tier ? json_object_get(user->tier) : json_object_new_string(""));
}

static int eleven_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    br_http_response response = {0}; eleven_user user = {0};
    char *transport_error = NULL; const char *cause = NULL; char status_cause[80];
    bool sent = false, verified = false; int rc = 0;
    if (!ctx) cause = "net/http: nil Context"; /* RETAIN false, never a constructor skip. */
    else {
        /* Captures are NUL-terminated ASCII; borrow the literal key through
         * synchronous send AND release. No auth prefix, Type, Accept or body. */
        const br_header headers[] = {{"xi-api-key", (const char *)token.data}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.elevenlabs.io/v1/user", .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = 994,
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            cause = transport_error ? transport_error : "HTTP transport failed";
        else if (response.status == 200) {
            /* Decoder scans buffered bytes before a terminal Reader error:
             * a complete object can win. Do NOT reject body_error outright. */
            int decoded = eleven_decode(response.body, response.body_error, &user, error);
            if (decoded < 0) rc = -1;
            else if (decoded) cause = user.cause; /* False, no partial Name/Tier publication. */
            else if (eleven_metadata(result, &user) != 0) rc = eleven_fail(error, "cannot store ElevenLabs user metadata");
            else verified = true;
        } else if (response.status != 400 && response.status != 401) {
            int len = snprintf(status_cause, sizeof(status_cause), "unexpected HTTP response status %d", response.status);
            if (len < 0 || (size_t)len >= sizeof(status_cause)) rc = eleven_fail(error, "cannot format ElevenLabs status cause");
            else cause = status_cause;
        }
    }
    if (!rc) {
        result->verified = verified;
        /* Retain the whole mixed shared setup/allocation/Do domain; no text
         * classifiers/stripping. Token ONLY, NULL no-op, even +1 failure fatal.
         * Copy/sanitize borrowed causes before releasing the ABI response. */
        if (br_result_set_verification_error(result, cause, &token, 1) != 0)
            rc = eleven_fail(error, "cannot sanitize ElevenLabs verification error");
    }
    /* Source drains+closes within verifyMatch. ABI1 eagerly buffers/releases;
     * complete Reader/drain/private-client/error-chain/JSON-unquoting semantics
     * and randomized map/global engine/output parity remain partial. */
    if (sent) br_http_release(ctx, &response);
    free(transport_error); eleven_user_clear(&user);
    return rc ? -1 : 0;
}

static int eleven_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return eleven_fail(error, "invalid or uninitialized ElevenLabs scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    /* Unique ORIGINAL strings: global-CI v1 recognizes uppercase hex, but its
     * deduplication does NOT lowercase. Native first-source order is only one
     * traversal choice, not randomized Go map-order parity. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) rc = eleven_fail(&owned_error, "cannot create ElevenLabs finding");
        if (!rc) {
            result.extra_data = json_object_new_object();
            if (!result.extra_data || eleven_add(result.extra_data, "version", json_object_new_string(detector->version == 1 ? "1" : "2")) != 0 ||
                (detector->version == 1 && eleven_add(result.extra_data, "rotation_guide", json_object_new_string(rotation_guide)) != 0))
                rc = eleven_fail(&owned_error, "cannot create ElevenLabs version metadata");
        }
        if (!rc && verify) rc = eleven_verify(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result) != 0) rc = eleven_fail(&owned_error, "cannot append ElevenLabs finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const eleven_keywords[] = {"elevenlabs", "xi-api-key", "xi_api_key"};
static br_detector eleven_v1 = {
    .type = 994, .version = 1, .name = "ElevenLabs", .custom_name = "",
    .description = "Elevenlabs is an AI-driven voice synthesis platform. Elevenlabs API keys can be used to access and manipulate voice synthesis features and services.",
    .keywords = eleven_keywords, .nkeywords = 3, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = eleven_scan,
};
static br_detector eleven_v2 = {
    .type = 994, .version = 2, .name = "ElevenLabs", .custom_name = "",
    .description = "ElevenLabs is a service that provides API keys for accessing their voice synthesis and other AI-powered tools. These keys can be used to interact with ElevenLabs' services programmatically.",
    .keywords = eleven_keywords, .nkeywords = 3, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = eleven_scan,
};

static int eleven_init(br_detector *detector, const char *pattern, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return eleven_fail(error, "invalid ElevenLabs detector output");
    *out = NULL;
    if (!detector->state) {
        br_regex *compiled = NULL;
        if (br_regex_compile(pattern, &compiled, error) != 0) return -1;
        detector->state = compiled;
    }
    *out = detector;
    return 0;
}

int br_elevenlabs_v1_init(const br_detector **out, char **error)
{
    /* Entire source DIRECT/global-CI grammar: mandatory non-dot rune, greedy
     * non-LF gap and exact separators. It is NOT the common PrefixRegex. */
    return eleven_init(&eleven_v1, "(?i)(?:elevenlabs|xi-api-key|el|token|key)[^\\.].{0,40}[ =:'\"]+([a-f0-9]{32})\\b", out, error);
}
int br_elevenlabs_v2_init(const br_detector **out, char **error)
{
    return eleven_init(&eleven_v2, "\\b((?:sk)_[a-f0-9]{48})\\b", out, error);
}
