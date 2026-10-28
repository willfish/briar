/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/fastlypersonaltoken/fastlypersonaltoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *id, *user, *expires, *scope; char *cause; } fastly_token;
typedef struct { br_json *extra; char *cause; bool verified; } fastly_verdict;

static int fastly_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int fastly_type(br_json *value, const char *field, const char *expected, fastly_token *token)
{
    if (token->cause) return 0; /* First ordinary type error survives later duplicates. */
    return br_json_type_cause(value, field, expected, &token->cause) == 0 ? 0 : -1;
}

static int fastly_string(br_json *value, br_json **slot, const char *field, fastly_token *token)
{
    if (!value) return 0; /* Primitive null is a no-op, not an empty assignment. */
    if (!json_object_is_type(value, json_type_string)) return fastly_type(value, field, "string", token);
    json_object_put(*slot); *slot = json_object_get(value);
    return 0;
}

static int fastly_member(void *state, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded; fastly_token *token = state;
    if (br_json_field_name(name, "id")) return fastly_string(value, &token->id, "token.id", token);
    if (br_json_field_name(name, "user_id")) return fastly_string(value, &token->user, "token.user_id", token);
    if (br_json_field_name(name, "expires_at")) return fastly_string(value, &token->expires, "token.expires_at", token);
    if (br_json_field_name(name, "scope")) return fastly_string(value, &token->scope, "token.scope", token);
    return 0; /* Typed unknown values/numbers are ignored, not map-float converted. */
}

static void fastly_token_clear(fastly_token *token)
{
    json_object_put(token->id); json_object_put(token->user); json_object_put(token->expires); json_object_put(token->scope);
    free(token->cause); *token = (fastly_token){0};
}

/* 0 typed success including root null/{}, +1 owned ordinary decode/read cause,
 * -1 fatal owned native resource/unsupported failure. Keep these domains distinct. */
static int fastly_decode(br_slice body, const char *body_error, fastly_token *token, char **error)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, body_error, &root, &end, &token->cause);
    if (rc != 0) {
        json_object_put(root);
        return rc < 0 ? fastly_fail(error, "cannot decode FastlyPersonalToken response") : 1;
    }
    if (root && !json_object_is_type(root, json_type_object)) {
        rc = fastly_type(root, NULL, "fastlypersonaltoken.token", token);
        json_object_put(root);
        return rc == 0 ? 1 : fastly_fail(error, "cannot create FastlyPersonalToken root type cause");
    }
    br_slice document = {body.data, end};
    /* Only consumed ORIGINAL JSON is guarded, never the input chunk, ignored
     * status bodies or trailing/unconsumed Reader bytes. Full Go invalid-UTF-8
     * replacement/unquoting is not supplied by json-c; do not normalize broadly. */
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return fastly_fail(error, "unsupported: FastlyPersonalToken invalid UTF-8 in consumed JSON document");
    }
    if (root) rc = br_json_each_member(document, fastly_member, token);
    json_object_put(root);
    /* Callback/cause resources fail BEFORE reporting a saved ordinary type
     * error. Continue known-field validation; later valid strings cannot erase it. */
    if (rc != 0) return fastly_fail(error, "cannot project FastlyPersonalToken response");
    return token->cause ? 1 : 0;
}

static int fastly_add(br_json *object, const char *key, br_json *owned)
{
    if (!owned) return -1;
    if (json_object_object_add(object, key, owned) == 0) return 0;
    json_object_put(owned); return -1;
}

static br_json *fastly_value(br_json *value)
{
    return value ? json_object_get(value) : json_object_new_string("");
}

static int fastly_metadata(fastly_verdict *verdict, const fastly_token *token, char **error)
{
    verdict->extra = json_object_new_object();
    /* All four fields are ALWAYS present after success. ExpiresAt uses Go byte
     * length, not strlen: an embedded-NUL nonempty value must NOT become never. */
    if (!verdict->extra || fastly_add(verdict->extra, "token_id", fastly_value(token->id)) != 0 ||
        fastly_add(verdict->extra, "user_id", fastly_value(token->user)) != 0 ||
        fastly_add(verdict->extra, "token_expires_at", br_json_text(token->expires).len ?
            json_object_get(token->expires) : json_object_new_string("never")) != 0 ||
        fastly_add(verdict->extra, "token_scope", fastly_value(token->scope)) != 0)
        return fastly_fail(error, "cannot create FastlyPersonalToken metadata");
    return 0;
}

static void fastly_verdict_clear(fastly_verdict *verdict)
{
    json_object_put(verdict->extra); free(verdict->cause); *verdict = (fastly_verdict){0};
}

static int fastly_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : fastly_fail(error, "cannot create FastlyPersonalToken verification cause");
}

static int fastly_request(const br_scan_ctx *ctx, br_slice key, fastly_verdict *verdict, char **error)
{
    if (!ctx) return fastly_cause(&verdict->cause, "net/http: nil Context", error); /* RETAIN false; never skip. */
    /* Header follows successful constructor handling. The capture is owned,
     * NUL-terminated ASCII and remains alive through synchronous send/release. */
    const br_header headers[] = {{"Fastly-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.fastly.com/tokens/self", .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 68,
    };
    br_http_response response = {0}; fastly_token token = {0}; char *transport_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* Whole mixed shared setup/allocation/Do errors remain ordinary causes.
         * MOVE the ABI-owned error; do not clone/strip/classify diagnostic text. */
        verdict->cause = transport_error; transport_error = NULL;
        if (!verdict->cause) rc = fastly_cause(&verdict->cause, "HTTP transport failed", error);
    } else if (response.status == 200) {
        /* Decoder can finish an object before observing a terminal Reader error;
         * do NOT unconditionally reject response.body_error. */
        int decoded = fastly_decode(response.body, response.body_error, &token, error);
        if (decoded < 0) rc = -1;
        else if (decoded) { verdict->cause = token.cause; token.cause = NULL; }
        else {
            rc = fastly_metadata(verdict, &token, error);
            if (!rc) verdict->verified = true;
        }
    } else if (response.status != 401 && response.status != 403) {
        char message[64]; int len = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        rc = len >= 0 && (size_t)len < sizeof(message) ? fastly_cause(&verdict->cause, message, error) :
             fastly_fail(error, "cannot format FastlyPersonalToken status cause");
    }
    /* Borrowed Reader causes and decoded strings are already owned before
     * release. Source drains+closes inside the verifier. Buffered Reader/drain,
     * full JSON/unquoting, native/private-client/error-chain/map-order and global
     * engine/output parity remain partial; native HTTP guards are unchanged. */
    br_http_release(ctx, &response);
    free(transport_error); fastly_token_clear(&token);
    return rc ? -1 : 0;
}

static int fastly_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fastly_fail(error, "invalid or uninitialized FastlyPersonalToken scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    /* Original byte uniqueness. First-source traversal is a native choice, not
     * randomized Go map-order parity. No trimming/case/token-alphabet filtering. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0}; fastly_verdict verdict = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) rc = fastly_fail(&owned_error, "cannot create FastlyPersonalToken finding");
        if (!rc && verify) {
            rc = fastly_request(ctx, key, &verdict, &owned_error);
            if (!rc) {
                /* Source ordering is Verified -> ExtraData replacement -> setter,
                 * NOT Eventbrite's post-setter replacement. Initially Extra=NULL. */
                result.verified = verdict.verified;
                json_object_put(result.extra_data); result.extra_data = verdict.extra; verdict.extra = NULL;
                if (br_result_set_verification_error(&result, verdict.cause, &key, 1) != 0)
                    rc = fastly_fail(&owned_error, "cannot sanitize FastlyPersonalToken verification error");
            }
        }
        if (!rc && br_results_push(out, &result) != 0) rc = fastly_fail(&owned_error, "cannot append FastlyPersonalToken finding");
        fastly_verdict_clear(&verdict); br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const fastly_keywords[] = {"fastly"};
static br_detector fastly_detector = {
    .type = 68, .version = 0, .name = "FastlyPersonalToken", .custom_name = "",
    .description = "Fastly is a content delivery network (CDN) and cloud service provider. Fastly personal tokens can be used to authenticate API requests to Fastly services.",
    .keywords = fastly_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fastly_scan,
};

int br_fastlypersonaltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fastly_fail(error, "invalid FastlyPersonalToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&fastly_detector, "\\b([A-Za-z0-9_-]{32})\\b", error) != 0) return -1;
    *out = &fastly_detector;
    return 0;
}
