/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aws/access_keys, aws/common.go,
 * aws/utils.go and detectors/account_filter.go. SDK verification is not ported. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char unsupported_verification[] = "unsupported: AWS SDK verification is not implemented";
static const char deny_reason[] = "Account ID is in the deny list for verification";
static const char allow_reason[] = "Account ID is not in the allow list for verification";
static const char thinkst_message[] = "This is an AWS canary token generated at canarytokens.org.";
static const char knockoff_message[] = "This is an off brand AWS Canary inspired by canarytokens.org.";
static const char *const thinkst_accounts[] = {
    "052310077262", "171436882533", "534261010715", "595918472158", "717712589309",
    "819147034852", "992382622183", "730335385048", "266735846894", "893192397702",
};
static const char *const knockoff_accounts[] = {
    "044858866125", "251535659677", "344043088457", "351906852752", "390477818340",
    "426127672474", "427150556519", "439872796651", "445142720921", "465867158099",
    "637958123769", "693412236332", "732624840810", "735421457923", "959235150393", "982842642351",
};

typedef struct { br_regex *id, *secret; } aws_patterns;
typedef struct { br_json *skip_ids, *allowed_accounts, *denied_accounts; } aws_options;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int option_list(const br_json *options, const char *name, br_json **out, char **error)
{
    *out = NULL;
    if (!options || !json_object_object_get_ex(options, name, out) || !*out) return 0;
    bool valid = json_object_is_type(*out, json_type_array);
    for (size_t i = 0; valid && i < json_object_array_length(*out); ++i)
        valid = json_object_is_type(json_object_array_get_idx(*out, i), json_type_string);
    if (valid) return 0;
    char message[128];
    snprintf(message, sizeof(message), "invalid AWS access key options: %s must be an array of strings", name);
    return fail(error, message);
}

static int read_options(const br_scan_ctx *ctx, aws_options *options, char **error)
{
    const br_json *value = ctx ? ctx->options : NULL;
    if (value && !json_object_is_type(value, json_type_object))
        return fail(error, "invalid AWS access key options: expected an object");
    if (option_list(value, "skip_ids", &options->skip_ids, error) != 0 ||
        option_list(value, "allowed_accounts", &options->allowed_accounts, error) != 0 ||
        option_list(value, "denied_accounts", &options->denied_accounts, error) != 0) return -1;
    return 0;
}

static bool list_contains(br_json *list, const char *text)
{
    size_t len = strlen(text), count = list ? json_object_array_length(list) : 0;
    for (size_t i = 0; i < count; ++i) {
        br_json *item = json_object_array_get_idx(list, i);
        if ((size_t)json_object_get_string_len(item) == len && !memcmp(json_object_get_string(item), text, len))
            return true;
    }
    return false;
}

/* Only the six pinned replacements, left to right without recursive decoding. */
static int replace_url_bytes(br_slice input, br_bytes *out, char **error)
{
    out->data = malloc(input.len ? input.len : 1);
    if (!out->data) return fail(error, "out of memory replacing AWS URL bytes");
    for (size_t i = 0; i < input.len; ++i) {
        unsigned char replacement = 0;
        if (input.data[i] == '%' && input.len - i >= 3) {
            unsigned char a = input.data[i + 1], b = input.data[i + 2];
            if (a == '2' && (b == 'B' || b == 'b')) replacement = '+';
            else if (a == '2' && (b == 'F' || b == 'f')) replacement = '/';
            else if (a == '3' && (b == 'D' || b == 'd')) replacement = '=';
        }
        if (replacement) { out->data[out->len++] = replacement; i += 2; }
        else out->data[out->len++] = input.data[i];
    }
    return 0;
}

static bool account_from_id(const char *id, char account[14])
{
    if (id[4] == 'I' || id[4] == 'J') return false;
    unsigned char decoded[10];
    unsigned buffer = 0, bits = 0;
    size_t count = 0;
    for (size_t i = 4; i < 20; ++i) {
        unsigned char c = (unsigned char)id[i];
        unsigned value;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else return false;
        buffer = (buffer << 5) | value;
        bits += 5;
        if (bits >= 8) { bits -= 8; decoded[count++] = (unsigned char)(buffer >> bits); }
        buffer &= (1u << bits) - 1;
    }
    if (count < 6) return false;
    uint64_t z = 0;
    for (size_t i = 0; i < 6; ++i) z = (z << 8) | decoded[i];
    uint64_t number = (z & UINT64_C(0x7fffffffff80)) >> 7;
    snprintf(account, 14, "%012" PRIu64, number); /* Minimum width, not truncation. */
    return true;
}

static bool known_account(const char *account, const char *const *list, size_t count)
{
    for (size_t i = 0; i < count; ++i) if (!strcmp(account, list[i])) return true;
    return false;
}

static int put_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int make_result(const br_detector *detector, const char *id, const char *secret,
                        const char *account, br_result *result)
{
    static const unsigned char colon[] = ":";
    if (br_finding_pair_bytes(result, detector->type, (br_slice){(const unsigned char *)id, 20}, "access_key_id",
            (br_slice){(const unsigned char *)secret, 40}, "secret_access_key", (br_slice){colon, 1}) != 0) return -1;
    result->redacted = strdup(id);
    result->extra_data = json_object_new_object();
    const char *resource = !strncmp(id, "AKIA", 4) ? "Access key" :
                           !strncmp(id, "ABIA", 4) ? "AWS STS service bearer token" : "Context-specific credential";
    if (!result->redacted || !result->extra_data || put_text(result->extra_data, "resource_type", resource) != 0) return -1;
    if (account) {
        if (put_text(result->extra_data, "account", account) != 0) return -1;
        bool thinkst = known_account(account, thinkst_accounts, sizeof(thinkst_accounts) / sizeof(thinkst_accounts[0]));
        bool knockoff = known_account(account, knockoff_accounts, sizeof(knockoff_accounts) / sizeof(knockoff_accounts[0]));
        if (thinkst && put_text(result->extra_data, "message", thinkst_message) != 0) return -1;
        if (knockoff && put_text(result->extra_data, "message", knockoff_message) != 0) return -1;
        if ((thinkst || knockoff) && put_text(result->extra_data, "is_canary", "true") != 0) return -1;
    }
    return 0;
}

static bool hash_like(const char *secret)
{
    /* Captures are exactly 40 bytes, so the unanchored [a-f0-9]{40} match is
     * equivalent to checking the entire capture. Keep this after verification. */
    for (size_t i = 0; i < 40; ++i)
        if (!((secret[i] >= 'a' && secret[i] <= 'f') || (secret[i] >= '0' && secret[i] <= '9'))) return false;
    return true;
}

static int scan_aws(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AWS access key scan arguments");
    aws_options options = {0};
    if (read_options(ctx, &options, error) != 0) return -1;
    const aws_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->secret) return fail(error, "uninitialized AWS access key patterns");
    br_bytes replaced = {0};
    br_captures ids = {0}, secrets = {0};
    int rc = replace_url_bytes(input, &replaced, error);
    br_slice normalized = {replaced.data, replaced.len};
    if (!rc) rc = br_captures_find(compiled->id, normalized, &ids, true, error);
    if (!rc) rc = br_captures_find(compiled->secret, normalized, &secrets, true, error);
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        const char *id = ids.items[i];
        if (br_ascii_shannon_entropy(br_captures_at(&ids, i)) < 3.0 || list_contains(options.skip_ids, id)) continue;
        char account[14];
        bool has_account = account_from_id(id, account);
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            if (br_ascii_shannon_entropy(secret) < 4.25) continue;
            br_result result = {0};
            if (make_result(detector, id, secrets.items[s], has_account ? account : NULL, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AWS access key result");
                break;
            }
            const char *skip_reason = NULL;
            if (verify && has_account) {
                if (list_contains(options.denied_accounts, account)) skip_reason = deny_reason;
                else if (options.allowed_accounts && json_object_array_length(options.allowed_accounts) &&
                         !list_contains(options.allowed_accounts, account)) skip_reason = allow_reason;
            }
            if (verify && br_result_set_verification_error(&result,
                    skip_reason ? skip_reason : unsupported_verification, &secret, 1) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory recording AWS verification guard");
                break;
            }
            /* Source account-filtered results bypass the post-verification hash
             * rejection. SDK verification is guarded for every other candidate:
             * no request, credential discovery, secret consumption or success. */
            if (!skip_reason && !result.verified && hash_like(secrets.items[s])) {
                br_result_clear(&result);
                continue;
            }
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending AWS access key result");
            }
        }
    }
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    free(replaced.data);
    return rc;
}

static bool same_id(const br_result *a, const br_result *b)
{
    return !strcmp(a->redacted ? a->redacted : "", b->redacted ? b->redacted : "");
}

static void clean_aws(const br_detector *detector, br_results *results, bool verification_enabled)
{
    (void)detector;
    if (!results || !verification_enabled) return;
    size_t kept = 0;
    for (size_t i = 0; i < results->len; ++i) {
        bool keep = true;
        for (size_t j = 0; keep && j < kept; ++j)
            if (same_id(&results->items[i], &results->items[j])) keep = false;
        for (size_t j = i + 1; keep && j < results->len; ++j)
            if (results->items[j].verified && same_id(&results->items[i], &results->items[j])) keep = false;
        if (!keep) br_result_clear(&results->items[i]);
        else {
            if (kept != i) {
                results->items[kept] = results->items[i];
                memset(&results->items[i], 0, sizeof(results->items[i]));
            }
            ++kept;
        }
    }
    results->len = kept;
}

static aws_patterns patterns;
static const char *const keywords[] = {"AKIA", "ABIA", "ACCA"};
static const br_detector aws = {
    .type = 1, .version = 0, .name = "AWS", .custom_name = "",
    .description = "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. "
                   "API keys for AWS can have varying amount of access to these services depending on the IAM policy attached.",
    .keywords = keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_aws, .clean = clean_aws, .clean_always = true,
};

int br_aws_access_keys_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AWS access key detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile("\\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\\b", &patterns.id, error) != 0) return -1;
    if (!patterns.secret && br_regex_compile("(?:[^A-Za-z0-9+/]|\\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\\z)", &patterns.secret, error) != 0)
        return -1;
    *out = &aws;
    return 0;
}
