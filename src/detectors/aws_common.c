/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aws/common.go, aws/utils.go
 * and detectors/account_filter.go. Protocol and filtering decisions stay local. */
#include "aws_common.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char br_aws_secret_pattern[] = "(?:[^A-Za-z0-9+/]|\\A)([A-Za-z0-9+/]{40})(?:[^A-Za-z0-9+/]|\\z)";

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int option_list(const br_json *options, const char *name, const char *prefix,
                         const br_json **out, char **error)
{
    br_json *value = NULL;
    *out = NULL;
    if (!options || !json_object_object_get_ex(options, name, &value) || !value) return 0;
    bool valid = json_object_is_type(value, json_type_array);
    for (size_t i = 0; valid && i < json_object_array_length(value); ++i)
        valid = json_object_is_type(json_object_array_get_idx(value, i), json_type_string);
    if (valid) { *out = value; return 0; }
    char message[160];
    snprintf(message, sizeof(message), "%s: %s must be an array of strings", prefix, name);
    return fail(error, message);
}

int br_aws_read_options(const br_scan_ctx *ctx, const char *prefix, br_aws_options *out, char **error)
{
    *out = (br_aws_options){0};
    const br_json *value = ctx ? ctx->options : NULL;
    if (value && !json_object_is_type(value, json_type_object)) {
        char message[160];
        snprintf(message, sizeof(message), "%s: expected an object", prefix);
        return fail(error, message);
    }
    if (option_list(value, "skip_ids", prefix, &out->skip_ids, error) != 0 ||
        option_list(value, "allowed_accounts", prefix, &out->allowed_accounts, error) != 0 ||
        option_list(value, "denied_accounts", prefix, &out->denied_accounts, error) != 0) return -1;
    return 0;
}

bool br_aws_list_contains(const br_json *list, const char *text)
{
    size_t len = strlen(text), count = list ? json_object_array_length(list) : 0;
    for (size_t i = 0; i < count; ++i) {
        br_json *item = json_object_array_get_idx(list, i);
        if ((size_t)json_object_get_string_len(item) == len && !memcmp(json_object_get_string(item), text, len))
            return true;
    }
    return false;
}

int br_aws_replace_url_bytes(br_slice input, br_bytes *out, char **error)
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

bool br_aws_account_from_id(const char id[21], char account[14])
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

bool br_aws_hash_like(const char secret[41])
{
    /* Exact 40-byte captures make the source's unanchored regex equivalent. */
    for (size_t i = 0; i < 40; ++i)
        if (!((secret[i] >= 'a' && secret[i] <= 'f') || (secret[i] >= '0' && secret[i] <= '9'))) return false;
    return true;
}

static bool same_id(const br_result *a, const br_result *b)
{
    return !strcmp(a->redacted ? a->redacted : "", b->redacted ? b->redacted : "");
}

void br_aws_clean(const br_detector *detector, br_results *results, bool verification_enabled)
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
