/* SPDX-License-Identifier: AGPL-3.0-only */
/* Offline subset of TruffleHog PR #5528, merge 188766766fd81cde66e5500b0db0379235637134.
 * Regional OAuth verification is deliberately not implemented. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static br_regex *secret_regex, *id_regex;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* IEEE reflected CRC32 over <tag>_<43 random characters>, encoded as six
 * base62 digits using the issuer's alphabet (not a hash of the whole prefix). */
static bool checksum_valid(const char *secret)
{
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    uint32_t crc = UINT32_MAX;
    for (size_t i = 11; i < 57; ++i) {
        crc ^= (unsigned char)secret[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    crc = ~crc;
    char encoded[6];
    for (size_t i = sizeof(encoded); i > 0; ) {
        encoded[--i] = alphabet[crc % 62];
        crc /= 62;
    }
    return !memcmp(encoded, secret + 57, sizeof(encoded));
}

static int add_string(br_json *object, const char *name, const char *value)
{
    br_json *v = json_object_new_string(value);
    if (!v) return -1;
    if (json_object_object_add(object, name, v) != 0) {
        json_object_put(v);
        return -1;
    }
    return 0;
}

static int finding(const br_detector *d, const char *secret, const char *id,
                   br_result *result, char **error)
{
    if (br_finding_key(result, d->type, secret, "client_secret") != 0)
        return fail(error, "cannot create Serval result");
    result->extra_data = json_object_new_object();
    const char *kind = secret[11] == 'p' ? "public_api" :
                       secret[11] == 'w' ? "worker" : "managed_worker";
    if (!result->extra_data || add_string(result->extra_data, "key_type", kind) != 0)
        return fail(error, "cannot create Serval metadata");
    if (id) {
        if (add_string(result->secret_parts, "client_id", id) != 0)
            return fail(error, "cannot create Serval client ID");
        size_t len = strlen(id) + 1 + strlen(secret);
        result->raw_v2.data = malloc(len);
        if (!result->raw_v2.data) return fail(error, "cannot create Serval pair");
        result->raw_v2.len = len;
        memcpy(result->raw_v2.data, id, strlen(id));
        result->raw_v2.data[strlen(id)] = ':';
        memcpy(result->raw_v2.data + strlen(id) + 1, secret, strlen(secret));
    }
    return 0;
}

static int scan(const br_detector *d, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, char **error)
{
    (void)ctx;
    if (error) *error = NULL;
    if (!d || !d->state || !out || (!input.data && input.len))
        return fail(error, "invalid Serval scan");
    if (verify) return fail(error, "Serval live verification is not implemented");
    size_t original_len = out->len;
    br_captures secrets = {0}, ids = {0}, normalized = {0};
    int rc = br_captures_find(secret_regex, input, &secrets, true, error);
    if (rc == 0 && secrets.len)
        rc = br_captures_find(id_regex, input, &ids, true, error);
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        for (char *p = ids.items[i]; *p; ++p)
            if (*p >= 'A' && *p <= 'F') *p += 'a' - 'A';
        rc = br_captures_push(&normalized, br_captures_at(&ids, i), true, error);
    }
    for (size_t i = 0; rc == 0 && i < secrets.len; ++i) {
        if (!checksum_valid(secrets.items[i])) continue;
        for (size_t j = 0; rc == 0 && j < (normalized.len ? normalized.len : 1); ++j) {
            br_result result = {0};
            rc = finding(d, secrets.items[i], normalized.len ? normalized.items[j] : NULL,
                         &result, error);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append Serval result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&ids);
    br_captures_clear(&normalized);
    return rc;
}

static const char *const keywords[] = {"svl_secret_"};
static br_detector detector = {
    .type = 1078, .version = 0, .name = "Serval", .custom_name = "",
    .description = "Serval API and worker credentials (offline checksum validation only).",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan,
};

int br_serval_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Serval detector output");
    *out = NULL;
    if (!secret_regex && br_regex_compile(
            "\\b(svl_secret_(?:pk|wk|mk)_[0-9A-Za-z]{49})\\b", &secret_regex, error) != 0)
        return -1;
    static const char *const id_keywords[] = {"serval", "client"};
    if (!id_regex && br_regex_compile_prefixed(id_keywords, 2,
            "\\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\b",
            &id_regex, error) != 0) return -1;
    detector.state = secret_regex;
    *out = &detector;
    return 0;
}
