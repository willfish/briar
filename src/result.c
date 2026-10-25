/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

void br_result_clear(br_result *r)
{
    if (!r) return;
    free(r->detector_name);
    free(r->raw.data);
    free(r->raw_v2.data);
    free(r->redacted);
    json_object_put(r->extra_data);
    json_object_put(r->secret_parts);
    json_object_put(r->structured_data);
    free(r->verification_error);
    free(r->primary_secret.data);
    memset(r, 0, sizeof(*r));
}

void br_results_clear(br_results *rs)
{
    if (!rs) return;
    for (size_t i = 0; i < rs->len; ++i) br_result_clear(&rs->items[i]);
    free(rs->items);
    memset(rs, 0, sizeof(*rs));
}

int br_results_push(br_results *rs, br_result *owned)
{
    if (!rs || !owned || rs->len > rs->cap || (rs->cap && !rs->items)) return 1;
    /* A pointer into the collection cannot be moved safely through realloc. */
    for (size_t i = 0; i < rs->len; ++i)
        if (owned == &rs->items[i]) return 1;
    if (rs->len == rs->cap) {
        size_t cap = rs->cap ? rs->cap * 2 : 8;
        if (cap < rs->cap || cap > SIZE_MAX / sizeof(*rs->items)) return 1;
        void *items = realloc(rs->items, cap * sizeof(*rs->items));
        if (!items) return 1;
        rs->items = items;
        rs->cap = cap;
    }
    rs->items[rs->len++] = *owned;
    memset(owned, 0, sizeof(*owned));
    return 0;
}

static int redact_one(char **text, br_slice secret)
{
    static const char replacement[] = "[REDACTED]";
    const size_t repl_len = sizeof(replacement) - 1;
    size_t len = strlen(*text), count = 0;
    /* Empty secret material must not expand an error at every rune boundary. */
    if (!secret.len) return 0;
    if (!secret.data) return 1;
    for (size_t i = 0; i < len;) {
        if (secret.len <= len - i && !memcmp(*text + i, secret.data, secret.len)) {
            ++count;
            i += secret.len;
        } else ++i;
    }
    if (!count) return 0;
    size_t new_len = len;
    if (repl_len >= secret.len) {
        size_t growth = repl_len - secret.len;
        if (growth && count > (SIZE_MAX - len - 1) / growth) return 1;
        new_len += count * growth;
    } else new_len -= count * (secret.len - repl_len);
    char *next = malloc(new_len + 1);
    if (!next) return 1;
    size_t dst = 0;
    for (size_t i = 0; i < len;) {
        if (secret.len <= len - i && !memcmp(*text + i, secret.data, secret.len)) {
            memcpy(next + dst, replacement, repl_len);
            dst += repl_len;
            i += secret.len;
        } else next[dst++] = (*text)[i++];
    }
    next[dst] = '\0';
    free(*text);
    *text = next;
    return 0;
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t nsecrets)
{
    if (!r) return 1;
    if (!cause) return 0;
    if (nsecrets && !secrets) return 1;
    char *text = strdup(cause);
    if (!text) return 1;
    for (size_t i = 0; i < nsecrets; ++i) {
        if (redact_one(&text, secrets[i])) {
            free(text);
            return 1;
        }
    }
    free(r->verification_error);
    r->verification_error = text;
    return 0;
}

static bool same_redacted(const br_result *a, const br_result *b)
{
    return !strcmp(a->redacted ? a->redacted : "", b->redacted ? b->redacted : "");
}

void br_clean_results(br_results *rs, bool verification_enabled)
{
    (void)verification_enabled; /* The upstream default ignores this argument. */
    if (!rs || !rs->len) return;
    bool verified = false;
    for (size_t i = 0; i < rs->len; ++i) verified |= rs->items[i].verified;
    if (!verified) {
        for (size_t i = 1; i < rs->len; ++i) br_result_clear(&rs->items[i]);
        rs->len = 1;
        return;
    }
    size_t kept = 0;
    for (size_t i = 0; i < rs->len; ++i) {
        bool keep = rs->items[i].verified;
        for (size_t j = i + 1; keep && j < rs->len; ++j)
            if (rs->items[j].verified && same_redacted(&rs->items[i], &rs->items[j]))
                keep = false; /* Map assignment: last verified value wins. */
        if (!keep) br_result_clear(&rs->items[i]);
        else {
            if (kept != i) {
                rs->items[kept] = rs->items[i];
                memset(&rs->items[i], 0, sizeof(rs->items[i]));
            }
            ++kept;
        }
    }
    rs->len = kept;
}
