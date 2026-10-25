/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <stdlib.h>
#include <string.h>

/* Immutable data copied from the four pinned upstream embedded lists. */
extern const char *const br_fp_words[];
extern const size_t br_fp_word_count;

static bool valid_utf8(br_slice s)
{
    for (size_t i = 0; i < s.len;) {
        unsigned char c = s.data[i++];
        if (c < 0x80) continue;
        uint32_t cp;
        size_t n;
        if (c >= 0xc2 && c <= 0xdf) { cp = c & 0x1f; n = 1; }
        else if (c >= 0xe0 && c <= 0xef) { cp = c & 0x0f; n = 2; }
        else if (c >= 0xf0 && c <= 0xf4) { cp = c & 7; n = 3; }
        else return false;
        if (n > s.len - i) return false;
        for (size_t j = 0; j < n; ++j) {
            c = s.data[i++];
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3f);
        }
        if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) ||
            (n == 3 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}

static size_t find(const unsigned char *data, size_t len, const char *term)
{
    size_t n = strlen(term);
    if (n > len) return SIZE_MAX;
    for (size_t i = 0; i <= len - n; ++i)
        if (!memcmp(data + i, term, n)) return i;
    return SIZE_MAX;
}

static bool found(char **reason, const char *prefix, const char *term)
{
    if (reason) {
        size_t a = strlen(prefix), b = strlen(term);
        if (a <= SIZE_MAX - b - 1) {
            *reason = malloc(a + b + 1);
            if (*reason) {
                memcpy(*reason, prefix, a);
                memcpy(*reason + a, term, b + 1);
            }
        }
    }
    return true;
}

bool br_known_false_positive(br_slice s, const char *const *terms, size_t nterms,
                             bool word_check, char **reason)
{
    if (reason) *reason = NULL;
    if ((!s.data && s.len) || !valid_utf8(s)) return found(reason, "invalid utf8", "");
    if ((nterms && !terms) || s.len == SIZE_MAX)
        return found(reason, "unsupported: invalid false-positive arguments", "");
    unsigned char *lower = malloc(s.len + 1);
    if (!lower) return found(reason, "unsupported: false-positive allocation failed", "");
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        /* First-batch credentials are ASCII. Do not pretend ASCII lower is Unicode lower. */
        if (c >= 0x80) {
            free(lower);
            return found(reason, "unsupported: Unicode false-positive case conversion", "");
        }
        lower[i] = c >= 'A' && c <= 'Z' ? (unsigned char)(c + 'a' - 'A') : c;
    }
    lower[s.len] = 0;
    for (size_t i = 0; i < nterms; ++i) {
        if (!terms[i]) continue;
        if (strlen(terms[i]) == s.len && !memcmp(lower, terms[i], s.len)) {
            free(lower);
            return found(reason, "matches term: ", terms[i]);
        }
    }
    for (size_t i = 0; i < nterms; ++i) {
        if (terms[i] && find(lower, s.len, terms[i]) != SIZE_MAX) {
            free(lower);
            return found(reason, "contains term: ", terms[i]);
        }
    }
    const char *word = NULL;
    size_t first_end = SIZE_MAX;
    if (word_check) {
        for (size_t i = 0; i < br_fp_word_count; ++i) {
            size_t at = find(lower, s.len, br_fp_words[i]);
            if (at != SIZE_MAX && at + strlen(br_fp_words[i]) < first_end) {
                first_end = at + strlen(br_fp_words[i]);
                word = br_fp_words[i];
            }
        }
    }
    free(lower);
    return word ? found(reason, "matches wordlist: ", word) : false;
}
