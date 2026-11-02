/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"
#include "go_unicode.h"
#include "utf8.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

double br_ascii_shannon_entropy(br_slice input)
{
    if (!input.len || !input.data) return 0;
    size_t counts[128] = {0};
    for (size_t i = 0; i < input.len; ++i) {
        unsigned char c = input.data[i];
        if (c >= 128) return 0;
        ++counts[c];
    }
    double value = 0;
    for (size_t i = 0; i < 128; ++i) {
        if (!counts[i]) continue;
        double probability = (double)counts[i] / (double)input.len;
        value -= probability * log2(probability);
    }
    return value;
}

/* Immutable data copied from the four pinned upstream embedded lists. */
extern const char *const br_fp_words[];
extern const size_t br_fp_word_count;

static size_t encode_rune(uint32_t rune, unsigned char *out)
{
    size_t width = rune <= 0x7f ? 1 : rune <= 0x7ff ? 2 : rune <= 0xffff ? 3 : 4;
    if (out) {
        if (width == 1) out[0] = (unsigned char)rune;
        else {
            uint32_t rest = rune;
            for (size_t i = width - 1; i > 0; --i) {
                out[i] = (unsigned char)(0x80 | (rest & 0x3f));
                rest >>= 6;
            }
            out[0] = (unsigned char)((width == 2 ? 0xc0 : width == 3 ? 0xe0 : 0xf0) | rest);
        }
    }
    return width;
}

static unsigned char *lower_utf8(br_slice input, size_t *length)
{
    /* IsKnownFalsePositive validates first, then strings.ToLower. Mapping one
     * scalar can shrink OR grow its UTF8 encoding; size the complete result. */
    size_t needed = 0;
    for (size_t at = 0; at < input.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){input.data + at, input.len - at}, &rune);
        if (!width) return NULL;
        size_t bytes = encode_rune(br_go_unicode_lower(rune), NULL);
        if (bytes > SIZE_MAX - needed - 1) return NULL;
        needed += bytes;
        at += width;
    }
    unsigned char *lower = malloc(needed + 1);
    if (!lower) return NULL;
    size_t used = 0;
    for (size_t at = 0; at < input.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){input.data + at, input.len - at}, &rune);
        if (!width) { free(lower); return NULL; }
        used += encode_rune(br_go_unicode_lower(rune), lower + used);
        at += width;
    }
    lower[used] = '\0';
    *length = used;
    return lower;
}

static size_t find(const unsigned char *data, size_t len, const char *term)
{
    size_t n = strlen(term);
    if (!n) return 0;
    if (n > len) return SIZE_MAX;
    size_t at = 0, positions = len - n + 1;
    while (at < positions) {
        const unsigned char *candidate = memchr(data + at, (unsigned char)term[0], positions - at);
        if (!candidate) break;
        if (!memcmp(candidate, term, n)) return (size_t)(candidate - data);
        at = (size_t)(candidate - data) + 1;
    }
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
    if (!br_utf8_valid(s)) return found(reason, "invalid utf8", "");
    if ((nterms && !terms) || s.len == SIZE_MAX)
        return found(reason, "unsupported: invalid false-positive arguments", "");
    size_t lower_len = 0;
    unsigned char *lower = lower_utf8(s, &lower_len);
    if (!lower) return found(reason, "unsupported: false-positive allocation failed", "");
    for (size_t i = 0; i < nterms; ++i) {
        if (!terms[i]) continue;
        if (strlen(terms[i]) == lower_len && !memcmp(lower, terms[i], lower_len)) {
            free(lower);
            return found(reason, "matches term: ", terms[i]);
        }
    }
    for (size_t i = 0; i < nterms; ++i) {
        if (terms[i] && find(lower, lower_len, terms[i]) != SIZE_MAX) {
            free(lower);
            return found(reason, "contains term: ", terms[i]);
        }
    }
    const char *word = NULL;
    size_t first_end = SIZE_MAX;
    if (word_check) {
        /* A word cannot occur unless its first byte pair occurs. This exact
         * necessary-condition bitmap avoids thousands of full substring scans;
         * find() and earliest-ending/source-order choice remain authoritative. */
        uint64_t pairs[1024] = {0};
        for (size_t i = 1; i < lower_len; ++i) {
            unsigned pair = ((unsigned)lower[i - 1] << 8) | lower[i];
            pairs[pair >> 6] |= UINT64_C(1) << (pair & 63);
        }
        for (size_t i = 0; i < br_fp_word_count; ++i) {
            const unsigned char *candidate = (const unsigned char *)br_fp_words[i];
            if (candidate[0] && candidate[1]) {
                unsigned pair = ((unsigned)candidate[0] << 8) | candidate[1];
                if (!(pairs[pair >> 6] & (UINT64_C(1) << (pair & 63)))) continue;
            }
            size_t at = find(lower, lower_len, br_fp_words[i]);
            if (at != SIZE_MAX && at + strlen(br_fp_words[i]) < first_end) {
                first_end = at + strlen(br_fp_words[i]);
                word = br_fp_words[i];
            }
        }
    }
    free(lower);
    return word ? found(reason, "matches wordlist: ", word) : false;
}
