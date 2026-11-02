/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/decoders/escaped_unicode.go. */
#include "briar_decoders.h"

#include <stdlib.h>
#include <string.h>

typedef enum { LONG, BRACE, PERL, HTML_HEX, PERCENT, ESCAPED, CODE_POINT, CSS, PATTERN_COUNT } pattern;
typedef struct { size_t hex, digits, end, replace_end; } escape_match;

static int fail(char **error)
{
    if (error) {
        const char message[] = "cannot decode escaped Unicode chunk";
        *error = malloc(sizeof(message));
        if (*error) memcpy(*error, message, sizeof(message));
    }
    return -1;
}

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool starts(br_slice input, size_t at, const char *text, size_t len)
{
    return input.len - at >= len && !memcmp(input.data + at, text, len);
}

static bool ascii_word(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static bool continuation(unsigned char c) { return (c & 0xc0) == 0x80; }

/* Go regexp's optional dot consumes one rune; malformed encodings consume a byte. */
static size_t dot_width(const unsigned char *p, size_t len)
{
    unsigned char c = p[0];
    if (c < 0x80) return 1;
    if (c >= 0xc2 && c <= 0xdf && len >= 2 && continuation(p[1])) return 2;
    if (c >= 0xe0 && c <= 0xef && len >= 3 && continuation(p[1]) && continuation(p[2]) &&
        !(c == 0xe0 && p[1] < 0xa0) && !(c == 0xed && p[1] >= 0xa0)) return 3;
    if (c >= 0xf0 && c <= 0xf4 && len >= 4 && continuation(p[1]) &&
        continuation(p[2]) && continuation(p[3]) && !(c == 0xf0 && p[1] < 0x90) &&
        !(c == 0xf4 && p[1] >= 0x90)) return 4;
    return 1;
}

static bool match_at(br_slice input, size_t at, pattern kind, escape_match *match)
{
    size_t hex, minimum, maximum;
    unsigned char closing = 0;
    switch (kind) {
    case LONG:
        if (!starts(input, at, "\\U", 2)) return false;
        hex = at + 2; minimum = maximum = 8; break;
    case BRACE:
        if (!starts(input, at, "\\u{", 3)) return false;
        hex = at + 3; minimum = 1; maximum = 6; closing = '}'; break;
    case PERL:
        if (!starts(input, at, "\\x{", 3)) return false;
        hex = at + 3; minimum = 1; maximum = 6; closing = '}'; break;
    case HTML_HEX:
        if (!starts(input, at, "&#x", 3)) return false;
        hex = at + 3; minimum = 1; maximum = 6; closing = ';'; break;
    case PERCENT:
        if (!starts(input, at, "%u", 2)) return false;
        hex = at + 2; minimum = maximum = 4; break;
    case ESCAPED: {
        if (input.data[at] != '\\') return false;
        size_t u = at + 1;
        if (u < input.len && input.data[u] == '\\') ++u;
        if (u == input.len || (input.data[u] != 'u' && input.data[u] != 'U')) return false;
        hex = u + 1; minimum = maximum = 4; break;
    }
    case CODE_POINT:
        if (!starts(input, at, "U+", 2) || (at && ascii_word(input.data[at - 1]))) return false;
        hex = at + 2; minimum = maximum = 4; break;
    case CSS:
        if (input.data[at] != '\\') return false;
        hex = at + 1; minimum = 1; maximum = 6; break;
    default: return false;
    }
    size_t digits = 0;
    while (digits < maximum && digits < input.len - hex && hex_value(input.data[hex + digits]) >= 0) ++digits;
    if (digits < minimum) return false;
    size_t end = hex + digits;
    if (closing) {
        if (end == input.len || input.data[end] != closing) return false;
        ++end;
    }
    if (kind == CSS && end < input.len) {
        unsigned char c = input.data[end];
        if (c != '\\' && c != ' ' && c != '\t' && c != '\n' && c != '\f' && c != '\r') return false;
        ++end;
    }
    if (kind == CODE_POINT && end < input.len && input.data[end] != '\n')
        end += dot_width(input.data + end, input.len - end);
    *match = (escape_match){hex, digits, end, end};
    /* The source restores one byte, not a whole rune, unless it consumed a space. */
    if (kind == CODE_POINT && end != hex + digits && input.data[end - 1] != ' ')
        --match->replace_end;
    return true;
}

/* Each syntax has a mandatory first byte. memchr skips ordinary text without
 * invoking its parser; syntax priority and match/replace endpoints stay intact. */
static size_t next_start(br_slice input, size_t at, pattern kind)
{
    static const unsigned char first[PATTERN_COUNT] = {'\\', '\\', '\\', '&', '%', '\\', 'U', '\\'};
    if (at >= input.len) return input.len;
    const unsigned char *found = memchr(input.data + at, first[kind], input.len - at);
    return found ? (size_t)(found - input.data) : input.len;
}

static size_t encode_rune(uint32_t cp, unsigned char out[4])
{
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) { out[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (unsigned char)(0xc0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 63));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (unsigned char)(0xe0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 63));
        out[2] = (unsigned char)(0x80 | (cp & 63));
        return 3;
    }
    out[0] = (unsigned char)(0xf0 | (cp >> 18));
    out[1] = (unsigned char)(0x80 | ((cp >> 12) & 63));
    out[2] = (unsigned char)(0x80 | ((cp >> 6) & 63));
    out[3] = (unsigned char)(0x80 | (cp & 63));
    return 4;
}

int br_escaped_unicode_decode(br_slice input, br_bytes *decoded, bool *applied, char **error)
{
    if (error) *error = NULL;
    if (decoded) *decoded = (br_bytes){0};
    if (applied) *applied = false;
    if (!decoded || !applied || (!input.data && input.len)) return fail(error);
    pattern selected = PATTERN_COUNT;
    escape_match match;
    /* FromChunk chooses exactly one syntax family by priority for this pass. */
    for (pattern kind = LONG; kind < PATTERN_COUNT && selected == PATTERN_COUNT; ++kind)
        for (size_t at = next_start(input, 0, kind); at < input.len; at = next_start(input, at + 1, kind))
            if (match_at(input, at, kind, &match)) { selected = kind; break; }
    if (selected == PATTERN_COUNT) return 0;
    unsigned char *out = malloc(input.len);
    if (!out) return fail(error);
    size_t written = 0, copied = 0;
    for (size_t at = next_start(input, 0, selected); at < input.len;) {
        if (!match_at(input, at, selected, &match)) { at = next_start(input, at + 1, selected); continue; }
        uint32_t cp = 0;
        for (size_t i = 0; i < match.digits; ++i)
            cp = (cp << 4) | (unsigned)hex_value(input.data[match.hex + i]);
        if (cp <= 0x10ffff) {
            unsigned char encoded[4];
            size_t len = encode_rune(cp, encoded);
            memcpy(out + written, input.data + copied, at - copied);
            written += at - copied;
            memcpy(out + written, encoded, len);
            written += len;
            copied = match.replace_end;
        }
        /* FindAll advances past the entire regex match, including restored bytes. */
        at = next_start(input, match.end, selected);
    }
    memcpy(out + written, input.data + copied, input.len - copied);
    *decoded = (br_bytes){out, written + input.len - copied};
    *applied = true;
    return 0;
}
