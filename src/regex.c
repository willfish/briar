/* SPDX-License-Identifier: AGPL-3.0-only */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "briar.h"
#include "re2_units.h"
#include "utf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    pcre2_code *search, **heads, *tail, *right;
    size_t count, dotted;
} br_regex_prefix;
struct br_regex { pcre2_code *code; size_t ngroups; br_regex_prefix *prefix; };

static int prefix_init(const char *, br_regex *, char **);

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

/* This is a bounded first-slice RE2 subset, not a custom-regex compatibility layer. */
static bool unsupported_syntax(const char *p)
{
    bool in_class = false;
    for (size_t i = 0; p[i]; ++i) {
        if (p[i] == '\\') {
            unsigned char c = (unsigned char)p[++i];
            if (!c) return true;
            if (c == 'Q') {
                while (p[i] && !(p[i] == '\\' && p[i + 1] == 'E')) ++i;
                if (!p[i]) return false;
                ++i;
            } else if ((c >= '0' && c <= '9') ||
                       (((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) &&
                        !strchr("aftrnvAbBdDsSwWpPxz", c))) return true;
            continue;
        }
        if (p[i] == '[') in_class = true;
        if (p[i] == ']') in_class = false;
        if (in_class) continue;
        if (p[i] == '(' && p[i + 1] == '*') return true;
        if (p[i] == '(' && p[i + 1] == '?') {
            size_t j = i + 2;
            if (p[j] == ':') continue;
            if (p[j] == '<' || (p[j] == 'P' && p[j + 1] == '<')) {
                if (p[j] == 'P') ++j;
                ++j;
                if (p[j] == '=' || p[j] == '!') return true;
                while (p[j] && p[j] != '>') ++j;
                if (!p[j]) return true;
                continue;
            }
            while (p[j] && strchr("imsU-", p[j])) ++j;
            if (j == i + 2 || (p[j] != ':' && p[j] != ')')) return true;
        }
        if (strchr("*+?}", p[i]) && p[i + 1] == '+') return true;
    }
    return false;
}

int br_regex_compile(const char *pattern, br_regex **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!pattern || !out) return fail(error, "invalid regex arguments");
    if (unsupported_syntax(pattern))
        return fail(error, "unsupported regex syntax outside the native RE2 subset");
    int code;
    PCRE2_SIZE offset;
    pcre2_compile_context *cc = pcre2_compile_context_create(NULL);
    if (!cc) return fail(error, "out of memory compiling regex");
    pcre2_set_newline(cc, PCRE2_NEWLINE_LF);
    /* This scalar-backed slice counts UTF runes but keeps word/digit classes
     * ASCII. Its invalid-byte barrier is narrower than pinned RE2's optimized
     * full-any ranges; source-closed named matchers handle those explicitly.
     * Do not normalize subjects or widen narrower classes to hide this gap. */
    pcre2_code *compiled = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                       PCRE2_UTF | PCRE2_MATCH_INVALID_UTF | PCRE2_DOLLAR_ENDONLY,
                                       &code, &offset, cc);
    pcre2_compile_context_free(cc);
    if (!compiled) {
        PCRE2_UCHAR detail[192];
        char message[288];
        if (pcre2_get_error_message(code, detail, sizeof(detail)) < 0)
            memcpy(detail, "unknown error", sizeof("unknown error"));
        snprintf(message, sizeof(message), "regex compile at byte %zu: %s",
                 (size_t)offset, (char *)detail);
        return fail(error, message);
    }
    br_regex *re = malloc(sizeof(*re));
    if (!re) {
        pcre2_code_free(compiled);
        return fail(error, "out of memory compiling regex");
    }
    uint32_t captures = 0;
    if (pcre2_pattern_info(compiled, PCRE2_INFO_CAPTURECOUNT, &captures) != 0) {
        pcre2_code_free(compiled);
        free(re);
        return fail(error, "cannot inspect regex captures");
    }
    re->code = compiled;
    re->ngroups = (size_t)captures + 1;
    re->prefix = NULL;
    if (prefix_init(pattern, re, error) != 0) {
        br_regex_free(re);
        return 1;
    }
    /* JIT is optional: unsupported platforms or unavailable executable memory
     * retain the interpreter. Only canonical prefixes use this ASCII fast path;
     * their non-ASCII calls still use the byte-unit compatibility walk. */
    if (re->prefix) (void)pcre2_jit_compile(re->code, PCRE2_JIT_COMPLETE);
    *out = re;
    return 0;
}

/* Admission only, not a regex interpreter: keep PCRE2's original suffix text.
 * Decline every consuming atom whose language is not provably ASCII here. */
static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool ascii_atom(const char **cursor, bool in_class)
{
    const unsigned char *p = (const unsigned char *)*cursor;
    if (!*p || *p >= 0x80) return false;
    if (*p == '\\') {
        unsigned char c = p[1];
        if (!c) return false;
        if (c == 'x') {
            int first = hex_digit(p[2]);
            if (first < 0 || first > 7 || hex_digit(p[3]) < 0) return false;
            *cursor += 4;
            return true;
        }
        if (strchr("afnrt", c) || (in_class && c == 'b')) {
            *cursor += 2;
            return true;
        }
        if (c >= 0x80 || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) return false;
        *cursor += 2;
        return true;
    }
    if (in_class ? (*p == '[' || *p == ']') : strchr("^$.[]()|*+?{}", *p) != NULL)
        return false;
    ++*cursor;
    return true;
}

static void boundary(const char **p)
{
    if ((*p)[0] == '\\' && ((*p)[1] == 'b' || (*p)[1] == 'B')) *p += 2;
}

static bool decimal_count(const char **p, size_t *value)
{
    const char *start = *p;
    *value = 0;
    while (**p >= '0' && **p <= '9') {
        size_t digit = (size_t)(**p - '0');
        if (*value > (SIZE_MAX - digit) / 10) return false;
        *value = *value * 10 + digit;
        ++*p;
    }
    return *p != start;
}

static bool ascii_suffix(const char *p)
{
    boundary(&p);
    if (*p++ != '(') return false;
    boundary(&p);
    bool any = false;
    /* Each atom consumes ASCII with a positive minimum. Repetitions bind to
     * that atom; the original PCRE2 suffix still owns lengths/backtracking. */
    for (;;) {
        if (*p == '[') {
            ++p;
            if (*p == '^') return false;
            const char *start = p;
            while (*p && *p != ']') if (!ascii_atom(&p, true)) return false;
            if (p == start || *p++ != ']') return false;
        } else if (!ascii_atom(&p, false)) break;
        any = true;
        bool repeated = false;
        if (*p == '+') { ++p; repeated = true; }
        else if (*p == '{') {
            size_t minimum = 0, maximum = 0;
            ++p;
            if (!decimal_count(&p, &minimum) || !minimum) return false;
            if (*p == ',') {
                ++p;
                if (*p != '}' && (!decimal_count(&p, &maximum) || maximum < minimum)) return false;
            }
            if (*p++ != '}') return false;
            repeated = true;
        }
        if (repeated && *p == '?') ++p;
    }
    if (!any) return false;
    boundary(&p);
    if (*p++ != ')') return false;
    boundary(&p);
    return !*p;
}

static bool head_byte(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static void prefix_free(br_regex_prefix *prefix)
{
    if (!prefix) return;
    pcre2_code_free(prefix->search);
    pcre2_code_free(prefix->tail);
    pcre2_code_free(prefix->right);
    if (prefix->heads)
        for (size_t i = 0; i < prefix->count; ++i) pcre2_code_free(prefix->heads[i]);
    free(prefix->heads);
    free(prefix);
}

static int piece_compile(const char *pattern, pcre2_code **out, char **error)
{
    br_regex *piece = NULL;
    int rc = br_regex_compile(pattern, &piece, error);
    if (rc != 0) { br_regex_free(piece); return rc; }
    *out = piece->code;
    piece->code = NULL;
    br_regex_free(piece);
    return 0;
}

static int folded_literal(const char *text, size_t len, pcre2_code **out, char **error)
{
    if (len > SIZE_MAX - sizeof("(?i:)")) return fail(error, "regex prefix too large");
    char *part = malloc(len + sizeof("(?i:)"));
    if (!part) return fail(error, "out of memory compiling regex prefix");
    memcpy(part, "(?i:", 4);
    memcpy(part + 4, text, len);
    memcpy(part + 4 + len, ")", 2);
    int rc = piece_compile(part, out, error);
    free(part);
    return rc;
}

static int prefix_init(const char *pattern, br_regex *re, char **error)
{
    static const char pre[] = "(?i:", post[] = ")(?s:.){0,40}?";
    if (re->ngroups != 2 || strncmp(pattern, pre, sizeof(pre) - 1)) return 0;
    const char *head = pattern + sizeof(pre) - 1, *end = strstr(head, post);
    if (!end || head == end || !ascii_suffix(end + sizeof(post) - 1)) return 0;
    size_t count = 1, dotted = SIZE_MAX;
    const char *dot = NULL, *dot_end = NULL;
    bool word = false;
    for (const char *p = head; p < end; ++p) {
        if (*p == '|') {
            if (!word) return 0;
            word = false;
            ++count;
        } else if (*p == '.') {
            /* One fixed L.R branch only, with nonempty literal pieces. */
            if (!word || dot) return 0;
            dot = p;
            dotted = count - 1;
            word = false;
        } else {
            if (!head_byte((unsigned char)*p)) return 0;
            word = true;
        }
    }
    if (!word) return 0;
    if (count > SIZE_MAX / sizeof(pcre2_code *)) return fail(error, "regex prefix too large");
    br_regex_prefix *prefix = calloc(1, sizeof(*prefix));
    if (!prefix) return fail(error, "out of memory compiling regex prefix");
    prefix->count = count;
    prefix->dotted = dotted;
    prefix->heads = calloc(count, sizeof(*prefix->heads));
    size_t len = (size_t)(end - pattern) + 1;
    if (dot) {
        dot_end = memchr(dot, '|', (size_t)(end - dot));
        if (!dot_end) dot_end = end;
        len -= (size_t)(dot_end - dot);
    }
    char *search = malloc(len + 1);
    if (!prefix->heads || !search) {
        free(search); prefix_free(prefix);
        return fail(error, "out of memory compiling regex prefix");
    }
    if (dot) {
        /* Search the literal L stem, not scalar L.R: otherwise an earlier
         * source match whose dot consumes a non-scalar unit can be hidden. */
        size_t first = (size_t)(dot - pattern);
        memcpy(search, pattern, first);
        memcpy(search + first, dot_end, (size_t)(end - dot_end) + 1);
    } else memcpy(search, pattern, len);
    search[len] = '\0';
    int rc = piece_compile(search, &prefix->search, error);
    free(search);
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        const char *next = memchr(head, '|', (size_t)(end - head));
        if (!next) next = end;
        const char *left_end = i == dotted ? dot : next;
        rc = folded_literal(head, (size_t)(left_end - head), &prefix->heads[i], error);
        if (rc == 0 && i == dotted)
            rc = folded_literal(dot + 1, (size_t)(next - dot - 1), &prefix->right, error);
        head = next == end ? end : next + 1;
    }
    if (rc == 0) rc = piece_compile(end + sizeof(post) - 1, &prefix->tail, error);
    if (rc != 0) { prefix_free(prefix); return rc; }
    re->prefix = prefix;
    return 0;
}

static int execution_error(char **error, int code)
{
    PCRE2_UCHAR detail[192];
    char message[256];
    if (pcre2_get_error_message(code, detail, sizeof(detail)) < 0)
        memcpy(detail, "match resource error", sizeof("match resource error"));
    snprintf(message, sizeof(message), "regex execution: %s", (char *)detail);
    return fail(error, message);
}

/* Canonical prefixes admit literal alternatives and at most one fixed L.R
 * branch. Other fragments and wide suffix atoms stay on the scalar path. */
static int each_prefixed(const br_regex *re, br_slice input, br_match_fn fn,
                          void *user, char **error)
{
    const br_regex_prefix *prefix = re->prefix;
    pcre2_match_data *search = pcre2_match_data_create_from_pattern(prefix->search, NULL);
    pcre2_match_data *head = pcre2_match_data_create_from_pattern(prefix->heads[0], NULL);
    pcre2_match_data *tail = pcre2_match_data_create_from_pattern(prefix->tail, NULL);
    pcre2_match_context *mc = pcre2_match_context_create(NULL);
    br_span *groups = malloc(re->ngroups * sizeof(*groups));
    if (!search || !head || !tail || !mc || !groups) {
        pcre2_match_data_free(search); pcre2_match_data_free(head); pcre2_match_data_free(tail);
        pcre2_match_context_free(mc); free(groups);
        return fail(error, "out of memory iterating regex");
    }
    pcre2_set_match_limit(mc, 1000000);
    pcre2_set_depth_limit(mc, 1000);
    pcre2_set_heap_limit(mc, 8192);
    const unsigned char *data = input.data ? input.data : (const unsigned char *)"";
    size_t offset = 0;
    int rc = 0;
    for (;;) {
        int n = pcre2_match(prefix->search, data, input.len, offset, 0, search, mc);
        if (n == PCRE2_ERROR_NOMATCH) break;
        if (n <= 0) { rc = execution_error(error, n); break; }
        size_t begin = pcre2_get_ovector_pointer(search)[0];
        bool found = false;
        for (size_t i = 0; rc == 0 && !found && i < prefix->count; ++i) {
            n = pcre2_match(prefix->heads[i], data, input.len, begin, PCRE2_ANCHORED, head, mc);
            if (n == PCRE2_ERROR_NOMATCH) continue;
            if (n <= 0) { rc = execution_error(error, n); break; }
            PCRE2_SIZE *head_spans = pcre2_get_ovector_pointer(head);
            /* MATCH_INVALID_UTF may restart ANCHORED matching in a later valid
             * fragment. Only the requested original continuation is eligible. */
            if (head_spans[0] != begin) continue;
            size_t at = head_spans[1];
            if (i == prefix->dotted) {
                size_t width = br_re2_any_unit_width((br_slice){data + at, input.len - at});
                /* Plain head dot excludes literal LF; only the later gap is DOTALL. */
                if (!width || data[at] == '\n') continue;
                at += width;
                n = pcre2_match(prefix->right, data, input.len, at, PCRE2_ANCHORED, head, mc);
                if (n == PCRE2_ERROR_NOMATCH) continue;
                if (n <= 0) { rc = execution_error(error, n); break; }
                head_spans = pcre2_get_ovector_pointer(head);
                if (head_spans[0] != at) continue;
                at = head_spans[1];
            }
            for (size_t gap = 0; gap <= 40; ++gap) {
                /* A nonnullable ASCII suffix cannot start on a non-ASCII byte.
                 * Keep original whole-subject boundaries and byte offsets. */
                if (at < input.len && data[at] < 0x80) {
                    n = pcre2_match(prefix->tail, data, input.len, at, PCRE2_ANCHORED, tail, mc);
                    if (n > 0) {
                        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(tail);
                        if (ov[0] == at) {
                            groups[0] = (br_span){begin, ov[1]};
                            groups[1] = (br_span){ov[2], ov[3]};
                            found = true;
                            break;
                        }
                    } else if (n != PCRE2_ERROR_NOMATCH) {
                        rc = execution_error(error, n);
                        break;
                    }
                }
                if (gap == 40) break;
                size_t width = br_re2_any_unit_width((br_slice){data + at, input.len - at});
                if (!width) break;
                at += width;
            }
        }
        if (rc != 0) break;
        if (found) {
            size_t end = groups[0].end;
            rc = fn(user, groups, re->ngroups);
            if (rc != 0) { fail(error, "regex callback aborted"); break; }
            offset = end;
        } else {
            uint32_t rune;
            size_t width = br_utf8_rune((br_slice){data + begin, input.len - begin}, &rune);
            if (!width) { rc = fail(error, "invalid regex prefix start"); break; }
            offset = begin + width; /* Failed heads may overlap at the next start. */
        }
    }
    free(groups);
    pcre2_match_context_free(mc);
    pcre2_match_data_free(search); pcre2_match_data_free(head); pcre2_match_data_free(tail);
    return rc;
}

static bool ascii_input(br_slice input)
{
    size_t at = 0;
    for (; input.len - at >= sizeof(uint64_t); at += sizeof(uint64_t)) {
        uint64_t word;
        memcpy(&word, input.data + at, sizeof(word));
        if (word & UINT64_C(0x8080808080808080)) return false;
    }
    for (; at < input.len; ++at) if (input.data[at] & 0x80) return false;
    return true;
}

int br_regex_each(const br_regex *re, br_slice input, br_match_fn fn,
                  void *user, char **error)
{
    if (error) *error = NULL;
    if (!re || !fn || (!input.data && input.len)) return fail(error, "invalid regex iteration arguments");
    /* The original compiled pattern has identical prefix/gap semantics on
     * ASCII, including NUL. Use one search instead of up to 41 anchored tail
     * calls per keyword. Non-ASCII retains the RE2 byte-unit compatibility
     * walk, including malformed encodings and folded Unicode keyword starts. */
    if (re->prefix && !ascii_input(input)) return each_prefixed(re, input, fn, user, error);
    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re->code, NULL);
    pcre2_match_context *mc = pcre2_match_context_create(NULL);
    br_span *groups = malloc(re->ngroups * sizeof(*groups));
    if (!md || !mc || !groups) {
        pcre2_match_data_free(md);
        pcre2_match_context_free(mc);
        free(groups);
        return fail(error, "out of memory iterating regex");
    }
    pcre2_set_match_limit(mc, 1000000);
    pcre2_set_depth_limit(mc, 1000);
    pcre2_set_heap_limit(mc, 8192);
    const unsigned char *data = input.data ? input.data : (const unsigned char *)"";
    size_t offset = 0, previous_end = SIZE_MAX;
    int rc = 0;
    for (;;) {
        int n = pcre2_match(re->code, data, input.len, offset, 0, md, mc);
        /* Do not turn JIT's smaller execution stack into a new rejection. */
        if (n == PCRE2_ERROR_JIT_STACKLIMIT)
            n = pcre2_match(re->code, data, input.len, offset, PCRE2_NO_JIT, md, mc);
        if (n == PCRE2_ERROR_NOMATCH) break;
        if (n <= 0) {
            rc = execution_error(error, n);
            break;
        }
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        for (size_t i = 0; i < re->ngroups; ++i) {
            groups[i].begin = ov[2 * i] == PCRE2_UNSET ? SIZE_MAX : ov[2 * i];
            groups[i].end = ov[2 * i + 1] == PCRE2_UNSET ? SIZE_MAX : ov[2 * i + 1];
        }
        size_t begin = groups[0].begin, end = groups[0].end;
        /* Go FindAll ignores an empty match abutting the previous match. */
        if (begin != end || begin != previous_end) {
            rc = fn(user, groups, re->ngroups);
            if (rc) {
                fail(error, "regex callback aborted");
                break;
            }
        }
        previous_end = end;
        if (begin == end) {
            if (end == input.len) break;
            offset = end + 1;
            while (offset < input.len && (data[offset] & 0xc0) == 0x80) ++offset;
        } else offset = end;
    }
    free(groups);
    pcre2_match_context_free(mc);
    pcre2_match_data_free(md);
    return rc;
}

void br_regex_free(br_regex *re)
{
    if (!re) return;
    prefix_free(re->prefix);
    pcre2_code_free(re->code);
    free(re);
}

int br_prefix_regex(const char *const *keywords, size_t count, char **pattern)
{
    static const char pre[] = "(?i:";
    /* RE2's (?:.|[\n\r]) accepts every rune. A single DOTALL atom has the
     * same language without PCRE2 backtracking over two ways to consume CR. */
    static const char post[] = ")(?s:.){0,40}?";
    if (!pattern) return 1;
    *pattern = NULL;
    if (count && !keywords) return 1;
    size_t len = sizeof(pre) - 1 + sizeof(post) - 1;
    for (size_t i = 0; i < count; ++i) {
        if (!keywords[i]) return 1;
        size_t n = strlen(keywords[i]);
        if (n > SIZE_MAX - len - 1 || (i && len + n == SIZE_MAX - 1)) return 1;
        len += n + (i != 0);
    }
    char *p = malloc(len + 1);
    if (!p) return 1;
    size_t at = sizeof(pre) - 1;
    memcpy(p, pre, at);
    for (size_t i = 0; i < count; ++i) {
        if (i) p[at++] = '|';
        size_t n = strlen(keywords[i]);
        memcpy(p + at, keywords[i], n);
        at += n;
    }
    memcpy(p + at, post, sizeof(post));
    *pattern = p;
    return 0;
}

int br_regex_compile_prefixed(const char *const *keywords, size_t count,
                              const char *capture, br_regex **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!capture || !out) return fail(error, "invalid prefixed regex arguments");
    char *prefix = NULL;
    if (br_prefix_regex(keywords, count, &prefix) != 0)
        return fail(error, "cannot allocate detector prefix pattern");
    size_t first = strlen(prefix), second = strlen(capture);
    if (second > SIZE_MAX - first - 1) {
        free(prefix);
        return fail(error, "detector pattern too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate detector pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, capture, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}
