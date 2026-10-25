/* SPDX-License-Identifier: AGPL-3.0-only */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "briar.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct br_regex { pcre2_code *code; size_t ngroups; };

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
    /* UTF counts runes for '.', but without UCP, word/digit classes stay ASCII.
     * Pinned RE2 treats invalid UTF-8 as a match barrier, not a subject-wide
     * error or RuneError substitution that would let matches cross bad bytes. */
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
    pcre2_pattern_info(compiled, PCRE2_INFO_CAPTURECOUNT, &captures);
    re->code = compiled;
    re->ngroups = (size_t)captures + 1;
    *out = re;
    return 0;
}

int br_regex_each(const br_regex *re, br_slice input, br_match_fn fn,
                  void *user, char **error)
{
    if (error) *error = NULL;
    if (!re || !fn || (!input.data && input.len)) return fail(error, "invalid regex iteration arguments");
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
        if (n == PCRE2_ERROR_NOMATCH) break;
        if (n <= 0) {
            PCRE2_UCHAR detail[192];
            char message[256];
            if (pcre2_get_error_message(n, detail, sizeof(detail)) < 0)
                memcpy(detail, "match resource error", sizeof("match resource error"));
            snprintf(message, sizeof(message), "regex execution: %s", (char *)detail);
            rc = fail(error, message);
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
