/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static size_t checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
#define SLICE(text) ((br_slice){ (const unsigned char *)(text), sizeof(text) - 1 })

static br_bytes bytes(const void *data, size_t len)
{
    br_bytes b = { malloc(len ? len : 1), len };
    CHECK(b.data != NULL);
    if (len) memcpy(b.data, data, len);
    return b;
}

static br_result candidate(const char *raw, const char *redacted, bool verified)
{
    br_result r = { .raw = bytes(raw, strlen(raw)), .verified = verified };
    if (redacted) { r.redacted = strdup(redacted); CHECK(r.redacted); }
    return r;
}

static void result_tests(void)
{
    br_result r = {0};
    br_results rs = {0};
    r.detector_name = strdup("synthetic");
    r.raw = bytes("x\0y", 3);
    r.raw_v2 = bytes("", 0);
    r.primary_secret = bytes("primary", 7);
    r.redacted = strdup("");
    r.extra_data = json_object_new_object();
    r.secret_parts = json_object_new_object();
    r.structured_data = json_object_new_object();
    br_json *external = json_object_get(r.secret_parts);
    r.primary_line = 2;
    r.chunk_offset_set = true;
    CHECK(br_results_push(&rs, &r) == 0);
    CHECK(!r.raw.data && !r.raw.len && !r.secret_parts && !r.chunk_offset_set);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 3);
    CHECK(rs.items[0].raw.data[1] == 0);
    CHECK(rs.items[0].raw_v2.data != NULL && !rs.items[0].raw_v2.len);
    CHECK(rs.items[0].chunk_offset_set);
    CHECK(br_results_push(&rs, &rs.items[0]) != 0);
    br_results_clear(&rs);
    CHECK(!rs.items && !rs.len && !rs.cap);
    CHECK(json_object_object_length(external) == 0);
    json_object_put(external);
    br_result_clear(&r);
    br_results_clear(&rs);
    r = candidate("unmoved", NULL, false);
    CHECK(br_results_push(NULL, &r) != 0 && r.raw.len == 7);
    br_result_clear(&r);

    const br_slice secrets[] = { SLICE("synthetic-key"), SLICE("other-key") };
    CHECK(br_result_set_verification_error(&r, "synthetic-key timeout synthetic-key other-key", secrets, 2) == 0);
    CHECK(!strcmp(r.verification_error, "[REDACTED] timeout [REDACTED] [REDACTED]"));
    CHECK(br_result_set_verification_error(&r, NULL, NULL, 0) == 0);
    CHECK(!strcmp(r.verification_error, "[REDACTED] timeout [REDACTED] [REDACTED]"));
    CHECK(br_result_set_verification_error(&r, "connection refused", NULL, 0) == 0);
    CHECK(!strcmp(r.verification_error, "connection refused"));
    CHECK(br_result_set_verification_error(&r, "not installed", NULL, 1) != 0);
    CHECK(!strcmp(r.verification_error, "connection refused"));
    br_result_clear(&r);

    r = candidate("first", NULL, false); CHECK(!br_results_push(&rs, &r));
    r = candidate("second", NULL, false); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, false);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 5 && !memcmp(rs.items[0].raw.data, "first", 5));
    br_results_clear(&rs);
    r = candidate("drop", "different", false); CHECK(!br_results_push(&rs, &r));
    r = candidate("old", "same", true); CHECK(!br_results_push(&rs, &r));
    r = candidate("new", "same", true);
    r.verification_from_cache = true;
    CHECK(!br_result_set_verification_error(&r, "preserved", NULL, 0));
    CHECK(!br_results_push(&rs, &r));
    r = candidate("distinct", "other", true); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, true);
    CHECK(rs.len == 2);
    CHECK(rs.items[0].raw.len == 3 && !memcmp(rs.items[0].raw.data, "new", 3));
    CHECK(rs.items[0].verification_from_cache && !strcmp(rs.items[0].verification_error, "preserved"));
    CHECK(!strcmp(rs.items[1].redacted, "other"));
    br_results_clear(&rs);
    r = candidate("null", NULL, true); CHECK(!br_results_push(&rs, &r));
    r = candidate("empty", "", true); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, false);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 5 && !memcmp(rs.items[0].raw.data, "empty", 5));
    br_results_clear(&rs);
}

typedef struct { br_span spans[16][4]; size_t ngroups[16], count; int abort_code; } captures;
static int capture(void *user, const br_span *groups, size_t n)
{
    captures *c = user;
    CHECK(c->count < 16 && n <= 4);
    c->ngroups[c->count] = n;
    memcpy(c->spans[c->count++], groups, n * sizeof(*groups));
    return c->abort_code;
}

static captures match(const char *pattern, br_slice input)
{
    br_regex *re = NULL;
    char *error = NULL;
    captures c = {0};
    CHECK(!br_regex_compile(pattern, &re, &error) && !error);
    CHECK(!br_regex_each(re, input, capture, &c, &error) && !error);
    br_regex_free(re);
    return c;
}

static void regex_tests(void)
{
    const char *const keywords[] = { "ab.tract", "abyssale" };
    char *prefix = NULL;
    CHECK(!br_prefix_regex(keywords, 2, &prefix));
    CHECK(!strcmp(prefix, "(?i:ab.tract|abyssale)(?s:.){0,40}?"));
    char prefixed[128], padded[64];
    snprintf(prefixed, sizeof(prefixed), "%s(key)", prefix);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(padded, "abyssale", 8);
        memset(padded + 8, '\r', gap);
        memcpy(padded + 8 + gap, "key", 3);
        captures padding = match(prefixed, (br_slice){(unsigned char *)padded, 11 + gap});
        CHECK(padding.count == (gap == 40 ? 1u : 0u));
    }
    free(prefix);
    CHECK(!br_prefix_regex(NULL, 0, &prefix));
    CHECK(!strcmp(prefix, "(?i:)(?s:.){0,40}?"));
    free(prefix);
    captures c = match("(a)?(b)", SLICE("b ab"));
    CHECK(c.count == 2 && c.ngroups[0] == 3);
    CHECK(c.spans[0][1].begin == SIZE_MAX && c.spans[0][1].end == SIZE_MAX);
    CHECK(c.spans[0][2].begin == 0 && c.spans[0][2].end == 1);
    CHECK(c.spans[1][0].begin == 2 && c.spans[1][0].end == 4);
    c = match("a*", SLICE("aaab"));
    CHECK(c.count == 2 && c.spans[0][0].end == 3 && c.spans[1][0].begin == 4);
    c = match("", SLICE("\xc3\xa9x"));
    CHECK(c.count == 3 && c.spans[1][0].begin == 2 && c.spans[2][0].begin == 3);
    c = match("x$", SLICE("x\n")); CHECK(c.count == 0);
    c = match("\\b(x)\\b", SLICE("\xc3\xa9x\xc3\xa9")); CHECK(c.count == 1);
    c = match("x", SLICE("x\0x")); CHECK(c.count == 2 && c.spans[1][0].begin == 2);
    c = match("(ab)", SLICE("\xff" "ab\xc0" "ab"));
    CHECK(c.count == 2 && c.spans[0][1].begin == 1 && c.spans[0][1].end == 3 &&
          c.spans[1][1].begin == 4 && c.spans[1][1].end == 6);
    c = match("a(?s:.)b", SLICE("a\xff" "b")); CHECK(c.count == 0);
    c = match("a(?s:.)b", SLICE("a\xef\xbf\xbd" "b")); CHECK(c.count == 1);
    c = match("a$|^b", SLICE("a\xff" "b")); CHECK(c.count == 0);
    c = match("(?i:keyword)([a-z]+)", SLICE("KEYWORDa KEYWORDA")); CHECK(c.count == 1);
    br_regex *re = NULL;
    char *error = NULL;
    const char *bad[] = { "[", "(?=a)", "(a)\\1", "a++", "(?R)", "\\K" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CHECK(br_regex_compile(bad[i], &re, &error) != 0 && error && !re);
        free(error); error = NULL;
    }
    CHECK(!br_regex_compile("x", &re, &error));
    c = (captures){ .abort_code = 7 };
    CHECK(br_regex_each(re, SLICE("xx"), capture, &c, &error) == 7 && c.count == 1 && error);
    free(error); error = NULL;
    c = (captures){0};
    CHECK(!br_regex_each(re, SLICE("\xffx"), capture, &c, &error) && !error && c.count == 1);
    CHECK(c.spans[0][0].begin == 1 && c.spans[0][0].end == 2);
    br_regex_free(re);
    CHECK(!br_regex_compile("(a+)+$", &re, &error));
    c = (captures){0};
    CHECK(br_regex_each(re, SLICE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"), capture, &c, &error) != 0 && error && !c.count);
    CHECK(strstr(error, "limit") != NULL);
    free(error);
    br_regex_free(re);
}

static captures prefix_match(const char *const *heads, size_t count, const char *tail,
                              br_slice input, bool rendered)
{
    br_regex *re = NULL; char *error = NULL; captures c = {0};
    if (rendered) {
        char *prefix = NULL;
        CHECK(!br_prefix_regex(heads, count, &prefix));
        size_t len = strlen(prefix) + strlen(tail) + 1;
        char *pattern = malloc(len); CHECK(pattern);
        snprintf(pattern, len, "%s%s", prefix, tail);
        CHECK(!br_regex_compile(pattern, &re, &error));
        free(pattern); free(prefix);
    } else CHECK(!br_regex_compile_prefixed(heads, count, tail, &re, &error));
    CHECK(!error && !br_regex_each(re, input, capture, &c, &error) && !error);
    bool ascii = true;
    for (size_t i = 0; i < input.len; ++i) if (input.data[i] & 0x80) ascii = false;
    if (ascii) {
        /* An unreachable invalid byte after the ASCII subject selects the
         * compatibility walk. All these suffixes keep identical boundaries;
         * require the fast path's entire capture sequence, not just counts. */
        unsigned char *fallback = malloc(input.len + 1); CHECK(fallback);
        if (input.len) memcpy(fallback, input.data, input.len);
        fallback[input.len] = 0xff;
        captures slow = {0};
        CHECK(!br_regex_each(re, (br_slice){fallback, input.len + 1}, capture, &slow, &error) && !error);
        CHECK(c.count == slow.count);
        for (size_t i = 0; i < c.count; ++i) {
            CHECK(c.ngroups[i] == slow.ngroups[i]);
            for (size_t j = 0; j < c.ngroups[i]; ++j)
                CHECK(c.spans[i][j].begin == slow.spans[i][j].begin && c.spans[i][j].end == slow.spans[i][j].end);
        }
        free(fallback);
    }
    br_regex_free(re); return c;
}

static void prefix_tests(void)
{
    const char *const alternatives[] = {"a", "ab"}, *const reversed[] = {"ab", "a"};
    const char *const overlap[] = {"aba"}, *const word[] = {"word"}, *const folded[] = {"k", "s"};
    char input[256];
    for (size_t mode = 0; mode < 2; ++mode) {
        memcpy(input, "AB", 2); memset(input + 2, '.', 40); input[42] = 'X';
        captures c = prefix_match(alternatives, 2, "(X)", (br_slice){(unsigned char *)input, 43}, mode != 0);
        CHECK(c.count == 1 && c.ngroups[0] == 2 && c.spans[0][0].begin == 0 && c.spans[0][0].end == 43);
        CHECK(c.spans[0][1].begin == 42 && c.spans[0][1].end == 43);
        c = prefix_match(reversed, 2, "([A-Z]+)", SLICE("AB1Z"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][1].begin == 3 && c.spans[0][1].end == 4);
        memcpy(input, "ababa", 5); memset(input + 5, '.', 40); input[45] = 'X';
        c = prefix_match(overlap, 1, "(X)", (br_slice){(unsigned char *)input, 46}, mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].begin == 2 && c.spans[0][1].begin == 45);
        c = prefix_match(word, 1, "([0-9]{2,4})", SLICE("word 1234"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][1].begin == 5 && c.spans[0][1].end == 9);
        c = prefix_match(word, 1, "([0-9]{2,4}?)", SLICE("word 1234"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].end == 7 && c.spans[0][1].end == 7);
        c = prefix_match(word, 1, "\\b([-])\\b", SLICE("word-X"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][1].begin == 4 && c.spans[0][1].end == 5);
        c = prefix_match(word, 1, "(\\B[X])", SLICE("wordX"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][1].begin == 4);
        c = prefix_match(word, 1, "(\\b[\\x21-\\x7e]{2,4}\\b)", SLICE("word a-bc"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][1].begin == 5 && c.spans[0][1].end == 9);
        c = prefix_match(word, 1, "([a-zA-Z]{4,5})", SLICE("word wordX"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].begin == 0 && c.spans[0][0].end == 10 && c.spans[0][1].begin == 5);
        c = prefix_match(word, 1, "(XX)", SLICE("word XX word XX"), mode != 0);
        CHECK(c.count == 2 && c.spans[0][0].end == 7 && c.spans[1][0].begin == 8 && c.spans[1][1].begin == 13);
        c = prefix_match(folded, 2, "(X)", SLICE("\xe2\x84\xaaX \xc5\xbfX"), mode != 0);
        CHECK(c.count == 2 && c.spans[0][1].begin == 3 && c.spans[1][1].begin == 7);
        static const unsigned char units[][4] = {{0xe0,0x80,0x80},{0xed,0xa0,0x80},{0xf0,0x80,0x80,0x80},{0xf4,0x90,0x80,0x80}};
        for (size_t u = 0; u < 4; ++u) for (size_t gap = 40; gap <= 41; ++gap) {
            size_t width = u < 2 ? 3 : 4, at = 4; memcpy(input, "word", 4);
            for (size_t n = 0; n < gap; ++n) { memcpy(input + at, units[u], width); at += width; }
            memcpy(input + at, "ABCD", 4);
            c = prefix_match(word, 1, "\\b([A-Z]{4})\\b", (br_slice){(unsigned char *)input, at + 4}, mode != 0);
            CHECK(c.count == (gap == 40 ? 1u : 0u));
            if (c.count) CHECK(c.spans[0][0].begin == 0 && c.spans[0][0].end == at + 4 && c.spans[0][1].begin == at);
        }
        c = prefix_match(word, 1, "(X)", SLICE("word\xffX word\0X"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].begin == 7 && c.spans[0][1].begin == 12);
        c = prefix_match(word, 1, "(X)", SLICE("word \xffX"), mode != 0); CHECK(!c.count);
        const char *const jumping[] = {"a", "b"};
        c = prefix_match(jumping, 2, "(X)", SLICE("a x\xff" "bX"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].begin == 4 && c.spans[0][1].begin == 5);
        const char *const fragments[] = {"ab.tract", "word"};
        c = prefix_match(fragments, 2, "(X)", SLICE("word\xed\xa0\x80X"), mode != 0);
        CHECK(c.count == 1 && c.spans[0][0].begin == 0 && c.spans[0][0].end == 8);
        CHECK(c.spans[0][1].begin == 7 && c.spans[0][1].end == 8);
        c = prefix_match(word, 1, "(A)(B)", SLICE("wordAB"), mode != 0); CHECK(c.count == 1 && c.ngroups[0] == 3);
        c = prefix_match(word, 1, "(A*)", SLICE("word"), mode != 0); CHECK(c.count == 1 && c.spans[0][1].begin == c.spans[0][1].end);
        c = prefix_match(NULL, 0, "(X)", SLICE("X"), mode != 0); CHECK(c.count == 1);
    }
    br_regex *re = NULL; char *error = NULL;
    CHECK(!br_regex_compile_prefixed(word, 1, "([A-Z]+)", &re, &error) && !error);
    const int aborts[] = {1, -7};
    for (size_t i = 0; i < 2; ++i) {
        captures c = {.abort_code = aborts[i]};
        CHECK(br_regex_each(re, SLICE("word X word Y"), capture, &c, &error) == aborts[i]);
        CHECK(c.count == 1 && error); free(error); error = NULL;
    }
    br_regex_free(re);
}

static void prefix_sequence_tests(void)
{
    static const char uuid[] = "01234567-89ab-cdef-0123-456789abcdef";
    static const char uuid_tail[] =
        "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b";
    static const char public_tail[] =
        "\\b(pk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b";
    static const char secret_tail[] =
        "\\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b";
    static const char kraken_public[] = "\\b([0-9A-Za-z\\/\\+=]{56}[ \"'\\r\\n]{1})";
    static const char kraken_private[] = "\\b([0-9A-Za-z\\/\\+=]{86,88}[ \"'\\r\\n]{1})";
    static const char kickbox[] = "\\b([a-zA-Z0-9_]+[a-zA-Z0-9]{64})\\b";
    char public_crlf[59], private_quote[90], public_tab[58], kick_long[67], kick_short[65];
    memset(public_crlf, 'A', 56); memcpy(public_crlf + 56, "\r\n", 3);
    memset(private_quote, 'A', 88); memcpy(private_quote + 88, "'", 2);
    memset(public_tab, 'A', 56); memcpy(public_tab + 56, "\t", 2);
    memcpy(kick_long, "p_", 2); memset(kick_long + 2, 'A', 64); kick_long[66] = '\0';
    memset(kick_short, 'A', 64); kick_short[64] = '\0';
    const struct {
        const char *head, *tail, *unit;
        size_t gap;
        const char *payload;
        size_t capture_len;
    } cases[] = {
        {"kucoin", uuid_tail, "\xed\xa0\x80", 40, uuid, 36},
        {"kucoin", uuid_tail, "\xed\xa0\x80", 41, uuid, 0},
        {"langfuse", public_tail, "\xe0\x80\x80", 1, "pk-lf-01234567-89ab-cdef-0123-456789abcdef", 42},
        {"langfuse", secret_tail, "\xe0\x80\x80", 1, "sk-lf-01234567-89ab-cdef-0123-456789abcdef", 42},
        {"langfuse", public_tail, "\xe0\x80\x80", 1, "PK-lf-01234567-89ab-cdef-0123-456789abcdef", 0},
        {"kraken", kraken_public, "\xe0\x80\x80", 1, public_crlf, 57},
        {"kraken", kraken_private, "\xe0\x80\x80", 1, private_quote, 89},
        {"kraken", kraken_public, "\xe0\x80\x80", 1, public_tab, 0},
        {"kickbox", kickbox, "\xf4\x90\x80\x80", 1, kick_long, 66},
        {"kickbox", kickbox, "\xf4\x90\x80\x80", 1, kick_short, 0},
        {"kucoin", "([ \\r\\n]{1}[!-~]{7,32}[ \\r\\n]{1})", "\xe0\x80\x80", 1, " abcDEF! ", 9},
        {"langfuse", public_tail, " \xff", 1, "pk-lf-01234567-89ab-cdef-0123-456789abcdef", 0},
        {"word", "(AB{2}C)", "\xe0\x80\x80", 1, "ABBC", 4},
        {"word", "(AB{2}C)", "\xe0\x80\x80", 1, "ABABC", 0},
    };
    for (size_t mode = 0; mode < 2; ++mode) for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char input[256];
        size_t at = strlen(cases[i].head), width = strlen(cases[i].unit);
        size_t end = at + cases[i].gap * width, payload = strlen(cases[i].payload);
        CHECK(end + payload <= sizeof(input));
        memcpy(input, cases[i].head, at);
        for (size_t gap = 0; gap < cases[i].gap; ++gap) {
            memcpy(input + at, cases[i].unit, width); at += width;
        }
        memcpy(input + at, cases[i].payload, payload);
        captures c = prefix_match(&cases[i].head, 1, cases[i].tail,
                                   (br_slice){(unsigned char *)input, end + payload}, mode != 0);
        CHECK(c.count == (cases[i].capture_len ? 1u : 0u));
        if (c.count) {
            CHECK(c.ngroups[0] == 2 && c.spans[0][0].begin == 0);
            CHECK(c.spans[0][0].end == end + cases[i].capture_len);
            CHECK(c.spans[0][1].begin == end && c.spans[0][1].end == end + cases[i].capture_len);
        }
    }
}

static void prefix_dot_tests(void)
{
    const struct {
        const char *first, *second, *tail;
        br_slice input;
        size_t count, begin, end, capture_begin, capture_end;
    } cases[] = {
        {"ab.tract", "word", "(X)", SLICE("ab\xed\xa0\x80tract X"), 1, 0, 12, 11, 12},
        {"ab.tract", "word", "(X)", SLICE("ab\ntract X"), 0, 0, 0, 0, 0},
        {"ab.tract", "word", "(X)", SLICE("ab\rtract X"), 1, 0, 10, 9, 10},
        {"ab.tract", "word", "(X)", SLICE("ab\xe0\x80\x8atract X"), 1, 0, 12, 11, 12},
        {"ab.tract", "word", "(X)", SLICE("word\nX"), 1, 0, 6, 5, 6},
        {"ab.tract", "ab", "([A-Z]+)", SLICE("abZtractX"), 1, 0, 9, 8, 9},
        {"ab", "ab.tract", "([A-Z]+)", SLICE("abZtractX"), 1, 0, 3, 2, 3},
        {"ab.tract", "word", "(X)", SLICE("ab#\xfftract X"), 0, 0, 0, 0, 0},
        {"ab.tract", "word", "(X)", SLICE("ab#\x80tract X"), 0, 0, 0, 0, 0},
        {"aba.tract", NULL, "(X)", SLICE("ababaZtractX"), 1, 2, 12, 11, 12},
        {"k.s", "word", "(X)", SLICE("\xe2\x84\xaa\xed\xa0\x80\xc5\xbfX"), 1, 0, 9, 8, 9},
    };
    for (size_t mode = 0; mode < 2; ++mode) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            const char *const heads[] = {cases[i].first, cases[i].second};
            captures c = prefix_match(heads, cases[i].second ? 2 : 1, cases[i].tail,
                                      cases[i].input, mode != 0);
            CHECK(c.count == cases[i].count);
            if (c.count) {
                CHECK(c.ngroups[0] == 2);
                CHECK(c.spans[0][0].begin == cases[i].begin && c.spans[0][0].end == cases[i].end);
                CHECK(c.spans[0][1].begin == cases[i].capture_begin && c.spans[0][1].end == cases[i].capture_end);
            }
        }
        const char *const heads[] = {"ab.tract", "word"};
        captures c = prefix_match(heads, 2, "(X)", SLICE("ab\xed\xa0\x80tract X word X"), mode != 0);
        CHECK(c.count == 2);
        CHECK(c.spans[0][0].begin == 0 && c.spans[0][0].end == 12 && c.spans[0][1].begin == 11);
        CHECK(c.spans[1][0].begin == 13 && c.spans[1][0].end == 19 && c.spans[1][1].begin == 18);
        c = prefix_match(heads, 2, "(X)", SLICE("abZtractXabYtractX"), mode != 0);
        CHECK(c.count == 2);
        CHECK(c.spans[0][0].begin == 0 && c.spans[0][0].end == 9 && c.spans[0][1].begin == 8);
        CHECK(c.spans[1][0].begin == 9 && c.spans[1][0].end == 18 && c.spans[1][1].begin == 17);
    }
}

static void fp_tests(void)
{
    CHECK(br_ascii_shannon_entropy(SLICE("")) == 0);
    CHECK(br_ascii_shannon_entropy(SLICE("aaaa")) == 0);
    CHECK(br_ascii_shannon_entropy(SLICE("abab")) == 1);
    CHECK(br_ascii_shannon_entropy(SLICE("abcd")) == 2);
    CHECK(br_ascii_shannon_entropy(SLICE("abcdefgh")) == 3);
    CHECK(br_ascii_shannon_entropy(SLICE("0123456789abcdef")) == 4);
    CHECK(br_ascii_shannon_entropy(SLICE("0123456789abcdefghijklmnopqrstuv")) == 5);
    CHECK(br_ascii_shannon_entropy(SLICE("\0x")) == 1);
    CHECK(br_ascii_shannon_entropy(SLICE("\xff")) == 0);
    CHECK(br_ascii_shannon_entropy((br_slice){NULL, 1}) == 0);
    static const char *const terms[] = { "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****" };
    char *reason = NULL;
    CHECK(br_known_false_positive(SLICE("EXAMPLE"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "matches term: example")); free(reason);
    CHECK(br_known_false_positive(SLICE("23ExAmPlE91"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "contains term: example")); free(reason);
    CHECK(br_known_false_positive(SLICE("\xff"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "invalid utf8")); free(reason);
    CHECK(!br_known_false_positive(SLICE("b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y"), terms, 7, true, &reason) && !reason);
    const char *words[] = { "password", "dictionary", "rustonomicon", "00000000-0000-0000-0000-000000000000" };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
        br_slice s = { (const unsigned char *)words[i], strlen(words[i]) };
        CHECK(br_known_false_positive(s, NULL, 0, true, &reason));
        CHECK(reason && !strncmp(reason, "matches wordlist: ", 18)); free(reason);
        CHECK(!br_known_false_positive(s, NULL, 0, false, &reason) && !reason);
    }
    CHECK(br_known_false_positive(SLICE("k\0example"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "contains term: example")); free(reason);
    CHECK(!br_known_false_positive(SLICE("\xc3\x89"), terms, 7, true, &reason));
    CHECK(!reason);
    CHECK(br_known_false_positive(SLICE("k\0password"), NULL, 0, true, &reason));
    CHECK(reason && !strcmp(reason, "matches wordlist: password")); free(reason);
    const char *const empty[] = {""};
    CHECK(br_known_false_positive(SLICE("Q7"), empty, 1, false, &reason));
    CHECK(reason && !strcmp(reason, "contains term: ")); free(reason);

    /* The byte-pair rejection must preserve every pinned word and the exact
     * earliest-ending/source-order winner, even when wordlist entries overlap. */
    extern const char *const br_fp_words[];
    extern const size_t br_fp_word_count;
    for (size_t i = 0; i < br_fp_word_count; ++i) {
        size_t len = strlen(br_fp_words[i]) + 6;
        char *input = malloc(len + 1); CHECK(input);
        snprintf(input, len + 1, "z9|%s|q7", br_fp_words[i]);
        for (size_t j = 0; j < len; ++j)
            if (input[j] >= 'A' && input[j] <= 'Z') input[j] += 'a' - 'A';
        const char *winner = NULL;
        size_t end = SIZE_MAX;
        for (size_t j = 0; j < br_fp_word_count; ++j) {
            const char *hit = strstr(input, br_fp_words[j]);
            size_t candidate_end = hit ? (size_t)(hit - input) + strlen(br_fp_words[j]) : SIZE_MAX;
            if (candidate_end < end) { end = candidate_end; winner = br_fp_words[j]; }
        }
        bool result = br_known_false_positive((br_slice){(unsigned char *)input, len}, NULL, 0, true, &reason);
        CHECK(result == (winner != NULL));
        if (winner) CHECK(reason && !strncmp(reason, "matches wordlist: ", 18) && !strcmp(reason + 18, winner));
        else CHECK(!reason);
        free(reason); free(input);
    }
}

typedef struct { size_t calls, releases; bool transport_failure; uint32_t timeout; br_http_profile profile; } fake;
static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *req,
                      br_http_response *response, char **error)
{
    fake *f = user;
    ++f->calls;
    CHECK(ctx->transport->user == f);
    CHECK(!strcmp(req->method, "POST") && !strcmp(req->url, "https://synthetic.invalid/path?q=a%20b"));
    CHECK(req->nheaders == 4);
    CHECK(!strcmp(req->headers[0].name, "X-Repeat") && !strcmp(req->headers[0].value, "one"));
    CHECK(!strcmp(req->headers[1].name, "X-Repeat") && !strcmp(req->headers[1].value, "two"));
    CHECK(!strcmp(req->headers[2].name, "User-Agent") && !strcmp(req->headers[2].value, "caller"));
    CHECK(!strcmp(req->headers[3].name, "User-Agent") && !strcmp(req->headers[3].value, "TruffleHog synthetic-tests"));
    CHECK(req->body.len == 3 && !memcmp(req->body.data, "a\0b", 3));
    CHECK(req->profile == f->profile && req->detector_type == 521);
    CHECK(req->timeout_ms > 0 && req->timeout_ms <= f->timeout);
    if (f->profile != BR_HTTP_SANE) CHECK(req->timeout_ms == f->timeout);
    if (f->transport_failure) { *error = strdup("synthetic timeout"); return 9; }
    response->status = 200;
    response->body = SLICE("partial");
    response->body_error = "synthetic body error";
    return 0;
}
static void fake_release(void *user, br_http_response *response)
{
    fake *f = user;
    ++f->releases;
    CHECK(response->status == 0 || response->status == 200);
}
static bool always_cancelled(void *user) { (void)user; return true; }

static void http_tests(void)
{
    const struct { br_slice user, password; const char *expected; } auth_cases[] = {
        {SLICE("secret"), SLICE("key"), "Basic c2VjcmV0OmtleQ=="},
        {SLICE("a"), SLICE("b"), "Basic YTpi"},
        {SLICE(""), SLICE("a"), "Basic OmE="},
        {SLICE(""), SLICE(""), "Basic Og=="},
        {SLICE("a\0"), SLICE("b"), "Basic YQA6Yg=="},
    };
    char *auth = NULL, *auth_error = NULL;
    for (size_t i = 0; i < sizeof(auth_cases) / sizeof(auth_cases[0]); ++i) {
        CHECK(!br_http_basic_auth(auth_cases[i].user, auth_cases[i].password, &auth, &auth_error));
        CHECK(!auth_error && !strcmp(auth, auth_cases[i].expected));
        free(auth); auth = NULL;
    }
    CHECK(br_http_basic_auth((br_slice){NULL, 1}, (br_slice){0}, &auth, &auth_error) != 0);
    CHECK(!auth && auth_error);
    free(auth_error);

    fake f = { .timeout = 5000 };
    const br_transport transport = { &f, fake_send, fake_release };
    br_scan_ctx ctx = { .transport = &transport, .user_agent = "synthetic-tests" };
    const br_header headers[] = { {"X-Repeat", "one"}, {"X-Repeat", "two"}, {"User-Agent", "caller"} };
    br_http_request request = {
        .method = "POST", .url = "https://synthetic.invalid/path?q=a%20b",
        .headers = headers, .nheaders = 3, .body = SLICE("a\0b"),
        .profile = BR_HTTP_SANE, .detector_type = 521,
    };
    br_http_response response = {0};
    char *error = NULL;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    CHECK(response.status == 200 && response.body.len == 7 && response.body_error);
    CHECK(!strcmp(headers[2].value, "caller") && !request.timeout_ms && request.nheaders == 3);
    br_http_release(&ctx, &response);
    CHECK(!response.status && !response.body.data && !response.body_error && f.releases == 1);
    f.transport_failure = true;
    CHECK(br_http_send(&ctx, &request, &response, &error) == 9 && error);
    free(error); error = NULL;
    br_http_release(&ctx, &response);
    f.transport_failure = false;
    request.timeout_ms = 123; f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error));
    br_http_release(&ctx, &response);
    request.timeout_ms = 0; f.timeout = 1000;
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    ctx.deadline_monotonic_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + 1000;
    CHECK(!br_http_send(&ctx, &request, &response, &error));
    br_http_release(&ctx, &response);
    size_t sent = f.calls;
    ctx.deadline_monotonic_ms = 1;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context deadline exceeded"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    ctx.deadline_monotonic_ms = 0; ctx.cancelled = always_cancelled;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context canceled"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    ctx.cancelled = NULL;
    for (int profile = BR_HTTP_DETECTOR_LOCAL; profile <= BR_HTTP_DETECTOR_PUBLIC; ++profile) {
        request.profile = f.profile = (br_http_profile)profile;
        request.timeout_ms = 0; f.timeout = 10000;
        CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
        br_http_release(&ctx, &response);
        request.timeout_ms = 123; f.timeout = 123;
        CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
        br_http_release(&ctx, &response);
    }
    request.profile = f.profile = BR_HTTP_AWS;
    request.timeout_ms = 0; f.timeout = 5000;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    request.timeout_ms = 123; f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    request.timeout_ms = 0;
    sent = f.calls;
    for (int profile = BR_HTTP_PINNED_RETRYABLE; profile <= BR_HTTP_RETRYABLE; ++profile) {
        request.profile = (br_http_profile)profile;
        CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "unsupported"));
        free(error); error = NULL; br_http_release(&ctx, &response);
    }
    request.profile = BR_HTTP_SANE; request.dedup_key = SLICE("synthetic");
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "coalescing"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    request.dedup_key = (br_slice){0}; ctx.user_agent = "bad\r\nvalue";
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "user agent"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    CHECK(f.calls == sent);
    ctx.transport = NULL;
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "not installed"));
    CHECK(!response.status && !response.body.data);
    free(error);
    br_http_release(&ctx, &response);
}

static int browserstack_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                              br_http_response *response, char **error)
{
    (void)error;
    fake *f = user;
    ++f->calls;
    CHECK(request->profile == BR_HTTP_BROWSERSTACK);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://synthetic.invalid/"));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog synthetic-tests"));
    CHECK(!request->body.data && !request->body.len);
    if (!f->timeout) CHECK(request->timeout_ms == 0);
    else {
        CHECK(request->timeout_ms > 0 && request->timeout_ms <= f->timeout);
        if (!ctx->deadline_monotonic_ms) CHECK(request->timeout_ms == f->timeout);
    }
    response->status = 200;
    return 0;
}

static void browserstack_http_tests(void)
{
    CHECK(BR_HTTP_BROWSERSTACK == 6 && BR_HTTP_AWS == 5);
    fake f = {0};
    const br_transport transport = {&f, browserstack_send, fake_release};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "synthetic-tests"};
    br_http_request request = {.method = "GET", .url = "https://synthetic.invalid/", .profile = BR_HTTP_BROWSERSTACK};
    br_http_response response = {0}; char *error = NULL;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    CHECK(!request.timeout_ms && !request.nheaders); /* No implicit 5/10 seconds or duplicate UA. */
    br_http_release(&ctx, &response);
    request.timeout_ms = f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    ctx.deadline_monotonic_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + 1000;
    request.timeout_ms = 0; f.timeout = 1000;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    request.timeout_ms = f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    size_t calls = f.calls;
    ctx.deadline_monotonic_ms = 1;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context deadline exceeded"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    CHECK(f.calls == calls);
    ctx.deadline_monotonic_ms = 0; ctx.cancelled = always_cancelled;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context canceled"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    CHECK(f.calls == calls);
    ctx.cancelled = NULL; ctx.deadline_monotonic_ms = INT64_MAX;
    request.timeout_ms = f.timeout = 0;
    CHECK(br_http_send(&ctx, &request, &response, &error) &&
          !strcmp(error, "unsupported: BrowserStack deadline exceeds 32-bit timeout"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    CHECK(f.calls == calls); /* Reject before narrowing or invoking transport. */
    request.timeout_ms = f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    br_http_release(&ctx, &response);
    CHECK(f.calls == calls + 1 && f.releases == 8);
}

/* Private adapter hook, also exercised by the isolated proxy regression. */
extern const br_transport *br_curl_transport_init(char **error);

static void unsupported_native_profiles(void)
{
    char *error = NULL;
    const br_transport *transport = br_curl_transport_init(&error);
    CHECK(transport != NULL && error == NULL);
    br_scan_ctx ctx = {.transport = transport};
    /* Invalid URL prevents DNS even if a future regression removes the guard. */
    br_http_request request = {
        .method = "GET", .url = "://invalid", .profile = BR_HTTP_DETECTOR_PUBLIC,
    };
    br_http_response response = {0};
    const br_http_profile unsupported[] = {BR_HTTP_DETECTOR_PUBLIC, BR_HTTP_AWS, BR_HTTP_BROWSERSTACK};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
        request.profile = unsupported[i];
        CHECK(br_http_send(&ctx, &request, &response, &error) != 0);
        CHECK(error && !strcmp(error, "unsupported: native curl HTTP client profile"));
        CHECK(response.status == 0 && response.body.data == NULL);
        free(error); error = NULL;
        br_http_release(&ctx, &response);
    }
}

int main(int argc, char **argv)
{
    bool prefixed_probe = argc >= 3 && !strcmp(argv[1], "--prefixed-regex-probe");
    if ((argc == 3 && !strcmp(argv[1], "--regex-probe")) || prefixed_probe) {
        unsigned char input[8192]; size_t len = fread(input, 1, sizeof(input), stdin);
        if (ferror(stdin) || len == sizeof(input)) return 2;
        captures c = prefixed_probe
            ? prefix_match((const char *const *)(argv + 3), (size_t)argc - 3, argv[2],
                           (br_slice){input, len}, false)
            : match(argv[2], (br_slice){input, len});
        putchar('[');
        for (size_t i = 0; i < c.count; ++i) {
            printf("%s[", i ? "," : "");
            for (size_t j = 0; j < c.ngroups[i]; ++j)
                printf("%s%lld,%lld", j ? "," : "", c.spans[i][j].begin == SIZE_MAX ? -1LL : (long long)c.spans[i][j].begin,
                       c.spans[i][j].end == SIZE_MAX ? -1LL : (long long)c.spans[i][j].end);
            putchar(']');
        }
        puts("]"); return 0;
    }
    CHECK(BR_ABI_REVISION == 1);
    result_tests(); regex_tests(); prefix_tests(); prefix_sequence_tests(); prefix_dot_tests(); fp_tests(); http_tests(); browserstack_http_tests(); unsupported_native_profiles();
    printf("core: %zu assertions, 0 failures\n", checks);
    return 0;
}
