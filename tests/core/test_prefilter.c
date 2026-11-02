/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/prefilter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL prefilter:%d: %s\n", __LINE__, #expr); exit(1); } } while (0)

/* The former CLI scalar loop is the regression oracle: visit start offsets
 * left-to-right, union adjacent windows, ASCII-fold without changing bytes. */
static bool scalar_hit(br_slice input, size_t at, const char *word)
{
    size_t len = strlen(word);
    if (len > input.len - at) return false;
    for (size_t j = 0; j < len; ++j) {
        unsigned char a = input.data[at + j], b = (unsigned char)word[j];
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return false;
    }
    return true;
}

static void compare(br_prefilter *filter, const br_detector *const *registry,
                    size_t count, const bool *selected, br_slice input)
{
    br_detector_windows *matches = NULL;
    size_t nmatch = 0, m = 0;
    char *error = NULL;
    CHECK(br_prefilter_find(filter, input, NULL, &matches, &nmatch, &error) == 0 && !error);
    br_span *expected = calloc(input.len ? input.len : 1, sizeof(*expected));
    CHECK(expected != NULL);
    for (size_t i = 0; i < count; ++i) {
        if (!selected[i]) continue;
        const br_detector *d = registry[i];
        size_t len = 0;
        for (size_t at = 0; at < input.len; ++at) {
            bool hit = false;
            for (size_t k = 0; k < d->nkeywords; ++k) hit |= scalar_hit(input, at, d->keywords[k]);
            if (!hit) continue;
            uint64_t before = 512, after = 512;
            if (d->max_credential_span >= 0) before = after = (uint64_t)d->max_credential_span;
            if (d->max_secret_size >= 0) after = (uint64_t)d->max_secret_size;
            if (d->start_offset >= 0) before = (uint64_t)d->start_offset;
            br_span span = {before > at ? 0 : at - (size_t)before,
                           after > input.len - at ? input.len : at + (size_t)after};
            if (span.begin >= span.end) span.begin = 0;
            if (len && span.begin <= expected[len - 1].end) {
                if (span.end > expected[len - 1].end) expected[len - 1].end = span.end;
            } else expected[len++] = span;
        }
        CHECK(m < nmatch && matches[m].detector == d && !matches[m].pending);
        CHECK(matches[m].len == len);
        for (size_t w = 0; w < len; ++w)
            CHECK(matches[m].windows[w].begin == expected[w].begin && matches[m].windows[w].end == expected[w].end);
        matches[m++].pending = true; /* next find must clear overlap state */
    }
    CHECK(m == nmatch);
    free(expected);
}

static bool cancel(void *user) { ++*(size_t *)user; return true; }

int main(void)
{
    const br_detector *const *registry = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_registry(&registry, &count, &error) == 0 && count && !error);
    static const char *const words0[] = {"ab", "AB", "ABCDEF", "b", "abcdefghi"};
    static const char *const words1[] = {"bc", "def", "b", "x\xff", "\xff"};
    static const char *const words2[] = {"", "bc"};
    br_detector detectors[3] = {*registry[0], *registry[0], *registry[0]};
    detectors[0].keywords = words0; detectors[0].nkeywords = 5;
    detectors[1].keywords = words1; detectors[1].nkeywords = 5;
    detectors[2].keywords = words2; detectors[2].nkeywords = 2;
    const br_detector *small[] = {&detectors[0], &detectors[1], &detectors[2]};
    bool selected[] = {true, true, true};
    unsigned char input[4096];
    memset(input, '~', sizeof(input));
    static const unsigned char text[] = "aBcdefghi abcdef bb Abc x\xff\0ABC ab";
    memcpy(input, text, sizeof(text));
    memcpy(input + 1024, text, sizeof(text));
    memcpy(input + 1024 + 33, text, sizeof(text));
    memcpy(input + 3000, text, sizeof(text));
    static const int64_t overrides[] = {-1, 0, 1, 16, 512, INT64_MAX};
    /* Exercise each independent override, precedence, disjoint/adjacent windows
     * and backwards emission of different-length keywords at the same start. */
    for (size_t a = 0; a < 6; ++a) for (size_t b = 0; b < 6; ++b) for (size_t c = 0; c < 6; ++c) {
        for (size_t i = 0; i < 3; ++i) {
            detectors[i].max_secret_size = overrides[a];
            detectors[i].start_offset = overrides[b];
            detectors[i].max_credential_span = overrides[c];
        }
        selected[1] = b % 2 == 0;
        br_prefilter *filter = NULL;
        CHECK(br_prefilter_create(small, 3, selected, &filter, &error) == 0 && !error);
        compare(filter, small, 3, selected, (br_slice){input, sizeof(input)});
        compare(filter, small, 3, selected, (br_slice){NULL, 0});
        compare(filter, small, 3, selected, (br_slice){text, sizeof(text)});
        br_prefilter_destroy(filter);
    }
    /* Every compiled keyword, with ASCII case swaps, embedded zero/high bytes
     * and shared/versioned keywords. Verify exact registry order and windows. */
    bool *all = calloc(count, sizeof(*all));
    size_t bytes = 1;
    CHECK(all != NULL);
    for (size_t i = 0; i < count; ++i) {
        all[i] = true;
        for (size_t k = 0; k < registry[i]->nkeywords; ++k) bytes += strlen(registry[i]->keywords[k]) + 3;
    }
    unsigned char *data = malloc(bytes);
    CHECK(data != NULL);
    size_t n = 0;
    for (size_t i = 0; i < count; ++i) for (size_t k = 0; k < registry[i]->nkeywords; ++k) {
        const unsigned char *p = (const unsigned char *)registry[i]->keywords[k];
        for (; *p; ++p) data[n++] = *p >= 'a' && *p <= 'z' ? (unsigned char)(*p - ('a' - 'A')) : *p;
        data[n++] = 0; data[n++] = 0xff; data[n++] = '~';
    }
    br_prefilter *filter = NULL;
    CHECK(br_prefilter_create(registry, count, all, &filter, &error) == 0 && !error);
    compare(filter, registry, count, all, (br_slice){data, n});
    compare(filter, registry, count, all, (br_slice){input, sizeof(input)});
    br_detector_windows *matches = NULL;
    size_t nmatch = 0, calls = 0;
    br_scan_ctx ctx = {.cancelled = cancel, .cancel_user = &calls};
    CHECK(br_prefilter_find(filter, (br_slice){data, n}, &ctx, &matches, &nmatch, &error) != 0);
    CHECK(calls == 1 && error && !strcmp(error, "context canceled") && !matches && !nmatch);
    free(error); error = NULL;
    compare(filter, registry, count, all, (br_slice){data, n});
    br_prefilter_destroy(filter);
    free(data); free(all);
    CHECK(br_prefilter_create(NULL, 0, NULL, &filter, &error) == 0 && !error);
    compare(filter, NULL, 0, NULL, (br_slice){input, sizeof(input)});
    br_prefilter_destroy(filter);
    puts("prefilter preserves scalar keyword windows, selection, order and cancellation");
    printf("prefilter: %zu assertions, 0 failures\n", checks);
    return 0;
}
