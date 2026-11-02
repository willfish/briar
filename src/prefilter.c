/* SPDX-License-Identifier: AGPL-3.0-only */
#include "prefilter.h"

#include <stdlib.h>
#include <string.h>

/* A reversed Aho-Corasick DFA emits keyword START offsets in descending order,
 * independent of keyword length. Merge windows while walking backwards, then
 * reverse each detector's windows. This avoids storing/sorting every keyword
 * occurrence and preserves the old start-ordered window union exactly.
 *
 * Fold only ASCII, as the existing CLI did. Do not change byte offsets or turn
 * this optimization into a change to the partial Unicode prefilter contract. */
typedef struct {
    uint32_t failure, suffix, output;
} keyword_node;

typedef struct { uint32_t detector, next; } keyword_output;

struct br_prefilter {
    keyword_node *nodes;
    uint32_t *edges;
    uint16_t symbols[256];
    size_t stride;
    keyword_output *outputs;
    br_detector_windows *matches;
    size_t count;
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

static unsigned char fold(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}

void br_prefilter_destroy(br_prefilter *filter)
{
    if (!filter) return;
    for (size_t i = 0; i < filter->count; ++i) free(filter->matches[i].windows);
    free(filter->matches);
    free(filter->outputs);
    free(filter->nodes);
    free(filter->edges);
    free(filter);
}

int br_prefilter_create(const br_detector *const *registry, size_t count,
                        const bool *selected, br_prefilter **out, char **error)
{
    if (!out || (count && (!registry || !selected)))
        return fail(error, "invalid keyword prefilter arguments");
    *out = NULL;
    size_t max_nodes = 1, max_outputs = 1, enabled = 0;
    uint16_t symbols[256] = {0};
    for (size_t i = 0; i < count; ++i) {
        if (!selected[i]) continue;
        const br_detector *d = registry[i];
        if (!d || !d->scan || !d->keywords || !d->nkeywords ||
            d->max_secret_size < -1 || d->max_credential_span < -1 || d->start_offset < -1)
            return fail(error, "invalid or unsupported detector prefilter capability");
        if (++enabled >= UINT32_MAX || d->nkeywords > UINT32_MAX - max_outputs)
            return fail(error, "keyword prefilter is too large");
        max_outputs += d->nkeywords;
        for (size_t k = 0; k < d->nkeywords; ++k) {
            if (!d->keywords[k]) return fail(error, "invalid keyword prefilter keyword");
            size_t len = strlen(d->keywords[k]);
            if (len > UINT32_MAX - max_nodes) return fail(error, "keyword prefilter is too large");
            max_nodes += len;
            for (size_t p = 0; p < len; ++p) symbols[fold((unsigned char)d->keywords[k][p])] = 1;
        }
    }
    /* Bytes absent from every keyword share the zero/reset column. Folding
     * also belongs in this map, keeping the scan loop to two table lookups. */
    size_t stride = 1;
    for (size_t c = 0; c < 256; ++c) if (symbols[c]) symbols[c] = (uint16_t)stride++;
    for (size_t c = 0; c < 256; ++c) symbols[c] = symbols[fold((unsigned char)c)];
    if (max_nodes > SIZE_MAX / stride / sizeof(uint32_t) ||
        max_nodes > SIZE_MAX / sizeof(keyword_node) ||
        max_outputs > SIZE_MAX / sizeof(keyword_output) ||
        enabled > SIZE_MAX / sizeof(br_detector_windows))
        return fail(error, "keyword prefilter is too large");
    br_prefilter *filter = calloc(1, sizeof(*filter));
    if (!filter) return fail(error, "out of memory creating keyword prefilter");
    filter->stride = stride;
    memcpy(filter->symbols, symbols, sizeof(symbols));
    filter->nodes = calloc(max_nodes, sizeof(*filter->nodes));
    filter->edges = calloc(max_nodes * stride, sizeof(*filter->edges));
    filter->outputs = calloc(max_outputs, sizeof(*filter->outputs));
    filter->matches = calloc(enabled ? enabled : 1, sizeof(*filter->matches));
    if (!filter->nodes || !filter->edges || !filter->outputs || !filter->matches) {
        br_prefilter_destroy(filter);
        return fail(error, "out of memory creating keyword prefilter");
    }
    uint32_t nnodes = 1, noutputs = 1;
    for (size_t i = 0; i < count; ++i) {
        if (!selected[i]) continue;
        const br_detector *d = registry[i];
        uint32_t detector = (uint32_t)filter->count++;
        filter->matches[detector].detector = d;
        for (size_t k = 0; k < d->nkeywords; ++k) {
            const unsigned char *word = (const unsigned char *)d->keywords[k];
            uint32_t state = 0;
            for (size_t p = strlen(d->keywords[k]); p > 0; --p) {
                uint32_t *edge = &filter->edges[(size_t)state * stride + symbols[word[p - 1]]];
                if (!*edge) *edge = nnodes++;
                state = *edge;
            }
            filter->outputs[noutputs] = (keyword_output){detector, filter->nodes[state].output};
            filter->nodes[state].output = noutputs++;
        }
    }
    uint32_t *queue = malloc((size_t)nnodes * sizeof(*queue));
    if (!queue) {
        br_prefilter_destroy(filter);
        return fail(error, "out of memory linking keyword prefilter");
    }
    size_t head = 0, tail = 0;
    for (size_t c = 0; c < stride; ++c)
        if (filter->edges[c]) queue[tail++] = filter->edges[c];
    while (head < tail) {
        uint32_t index = queue[head++];
        uint32_t *edges = filter->edges + (size_t)index * stride;
        uint32_t *fallback = filter->edges + (size_t)filter->nodes[index].failure * stride;
        for (size_t c = 0; c < stride; ++c) {
            uint32_t child = edges[c];
            if (!child) { edges[c] = fallback[c]; continue; }
            keyword_node *target = &filter->nodes[child];
            target->failure = fallback[c];
            keyword_node *suffix = &filter->nodes[target->failure];
            target->suffix = suffix->output ? target->failure : suffix->suffix;
            queue[tail++] = child;
        }
    }
    free(queue);
    *out = filter;
    return 0;
}

static br_span keyword_span(const br_detector *detector, size_t at, size_t input_len)
{
    uint64_t before = 512, after = 512;
    /* Independent overrides, in pinned order. Zero is present; -1 is absent. */
    if (detector->max_credential_span >= 0) before = after = (uint64_t)detector->max_credential_span;
    if (detector->max_secret_size >= 0) after = (uint64_t)detector->max_secret_size;
    if (detector->start_offset >= 0) before = (uint64_t)detector->start_offset;
    br_span span = {
        before > at ? 0 : at - (size_t)before,
        after > input_len - at ? input_len : at + (size_t)after,
    };
    if (span.begin >= span.end) span.begin = 0;
    return span;
}

static int add_hit(br_detector_windows *match, size_t at, size_t input_len, char **error)
{
    br_span span = keyword_span(match->detector, at, input_len);
    if (match->len && span.end >= match->windows[match->len - 1].begin) {
        br_span *last = &match->windows[match->len - 1];
        if (span.begin < last->begin) last->begin = span.begin;
        if (span.end > last->end) last->end = span.end;
        return 0;
    }
    if (match->len == match->capacity) {
        if (match->capacity > SIZE_MAX / sizeof(*match->windows) / 2)
            return fail(error, "too many detector windows");
        size_t capacity = match->capacity ? match->capacity * 2 : 4;
        br_span *windows = realloc(match->windows, capacity * sizeof(*windows));
        if (!windows) return fail(error, "out of memory collecting detector windows");
        match->windows = windows;
        match->capacity = capacity;
    }
    match->windows[match->len++] = span;
    return 0;
}

static int emit(br_prefilter *filter, uint32_t output, size_t at, size_t len, char **error)
{
    for (; output; output = filter->outputs[output].next)
        if (add_hit(&filter->matches[filter->outputs[output].detector], at, len, error)) return 1;
    return 0;
}

int br_prefilter_find(br_prefilter *filter, br_slice input, const br_scan_ctx *ctx,
                      br_detector_windows **matches, size_t *count, char **error)
{
    if (!filter || !matches || !count || (input.len && !input.data))
        return fail(error, "invalid keyword prefilter arguments");
    *matches = NULL;
    *count = 0;
    for (size_t i = 0; i < filter->count; ++i) {
        filter->matches[i].len = 0;
        filter->matches[i].pending = false;
    }
    uint32_t state = 0;
    if (ctx && ctx->cancelled && ctx->cancelled(ctx->cancel_user)) return fail(error, "context canceled");
    for (size_t at = input.len; at > 0;) {
        --at;
        if (!(at & 4095) && ctx && ctx->cancelled && ctx->cancelled(ctx->cancel_user))
            return fail(error, "context canceled");
        state = filter->edges[(size_t)state * filter->stride + filter->symbols[input.data[at]]];
        uint32_t first = filter->nodes[state].output ? state : filter->nodes[state].suffix;
        for (uint32_t s = first; s; s = filter->nodes[s].suffix)
            if (emit(filter, filter->nodes[s].output, at, input.len, error)) return 1;
        /* Empty keywords match each byte position, but not the end of input. */
        if (filter->nodes[0].output && emit(filter, filter->nodes[0].output, at, input.len, error)) return 1;
    }
    for (size_t i = 0; i < filter->count; ++i) {
        br_detector_windows *match = &filter->matches[i];
        for (size_t a = 0, b = match->len; a < b && a < --b; ++a) {
            br_span tmp = match->windows[a];
            match->windows[a] = match->windows[b];
            match->windows[b] = tmp;
        }
    }
    *matches = filter->matches;
    *count = filter->count;
    return 0;
}
