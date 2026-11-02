/* SPDX-License-Identifier: AGPL-3.0-only */
#include "captures.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    br_slice input;
    br_captures *values;
    bool unique;
    char *error;
} capture_context;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

void br_captures_clear(br_captures *values)
{
    for (size_t i = 0; i < values->len; ++i) free(values->items[i]);
    free(values->items);
    free(values->lengths);
    memset(values, 0, sizeof(*values));
}

br_slice br_captures_at(const br_captures *values, size_t index)
{
    return (br_slice){(const unsigned char *)values->items[index], values->lengths[index]};
}

int br_captures_push(br_captures *values, br_slice value, bool unique, char **error)
{
    if (!value.data || !value.len || value.len == SIZE_MAX)
        return fail(error, "invalid detector capture");
    if (unique) {
        for (size_t i = 0; i < values->len; ++i)
            if (values->lengths[i] == value.len &&
                !memcmp(values->items[i], value.data, value.len)) return 0;
    }
    if (values->len == values->cap) {
        if (values->cap > SIZE_MAX / sizeof(*values->items) / 2 ||
            values->cap > SIZE_MAX / sizeof(*values->lengths) / 2)
            return fail(error, "too many detector captures");
        size_t cap = values->cap ? values->cap * 2 : 8;
        char **items = malloc(cap * sizeof(*items));
        size_t *lengths = malloc(cap * sizeof(*lengths));
        if (!items || !lengths) {
            free(items);
            free(lengths);
            return fail(error, "out of memory collecting detector captures");
        }
        if (values->len) {
            memcpy(items, values->items, values->len * sizeof(*items));
            memcpy(lengths, values->lengths, values->len * sizeof(*lengths));
        }
        free(values->items);
        free(values->lengths);
        values->items = items;
        values->lengths = lengths;
        values->cap = cap;
    }
    char *copy = malloc(value.len + 1);
    if (!copy) return fail(error, "out of memory copying detector capture");
    memcpy(copy, value.data, value.len);
    copy[value.len] = '\0';
    values->items[values->len] = copy;
    values->lengths[values->len++] = value.len;
    return 0;
}

static int collect(void *user, const br_span *groups, size_t ngroups)
{
    capture_context *context = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > context->input.len)
        return fail(&context->error, "invalid detector capture");
    br_slice value = {context->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    return br_captures_push(context->values, value, context->unique, &context->error);
}

int br_captures_find(const br_regex *regex, br_slice input, br_captures *values,
                      bool unique, char **error)
{
    capture_context context = {input, values, unique, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(regex, input, collect, &context, &regex_error);
    if (context.error) {
        free(regex_error);
        regex_error = context.error;
    }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}
