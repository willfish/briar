/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/endpoint_customizer.go. */
#include "endpoints.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

int br_endpoint_list_push(br_endpoint_list *list, const char *item, bool unique, char **error)
{
    if (error) *error = NULL;
    if (!list || !item) return fail(error, "invalid endpoint string");
    if (unique) {
        for (size_t i = 0; i < list->len; ++i)
            if (!strcmp(list->items[i], item)) return 0;
    }
    char *copy = strdup(item);
    if (!copy) return fail(error, "out of memory copying endpoint");
    if (list->len == list->cap) {
        if (list->cap > SIZE_MAX / sizeof(*list->items) / 2) {
            free(copy);
            return fail(error, "too many endpoints");
        }
        size_t next = list->cap ? list->cap * 2 : 8;
        char **items = realloc(list->items, next * sizeof(*items));
        if (!items) {
            free(copy);
            return fail(error, "out of memory collecting endpoints");
        }
        list->items = items;
        list->cap = next;
    }
    list->items[list->len++] = copy;
    return 0;
}

void br_endpoint_list_clear(br_endpoint_list *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->len; ++i) free(list->items[i]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

int br_endpoints_collect(const br_endpoints *settings, const char *default_cloud,
                        const br_captures *found, br_endpoint_list *out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid endpoint output");
    if (settings && settings->nconfigured && !settings->configured) {
        br_endpoint_list_clear(out);
        return fail(error, "invalid configured endpoints");
    }
    int rc = 0;
    if (settings) {
        for (size_t i = 0; !rc && i < settings->nconfigured; ++i)
            rc = br_endpoint_list_push(out, settings->configured[i], true, error);
    }
    const char *cloud = settings && settings->cloud ? settings->cloud : default_cloud;
    if (!rc && (!settings || settings->use_cloud) && cloud && *cloud)
        rc = br_endpoint_list_push(out, cloud, false, error);
    if (!rc && (!settings || settings->use_found) && found) {
        for (size_t i = 0; !rc && i < found->len; ++i)
            rc = br_endpoint_list_push(out, found->items[i], false, error);
    }
    if (rc) br_endpoint_list_clear(out);
    return rc;
}

int br_byte_endpoints_push(br_byte_endpoints *list, br_slice item, bool unique, char **error)
{
    if (error) *error = NULL;
    if (!list || (!item.data && item.len) || item.len == SIZE_MAX)
        return fail(error, "invalid endpoint bytes");
    if (unique) {
        for (size_t i = 0; i < list->len; ++i)
            if (list->items[i].len == item.len &&
                (!item.len || !memcmp(list->items[i].data, item.data, item.len))) return 0;
    }
    unsigned char *copy = malloc(item.len + 1);
    if (!copy) return fail(error, "out of memory copying byte endpoint");
    if (item.len) memcpy(copy, item.data, item.len);
    copy[item.len] = 0;
    if (list->len == list->cap) {
        if (list->cap > SIZE_MAX / sizeof(*list->items) / 2) {
            free(copy);
            return fail(error, "too many byte endpoints");
        }
        size_t next = list->cap ? list->cap * 2 : 8;
        br_bytes *items = realloc(list->items, next * sizeof(*items));
        if (!items) {
            free(copy);
            return fail(error, "out of memory collecting byte endpoints");
        }
        list->items = items;
        list->cap = next;
    }
    list->items[list->len++] = (br_bytes){copy, item.len};
    return 0;
}

void br_byte_endpoints_clear(br_byte_endpoints *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->len; ++i) free(list->items[i].data);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

br_slice br_byte_endpoints_at(const br_byte_endpoints *list, size_t index)
{
    if (!list || index >= list->len) return (br_slice){0};
    return (br_slice){list->items[index].data, list->items[index].len};
}

int br_endpoints_collect_bytes(const br_endpoints *settings, const char *default_cloud,
                              const br_captures *found, br_byte_endpoints *out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid endpoint output");
    if (settings && settings->nconfigured && !settings->configured) {
        br_byte_endpoints_clear(out);
        return fail(error, "invalid configured endpoints");
    }
    int rc = 0;
    if (settings) {
        for (size_t i = 0; !rc && i < settings->nconfigured; ++i) {
            const char *item = settings->configured[i];
            rc = !item ? fail(error, "invalid endpoint string") :
                br_byte_endpoints_push(out, (br_slice){(const unsigned char *)item, strlen(item)}, true, error);
        }
    }
    const char *cloud = settings && settings->cloud ? settings->cloud : default_cloud;
    if (!rc && (!settings || settings->use_cloud) && cloud && *cloud)
        rc = br_byte_endpoints_push(out, (br_slice){(const unsigned char *)cloud, strlen(cloud)}, false, error);
    if (!rc && (!settings || settings->use_found) && found) {
        for (size_t i = 0; !rc && i < found->len; ++i)
            rc = br_byte_endpoints_push(out, br_captures_at(found, i), false, error);
    }
    if (rc) br_byte_endpoints_clear(out);
    return rc;
}

int br_endpoints_validate_configured(const br_endpoints *settings, char **error)
{
    if (error) *error = NULL;
    if (!settings || !settings->nconfigured) return fail(error, "at least one endpoint required");
    if (!settings->configured) return fail(error, "invalid configured endpoints");
    for (size_t i = 0; i < settings->nconfigured; ++i)
        if (!settings->configured[i]) return fail(error, "invalid endpoint string");
    return 0;
}
