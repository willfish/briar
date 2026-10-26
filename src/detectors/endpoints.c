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
        size_t next = list->cap ? list->cap * 2 : 8;
        if (next < list->cap || next > SIZE_MAX / sizeof(*list->items)) {
            free(copy);
            return fail(error, "too many endpoints");
        }
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

int br_endpoints_validate_configured(const br_endpoints *settings, char **error)
{
    if (error) *error = NULL;
    if (!settings || !settings->nconfigured) return fail(error, "at least one endpoint required");
    if (!settings->configured) return fail(error, "invalid configured endpoints");
    for (size_t i = 0; i < settings->nconfigured; ++i)
        if (!settings->configured[i]) return fail(error, "invalid endpoint string");
    return 0;
}
