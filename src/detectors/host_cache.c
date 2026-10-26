/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/cache/simple. */
#include "host_cache.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct br_host_cache_entry {
    int64_t expires_ns;
    struct br_host_cache_entry *next;
    char host[];
};
static const int64_t host_ttl_ns = 12LL * 60 * 60 * 1000000000;

static int wall_clock_ns(int64_t *out)
{
    struct timespec now;
    if (timespec_get(&now, TIME_UTC) != TIME_UTC || now.tv_sec < 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000 ||
        (uint64_t)now.tv_sec > (uint64_t)(INT64_MAX - host_ttl_ns) / 1000000000)
        return -1;
    int64_t seconds_ns = (int64_t)now.tv_sec * 1000000000;
    if (now.tv_nsec > INT64_MAX - host_ttl_ns - seconds_ns) return -1;
    *out = seconds_ns + now.tv_nsec;
    return 0;
}

static void lock_cache(br_host_cache *cache)
{
    while (atomic_flag_test_and_set_explicit(&cache->lock, memory_order_acquire)) { }
}
static void unlock_cache(br_host_cache *cache)
{
    atomic_flag_clear_explicit(&cache->lock, memory_order_release);
}

int br_host_cache_contains(br_host_cache *cache, const char *host, bool *found)
{
    if (found) *found = false;
    int64_t now;
    if (!cache || !host || !found || wall_clock_ns(&now) != 0) return -1;
    lock_cache(cache);
    br_host_cache_entry **link = &cache->entries;
    while (*link) {
        br_host_cache_entry *entry = *link;
        if (now > entry->expires_ns) {
            *link = entry->next;
            free(entry);
        } else {
            if (!strcmp(entry->host, host)) *found = true;
            link = &entry->next;
        }
    }
    unlock_cache(cache);
    return 0;
}

int br_host_cache_add(br_host_cache *cache, const char *host)
{
    int64_t now;
    if (!cache || !host || wall_clock_ns(&now) != 0) return -1;
    size_t len = strlen(host);
    if (len > SIZE_MAX - sizeof(br_host_cache_entry) - 1) return -1;
    lock_cache(cache);
    for (br_host_cache_entry *entry = cache->entries; entry; entry = entry->next) {
        if (!strcmp(entry->host, host)) {
            entry->expires_ns = now + host_ttl_ns;
            unlock_cache(cache);
            return 0;
        }
    }
    br_host_cache_entry *entry = malloc(sizeof(*entry) + len + 1);
    if (!entry) { unlock_cache(cache); return -1; }
    memcpy(entry->host, host, len + 1);
    entry->expires_ns = now + host_ttl_ns;
    entry->next = cache->entries;
    cache->entries = entry;
    unlock_cache(cache);
    return 0;
}
