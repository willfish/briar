/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/host_cache.h"
#include "../support/detector_test.h"
#include <time.h>

static int64_t now_ns = 1700000000000000000LL;
static bool clock_failed;
int timespec_get(struct timespec *time, int base)
{
    if (base != TIME_UTC || clock_failed) return 0;
    time->tv_sec = (time_t)(now_ns / 1000000000);
    time->tv_nsec = (long)(now_ns % 1000000000);
    return TIME_UTC;
}

int main(void)
{
    static br_host_cache first = BR_HOST_CACHE_INIT, second = BR_HOST_CACHE_INIT;
    char host[73], upper[73];
    memset(host, 'a', 63);
    memcpy(host + 63, ".jfrog.io", 10);
    strcpy(upper, host);
    upper[0] = 'A';
    bool found = true;
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && !found);
    CHECK(br_host_cache_add(&first, host) == 0);
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && found);
    CHECK(br_host_cache_contains(&second, host, &found) == 0 && !found);
    CHECK(br_host_cache_contains(&first, upper, &found) == 0 && !found);
    host[0] = 'X'; /* Cache owns the original key, beyond Algolia's ten-byte IDs. */
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && !found);
    host[0] = 'a';
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && found);
    CHECK(br_host_cache_add(&first, "") == 0);
    CHECK(br_host_cache_contains(&first, "", &found) == 0 && found);
    CHECK(br_host_cache_contains(&second, "", &found) == 0 && !found);

    const int64_t ttl = 12LL * 60 * 60 * 1000000000;
    const int64_t initial = now_ns;
    now_ns += 5;
    CHECK(br_host_cache_add(&first, host) == 0); /* Refresh, not a second entry. */
    now_ns = initial + ttl;
    CHECK(br_host_cache_contains(&first, "", &found) == 0 && found);
    ++now_ns;
    CHECK(br_host_cache_contains(&first, "", &found) == 0 && !found);
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && found);
    now_ns = initial + ttl + 5;
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && found);
    ++now_ns;
    CHECK(br_host_cache_contains(&first, host, &found) == 0 && !found);
    bool value = true;
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == 0 && !found && !value);
    CHECK(br_host_cache_set_bool(&second, "tenant", false) == 0);
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == 0 && found && !value);
    CHECK(br_host_cache_contains(&second, "tenant", &found) == 0 && found);
    CHECK(br_host_cache_get_bool(&first, "tenant", &value, &found) == 0 && !found);
    CHECK(br_host_cache_get_bool(&second, "Tenant", &value, &found) == 0 && !found);
    CHECK(br_host_cache_add(&second, "tenant") == 0);
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == 0 && found && value);
    now_ns += 5;
    const int64_t boolean_start = now_ns;
    CHECK(br_host_cache_set_bool(&second, "tenant", false) == 0);
    now_ns = boolean_start + ttl;
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == 0 && found && !value);
    ++now_ns;
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == 0 && !found && !value);
    CHECK(br_host_cache_set_bool(&second, "", false) == 0);
    CHECK(br_host_cache_get_bool(&second, "", &value, &found) == 0 && found && !value);
    clock_failed = true;
    value = found = true;
    CHECK(br_host_cache_get_bool(&second, "tenant", &value, &found) == -1 && !found && !value);
    CHECK(br_host_cache_set_bool(&second, "tenant", false) == -1);
    CHECK(br_host_cache_add(&first, host) == -1);
    found = true;
    CHECK(br_host_cache_contains(&first, host, &found) == -1 && !found);
    return test_finish("Independent twelve-hour host caches");
}
