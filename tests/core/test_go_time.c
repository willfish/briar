/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/go_time.h"
#include "../support/detector_test.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static bool fail_malloc, fail_calloc, positive_once;
static void *watched_malloc(size_t n) { return fail_malloc ? NULL : malloc(n); }
static void *watched_calloc(size_t n, size_t size) { return fail_calloc ? NULL : calloc(n, size); }
static int watched_once(pthread_once_t *once, void (*initialize)(void))
{
    return positive_once ? 1 : pthread_once(once, initialize);
}
#define br_go_time_unix_string observed_time_string
#define malloc watched_malloc
#define calloc watched_calloc
#define pthread_once watched_once
#include "../../src/go_time.c"
#undef pthread_once
#undef calloc
#undef malloc
#undef br_go_time_unix_string

static void expected(int64_t seconds, const unsigned char *text, size_t len)
{
    br_bytes out = {0}; char *error = NULL;
    CHECK(br_go_time_unix_string(seconds, &out, &error) == 0 && !error);
    CHECK(out.data && out.len == len && !memcmp(out.data, text, len));
    CHECK(out.data && out.data[out.len] == 0);
    free(out.data); free(error);
}
#define EXPECT(sec, text) expected((sec), (const unsigned char *)(text), sizeof(text) - 1)

static void be32(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24); out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8); out[3] = (unsigned char)value;
}
static void le16(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)value; out[1] = (unsigned char)(value >> 8);
}
static void le32(unsigned char *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) out[i] = (unsigned char)(value >> (8 * i));
}
static size_t zone_bytes(unsigned char *out, unsigned version, int32_t offset_value,
                         const char *name, br_slice tail)
{
    size_t n = 0, chars = strlen(name) + 1;
    for (unsigned i = 0; i < (version ? 2u : 1u); ++i) {
        memset(out + n, 0, 44); memcpy(out + n, "TZif", 4); out[n + 4] = (unsigned char)version;
        be32(out + n + 36, 1); be32(out + n + 40, (uint32_t)chars); n += 44;
        be32(out + n, (uint32_t)offset_value); out[n + 4] = out[n + 5] = 0; n += 6;
        memcpy(out + n, name, chars); n += chars;
    }
    if (tail.data) {
        out[n++] = '\n'; memcpy(out + n, tail.data, tail.len); n += tail.len; out[n++] = '\n';
    }
    return n;
}
static void file_bytes(const char *path, const void *bytes, size_t len)
{
    FILE *file = fopen(path, "wb"); CHECK(file != NULL);
    if (file) { CHECK(fwrite(bytes, 1, len, file) == len); CHECK(fclose(file) == 0); }
}
static void write_zone(const char *path, unsigned version, int32_t off, const char *name, br_slice tail)
{
    unsigned char bytes[1024]; size_t n = zone_bytes(bytes, version, off, name, tail); CHECK(n <= sizeof(bytes));
    file_bytes(path, bytes, n);
}
static void stored_zip(const char *path, const char *name)
{
    unsigned char data[256], zip[2048]; size_t size = zone_bytes(data, 0, 7200, "ZIP", (br_slice){0});
    size_t len = strlen(name), central = 30 + len + size, end = central + 46 + len;
    memset(zip, 0, sizeof(zip)); le32(zip, UINT32_C(0x04034b50));
    le32(zip + 18, (uint32_t)size); le32(zip + 22, (uint32_t)size); le16(zip + 26, (unsigned)len);
    memcpy(zip + 30, name, len); memcpy(zip + 30 + len, data, size);
    le32(zip + central, UINT32_C(0x02014b50)); le32(zip + central + 20, (uint32_t)size);
    le32(zip + central + 24, (uint32_t)size); le16(zip + central + 28, (unsigned)len);
    memcpy(zip + central + 46, name, len);
    le32(zip + end, UINT32_C(0x06054b50)); le16(zip + end + 8, 1); le16(zip + end + 10, 1);
    le32(zip + end + 12, (uint32_t)(46 + len)); le32(zip + end + 16, (uint32_t)central);
    CHECK(end + 22 <= sizeof(zip)); file_bytes(path, zip, end + 22);
}
static const char *self;
static void child(const char *tz, const char *goroot, const char *mode, const char *directory)
{
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        if (tz) { if (setenv("TZ", tz, 1)) _exit(120); }
        else if (unsetenv("TZ")) _exit(120);
        if (goroot) { if (setenv("GOROOT", goroot, 1)) _exit(120); }
        else if (unsetenv("GOROOT")) _exit(120);
        execl(self, self, "child", mode, directory, (char *)NULL); _exit(121);
    }
    if (pid > 0) { int status = 0; CHECK(waitpid(pid, &status, 0) == pid); CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0); }
}
static int child_checks(const char *mode, const char *directory)
{
    if (!strcmp(mode, "utc")) {
        EXPECT(0, "1970-01-01 00:00:00 +0000 UTC"); EXPECT(-1, "1969-12-31 23:59:59 +0000 UTC");
        EXPECT(INT64_MIN, "292277026596-12-04 15:30:08 +0000 UTC");
        EXPECT(INT64_MAX, "292277026596-12-04 15:30:07 +0000 UTC");
        EXPECT(INT64_C(-62135596800), "0001-01-01 00:00:00 +0000 UTC");
        EXPECT(INT64_C(-62167219200), "0000-01-01 00:00:00 +0000 UTC");
        EXPECT(INT64_C(-62198755200), "-0001-01-01 00:00:00 +0000 UTC");
        EXPECT(INT64_C(253402300799), "9999-12-31 23:59:59 +0000 UTC");
        EXPECT(INT64_C(253402300800), "10000-01-01 00:00:00 +0000 UTC");
        EXPECT(INT64_C(951782400), "2000-02-29 00:00:00 +0000 UTC");
    } else if (!strcmp(mode, "fixed")) EXPECT(0, "1970-01-01 00:01:15 +0001 FIX");
    else if (!strcmp(mode, "negative")) EXPECT(0, "1969-12-31 23:59:59 +0000 +0000");
    else if (!strcmp(mode, "binary")) EXPECT(0, "1970-01-01 00:00:00 +0000 \xff");
    else if (!strcmp(mode, "nul")) EXPECT(0, "1970-01-01 00:00:00 +0000 A\0B");
    else if (!strcmp(mode, "summer")) {
        EXPECT(INT64_C(1719792000), "2024-07-01 01:00:00 +0100 DST");
        EXPECT(INT64_C(1735689600), "2025-01-01 00:00:00 +0000 STD");
    } else if (!strcmp(mode, "south")) {
        EXPECT(INT64_C(1719792000), "2024-07-01 10:00:00 +1000 STD");
        EXPECT(INT64_C(1735689600), "2025-01-01 11:00:00 +1100 DST");
    } else if (!strcmp(mode, "once")) {
        EXPECT(0, "1970-01-01 00:01:15 +0001 FIX"); CHECK(setenv("TZ", "UTC", 1) == 0);
        char path[512]; CHECK(snprintf(path, sizeof(path), "%s/fixed", directory) > 0);
        write_zone(path, 0, 3600, "NEW", (br_slice){0});
        EXPECT(1, "1970-01-01 00:01:16 +0001 FIX");
    } else if (!strcmp(mode, "zip")) {
        CHECK(setenv("GOROOT", "/nonexistent-after-start", 1) == 0);
        EXPECT(0, "1970-01-01 02:00:00 +0200 ZIP");
    } else if (!strcmp(mode, "late-goroot")) {
        CHECK(setenv("GOROOT", directory, 1) == 0); EXPECT(0, "1970-01-01 00:00:00 +0000 UTC");
    } else if (!strcmp(mode, "init-failure")) {
        br_bytes out = {0}; char *error = NULL; fail_calloc = true;
        CHECK(observed_time_string(0, &out, &error) != 0 && error && !out.data && !out.len);
        free(error); error = NULL; fail_calloc = false;
        CHECK(observed_time_string(0, &out, &error) != 0 && error && !out.data && !out.len);
        free(error);
    } else if (!strcmp(mode, "format-failure")) {
        br_bytes out = {0}; char *error = NULL; fail_malloc = true;
        CHECK(observed_time_string(0, &out, &error) != 0 && error && !out.data && !out.len);
        free(error); error = NULL; fail_malloc = false;
        CHECK(observed_time_string(0, &out, &error) == 0 && !error && out.len == 29);
        free(out.data);
        positive_once = true; out = (br_bytes){0};
        CHECK(observed_time_string(0, &out, &error) != 0 && error && !out.data && !out.len);
        free(error);
    } else CHECK(false);
    return test_finish("Go time isolated profile");
}
int main(int argc, char **argv)
{
    self = argv[0];
    if (argc == 4 && !strcmp(argv[1], "child")) return child_checks(argv[2], argv[3]);
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            char *end = NULL; errno = 0; intmax_t sec = strtoimax(argv[i], &end, 10);
            if (errno || !end || *end || sec < INT64_MIN || sec > INT64_MAX) return 2;
            br_bytes out = {0}; char *error = NULL;
            if (br_go_time_unix_string((int64_t)sec, &out, &error) != 0) { free(error); return 3; }
            for (size_t j = 0; j < out.len; ++j) printf("%02x", out.data[j]);
            putchar('\n'); free(out.data);
        }
        return 0;
    }
    char directory[] = "/tmp/briar-go-time-XXXXXX"; CHECK(mkdtemp(directory));
    char fixed[512], negative[512], binary[512], nul[512], summer[512], south[512], defaults[512], bad[512], lib[512], times[512], zip[512];
    const char *names[] = {"fixed", "negative", "binary", "nul", "summer", "south", "defaults", "bad", "lib", "lib/time", "lib/time/zoneinfo.zip"};
    char *paths[] = {fixed, negative, binary, nul, summer, south, defaults, bad, lib, times, zip};
    for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); ++i) CHECK(snprintf(paths[i], 512, "%s/%s", directory, names[i]) > 0);
    write_zone(fixed, 0, 75, "FIX", (br_slice){0}); write_zone(negative, 0, -1, "", (br_slice){0});
    write_zone(binary, '2', 0, "\xff", (br_slice){0});
    static const unsigned char nul_tail[] = {'<', 'A', 0, 'B', '>', '0'};
    write_zone(nul, 0, 0, "OLD", (br_slice){nul_tail, sizeof(nul_tail)});
    const char *north_tail = "STD0DST,M3.2.0,M11.1.0", *south_tail = "STD-10DST-11,M10.1.0,M4.1.0";
    write_zone(summer, '2', 0, "OLD", (br_slice){(const unsigned char *)north_tail, strlen(north_tail)});
    write_zone(south, '3', 0, "OLD", (br_slice){(const unsigned char *)south_tail, strlen(south_tail)});
    write_zone(defaults, 0, 0, "OLD", (br_slice){(const unsigned char *)"STD0DST", 7});
    file_bytes(bad, "not TZif", 8);
    CHECK(mkdir(lib, 0700) == 0 && mkdir(times, 0700) == 0); stored_zip(zip, "briar-only");
    child("UTC", NULL, "utc", directory); child("", NULL, "utc", directory); child(":", NULL, "utc", directory);
    child(fixed, NULL, "fixed", directory);
    char colon[520]; CHECK(snprintf(colon, sizeof(colon), ":%s", fixed) > 0); child(colon, NULL, "fixed", directory);
    child(negative, NULL, "negative", directory); child(binary, NULL, "binary", directory); child(nul, NULL, "nul", directory);
    child(summer, NULL, "summer", directory); child(defaults, NULL, "summer", directory); child(south, NULL, "south", directory);
    child(bad, NULL, "utc", directory); child("briar-only", directory, "zip", directory);
    child("briar-only", NULL, "late-goroot", directory);
    child(fixed, NULL, "init-failure", directory); child("UTC", NULL, "format-failure", directory);
    child(fixed, NULL, "once", directory);
    for (size_t i = 0; i < 8; ++i) CHECK(unlink(paths[i]) == 0);
    CHECK(unlink(zip) == 0 && rmdir(times) == 0 && rmdir(lib) == 0 && rmdir(directory) == 0);
    char *error = NULL; CHECK(br_go_time_unix_string(0, NULL, &error) != 0 && error); free(error);
    return test_finish("Pinned Go Unix-second calendar/Local/TZif/POSIX/ZIP/initial environment/owned failure");
}
