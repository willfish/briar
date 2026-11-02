/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected Go1.26.7 time calendar, fixed String layout and Unix Local loader.
 * Copyright 2009, 2011, 2012, 2022 The Go Authors. BSD-3-Clause-Go.txt applies.
 * The first zone source is the exact reference compiler's Nix tzdata patch. */
#include "go_time.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define UNIX_ABSOLUTE UINT64_C(9223372028741760000)
#define ABSOLUTE_YEARS UINT64_C(292277022400)
#define DAY INT64_C(86400)

typedef struct { br_slice name; int64_t offset; bool dst; } zone;
typedef struct { int64_t when; unsigned char index; } transition;
typedef struct {
    br_bytes blob;
    zone *zones;
    size_t nzones;
    transition *tx;
    size_t ntx;
    br_slice extend;
    bool cached;
    int64_t cache_start, cache_end;
    zone cache_zone;
} location;
typedef struct { zone value; int64_t start, end; } lookup;
typedef struct { int64_t year; int month, day, yday; } calendar;
typedef struct { br_slice bytes; bool bad; } reader;
typedef struct { unsigned char *data; size_t len; bool overflow; } writer;
typedef struct { int kind, day, week, month, seconds; } rule;

static location local;
static pthread_once_t local_once = PTHREAD_ONCE_INIT;
static char *initial_goroot;
static bool goroot_failed;
static const char *local_failure;

/* runtime.GOROOT consults runtime's INITIAL copied environment. In contrast,
 * syscall.Getenv("TZ") is deliberately deferred until the first Local lookup. */
static void capture_goroot(void) __attribute__((constructor));
static void capture_goroot(void)
{
    const char *value = getenv("GOROOT");
    if (value && *value && !(initial_goroot = strdup(value))) goroot_failed = true;
}

static int problem(const char **why, const char *message)
{
    if (why) *why = message;
    return -1;
}
static int fail(char **fatal, const char *message)
{
    if (fatal) *fatal = strdup(message);
    return -1;
}
static int64_t signed_bits(uint64_t value)
{
    int64_t out; memcpy(&out, &value, sizeof(out)); return out;
}
static int64_t add64(int64_t a, int64_t b)
{
    return signed_bits((uint64_t)a + (uint64_t)b);
}
static br_slice cut(br_slice s, size_t start, size_t len)
{
    return (br_slice){s.data ? s.data + start : NULL, len};
}
static calendar civil(uint64_t absolute)
{
    uint64_t d = 4 * (absolute / (uint64_t)DAY) + 3;
    uint64_t century = d / 146097;
    uint32_t cd = (uint32_t)(d % 146097) | 3;
    uint64_t product = UINT64_C(2939745) * cd;
    unsigned cyear = (unsigned)(product >> 32);
    unsigned ayday = (uint32_t)product / 2939745 / 4;
    unsigned month_day = 2141 * ayday + 197913;
    unsigned jf = ayday >= 306;
    unsigned leap = (cyear % 4 == 0) && (cyear != 0 || century % 4 == 0);
    return (calendar){
        .year = add64(signed_bits(century * 100 - ABSOLUTE_YEARS), (int64_t)(cyear + jf)),
        .month = (int)(month_day >> 16) - 12 * (int)jf,
        .day = 1 + (int)((month_day & 65535) / 2141),
        .yday = (int)ayday + 60 + (int)(leap & ~jf) - 365 * (int)jf,
    };
}
static bool leap_year(int64_t year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}
static int days_before(int month)
{
    return (214 * month - 211) / 7 + (month >= 3 ? -2 : 0);
}
static int month_days(int month, int64_t year)
{
    if (month == 2) return leap_year(year) ? 29 : 28;
    return 30 + ((month + (month >> 3)) & 1);
}

static bool number(br_slice *s, int minimum, int maximum, int *value)
{
    int n = 0; size_t i = 0;
    while (i < s->len && s->data[i] >= '0' && s->data[i] <= '9') {
        n = 10 * n + s->data[i++] - '0';
        if (n > maximum) return false;
    }
    if (!i || n < minimum) return false;
    *s = cut(*s, i, s->len - i); *value = n; return true;
}
static bool zone_name(br_slice *s, br_slice *name)
{
    if (!s->len) return false;
    if (s->data[0] == '<') {
        for (size_t i = 1; i < s->len; ++i) if (s->data[i] == '>') {
            *name = cut(*s, 1, i - 1); *s = cut(*s, i + 1, s->len - i - 1); return true;
        }
        return false;
    }
    size_t i = 0;
    for (; i < s->len; ++i) {
        unsigned char c = s->data[i];
        if ((c >= '0' && c <= '9') || c == ',' || c == '-' || c == '+') break;
    }
    if (i < 3) return false;
    *name = cut(*s, 0, i); *s = cut(*s, i, s->len - i); return true;
}
static bool offset(br_slice *s, int *value)
{
    if (!s->len) return false;
    bool negative = s->data[0] == '-';
    if (negative || s->data[0] == '+') *s = cut(*s, 1, s->len - 1);
    int hours, minutes = 0, seconds = 0;
    if (!number(s, 0, 168, &hours)) return false;
    if (s->len && s->data[0] == ':') {
        *s = cut(*s, 1, s->len - 1);
        if (!number(s, 0, 59, &minutes)) return false;
        if (s->len && s->data[0] == ':') {
            *s = cut(*s, 1, s->len - 1);
            if (!number(s, 0, 59, &seconds)) return false;
        }
    }
    *value = (hours * 3600 + minutes * 60 + seconds) * (negative ? -1 : 1);
    return true;
}
static bool read_rule(br_slice *s, rule *out)
{
    *out = (rule){.seconds = 7200};
    if (!s->len) return false;
    if (s->data[0] == 'J') {
        *s = cut(*s, 1, s->len - 1); out->kind = 0;
        if (!number(s, 1, 365, &out->day)) return false;
    } else if (s->data[0] == 'M') {
        *s = cut(*s, 1, s->len - 1); out->kind = 2;
        if (!number(s, 1, 12, &out->month) || !s->len || s->data[0] != '.') return false;
        *s = cut(*s, 1, s->len - 1);
        if (!number(s, 1, 5, &out->week) || !s->len || s->data[0] != '.') return false;
        *s = cut(*s, 1, s->len - 1);
        if (!number(s, 0, 6, &out->day)) return false;
    } else {
        out->kind = 1;
        if (!number(s, 0, 365, &out->day)) return false;
    }
    if (s->len && s->data[0] == '/') {
        *s = cut(*s, 1, s->len - 1);
        if (!offset(s, &out->seconds)) return false;
    }
    return true;
}
static int64_t rule_seconds(int64_t year, rule r, int64_t off)
{
    int64_t seconds;
    if (r.kind == 0) seconds = (r.day - 1 + (leap_year(year) && r.day >= 60)) * DAY;
    else if (r.kind == 1) seconds = r.day * DAY;
    else {
        int m1 = (r.month + 9) % 12 + 1;
        int64_t y0 = year - (r.month <= 2), y1 = y0 / 100, y2 = y0 % 100;
        int dow = (int)(((26 * m1 - 2) / 10 + 1 + y2 + y2 / 4 + y1 / 4 - 2 * y1) % 7);
        if (dow < 0) dow += 7;
        int day = r.day - dow;
        if (day < 0) day += 7;
        for (int i = 1; i < r.week && day + 7 < month_days(r.month, year); ++i) day += 7;
        day += days_before(r.month) + (leap_year(year) && r.month > 2);
        seconds = day * DAY;
    }
    return seconds + r.seconds - off;
}
static bool extended(br_slice s, int64_t last, int64_t sec, lookup *out)
{
    zone standard = {0}, daylight = {.dst = true}; int parsed;
    if (!zone_name(&s, &standard.name) || !offset(&s, &parsed)) return false;
    standard.offset = -(int64_t)parsed;
    if (!s.len || s.data[0] == ',') {
        *out = (lookup){standard, last, INT64_MAX}; return true;
    }
    if (!zone_name(&s, &daylight.name)) return false;
    if (!s.len || s.data[0] == ',') daylight.offset = standard.offset + 3600;
    else { if (!offset(&s, &parsed)) return false; daylight.offset = -(int64_t)parsed; }
    static const unsigned char default_rules[] = ",M3.2.0,M11.1.0";
    if (!s.len) s = (br_slice){default_rules, sizeof(default_rules) - 1};
    if (s.data[0] != ',' && s.data[0] != ';') return false;
    s = cut(s, 1, s.len - 1); rule start_rule, end_rule;
    if (!read_rule(&s, &start_rule) || !s.len || s.data[0] != ',') return false;
    s = cut(s, 1, s.len - 1);
    if (!read_rule(&s, &end_rule) || s.len) return false;
    calendar c = civil((uint64_t)sec + UNIX_ABSOLUTE);
    int64_t ysec = (c.yday - 1) * DAY + sec % DAY;
    int64_t ystart = signed_bits((uint64_t)sec - (uint64_t)ysec);
    int64_t start = rule_seconds(c.year, start_rule, standard.offset);
    int64_t end = rule_seconds(c.year, end_rule, daylight.offset);
    if (end < start) {
        int64_t temporary = start; start = end; end = temporary;
        zone z = standard; standard = daylight; daylight = z;
    }
    if (ysec < start) *out = (lookup){standard, ystart, add64(ystart, start)};
    else if (ysec >= end) *out = (lookup){standard, add64(ystart, end), add64(ystart, 365 * DAY)};
    else *out = (lookup){daylight, add64(ystart, start), add64(ystart, end)};
    return true;
}
static size_t first_zone(const location *l)
{
    bool used = false;
    for (size_t i = 0; i < l->ntx; ++i) if (!l->tx[i].index) { used = true; break; }
    if (!used) return 0;
    if (l->ntx && l->zones[l->tx[0].index].dst)
        for (size_t i = l->tx[0].index; i; --i) if (!l->zones[i - 1].dst) return i - 1;
    for (size_t i = 0; i < l->nzones; ++i) if (!l->zones[i].dst) return i;
    return 0;
}
static lookup zone_at(const location *l, int64_t sec)
{
    if (!l->nzones) return (lookup){{{(const unsigned char *)"UTC", 3}, 0, false}, INT64_MIN, INT64_MAX};
    if (l->cached && l->cache_start <= sec && sec < l->cache_end)
        return (lookup){l->cache_zone, l->cache_start, l->cache_end};
    if (!l->ntx || sec < l->tx[0].when)
        return (lookup){l->zones[first_zone(l)], INT64_MIN, l->ntx ? l->tx[0].when : INT64_MAX};
    size_t lo = 0, hi = l->ntx; int64_t end = INT64_MAX;
    while (hi - lo > 1) {
        size_t middle = lo + (hi - lo) / 2;
        if (sec < l->tx[middle].when) { end = l->tx[middle].when; hi = middle; }
        else lo = middle;
    }
    lookup result = {l->zones[l->tx[lo].index], l->tx[lo].when, end}, extension;
    if (lo == l->ntx - 1 && l->extend.len && extended(l->extend, result.start, sec, &extension)) return extension;
    return result;
}

static void clear_location(location *l)
{
    free(l->blob.data); free(l->zones); free(l->tx); *l = (location){0};
}
static br_slice take(reader *r, size_t size)
{
    if (r->bad || size > r->bytes.len) { r->bad = true; r->bytes = (br_slice){0}; return (br_slice){0}; }
    br_slice value = cut(r->bytes, 0, size);
    r->bytes = cut(r->bytes, size, r->bytes.len - size); return value;
}
static uint32_t big4(reader *r)
{
    br_slice s = take(r, 4);
    return s.len == 4 ? (uint32_t)s.data[0] << 24 | (uint32_t)s.data[1] << 16 | (uint32_t)s.data[2] << 8 | s.data[3] : 0;
}
static uint64_t big8(reader *r)
{
    uint64_t high = big4(r), low = big4(r); return high << 32 | low;
}
static int parse_zone(br_bytes data, location *l, bool *accepted, const char **why)
{
    *accepted = false; *l = (location){0};
    reader r = {{data.data, data.len}, false}; br_slice magic = take(&r, 4), header = take(&r, 16);
    if (magic.len != 4 || memcmp(magic.data, "TZif", 4) || header.len != 16) return 0;
    unsigned version = header.data[0];
    if (version != 0 && version != '2' && version != '3') return 0;
    uint32_t counts[6]; for (size_t i = 0; i < 6; ++i) counts[i] = big4(&r);
    bool wide = version != 0;
    if (wide) {
        uint64_t skip = (uint64_t)counts[3] * 5 + (uint64_t)counts[4] * 6 + counts[5] +
            (uint64_t)counts[2] * 8 + counts[1] + counts[0] + 20;
        if (skip > SIZE_MAX) return problem(why, "Go timezone data span overflow");
        take(&r, (size_t)skip);
        for (size_t i = 0; i < 6; ++i) counts[i] = big4(&r);
    }
    size_t width = wide ? 8 : 4;
    reader times = {take(&r, (size_t)counts[3] * width), false};
    br_slice indices = take(&r, counts[3]); reader zones = {take(&r, (size_t)counts[4] * 6), false};
    br_slice abbrev = take(&r, counts[5]);
    take(&r, (size_t)counts[2] * (width + 4)); take(&r, counts[1]); take(&r, counts[0]);
    if (r.bad || !counts[4]) return 0;
    l->zones = calloc(counts[4], sizeof(*l->zones));
    if (!l->zones) return problem(why, "cannot allocate Go timezone zones");
    l->nzones = counts[4];
    for (size_t i = 0; i < l->nzones; ++i) {
        uint32_t off = big4(&zones); br_slice flags = take(&zones, 2);
        if (zones.bad || flags.data[1] >= abbrev.len) goto ordinary;
        br_slice name = cut(abbrev, flags.data[1], abbrev.len - flags.data[1]);
        const unsigned char *nul = memchr(name.data, 0, name.len);
        if (nul) name.len = (size_t)(nul - name.data);
        int32_t signed_off; memcpy(&signed_off, &off, sizeof(off));
        l->zones[i] = (zone){name, signed_off, flags.data[0] != 0};
    }
    l->ntx = counts[3] ? counts[3] : 1;
    l->tx = calloc(l->ntx, sizeof(*l->tx));
    if (!l->tx) { clear_location(l); return problem(why, "cannot allocate Go timezone transitions"); }
    for (size_t i = 0; i < counts[3]; ++i) {
        int64_t when;
        if (wide) when = signed_bits(big8(&times));
        else { uint32_t raw = big4(&times); int32_t signed_time; memcpy(&signed_time, &raw, sizeof(raw)); when = signed_time; }
        if (times.bad || indices.data[i] >= l->nzones) goto ordinary;
        l->tx[i] = (transition){when, indices.data[i]};
    }
    if (!counts[3]) l->tx[0].when = INT64_MIN;
    if (r.bytes.len > 2 && r.bytes.data[0] == '\n' && r.bytes.data[r.bytes.len - 1] == '\n')
        l->extend = cut(r.bytes, 1, r.bytes.len - 2);
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) { clear_location(l); return problem(why, "cannot sample Go timezone cache clock"); }
    int64_t sec = now.tv_sec;
    for (size_t i = 0; i < l->ntx; ++i) if (l->tx[i].when <= sec && (i + 1 == l->ntx || sec < l->tx[i + 1].when)) {
        l->cached = true; l->cache_start = l->tx[i].when;
        l->cache_end = i + 1 < l->ntx ? l->tx[i + 1].when : INT64_MAX;
        l->cache_zone = l->zones[l->tx[i].index];
        lookup extension;
        if (i + 1 == l->ntx && l->extend.len && extended(l->extend, l->cache_start, sec, &extension)) {
            l->cache_start = extension.start; l->cache_end = extension.end; l->cache_zone = extension.value;
        }
        break;
    }
    l->blob = data; *accepted = true; return 0;
ordinary:
    clear_location(l); return 0;
}

/* Ordinary I/O/format failures are separate booleans, never owned failure
 * statuses. Resource failure cannot silently turn a candidate into UTC.
 * Paths come only from trusted process TZ/GOROOT configuration and system
 * timezone directories. Follow their symlinks, including /etc/localtime. */
static int read_file(const char *path, br_bytes *out, bool *loaded, const char **why)
{
    *out = (br_bytes){0}; *loaded = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    unsigned char buffer[4096]; int rc = 0;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0) break;
        if (!n) { *loaded = true; break; }
        if ((size_t)n > SIZE_MAX - out->len) { rc = problem(why, "Go timezone file too large"); break; }
        unsigned char *grown = realloc(out->data, out->len + (size_t)n);
        if (!grown) { rc = problem(why, "cannot read Go timezone bytes"); break; }
        out->data = grown; memcpy(grown + out->len, buffer, (size_t)n); out->len += (size_t)n;
        if (out->len > (10u << 20)) break;
    }
    if (close(fd) != 0) *loaded = false;
    if (!*loaded || rc) { free(out->data); *out = (br_bytes){0}; }
    return rc;
}
static unsigned little2(const unsigned char *p)
{
    return (unsigned)p[0] | (unsigned)p[1] << 8;
}
static uint32_t little4(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bool read_at(int fd, void *data, size_t len, int64_t off)
{
    if (lseek(fd, (off_t)off, off < 0 ? SEEK_END : SEEK_SET) < 0) return false;
    unsigned char *p = data;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return false;
        p += (size_t)n; len -= (size_t)n;
    }
    return true;
}
static int read_zip(const char *path, const char *name, br_bytes *out, bool *loaded, const char **why)
{
    *out = (br_bytes){0}; *loaded = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) return 0;
    unsigned char tail[22], *directory = NULL, *header = NULL;
    int rc = 0;
    if (!read_at(fd, tail, sizeof(tail), -22) || little4(tail) != UINT32_C(0x06054b50)) goto done;
    unsigned entries = little2(tail + 10); size_t size = little4(tail + 12);
    uint32_t directory_offset = little4(tail + 16);
    if (size && !(directory = malloc(size))) { rc = problem(why, "cannot read Go timezone ZIP directory"); goto done; }
    if (!read_at(fd, directory, size, directory_offset)) goto done;
    size_t at = 0;
    for (unsigned i = 0; i < entries; ++i) {
        size_t left = size - at;
        if (left < 4 || little4(directory + at) != UINT32_C(0x02014b50)) break;
        if (left < 46) { rc = problem(why, "unsupported: Go timezone ZIP header panic boundary"); goto done; }
        const unsigned char *record = directory + at;
        unsigned method = little2(record + 10), namelen = little2(record + 28), extra = little2(record + 30), comment = little2(record + 32);
        size_t record_size = 46u + namelen + extra + comment;
        if (record_size > left) { rc = problem(why, "unsupported: Go timezone ZIP name panic boundary"); goto done; }
        at += record_size;
        if (strlen(name) != namelen || memcmp(record + 46, name, namelen)) continue;
        if (method) goto done;
        uint32_t file_size = little4(record + 24), off = little4(record + 42);
        header = malloc(30u + namelen);
        if (!header) { rc = problem(why, "cannot read Go timezone ZIP header"); goto done; }
        if (!read_at(fd, header, 30u + namelen, off) || little4(header) != UINT32_C(0x04034b50) ||
            little2(header + 8) != method || little2(header + 26) != namelen || memcmp(header + 30, name, namelen)) goto done;
        uint64_t data_offset = (uint64_t)off + 30 + namelen + little2(header + 28);
        if (file_size && !(out->data = malloc(file_size))) { rc = problem(why, "cannot read Go timezone ZIP entry"); goto done; }
        out->len = file_size;
        if (!read_at(fd, out->data, out->len, (int64_t)data_offset)) goto done;
        *loaded = true; break;
    }
done:
    if (close(fd) != 0) *loaded = false;
    free(directory); free(header);
    if (!*loaded || rc) { free(out->data); *out = (br_bytes){0}; }
    return rc;
}
static int joined(const char *a, const char *b, const char *separator, char **out, const char **why)
{
    size_t alen = strlen(a), blen = strlen(b), middle = strlen(separator);
    if (alen > SIZE_MAX - middle || alen + middle > SIZE_MAX - blen - 1)
        return problem(why, "Go timezone path too large");
    char *p = malloc(alen + middle + blen + 1);
    if (!p) return problem(why, "cannot construct Go timezone path");
    memcpy(p, a, alen); memcpy(p + alen, separator, middle); memcpy(p + alen + middle, b, blen + 1);
    *out = p; return 0;
}
static int candidate(const char *source, const char *name, location *out, bool *accepted, const char **why)
{
    *accepted = false; br_bytes bytes = {0}; bool loaded = false; int rc;
    size_t n = strlen(source);
    if (n > 4 && !memcmp(source + n - 4, ".zip", 4)) rc = read_zip(source, name, &bytes, &loaded, why);
    else {
        char *path = NULL;
        if (n && joined(source, name, "/", &path, why) != 0) return -1;
        rc = read_file(path ? path : name, &bytes, &loaded, why); free(path);
    }
    if (!rc && loaded) rc = parse_zone(bytes, out, accepted, why);
    if (!*accepted) free(bytes.data);
    return rc;
}
static int load_location(const char *name, const char *const *sources, size_t count,
                          location *out, bool *accepted, const char **why)
{
    *accepted = false;
    for (size_t i = 0; i < count; ++i) {
        int rc = candidate(sources[i], name, out, accepted, why);
        if (rc || *accepted) return rc;
    }
    /* The actual reference has no time/tzdata registration, and -trimpath
     * leaves defaultGOROOT empty. An initial nonempty GOROOT still participates. */
    if (initial_goroot) {
        char *source = NULL;
        if (joined(initial_goroot, "/lib/time/zoneinfo.zip", "", &source, why) != 0) return -1;
        int rc = candidate(source, name, out, accepted, why); free(source); return rc;
    }
    return 0;
}
static void initialize_local(void)
{
    if (goroot_failed) { local_failure = "cannot capture initial Go timezone GOROOT"; return; }
    const char *tz = getenv("TZ"); bool accepted = false; int rc = 0;
    if (!tz) {
        const char *sources[] = {"/etc"};
        rc = load_location("localtime", sources, 1, &local, &accepted, &local_failure);
    } else if (*tz) {
        if (*tz == ':') ++tz;
        if (*tz == '/') {
            const char *sources[] = {""};
            rc = load_location(tz, sources, 1, &local, &accepted, &local_failure);
        } else if (*tz && strcmp(tz, "UTC")) {
            static const char *const sources[] = {
                "/nix/store/p0ff33dca0fbkskqwrl3spvxcn5974h0-tzdata-2026c/share/zoneinfo/",
                "/usr/share/zoneinfo/", "/usr/share/lib/zoneinfo/", "/usr/lib/locale/TZ/", "/etc/zoneinfo",
            };
            rc = load_location(tz, sources, sizeof(sources) / sizeof(*sources), &local, &accepted, &local_failure);
        }
    }
    if (rc != 0 && !local_failure) local_failure = "cannot load Go Local timezone";
}

static void put(writer *w, unsigned char c)
{
    if (w->len == SIZE_MAX) { w->overflow = true; return; }
    if (w->data) w->data[w->len] = c;
    ++w->len;
}
static void decimal(writer *w, int64_t value, unsigned width)
{
    uint64_t n = (uint64_t)value;
    if (value < 0) { put(w, '-'); n = UINT64_C(0) - n; }
    unsigned char digits[20]; unsigned count = 0;
    do { digits[count++] = (unsigned char)('0' + n % 10); n /= 10; } while (n);
    for (unsigned i = count; i < width; ++i) put(w, '0');
    while (count) put(w, digits[--count]);
}
static void numeric_zone(writer *w, int64_t seconds)
{
    int64_t minutes = seconds / 60;
    put(w, minutes < 0 ? '-' : '+');
    if (minutes < 0) minutes = -minutes;
    decimal(w, minutes / 60, 2); decimal(w, minutes % 60, 2);
}
static void write_time(writer *w, int64_t sec, zone z)
{
    uint64_t absolute = (uint64_t)sec + (uint64_t)z.offset + UNIX_ABSOLUTE;
    calendar c = civil(absolute); unsigned day_sec = (unsigned)(absolute % (uint64_t)DAY);
    decimal(w, c.year, 4); put(w, '-'); decimal(w, c.month, 2); put(w, '-'); decimal(w, c.day, 2);
    put(w, ' '); decimal(w, day_sec / 3600, 2); put(w, ':'); decimal(w, day_sec / 60 % 60, 2);
    put(w, ':'); decimal(w, day_sec % 60, 2); put(w, ' '); numeric_zone(w, z.offset); put(w, ' ');
    if (z.name.len) for (size_t i = 0; i < z.name.len; ++i) put(w, z.name.data[i]);
    else numeric_zone(w, z.offset);
}
int br_go_time_unix_string(int64_t sec, br_bytes *out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out) return fail(fatal, "invalid Go time output");
    *out = (br_bytes){0};
    int status = pthread_once(&local_once, initialize_local);
    if (status != 0) return fail(fatal, "cannot initialize Go Local time");
    if (local_failure) return fail(fatal, local_failure);
    zone z = zone_at(&local, sec).value;
    writer measure = {0}; write_time(&measure, sec, z);
    if (measure.overflow || measure.len == SIZE_MAX) return fail(fatal, "Go time string too large");
    unsigned char *data = malloc(measure.len + 1);
    if (!data) return fail(fatal, "cannot construct Go time string");
    writer result = {.data = data}; write_time(&result, sec, z); data[result.len] = 0;
    *out = (br_bytes){data, result.len}; return 0;
}
