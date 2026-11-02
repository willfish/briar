/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"
#include "briar_decoders.h"
#include "http_internal.h"
#include "overlap.h"
#include "prefilter.h"
#include "utf8.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define INPUT_LIMIT (64 * 1024)
#define SOURCE_CONTENT_SIZE (10 * 1024)
#define SOURCE_PEEK_SIZE (3 * 1024)
#define DECODE_MAX_DEPTH 5 /* Pinned CLI default; other depth options remain unsupported. */
/* Three non-PLAIN codecs, five passes; the last pass schedules no frontier. */
#define DECODE_VIEW_LIMIT (3u + 9u + 27u + 81u + 243u)
#define DECODE_FRONTIER_LIMIT 81u
_Static_assert(DECODE_MAX_DEPTH == 5, "update decoder bounds when changing depth");

typedef struct {
    bool json, no_verification, clean, fail;
    bool verified, unverified, unknown, retain_fp;
    const char *include, *exclude, *command;
    const char **paths;
    size_t npaths;
} cli_options;

typedef struct {
    int64_t source_id, job_id, secret_id, first_line;
    int32_t source_type;
    const char *source_name, *path, *decoder_name;
    br_slice original, data;
} source_frame;

typedef struct {
    const source_frame *source;
    const br_detector *detector;
    br_result *result;
    int64_t line;
    bool wordlist_fp;
    br_slice chunk_data;
} result_frame;

static volatile sig_atomic_t stopped;
static void stop_signal(int signum) { (void)signum; stopped = 1; }
static bool cancelled(void *user) { (void)user; return stopped != 0; }

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

static int write_all(int fd, const char *text, size_t len)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return 1;
    bool nonblocking = (flags & O_NONBLOCK) != 0;
    while (len) {
        /* A full output pipe must not trap cancellation in a restarted write.
         * Keep writes atomic for pipes and still allow a final diagnostic when
         * its descriptor is writable, without changing shared descriptor flags. */
        if (!nonblocking) {
            struct pollfd output = { .fd = fd, .events = POLLOUT };
            int ready = poll(&output, 1, stopped ? 0 : 100);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) return 1;
            if (!ready) {
                if (stopped) { errno = EINTR; return 1; }
                continue;
            }
        }
        size_t count = len > PIPE_BUF ? PIPE_BUF : len;
        ssize_t n = write(fd, text, count);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 1;
        text += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* Do not change process-wide SIGPIPE disposition, including in HTTP workers.
 * Only consume a newly generated EPIPE signal, never one pending on entry. */
static int print_line(int fd, const char *prefix, const char *text)
{
    sigset_t block, previous, pending;
    if (sigemptyset(&block) || sigaddset(&block, SIGPIPE) ||
        pthread_sigmask(SIG_BLOCK, &block, &previous)) return 1;
    int rc = 1;
    if (sigpending(&pending)) goto restore;
    int prior = sigismember(&pending, SIGPIPE);
    if (prior < 0) goto restore;
    rc = write_all(fd, prefix, strlen(prefix)) || write_all(fd, text, strlen(text)) ||
         write_all(fd, "\n", 1);
    if (rc && errno == EPIPE && !prior) {
        if (sigpending(&pending)) rc = 1;
        else if (sigismember(&pending, SIGPIPE) == 1) {
            int caught;
            if (sigwait(&block, &caught)) rc = 1;
        }
    }
restore:
    if (pthread_sigmask(SIG_SETMASK, &previous, NULL)) rc = 1;
    return rc;
}

static int usage(void)
{
    return print_line(STDOUT_FILENO, "", "Usage: briar stdin --json --no-verification --include-detectors CSV [OPTIONS]\n"
         "       briar filesystem FILE... --json --no-verification --include-detectors CSV [OPTIONS]\n"
         "Options: --exclude-detectors CSV\n"
         "         --filter-unverified  --results CSV  --fail\n"
         "Native slice: explicit supported detector selection required; default/all scans fail.\n"
         "Only selected upstream-enabled implementations run; Abstract remains disabled.\n"
         "Inputs: explicit regular files or stdin, at most 64 KiB each.\n"
         "Source chunks: 10 KiB content + 3 KiB forward peek, before decoding.\n"
         "PLAIN runs first; BASE64/UTF16/ESCAPED_UNICODE fan-out iterates to depth five.\n"
         "UTF16 is the pinned printable-ASCII heuristic, not general Unicode decoding.\n"
         "No directory traversal, archives, HTML decoder, depth options, CLI verification/cache,\n"
         "entropy, custom configuration, non-JSON printers or other sources yet.\n"
         "Unported options and commands fail explicitly. JSON is newline-delimited.");
}

static const char *option_value(int argc, char **argv, int *i, const char *name)
{
    size_t n = strlen(name);
    if (!strncmp(argv[*i], name, n) && argv[*i][n] == '=') return argv[*i] + n + 1;
    if (!strcmp(argv[*i], name) && *i + 1 < argc) return argv[++*i];
    return NULL;
}

static int result_selection(cli_options *o, const char *value, char **error)
{
    o->verified = o->unverified = o->unknown = o->retain_fp = false;
    char *copy = strdup(value);
    if (!copy) return fail(error, "out of memory parsing result selection");
    char *save = NULL;
    bool any = false;
    for (char *p = strtok_r(copy, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        any = true;
        if (!strcmp(p, "verified")) o->verified = true;
        else if (!strcmp(p, "unverified")) o->unverified = true;
        else if (!strcmp(p, "unknown")) o->unknown = true;
        else if (!strcmp(p, "filtered_unverified")) o->retain_fp = o->unverified = true;
        else { free(copy); return fail(error, "invalid --results selection"); }
    }
    free(copy);
    return any ? 0 : fail(error, "empty --results selection");
}

static int parse_cli(int argc, char **argv, cli_options *o, char **error)
{
    o->exclude = "";
    o->verified = o->unverified = o->unknown = true;
    o->paths = calloc((size_t)argc, sizeof(*o->paths));
    if (!o->paths) return fail(error, "out of memory parsing command line");
    bool positional = false;
    for (int i = 1; i < argc; ++i) {
        const char *value;
        if (!positional && !strcmp(argv[i], "--")) { positional = true; continue; }
        if (!positional && !strcmp(argv[i], "--json")) o->json = true;
        else if (!positional && !strcmp(argv[i], "--no-verification")) o->no_verification = true;
        else if (!positional && !strcmp(argv[i], "--filter-unverified")) o->clean = true;
        else if (!positional && !strcmp(argv[i], "--fail")) o->fail = true;
        else if (!positional && (value = option_value(argc, argv, &i, "--include-detectors"))) o->include = value;
        else if (!positional && (value = option_value(argc, argv, &i, "--exclude-detectors"))) o->exclude = value;
        else if (!positional && (value = option_value(argc, argv, &i, "--results"))) {
            if (result_selection(o, value, error)) return 1;
        } else if (!positional && argv[i][0] == '-') return fail(error, "unsupported or incomplete CLI option; see --help");
        else if (!o->command) o->command = argv[i];
        else o->paths[o->npaths++] = argv[i];
    }
    if (!o->command || (strcmp(o->command, "stdin") && strcmp(o->command, "filesystem")))
        return fail(error, "unsupported or missing source command; see --help");
    if ((!strcmp(o->command, "stdin") && o->npaths) || (!strcmp(o->command, "filesystem") && !o->npaths))
        return fail(error, "stdin takes no paths; filesystem requires explicit regular files");
    if (!o->include || !*o->include)
        return fail(error, "incomplete detector port: explicit --include-detectors selection required; default/all scans are unavailable");
    if (!o->json) return fail(error, "unsupported output format: this slice requires --json");
    if (!o->no_verification)
        return fail(error, "unsupported CLI verification pipeline: this slice requires --no-verification; injected detector verification is available through ABI 1");
    return 0;
}

static int selectors(const char *csv, const br_detector *const *registry, size_t count,
                      bool *matches, bool allow_all, char **error)
{
    char *copy = strdup(csv);
    if (!copy) return fail(error, "out of memory parsing detector selectors");
    char *save = NULL;
    for (char *token = strtok_r(copy, ",", &save); token; token = strtok_r(NULL, ",", &save)) {
        while (*token == ' ' || *token == '\t') ++token;
        size_t n = strlen(token);
        while (n && (token[n - 1] == ' ' || token[n - 1] == '\t')) token[--n] = 0;
        if (!*token) continue;
        if (!strcasecmp(token, "all")) {
            if (!allow_all) { free(copy); return fail(error, "incomplete detector port: all-detector scans are unavailable; select supported detector IDs explicitly"); }
            for (size_t j = 0; j < count; ++j) matches[j] = true;
            continue;
        }
        if (strchr(token, '-')) { free(copy); return fail(error, "unsupported detector range selector"); }
        int32_t version = 0;
        char *dot = strchr(token, '.');
        if (dot) {
            *dot++ = 0;
            char *end;
            if (*dot != 'v' && *dot != 'V') { free(copy); return fail(error, "invalid detector version selector"); }
            errno = 0;
            long v = strtol(dot + 1, &end, 10);
            if (errno || end == dot + 1 || *end || v < 0 || v > INT32_MAX) {
                free(copy); return fail(error, "invalid detector version selector");
            }
            version = (int32_t)v;
        }
        char *end;
        errno = 0;
        long id = strtol(token, &end, 10);
        bool numeric = !errno && end != token && !*end && id >= 0 && id <= INT32_MAX;
        bool found = false;
        for (size_t j = 0; j < count; ++j) {
            const br_detector *d = registry[j];
            if ((numeric ? d->type == id : !strcasecmp(token, d->name)) &&
                (!version || d->version == version)) {
                found = true;
                matches[j] = true;
            }
        }
        if (!found) { free(copy); return fail(error, "unsupported or unknown detector/version selector"); }
    }
    free(copy);
    return 0;
}

static bool same_bytes(br_slice a, br_slice b)
{
    return a.len == b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

static br_slice effective_secret(const br_result *r)
{
    br_bytes b = r->primary_secret.len ? r->primary_secret : r->raw;
    return (br_slice){ b.data, b.len };
}

static void duplicate_offsets(br_slice input, br_results *results)
{
    /* Match upstream grouping and forward, non-overlapping occurrence assignment. */
    for (size_t i = 0; i < results->len; ++i) {
        br_slice key = effective_secret(&results->items[i]);
        bool seen = false;
        size_t count = 0;
        for (size_t j = 0; j < results->len; ++j) {
            if (same_bytes(key, effective_secret(&results->items[j]))) {
                if (j < i) seen = true;
                ++count;
            }
        }
        if (seen || count < 2) continue;
        size_t from = 0;
        for (size_t j = i; j < results->len; ++j) {
            if (!same_bytes(key, effective_secret(&results->items[j]))) continue;
            size_t pos = br_slice_find(input, key, from);
            if (pos == SIZE_MAX) break;
            results->items[j].chunk_offset = (int64_t)pos;
            results->items[j].chunk_offset_set = true;
            from = pos + key.len;
        }
    }
}

static int64_t newline_count(br_slice input)
{
    int64_t count = 0;
    size_t at = 0;
    while (at < input.len) {
        const unsigned char *newline = memchr(input.data + at, '\n', input.len - at);
        if (!newline) break;
        ++count;
        at = (size_t)(newline - input.data) + 1;
    }
    return count;
}

static bool locate(result_frame *frame)
{
    const source_frame *s = frame->source;
    if (s->source_type != 15) return false; /* Upstream stdin has neither lines nor ignore handling. */
    br_result *r = frame->result;
    br_slice key = effective_secret(r);
    size_t offset = r->chunk_offset_set && r->chunk_offset >= 0
        ? (size_t)r->chunk_offset : br_slice_find(s->data, key, 0);
    frame->line = s->first_line;
    if (offset == SIZE_MAX || offset > s->data.len || key.len > s->data.len - offset) return false;
    int64_t line_offset = newline_count((br_slice){s->data.data, offset});
    frame->line += line_offset;
    if (r->primary_secret.len) r->primary_line = line_offset;
    size_t start = offset + key.len, end = start;
    while (end < s->data.len && s->data.data[end] != '\n') ++end;
    br_slice tail = { s->data.data + start, end - start };
    static const unsigned char tag[] = "trufflehog:ignore";
    return br_slice_find(tail, (br_slice){ tag, sizeof(tag) - 1 }, 0) != SIZE_MAX;
}

static int jadd(br_json *object, const char *key, br_json *value)
{
    if (json_object_object_add(object, key, value)) { json_object_put(value); return 1; }
    return 0;
}

static br_json *metadata(const result_frame *f)
{
    br_json *root = json_object_new_object(), *data = json_object_new_object();
    br_json *file = NULL;
    if (!root || !data) goto failed;
    if (f->source->source_type == 15) {
        file = json_object_new_object();
        br_json *path = json_object_new_string(f->source->path);
        if (!file || !path) { json_object_put(path); goto failed; }
        if (jadd(file, "file", path)) goto failed;
        br_json *line = json_object_new_int64(f->line);
        if (!line || jadd(file, "line", line)) goto failed;
        if (jadd(data, "Filesystem", file)) { file = NULL; goto failed; }
        file = NULL;
    } else {
        br_json *stdin_metadata = json_object_new_object();
        if (!stdin_metadata || jadd(data, "Stdin", stdin_metadata)) goto failed;
    }
    if (jadd(root, "Data", data)) { data = NULL; goto failed; }
    return root;
failed:
    json_object_put(file); json_object_put(data); json_object_put(root);
    return NULL;
}

/* A provider may deliberately byte-slice a Go string (ADC Redacted). Keep
 * those original bytes in the C result; Go's outer JSON encoder replaces EACH
 * invalid byte with RuneError. json-c otherwise emits invalid UTF8 verbatim. */
static br_json *json_redacted(const char *value)
{
    br_slice text = {(const unsigned char *)(value ? value : ""), value ? strlen(value) : 0};
    if (br_utf8_valid(text)) return json_object_new_string(value ? value : "");
    size_t size = 0;
    for (size_t i = 0; i < text.len;) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){text.data + i, text.len - i}, &rune);
        size_t add = n ? n : 3;
        if (size > INT_MAX - add) return NULL;
        size += add; i += n ? n : 1;
    }
    unsigned char *repaired = malloc(size);
    if (!repaired) return NULL;
    size_t at = 0;
    for (size_t i = 0; i < text.len;) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){text.data + i, text.len - i}, &rune);
        if (n) { memcpy(repaired + at, text.data + i, n); at += n; i += n; }
        else { memcpy(repaired + at, "\xef\xbf\xbd", 3); at += 3; ++i; }
    }
    br_json *result = json_object_new_string_len((const char *)repaired, (int)size);
    free(repaired); return result;
}

static br_json *json_result(const result_frame *f)
{
    const br_result *r = f->result;
    br_json *object = json_object_new_object();
    if (!object) return NULL;
#define ADD(key, expr) do { br_json *v = (expr); if (!v || jadd(object, key, v)) goto failed; } while (0)
    ADD("SourceMetadata", metadata(f));
    ADD("SourceID", json_object_new_int64(f->source->source_id));
    ADD("SourceType", json_object_new_int(f->source->source_type));
    ADD("SourceName", json_object_new_string(f->source->source_name));
    ADD("DetectorType", json_object_new_int(r->detector_type));
    const char *type_name = br_detector_type_name(r->detector_type);
    if (!type_name) goto failed;
    ADD("DetectorName", json_object_new_string(type_name));
    ADD("DetectorDescription", json_object_new_string(f->detector->description));
    ADD("DecoderName", json_object_new_string(f->source->decoder_name));
    ADD("Verified", json_object_new_boolean(r->verified));
    if (r->verification_error && *r->verification_error)
        ADD("VerificationError", json_object_new_string(r->verification_error));
    ADD("VerificationFromCache", json_object_new_boolean(r->verification_from_cache));
    ADD("Raw", json_object_new_string_len(r->raw.data ? (const char *)r->raw.data : "", (int)r->raw.len));
    ADD("RawV2", json_object_new_string_len(r->raw_v2.data ? (const char *)r->raw_v2.data : "", (int)r->raw_v2.len));
    ADD("Redacted", json_redacted(r->redacted));
    if (jadd(object, "ExtraData", json_object_get(r->extra_data)) ||
        jadd(object, "StructuredData", json_object_get(r->structured_data)) ||
        jadd(object, "SecretParts", json_object_get(r->secret_parts))) goto failed;
#undef ADD
    return object;
failed:
    json_object_put(object);
    return NULL;
}

static int append_output(br_json *output, br_json *keys, const result_frame *f, char **error)
{
    br_json *object = json_result(f), *key = json_object_new_array();
    if (!object || !key) goto failed;
    br_json *custom = json_object_new_string(f->detector->custom_name ? f->detector->custom_name : "");
    if (!custom) goto failed;
    if (json_object_array_add(key, custom)) { json_object_put(custom); goto failed; }
    const char *fields[] = { "DetectorType", "Raw", "RawV2", "SourceMetadata" };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        br_json *v = NULL;
        if (!json_object_object_get_ex(object, fields[i], &v)) goto failed;
        v = json_object_get(v);
        if (json_object_array_add(key, v)) { json_object_put(v); goto failed; }
    }
    /* This private tuple contains strings, integer DetectorType and metadata
     * constructed above in a fixed field order. Its JSON encoding is an exact
     * key, including embedded NULs and escaped path bytes. Hash lookup preserves
     * first-result wins without comparing every earlier finding. */
    const char *identity = json_object_to_json_string_ext(key, JSON_C_TO_STRING_PLAIN);
    br_json *existing = NULL;
    if (!identity) goto failed;
    if (json_object_object_get_ex(keys, identity, &existing)) {
        json_object_put(object); json_object_put(key);
        return 0;
    }
    if (json_object_object_add(keys, identity, NULL)) goto failed;
    json_object_put(key);
    key = NULL;
    if (json_object_array_add(output, object)) goto failed;
    return 0;
failed:
    json_object_put(object); json_object_put(key);
    return fail(error, "cannot construct JSON result");
}

static void filter_results(const cli_options *o, const br_detector *d, br_results *results)
{
    if (o->clean || d->clean_always) {
        if (d->clean) d->clean(d, results, false);
        else br_clean_results(results, false);
    }
}

static int dispatch_result(const cli_options *o, const source_frame *source,
                            const br_detector *d, br_result *r,
                            br_json *output, br_json *keys, char **error)
{
    static const char *const terms[] = { "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****" };
    if (stopped) return fail(error, "context canceled");
    result_frame f = { .source = source, .detector = d, .result = r, .chunk_data = source->original };
    if (locate(&f)) return 0;
    if (!r->verified && r->raw.data) {
        char *reason = NULL;
        f.wordlist_fp = d->false_positive ? d->false_positive(d, r, &reason)
            : br_known_false_positive((br_slice){ r->raw.data, r->raw.len }, terms, 7, true, &reason);
        if (f.wordlist_fp && (!reason || !strncmp(reason, "unsupported:", 12))) {
            free(reason);
            return fail(error, "unsupported or failed false-positive check");
        }
        free(reason);
    }
    if ((!r->verified && f.wordlist_fp && !o->retain_fp) ||
        (r->verified && !o->verified) ||
        (!r->verified && r->verification_error && !o->unknown) ||
        (!r->verified && !r->verification_error && !o->unverified)) return 0;
    return append_output(output, keys, &f, error);
}

static int process_results(const cli_options *o, const source_frame *source,
                            const br_detector *d, br_results *results,
                            br_json *output, br_json *keys, char **error)
{
    filter_results(o, d, results);
    duplicate_offsets(source->data, results);
    for (size_t i = 0; i < results->len; ++i)
        if (dispatch_result(o, source, d, &results->items[i], output, keys, error)) return 1;
    return 0;
}

typedef struct { const br_detector *detector; br_bytes value; } overlap_seen;

static br_slice overlap_value(const br_result *result)
{
    br_bytes value = result->raw_v2.data ? result->raw_v2 : result->raw;
    return (br_slice){value.data, value.len};
}

static bool same_detector(const br_detector *a, const br_detector *b)
{
    return a->type == b->type && a->version == b->version &&
        !strcmp(a->custom_name ? a->custom_name : "", b->custom_name ? b->custom_name : "");
}

static int probe_overlaps(const cli_options *o, const source_frame *source,
                          const br_scan_ctx *ctx, const br_native_http *http,
                          br_detector_windows *matches, size_t count,
                          br_json *output, br_json *keys, char **error)
{
    static const char cause[] = "more than one detector has found this result; for your safety, verification has been disabled. "
                                "You can override this behavior by using the --allow-verification-overlap flag";
    overlap_seen *seen = NULL;
    size_t nseen = 0;
    int rc = 0;
    /* Registry order is one valid deterministic order. Upstream iterates a Go
     * map here, so which different-type detector wins is not deterministic. */
    for (size_t m = 0; !rc && m < count; ++m) {
        br_detector_windows *match = &matches[m];
        if (!match->len) continue;
        const br_detector *d = match->detector;
        br_scan_ctx scan_ctx = *ctx;
        br_native_http_bind(http, d, &scan_ctx);
        for (size_t w = 0; !rc && w < match->len; ++w) {
            br_span span = match->windows[w];
            br_results results = {0};
            rc = d->scan(d, &scan_ctx, false, (br_slice){source->data.data + span.begin, span.end - span.begin}, &results, error);
            if (!rc && results.len) match->pending = true; /* A later window can re-add a removed detector. */
            if (!rc) filter_results(o, d, &results);
            for (size_t r = 0; !rc && r < results.len; ++r) {
                br_result *result = &results.items[r];
                br_slice value = overlap_value(result);
                bool duplicate = false, similar = false;
                for (size_t s = 0; s < nseen; ++s) {
                    br_slice prior = {seen[s].value.data, seen[s].value.len};
                    if (same_detector(d, seen[s].detector) && same_bytes(value, prior)) { duplicate = true; break; }
                }
                if (duplicate) continue;
                for (size_t s = 0; !rc && !similar && s < nseen; ++s) {
                    if (d->type != seen[s].detector->type)
                        rc = br_overlap_similar(value, (br_slice){seen[s].value.data, seen[s].value.len}, &similar, error);
                }
                if (!rc && similar) {
                    rc = br_result_set_verification_error(result, cause, NULL, 0);
                    if (rc) rc = fail(error, "out of memory annotating overlap result");
                    if (!rc) rc = dispatch_result(o, source, d, result, output, keys, error);
                    match->pending = false;
                }
                if (!rc) {
                    if (nseen >= SIZE_MAX / sizeof(*seen) || value.len == SIZE_MAX) {
                        rc = fail(error, "too many overlap candidates");
                        break;
                    }
                    overlap_seen *next = realloc(seen, (nseen + 1) * sizeof(*next));
                    if (!next) { rc = fail(error, "out of memory tracking overlap candidates"); break; }
                    seen = next;
                    unsigned char *copy = malloc(value.len ? value.len : 1);
                    if (!copy) { rc = fail(error, "out of memory copying overlap candidate"); break; }
                    if (value.len) memcpy(copy, value.data, value.len);
                    seen[nseen++] = (overlap_seen){d, {copy, value.len}};
                }
            }
            br_results_clear(&results);
        }
    }
    for (size_t i = 0; i < nseen; ++i) free(seen[i].value.data);
    free(seen);
    return rc;
}

static int scan_source(const cli_options *o, const source_frame *source,
                        const br_scan_ctx *ctx, const br_native_http *http,
                        br_prefilter *prefilter, br_json *output,
                        br_json *keys, char **error)
{
    br_slice input = source->data;
    br_detector_windows *matches = NULL;
    size_t count = 0, nmatch = 0;
    int rc = br_prefilter_find(prefilter, input, ctx, &matches, &count, error);
    if (rc) return rc;
    for (size_t m = 0; m < count; ++m) if (matches[m].len) ++nmatch;
    if (nmatch > 1) rc = probe_overlaps(o, source, ctx, http, matches, count, output, keys, error);
    for (size_t m = 0; !rc && m < count; ++m) {
        br_detector_windows *match = &matches[m];
        if (!match->len || (nmatch > 1 && !match->pending)) continue;
        br_scan_ctx scan_ctx = *ctx;
        br_native_http_bind(http, match->detector, &scan_ctx);
        for (size_t w = 0; !rc && w < match->len; ++w) {
            br_span span = match->windows[w];
            br_results results = {0};
            rc = match->detector->scan(match->detector, &scan_ctx, false,
                (br_slice){input.data + span.begin, span.end - span.begin}, &results, error);
            if (!rc) rc = process_results(o, source, match->detector, &results, output, keys, error);
            br_results_clear(&results);
        }
    }
    return rc;
}

static int scan_decoders(const cli_options *o, const source_frame *source,
                          const br_scan_ctx *ctx, const br_native_http *http,
                          br_prefilter *prefilter, br_json *output,
                          br_json *keys, char **error)
{
    source_frame plain = *source;
    plain.decoder_name = "PLAIN";
    br_bytes plain_storage = {0};
    int rc = br_utf8_decode(source->original, &plain.data, &plain_storage, error);
    if (!rc && plain.data.len) rc = scan_source(o, &plain, ctx, http, prefilter, output, keys, error);
    free(plain_storage.data);
    if (rc) return rc;

    /* Breadth-first iterativeDecode for the three ported non-PLAIN codecs.
     * All first see original bytes, never PLAIN's sanitized view. Keep owned
     * outputs alive for frontier/seen slices; neither cache includes metadata. */
    br_bytes owned[DECODE_VIEW_LIMIT] = {0};
    br_slice current[DECODE_FRONTIER_LIMIT] = {0}, next[DECODE_FRONTIER_LIMIT] = {0};
    br_slice seen[DECODE_VIEW_LIMIT] = {0};
    /* Pinned DefaultDecoders order; HTML remains unported. */
    static const struct {
        const char *name;
        int (*decode)(br_slice, br_bytes *, bool *, char **);
    } codecs[] = {
        {"BASE64", br_base64_decode},
        {"UTF16", br_utf16_decode},
        {"ESCAPED_UNICODE", br_escaped_unicode_decode},
    };
    _Static_assert(sizeof(codecs) / sizeof(*codecs) == 3, "update decoder bounds when adding a codec");
    size_t nowned = 0, nseen = 0, ncurrent = 1;
    current[0] = source->original;
    for (size_t depth = 0; !rc && ncurrent && depth < DECODE_MAX_DEPTH; ++depth) {
        size_t nnext = 0;
        for (size_t i = 0; !rc && i < ncurrent; ++i) {
            for (size_t codec = 0; !rc && codec < sizeof(codecs) / sizeof(*codecs); ++codec) {
                if (stopped) { rc = fail(error, "context canceled"); break; }
                bool applied = false;
                br_bytes decoded = {0};
                rc = codecs[codec].decode(current[i], &decoded, &applied, error);
                if (rc || !applied) { free(decoded.data); continue; }
                if (nowned == DECODE_VIEW_LIMIT) {
                    free(decoded.data);
                    rc = fail(error, "decoder view bound exceeded");
                    break;
                }
                owned[nowned++] = decoded;
                source_frame chunk = *source;
                chunk.decoder_name = codecs[codec].name;
                chunk.data = (br_slice){ decoded.data, decoded.len };
                /* Append/scan intermediate results even if their data was seen.
                 * Only scheduling is deduplicated; verification-cache flags and
                 * original chunk metadata must not be changed by decoder reuse. */
                rc = scan_source(o, &chunk, ctx, http, prefilter, output, keys, error);
                if (rc || depth + 1 == DECODE_MAX_DEPTH || same_bytes(chunk.data, current[i])) continue;
                bool repeat = false;
                for (size_t j = 0; j < nseen; ++j)
                    if (same_bytes(chunk.data, seen[j])) repeat = true;
                if (repeat) continue;
                if (nseen == DECODE_VIEW_LIMIT || nnext == DECODE_FRONTIER_LIMIT) {
                    rc = fail(error, "decoder frontier bound exceeded");
                    break;
                }
                seen[nseen++] = chunk.data;
                next[nnext++] = chunk.data;
            }
        }
        memcpy(current, next, nnext * sizeof(*current));
        ncurrent = nnext;
    }
    for (size_t i = 0; i < nowned; ++i) free(owned[i].data);
    return rc;
}

static int scan_chunks(const cli_options *o, const source_frame *source,
                        const br_scan_ctx *ctx, const br_native_http *http,
                        br_prefilter *prefilter, br_json *output,
                        br_json *keys, char **error)
{
    int64_t first_line = 1;
    for (size_t start = 0; start < source->original.len;) {
        if (stopped) return fail(error, "context canceled");
        size_t remaining = source->original.len - start;
        size_t content = remaining < SOURCE_CONTENT_SIZE ? remaining : SOURCE_CONTENT_SIZE;
        size_t view_len = remaining < content + SOURCE_PEEK_SIZE ? remaining : content + SOURCE_PEEK_SIZE;
        source_frame chunk = *source;
        chunk.first_line = first_line;
        /* OriginalData is this raw content+peek view, never the decoded window. */
        chunk.original = (br_slice){ source->original.data + start, view_len };
        int rc = scan_decoders(o, &chunk, ctx, http, prefilter, output, keys, error);
        if (rc) return rc;
        /* Peek bytes are read again as content in the next chunk. Stdin has no
         * line/ignore metadata, while filesystem advances only over raw content. */
        if (source->source_type == 15)
            first_line += newline_count((br_slice){source->original.data + start, content});
        start += content;
    }
    return 0;
}

static int read_input(int fd, br_bytes *input, char **error)
{
    unsigned char *data = malloc(INPUT_LIMIT + 1);
    if (!data) return fail(error, "out of memory reading input");
    size_t len = 0;
    for (;;) {
        if (stopped) { free(data); return fail(error, "context canceled"); }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ready = poll(&pfd, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { free(data); return fail(error, "input poll failed"); }
        if (!ready) continue;
        ssize_t n = read(fd, data + len, INPUT_LIMIT + 1 - len);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) { free(data); return fail(error, "input read failed"); }
        if (!n) break;
        len += (size_t)n;
        if (len > INPUT_LIMIT) { free(data); return fail(error, "unsupported: input exceeds the 64 KiB source cap"); }
    }
    input->data = data;
    input->len = len;
    return 0;
}

static int open_input(const char *path, int *out, char **error)
{
    char *copy = strdup(path);
    if (!copy) return fail(error, "out of memory opening filesystem input");
    char *name = strrchr(copy, '/');
    const char *parent = ".";
    if (name) {
        *name++ = '\0';
        size_t len = strlen(copy);
        while (len > 1 && copy[len - 1] == '/') copy[--len] = '\0';
        parent = len ? copy : "/";
    } else name = copy;
    /* Pin the immediate parent, then inspect the opened file, not a path
     * checked before open. This is not a sandbox for all ancestor components. */
    int directory = openat(AT_FDCWD, parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { free(copy); return fail(error, "cannot open filesystem input parent"); }
    int fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    /* Always close the parent; retain an earlier open failure if both fail. */
    int close_rc = close(directory);
    free(copy);
    if (fd < 0) return fail(error, "cannot open filesystem input");
    struct stat st;
    if (close_rc || fstat(fd, &st) || !S_ISREG(st.st_mode)) {
        /* Already failing; a cleanup close error cannot make this successful. */
        (void)close(fd);
        return fail(error, "filesystem input or parent is unavailable or not regular");
    }
    *out = fd;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) return usage();
    cli_options options = {0};
    char *error = NULL;
    bool *included = NULL, *excluded = NULL, *selected = NULL;
    br_json *output = NULL, *keys = NULL;
    br_native_http *http = NULL;
    br_prefilter *prefilter = NULL;
    int rc = 1;
    struct sigaction action = { .sa_handler = stop_signal };
    if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGTERM, &action, NULL)) {
        fail(&error, "cannot install cancellation signal handlers"); goto done;
    }
    if (parse_cli(argc, argv, &options, &error)) goto done;
    const br_detector *const *registry = NULL;
    size_t count = 0;
    if (br_registry(&registry, &count, &error)) goto done;
    if (!registry || !count) { fail(&error, "no compiled detectors available"); goto done; }
    included = calloc(count, sizeof(bool)); excluded = calloc(count, sizeof(bool)); selected = calloc(count, sizeof(bool));
    if (!included || !excluded || !selected) { fail(&error, "out of memory selecting detectors"); goto done; }
    if (selectors(options.include, registry, count, included, false, &error) ||
        selectors(options.exclude, registry, count, excluded, true, &error)) goto done;
    size_t nselected = 0;
    for (size_t i = 0; i < count; ++i) {
        selected[i] = br_detector_is_default(registry[i], NULL) && included[i] && !excluded[i];
        if (selected[i]) ++nselected;
    }
    if (!nselected) { fail(&error, "no enabled implemented detectors selected; include selectors cannot enable disabled upstream detectors"); goto done; }
    br_scan_ctx ctx = { .cancelled = cancelled };
    if (br_prefilter_create(registry, count, selected, &prefilter, &error)) goto done;
    if (br_native_http_init(&http, &error)) goto done;
    ctx.transport = br_native_http_raw(http);
    output = json_object_new_array(); keys = json_object_new_object();
    if (!output || !keys) { fail(&error, "out of memory initializing output"); goto done; }
    char notice[320];
    snprintf(notice, sizeof(notice), "limited native slice, %zu explicitly selected enabled detector(s); 10 KiB + 3 KiB source chunks, PLAIN/BASE64/UTF16/ESCAPED_UNICODE only (decode depth five), no HTML decoder or CLI verification", nselected);
    if (print_line(STDERR_FILENO, "briar: ", notice)) { fail(&error, "cannot write scan diagnostic"); goto done; }
    size_t nsources = !strcmp(options.command, "stdin") ? 1 : options.npaths;
    for (size_t i = 0; i < nsources; ++i) {
        bool is_stdin = !strcmp(options.command, "stdin");
        int fd = STDIN_FILENO;
        if (!is_stdin && open_input(options.paths[i], &fd, &error)) goto done;
        br_bytes input = {0};
        int read_rc = read_input(fd, &input, &error);
        /* Always close owned input; retain a prior read error if close also fails. */
        if (!is_stdin && close(fd) && !read_rc) read_rc = fail(&error, "cannot close filesystem input");
        if (read_rc) { free(input.data); goto done; }
        source_frame source = {
            .source_id = 1, .job_id = 1, .secret_id = 0, .first_line = 1,
            .source_type = is_stdin ? 40 : 15,
            .source_name = is_stdin ? "trufflehog - stdin" : "trufflehog - filesystem",
            .path = is_stdin ? NULL : options.paths[i], .original = { input.data, input.len },
        };
        int scan_rc = scan_chunks(&options, &source, &ctx, http, prefilter, output, keys, &error);
        free(input.data);
        if (scan_rc) goto done;
    }
    if (stopped) { fail(&error, "context canceled"); goto done; }
    for (size_t i = 0; i < json_object_array_length(output); ++i) {
        const char *line = json_object_to_json_string_ext(json_object_array_get_idx(output, i),
                                                        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
        if (!line || print_line(STDOUT_FILENO, "", line)) { fail(&error, "cannot write JSON output"); goto done; }
    }
    rc = options.fail && json_object_array_length(output) ? 183 : 0;
done:
    /* Already failing; intentionally discard a final diagnostic write failure. */
    if (rc && rc != 183) (void)print_line(STDERR_FILENO, "briar: ", error ? error : "scan failed");
    free(error); free(options.paths); free(included); free(excluded); free(selected);
    json_object_put(output); json_object_put(keys);
    br_native_http_destroy(http);
    br_prefilter_destroy(prefilter);
    return rc;
}
