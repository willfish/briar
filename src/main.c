/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"
#include "briar_decoders.h"

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* Private runtime setup, not part of the detector ABI. */
extern const br_transport *br_curl_transport_init(char **error);

#define INPUT_LIMIT (64 * 1024)
#define SOURCE_CONTENT_SIZE (10 * 1024)
#define SOURCE_PEEK_SIZE (3 * 1024)
#define DECODE_MAX_DEPTH 5 /* Pinned CLI default; other depth options remain unsupported. */
/* Two non-PLAIN codecs produce at most 2+4+8+16+32 owned views. */
#define DECODE_VIEW_LIMIT ((1u << (DECODE_MAX_DEPTH + 1)) - 2u)
#define DECODE_FRONTIER_LIMIT (1u << (DECODE_MAX_DEPTH - 1))

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

static void usage(void)
{
    puts("Usage: briar stdin --json --no-verification --include-detectors CSV [OPTIONS]\n"
         "       briar filesystem FILE... --json --no-verification --include-detectors CSV [OPTIONS]\n"
         "Options: --exclude-detectors CSV\n"
         "         --filter-unverified  --results CSV  --fail\n"
         "Native slice: explicit supported detector selection required; default/all scans fail.\n"
         "Only selected upstream-enabled implementations run; Abstract remains disabled.\n"
         "Inputs: explicit regular files or stdin, PLAIN/BASE64/UTF16, at most 64 KiB each.\n"
         "Source chunks: 10 KiB content + 3 KiB forward peek, before decoding.\n"
         "PLAIN runs first; independent Base64/UTF16 fan-out iterates to depth five.\n"
         "UTF16 is the pinned printable-ASCII heuristic, not general Unicode decoding.\n"
         "No directory traversal, archives, other decoders, depth options, CLI verification/cache,\n"
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

static size_t find_bytes(br_slice s, br_slice needle, size_t start)
{
    if (start > s.len || needle.len > s.len - start) return SIZE_MAX;
    for (size_t i = start; i <= s.len - needle.len; ++i)
        if (!needle.len || !memcmp(s.data + i, needle.data, needle.len)) return i;
    return SIZE_MAX;
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
            size_t pos = find_bytes(input, key, from);
            if (pos == SIZE_MAX) break;
            results->items[j].chunk_offset = (int64_t)pos;
            results->items[j].chunk_offset_set = true;
            from = pos + key.len;
        }
    }
}

static bool locate(result_frame *frame)
{
    const source_frame *s = frame->source;
    if (s->source_type != 15) return false; /* Upstream stdin has neither lines nor ignore handling. */
    br_result *r = frame->result;
    br_slice key = effective_secret(r);
    size_t offset = r->chunk_offset_set && r->chunk_offset >= 0
        ? (size_t)r->chunk_offset : find_bytes(s->data, key, 0);
    frame->line = s->first_line;
    if (offset == SIZE_MAX || offset > s->data.len || key.len > s->data.len - offset) return false;
    int64_t line_offset = 0;
    for (size_t i = 0; i < offset; ++i) if (s->data.data[i] == '\n') ++line_offset;
    frame->line += line_offset;
    if (r->primary_secret.len) r->primary_line = line_offset;
    size_t start = offset + key.len, end = start;
    while (end < s->data.len && s->data.data[end] != '\n') ++end;
    br_slice tail = { s->data.data + start, end - start };
    static const unsigned char tag[] = "trufflehog:ignore";
    return find_bytes(tail, (br_slice){ tag, sizeof(tag) - 1 }, 0) != SIZE_MAX;
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
    ADD("Redacted", json_object_new_string(r->redacted ? r->redacted : ""));
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
    for (size_t i = 0; i < json_object_array_length(keys); ++i) {
        if (json_object_equal(key, json_object_array_get_idx(keys, i))) {
            json_object_put(object); json_object_put(key);
            return 0;
        }
    }
    if (json_object_array_add(keys, key)) goto failed;
    key = NULL;
    if (json_object_array_add(output, object)) goto failed;
    return 0;
failed:
    json_object_put(object); json_object_put(key);
    return fail(error, "cannot construct JSON result");
}

static int process_results(const cli_options *o, const source_frame *source,
                            const br_detector *d, br_results *results,
                            br_json *output, br_json *keys, char **error)
{
    static const char *const terms[] = { "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****" };
    if (o->clean || d->clean_always) {
        if (d->clean) d->clean(d, results, false);
        else br_clean_results(results, false);
    }
    duplicate_offsets(source->data, results);
    for (size_t i = 0; i < results->len; ++i) {
        if (stopped) return fail(error, "context canceled");
        br_result *r = &results->items[i];
        result_frame f = { .source = source, .detector = d, .result = r, .chunk_data = source->original };
        if (locate(&f)) continue;
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
            (!r->verified && !r->verification_error && !o->unverified)) continue;
        if (append_output(output, keys, &f, error)) return 1;
    }
    return 0;
}

static bool keyword_at(br_slice input, size_t at, const char *word)
{
    size_t n = strlen(word);
    if (n > input.len - at) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char a = input.data[at + i], b = (unsigned char)word[i];
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return false;
    }
    return true;
}

static br_span keyword_span(const br_detector *detector, size_t at, size_t input_len)
{
    uint64_t before = 512, after = 512;
    /* Independent overrides, in pinned order. Zero is present; -1 is absent. */
    if (detector->max_credential_span >= 0)
        before = after = (uint64_t)detector->max_credential_span;
    if (detector->max_secret_size >= 0) after = (uint64_t)detector->max_secret_size;
    if (detector->start_offset >= 0) before = (uint64_t)detector->start_offset;
    br_span span = {
        before > at ? 0 : at - (size_t)before,
        after > input_len - at ? input_len : at + (size_t)after,
    };
    if (span.begin >= span.end) span.begin = 0;
    return span;
}

static int scan_source(const cli_options *o, const source_frame *source,
                        const br_scan_ctx *ctx, const br_detector *const *registry,
                        size_t count, const bool *selected, br_json *output,
                        br_json *keys, char **error)
{
    br_slice input = source->data;
    for (size_t i = 0; i < count; ++i) {
        if (!selected[i]) continue;
        const br_detector *d = registry[i];
        if (!d->scan || !d->keywords || !d->nkeywords || d->max_secret_size < -1 ||
            d->max_credential_span < -1 || d->start_offset < -1)
            return fail(error, "invalid or unsupported detector prefilter capability");
        /* OR only the descriptor keywords, not its extraction-pattern aliases. */
        br_span merged = { SIZE_MAX, SIZE_MAX };
        for (size_t at = 0; at < input.len; ++at) {
            if (stopped) return fail(error, "context canceled");
            bool hit = false;
            for (size_t k = 0; k < d->nkeywords; ++k) hit |= keyword_at(input, at, d->keywords[k]);
            if (!hit) continue;
            br_span span = keyword_span(d, at, input.len);
            if (merged.begin == SIZE_MAX) merged = span;
            else if (span.begin <= merged.end) merged.end = span.end > merged.end ? span.end : merged.end;
            else {
                br_results results = {0};
                int rc = d->scan(d, ctx, false, (br_slice){ input.data + merged.begin, merged.end - merged.begin }, &results, error);
                if (!rc) rc = process_results(o, source, d, &results, output, keys, error);
                br_results_clear(&results);
                if (rc) return rc;
                merged = span;
            }
        }
        if (merged.begin != SIZE_MAX) {
            br_results results = {0};
            int rc = d->scan(d, ctx, false, (br_slice){ input.data + merged.begin, merged.end - merged.begin }, &results, error);
            if (!rc) rc = process_results(o, source, d, &results, output, keys, error);
            br_results_clear(&results);
            if (rc) return rc;
        }
    }
    return 0;
}

static int scan_decoders(const cli_options *o, const source_frame *source,
                          const br_scan_ctx *ctx, const br_detector *const *registry,
                          size_t count, const bool *selected, br_json *output,
                          br_json *keys, char **error)
{
    source_frame plain = *source;
    plain.decoder_name = "PLAIN";
    br_bytes plain_storage = {0};
    int rc = br_utf8_decode(source->original, &plain.data, &plain_storage, error);
    if (!rc && plain.data.len) rc = scan_source(o, &plain, ctx, registry, count, selected, output, keys, error);
    free(plain_storage.data);
    if (rc) return rc;

    /* Breadth-first iterativeDecode for the two ported non-PLAIN codecs.
     * Both first see original bytes, never PLAIN's sanitized view. Keep owned
     * outputs alive for frontier/seen slices; neither cache includes metadata. */
    br_bytes owned[DECODE_VIEW_LIMIT] = {0};
    br_slice current[DECODE_FRONTIER_LIMIT] = {0}, next[DECODE_FRONTIER_LIMIT] = {0};
    br_slice seen[DECODE_VIEW_LIMIT] = {0};
    size_t nowned = 0, nseen = 0, ncurrent = 1;
    current[0] = source->original;
    for (size_t depth = 0; !rc && ncurrent && depth < DECODE_MAX_DEPTH; ++depth) {
        size_t nnext = 0;
        for (size_t i = 0; !rc && i < ncurrent; ++i) {
            /* Preserve DefaultDecoders order: Base64, then UTF16. */
            for (size_t codec = 0; !rc && codec < 2; ++codec) {
                if (stopped) { rc = fail(error, "context canceled"); break; }
                bool applied = false;
                br_bytes decoded = {0};
                rc = codec == 0 ? br_base64_decode(current[i], &decoded, &applied, error)
                                : br_utf16_decode(current[i], &decoded, &applied, error);
                if (rc || !applied) { free(decoded.data); continue; }
                if (nowned == DECODE_VIEW_LIMIT) {
                    free(decoded.data);
                    rc = fail(error, "decoder view bound exceeded");
                    break;
                }
                owned[nowned++] = decoded;
                source_frame chunk = *source;
                chunk.decoder_name = codec == 0 ? "BASE64" : "UTF16";
                chunk.data = (br_slice){ decoded.data, decoded.len };
                /* Append/scan intermediate results even if their data was seen.
                 * Only scheduling is deduplicated; verification-cache flags and
                 * original chunk metadata must not be changed by decoder reuse. */
                rc = scan_source(o, &chunk, ctx, registry, count, selected, output, keys, error);
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
                        const br_scan_ctx *ctx, const br_detector *const *registry,
                        size_t count, const bool *selected, br_json *output,
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
        int rc = scan_decoders(o, &chunk, ctx, registry, count, selected, output, keys, error);
        if (rc) return rc;
        /* Peek bytes are read again as content in the next chunk. Stdin has no
         * line/ignore metadata, while filesystem advances only over raw content. */
        if (source->source_type == 15)
            for (size_t i = 0; i < content; ++i)
                if (source->original.data[start + i] == '\n') ++first_line;
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

int main(int argc, char **argv)
{
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) { usage(); return 0; }
    struct sigaction action = { .sa_handler = stop_signal };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    cli_options options = {0};
    char *error = NULL;
    bool *included = NULL, *excluded = NULL, *selected = NULL;
    br_json *output = NULL, *keys = NULL;
    bool curl_initialized = false;
    int rc = 1;
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
    ctx.transport = br_curl_transport_init(&error);
    if (!ctx.transport) goto done;
    curl_initialized = true;
    output = json_object_new_array(); keys = json_object_new_array();
    if (!output || !keys) { fail(&error, "out of memory initializing output"); goto done; }
    fprintf(stderr, "briar: limited native slice, %zu explicitly selected enabled detector(s); 10 KiB + 3 KiB source chunks, PLAIN/BASE64/UTF16 only (decode depth five), no other decoders or CLI verification\n", nselected);
    size_t nsources = !strcmp(options.command, "stdin") ? 1 : options.npaths;
    for (size_t i = 0; i < nsources; ++i) {
        bool is_stdin = !strcmp(options.command, "stdin");
        int fd = STDIN_FILENO;
        if (!is_stdin) {
            struct stat st;
            if (lstat(options.paths[i], &st)) { fail(&error, "cannot stat filesystem input"); goto done; }
            if (!S_ISREG(st.st_mode)) { fail(&error, "unsupported: filesystem input must be an explicit regular file, not a directory or symlink"); goto done; }
            int flags = O_RDONLY | O_NONBLOCK;
#ifdef O_NOFOLLOW
            flags |= O_NOFOLLOW;
#endif
            fd = open(options.paths[i], flags);
            if (fd < 0) { fail(&error, "cannot open filesystem input"); goto done; }
            if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
                close(fd); fail(&error, "filesystem input changed or is not regular"); goto done;
            }
        }
        br_bytes input = {0};
        int read_rc = read_input(fd, &input, &error);
        if (!is_stdin && close(fd) && !read_rc) read_rc = fail(&error, "cannot close filesystem input");
        if (read_rc) { free(input.data); goto done; }
        source_frame source = {
            .source_id = 1, .job_id = 1, .secret_id = 0, .first_line = 1,
            .source_type = is_stdin ? 40 : 15,
            .source_name = is_stdin ? "trufflehog - stdin" : "trufflehog - filesystem",
            .path = is_stdin ? NULL : options.paths[i], .original = { input.data, input.len },
        };
        int scan_rc = scan_chunks(&options, &source, &ctx, registry, count, selected, output, keys, &error);
        free(input.data);
        if (scan_rc) goto done;
    }
    if (stopped) { fail(&error, "context canceled"); goto done; }
    for (size_t i = 0; i < json_object_array_length(output); ++i) {
        const char *line = json_object_to_json_string_ext(json_object_array_get_idx(output, i),
                                                        JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
        if (!line || puts(line) == EOF) { fail(&error, "cannot write JSON output"); goto done; }
    }
    if (fflush(stdout)) { fail(&error, "cannot flush JSON output"); goto done; }
    rc = options.fail && json_object_array_length(output) ? 183 : 0;
done:
    if (rc && rc != 183) fprintf(stderr, "briar: %s\n", error ? error : "scan failed");
    free(error); free(options.paths); free(included); free(excluded); free(selected);
    json_object_put(output); json_object_put(keys);
    if (curl_initialized) curl_global_cleanup();
    return rc;
}
