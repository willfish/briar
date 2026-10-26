/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_H
#define BRIAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BR_ABI_REVISION 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct json_object br_json;
typedef struct { const unsigned char *data; size_t len; } br_slice;
typedef struct { unsigned char *data; size_t len; } br_bytes;
typedef struct br_detector br_detector;
typedef struct br_scan_ctx br_scan_ctx;

/* Zero-initialize. All non-const pointers and JSON references are owned. */
typedef struct {
    int32_t detector_type;
    char *detector_name;
    bool verified, verification_from_cache;
    br_bytes raw, raw_v2;
    char *redacted;
    br_json *extra_data, *secret_parts, *structured_data;
    char *verification_error;
    br_bytes primary_secret;
    int64_t primary_line, chunk_offset;
    bool chunk_offset_set;
} br_result;
typedef struct { br_result *items; size_t len, cap; } br_results;

typedef struct { const char *name, *value; } br_header;
/* AWS is a distinct SDK-client policy, currently injected-transport only. */
typedef enum {
    BR_HTTP_SANE, BR_HTTP_DETECTOR_LOCAL, BR_HTTP_DETECTOR_PUBLIC,
    BR_HTTP_PINNED_RETRYABLE, BR_HTTP_RETRYABLE, BR_HTTP_AWS
} br_http_profile;
typedef struct {
    const char *method, *url;
    const br_header *headers;
    size_t nheaders;
    br_slice body;
    br_http_profile profile;
    uint32_t timeout_ms;
    int32_t detector_type;
    br_slice dedup_key;
} br_http_request;
typedef struct {
    int status;
    const br_header *headers;
    size_t nheaders;
    br_slice body;
    const char *body_error;
} br_http_response;
typedef struct {
    void *user;
    int (*send)(void *, const br_scan_ctx *, const br_http_request *,
                br_http_response *, char **error);
    void (*release)(void *, br_http_response *);
} br_transport;

typedef struct {
    const char *const *configured;
    size_t nconfigured;
    const char *cloud;
    bool use_cloud, use_found;
} br_endpoints;
struct br_scan_ctx {
    const br_transport *transport;
    int64_t deadline_monotonic_ms;
    bool (*cancelled)(void *);
    void *cancel_user;
    const char *user_agent;
    const br_endpoints *endpoints;
    const br_json *options;
};
struct br_detector {
    int32_t type, version;
    const char *name, *custom_name, *description;
    const char *const *keywords;
    size_t nkeywords;
    int64_t max_secret_size, start_offset, max_credential_span;
    const void *state;
    int (*scan)(const br_detector *, const br_scan_ctx *, bool verify,
                br_slice input, br_results *out, char **error);
    void (*clean)(const br_detector *, br_results *, bool verification_enabled);
    bool clean_always;
    bool (*false_positive)(const br_detector *, const br_result *, char **reason);
    int (*validate_endpoints)(const br_endpoints *, char **error);
    const char *cloud_endpoint;
};

/* Search borrowed bytes from start; SIZE_MAX means absent. An empty needle matches start. */
size_t br_slice_find(br_slice input, br_slice needle, size_t start);

void br_result_clear(br_result *);
void br_results_clear(br_results *);
/* Move and zero owned only on success. */
int br_results_push(br_results *, br_result *owned);
/* NULL cause is a no-op; every occurrence of every nonempty secret is redacted. */
int br_result_set_verification_error(br_result *, const char *innermost_error,
                                     const br_slice *secrets, size_t nsecrets);
void br_clean_results(br_results *, bool verification_enabled);
/* ASCII-only Shannon entropy for credential filtering. Empty, invalid or
 * non-ASCII input returns zero; this is not Go's Unicode-rune calculation. */
double br_ascii_shannon_entropy(br_slice);
bool br_known_false_positive(br_slice, const char *const *terms, size_t nterms,
                             bool word_check, char **reason);
/* Missing transports fail closed. Release once after every send, even failure.
 * Injected transports own the requested profile's redirect and address policy;
 * the native adapter rejects profiles whose policies are not implemented. */
int br_http_send(const br_scan_ctx *, const br_http_request *,
                 br_http_response *, char **error);
void br_http_release(const br_scan_ctx *, br_http_response *);
/* Build an owned, NUL-terminated Basic Authorization value without I/O. */
int br_http_basic_auth(br_slice username, br_slice password, char **out, char **error);

/* Registry implementations are owned by src/detectors. Initialize pre-workers. */
int br_registry(const br_detector *const **out, size_t *count, char **error);
bool br_detector_is_default(const br_detector *, const br_json *feature_flags);
const char *br_detector_type_name(int32_t type);

/* PLAIN decoding borrows valid input unchanged; otherwise decoded aliases storage.
 * Zero-initialize storage and free(storage.data) after using decoded. Original input
 * is never modified. Empty input stays empty; errors clear both outputs. */
int br_utf8_decode(br_slice input, br_slice *decoded, br_bytes *storage, char **error);

typedef struct br_regex br_regex;
typedef struct { size_t begin, end; } br_span;
typedef int (*br_match_fn)(void *, const br_span *groups, size_t ngroups);
int br_regex_compile(const char *pattern, br_regex **out, char **error);
/* Unmatched captures are {SIZE_MAX, SIZE_MAX}; callback spans are temporary. */
int br_regex_each(const br_regex *, br_slice, br_match_fn, void *, char **error);
void br_regex_free(br_regex *);
int br_prefix_regex(const char *const *keywords, size_t count, char **pattern);
int br_regex_compile_prefixed(const char *const *keywords, size_t count,
                              const char *capture, br_regex **out, char **error);

#ifdef __cplusplus
}
#endif
#endif
