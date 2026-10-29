# Native TruffleHog port

## Boundary and implementation order

Reproduce all behavior of TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`, as pinned in `UPSTREAM.json`. `.reference/trufflehog` is read-only specification evidence, never runtime code. Port detector logic and supporting components directly to C. Do not build a general Go runtime/compatibility framework or call Go as the implementation.

Use the declared PCRE2, libcurl, json-c and OpenSSL dependencies for matching, HTTP, structured values and native request signing. Track additional archive, database, SSH or other native dependencies with their concrete ports. Preserve AGPL-3.0-only licensing for the port and upstream notices and file-specific licenses, including the isolated MPL-2.0 MySQL DSN translation. Development and acceptance use synthetic inputs and injected responses, never real credentials or service verification.

Build in vertical slices: shared primitives and three complete detectors; remaining detector families and decoders; sources/file handlers; analysis and remaining CLI/runtime behavior. Each slice leaves the full inventory visible. Unsupported behavior is an explicit gap, not an empty successful scan.

Private URL helpers share selected byte parsing, decoding and query lookup, while Jira endpoint, request and diagnostic policy and LDAP's authority URL.String projection stay in named helpers. Their semantic baseline is the selected Go 1.26.7 source with the pinned binary's urlstrictcolons=0 setting, not a general Go runtime or proof of native/Nix-patch equivalence.

The private SQL boundary clones immutable detector configuration and exchanges DSN bytes, database handles and explicit ordinary error-type facts through Open, Ping and Close. It does not accept verification verdicts or use global callbacks or HTTP userdata. The separate MySQL DSN translation preserves ordered validation and lexical address normalization even before verification; reached native database, named timezone and ambient TLS/key-registry behavior remains guarded rather than approximated. Driver-specific connection acquisition and context timing are not interchangeable.

The private LDAP boundary similarly copies immutable I/O configuration and exchanges owned innermost error bytes, explicit error presence, typed cancellation/network facts and connection handles. Empty diagnostic bytes do not mean success. Dial, Bind and StartTLS remain whole library calls; StartTLS inherits the dial-established connection context rather than receiving a new deadline. Native LDAP remains unsupported. Scheme routing follows the parsed scheme, including empty-authority URLs whose serialized form omits the double slash.

The shared time helper implements one fixed Unix-second String projection, not a Go layout interpreter. It preserves unsigned calendar wrapping and initializes an immutable Local timezone lazily. The pinned Linux reference's Nix-patched timezone search, TZif transitions, POSIX tails and STORED-ZIP fallback remain explicit; libc timezone state is not substituted. Initial GOROOT and first-use TZ have different sampling lifetimes. NumericDate conversion, truncation and metadata publication remain detector responsibilities.

Provider constructor skips do not bypass required capture, finding or dynamic URL work. JupiterOne's reached error setter runs before release, including a missing shared diagnostic, while fatal formatting or setter failure still performs attempted-send cleanup. MagicBell keeps required emails hidden, Mailboxlayer distinguishes read-drop from send-error retention, and MailJet Basic authorization is literal captured text rather than a fresh Base64 encoding.

## Shared C ABI, revision 1

This is an internal source ABI, not a stable plugin interface. The engine builder owns its declaration in `include/briar.h`. Forward-declare json-c values; do not expose PCRE2 or curl handles. All sizes/offsets are byte-based unless specified otherwise.

```c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct json_object br_json;
typedef struct { const unsigned char *data; size_t len; } br_slice;
typedef struct { unsigned char *data; size_t len; } br_bytes;
typedef struct br_detector br_detector;
typedef struct br_scan_ctx br_scan_ctx;

typedef struct {
    int32_t detector_type;
    char *detector_name;                 /* custom name, otherwise empty */
    bool verified, verification_from_cache;
    br_bytes raw, raw_v2;
    char *redacted;
    br_json *extra_data, *secret_parts, *structured_data;
    char *verification_error;            /* sanitized setter only */
    br_bytes primary_secret;
    int64_t primary_line, chunk_offset;
    bool chunk_offset_set;
} br_result;
typedef struct { br_result *items; size_t len, cap; } br_results;

typedef struct { const char *name, *value; } br_header;
typedef enum {
    BR_HTTP_SANE, BR_HTTP_DETECTOR_LOCAL, BR_HTTP_DETECTOR_PUBLIC,
    BR_HTTP_PINNED_RETRYABLE, BR_HTTP_RETRYABLE
} br_http_profile;
typedef struct {
    const char *method, *url;
    const br_header *headers;
    size_t nheaders;
    br_slice body;
    br_http_profile profile;
    uint32_t timeout_ms;                 /* 0 = profile default */
    int32_t detector_type;
    br_slice dedup_key;                  /* empty = no request coalescing */
} br_http_request;
typedef struct {
    int status;
    const br_header *headers;
    size_t nheaders;
    br_slice body;
    const char *body_error;              /* read failure after headers */
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
    int64_t deadline_monotonic_ms;        /* 0 = no deadline */
    bool (*cancelled)(void *);
    void *cancel_user;
    const char *user_agent;
    const br_endpoints *endpoints;        /* validated before workers */
    const br_json *options;              /* immutable detector config */
};
struct br_detector {
    int32_t type, version;               /* protobuf ID; 0 = unversioned */
    const char *name, *custom_name, *description;
    const char *const *keywords;
    size_t nkeywords;
    int64_t max_secret_size, start_offset, max_credential_span;
                                        /* -1 = interface absent */
    const void *state;                   /* immutable compiled/config state */
    int (*scan)(const br_detector *, const br_scan_ctx *, bool verify,
                br_slice input, br_results *out, char **error);
    void (*clean)(const br_detector *, br_results *, bool verification_enabled);
    bool clean_always;
    bool (*false_positive)(const br_detector *, const br_result *, char **reason);
    int (*validate_endpoints)(const br_endpoints *, char **error);
                                        /* NULL = not customizable */
    const char *cloud_endpoint;          /* NULL = no CloudProvider */
};

void br_result_clear(br_result *);
void br_results_clear(br_results *);
int br_results_push(br_results *, br_result *owned);
int br_result_set_verification_error(br_result *, const char *innermost_error,
                                     const br_slice *secrets, size_t nsecrets);
void br_clean_results(br_results *, bool verification_enabled);
bool br_known_false_positive(br_slice, const char *const *terms, size_t nterms,
                             bool word_check, char **reason);
int br_http_send(const br_scan_ctx *, const br_http_request *,
                 br_http_response *, char **error);
void br_http_release(const br_scan_ctx *, br_http_response *);

/* Initialize before workers; publish only actual C implementations. */
int br_registry(const br_detector *const **out, size_t *count, char **error);
bool br_detector_is_default(const br_detector *, const br_json *feature_flags);
const char *br_detector_type_name(int32_t type);

typedef struct br_regex br_regex;
typedef struct { size_t begin, end; } br_span;
typedef int (*br_match_fn)(void *, const br_span *groups, size_t ngroups);
int br_regex_compile(const char *pattern, br_regex **out, char **error);
int br_regex_each(const br_regex *, br_slice, br_match_fn, void *, char **error);
void br_regex_free(br_regex *);
int br_prefix_regex(const char *const *keywords, size_t count, char **pattern);
```

### Ownership and execution contracts

- Zero-initialize results/collections. Result strings, bytes and JSON references are owned; clear functions release them. `br_results_push` moves and zeros its argument only on success. Preserve NULL versus empty bytes/maps where upstream distinguishes them. `extra_data` and `secret_parts` contain string values; `structured_data` follows `proto/detectors.proto`, not an untyped replacement schema.
- Functions returning `int` use zero for success, nonzero for failure. Owned `char **error`/`reason` outputs are caller-freed and initialized to NULL. A scan failure is distinct from a candidate's verification error. Verification rejection is `verified=false` with no error; indeterminate verification has a sanitized error. Skipped verification also has no error, as upstream does. Do not replace these independent fields with one boolean or lose errors on cache copies.
- `br_result_set_verification_error` receives the innermost cause, replaces every supplied secret with `[REDACTED]`, and does nothing for a NULL cause. Never log transport errors before redaction. Keep `raw_v2`, `secret_parts`, primary-secret value/line, and the explicit offset-presence bit even when the first batch leaves them empty. A result does not acquire an invented version field; its detector instance supplies the version.
- Descriptors, compiled patterns and options are immutable during scans. Initialize the registry before starting workers; propagate initialization errors. Each scan owns its results and regex match state. Check cancellation/deadlines in loops and I/O. Custom configured descriptors use the same ABI, with lifetime managed by the configuration owner.
- Built-in `name` is the protobuf enum name; `custom_name` is empty except for custom detectors. Registry identity is `(type, version, custom_name)`, not just the enum. Version 0 means unversioned in a descriptor, but means all versions in CLI selectors. A selector is not a single-instance lookup.
- `br_registry` exposes compiled implementations, including fully ported disabled ones for direct testing. Default selection first applies upstream registry membership and feature gates, then include/exclude selectors. An include selector must not resurrect a commented-out upstream constructor. Keep the inventory separate from this executable registry: no metadata-only entries, NULL scans or generic regex fallback stubs. `br_detector_is_default` inherits pinned OSS CLI feature defaults for NULL/missing overrides, not Go package atomic-zero defaults. The implemented `BraintrustDetectorEnabled` override accepts only an exact-name JSON boolean; false reproduces its package-zero state. Invalid values or non-object flags disable that gated identity, without enabling disabled, custom or unsupported-version identities.
- A NULL `clean` selects `br_clean_results`; a NULL `false_positive` selects the shared default checker. Do not clean inside `scan`: the engine sometimes bypasses cleaning, notably for targeted reverification. Endpoint options replace mutable Go setters with validated per-scan configuration. For customizers, default both endpoint-use flags to true and supply `cloud_endpoint` when present.
- `br_regex_each` yields non-overlapping matches in source order, with group 0 for the whole match and byte spans for captures; unmatched captures are `{SIZE_MAX, SIZE_MAX}`. Spans live only during the callback. Callback nonzero aborts and propagates failure; regex/resource errors are not “no matches.” Compiled code is shareable, match scratch space is not.

### Transport boundary

`br_http_send` applies shared headers/policy, including the upstream `TruffleHog` User-Agent plus configured suffix, before calling the injected transport. The mock sees the effective request, including repeated headers, method, exact URL/query and binary body. Responses remain valid until `br_http_release`, which delegates to `release`. Initialize a response before sending and release it once after every send, including failure; adapters must accept an empty response.

Use the private length-bearing endpoint collection when found captures admit NUL. It preserves original bytes, empty configured entries and source order: deduplicate configured values only, then append enabled cloud/found values without cross-deduplication. Configured/cloud settings remain ABI1 C strings, and the existing string helpers are unchanged. Collection neither normalizes nor validates provider URLs.

A nonzero `send` return means no usable HTTP response. A body-read failure after response headers instead returns success with `status` and `body_error`; only detectors that read that body consume the error. This distinction is required by Abstract and Abyssale, which inspect status only. Do not let eager curl buffering turn their ignored body errors into verification failures. Keyed singleflight differs: its transport buffers the whole body before returning, so any read error becomes a send error.

Private owned clients in `src/http_internal.h` provide one in-flight namespace per upstream client transport. They preserve complete type-and-credential key bytes, detach winning work from caller cancellation while retaining its entry-time deadline, and give waiters independent response/error copies. Remove completed keys before publishing results; this is not a persistent cache. Ordinary borrowed transports still reject keyed requests.

The client owns the backend lifetime and the winning request/context snapshot. Keep prepared request storage, including synthesized headers and User-Agent, alive through raw backend release. Deep-copy JSON options before detachment because the configured json-c reference counts are not atomic. Unsupported custom option state fails closed. Drain active sends and abandoned workers before destroying the backend or ending curl's lifetime. The ordinary ABI1 path still ends synthesized-request storage at send return; it does not gain this through-release guarantee.

Owned clients accept SANE, LOCAL and PUBLIC without changing the declared profile. PUBLIC retains its ten-second policy; an injected backend must serve that contract. Native curl still rejects PUBLIC before I/O, including through owned coalescing, so this capability does not establish DNS/SSRF or full native Go HTTP parity. Keyed native SANE redirects fail closed because the curl adapter wraps a whole request operation rather than one RoundTrip. Explicit owned-client integration must preserve source client namespaces; do not infer ownership from an arbitrary injected transport or use one global group for unrelated clients.

The private native runtime owns curl's initialization and distinct source clients for Cliengo, Clockify, Databox, Duffel's default, Finage, Geocode, Gitter, HolidayAPI, IPInfo and the two Vault token implementations. Each row declares its actual profile; the two Vault clients remain separate PUBLIC instances rather than sharing a detector-type namespace. Bind a local scan context before each detector invocation and use that same context through send/release. Match actual built-in descriptor identities, not arbitrary detector types; preserve injected or explicitly selected clients. Unknown descriptors keep the raw transport and its keyed guard. After callers and response releases are quiescent, drain every client before destroying any client or cleaning up curl. These per-runtime instances do not reproduce Go package-client sharing across independent engines or Duffel's optional custom-client override. CLI scanning remains NoV.

A missing transport fails closed, never falls back to curl. Tests install a fake with no DNS/socket access and can return timeouts, cancellation, headers, arbitrary body bytes and partial-body errors. Never access the network behind the injected boundary. Later non-HTTP verifiers and sources need concrete protocol-specific injected adapters, for example DNS, database, SSH and TLS operations, rather than pretending every verification is HTTP.

`common.SaneHttpClientTimeOut(5s)` wraps Go DefaultTransport, not the ordinary saneTransport. The private `br_http_default_transport_5s_send` boundary permits knowingly installed byte backends only: SANE plus explicit 5000 ms projects common request preparation, not source transport-policy equivalence. It rejects known raw/copied curl, every owned SANE/LOCAL/PUBLIC client and nonempty coalescing keys before I/O. Arbitrary forwarding wrappers cannot be detected or certified. Native default-transport behavior and ordinary request-storage lifetime remain separate gaps; do not substitute another public profile.

Package `http.Post` instead uses DefaultClient with zero client timeout and a background request context, without the common TruffleHog UA wrapper. Its private JSON-POST byte boundary uses an unpublished DefaultClient tag, rejected by ordinary public preparation. Pass only the explicitly installed injected transport into the synchronous background context; caller cancellation, deadline, UA, endpoints and options do not participate. Do not synthesize a wire UA or run SANE preparation. Known raw/copied curl, every owned client and nonempty coalescing keys remain rejected before I/O. Keep provider request storage through one ordinary release per attempt, but never retain the projected context beyond send return. Native policy, global DefaultClient replacement, redirects and streaming behavior remain unsupported, as do uncertifiable forwarding wrappers.

GitHub OAuth2 uses the provider-private byte interface in `src/detectors/github_oauth2_private.h`, installed through a caller-owned state clone. The source SDK selects a context-provided client or Go DefaultClient, with no explicit SDK User-Agent or client timeout; do not substitute SANE preparation, scanner UA or another public profile. Callbacks exchange only request, response and error bytes, never parsed tokens or verification booleans. Their state is borrowed synchronously through scan completion; release every attempted response before retry while keeping request values alive. Negative callback/resource failures are fatal before SDK error suppression or probing. Native SDK integration fails explicitly at the needed request step, after deterministic request construction; nil-context source panics have a separate safe boundary.

GitHub's two versions use the existing endpoint configuration without inventing SDK state. NULL settings select engine defaults, including the cloud endpoint; an explicit zeroed `br_endpoints` represents a source scanner with no endpoints and makes no requests. Construct literal `endpoint + "/user"` without joining or normalization. After allocation and nil-context handling, support only endpoints matching `https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?`, with ASCII checks and no additional DNS or numeric-port rules. Other forms fail explicitly unsupported before transport callbacks. Apply this boundary only when an attempt is reached: earlier success must win over a later unsupported endpoint, while NoV, v1's early-filtered tokens and zero endpoints must not encounter it. This provider-local subset is not full Go constructor parity and must not be widened by diagnostic-text classification or injected mock success.

GitLab versions and GitLab OAuth use that same supported URL subset only for reached verification attempts. Their endpoint loop also constructs each finding, so explicit zero endpoint settings yield no findings even in NoV. Endpoint bytes belong to RawV2 and secret parts; do not prevalidate NoV endpoint metadata or let later unsupported endpoints defeat an earlier successful binding. GitLab versions share response policy, not source-client identity or extraction grammar.

Vault tokens use discovery group1 origins, while AppRole retains whole URL matches and deduplicates the final endpoint list. Both preserve original endpoint bytes in NoV, including NUL. Token verification reaches the provider-local canonical ASCII JoinPath subset before nil-context construction and lexically cleans paths without changing BASE metadata or coalescing keys. AppRole instead constructs sorted JSON and literally appends its login path before nil handling, then applies its reached canonical request boundary. Do not interchange these builders, normalize NoV endpoints or certify unsupported URL forms with an injected success.

GoCanvas retains its nonempty GET form body; the native curl bodyless-GET guard is not bypassed. Its XML decoder stays provider-local, with separate decoded, definite source-decode failure, unsupported and resource outcomes. After successful ReadAll, decode failures drop the pair at every status; read errors instead retain a false finding. Only direct local-name Error children populate the error slice, and each direct ErrorCode is parsed in source order until the first failure. The supported subset is complete UTF-8 XML 1.0 without DTDs. Use context-local deny-all resource loading plus NO_XXE and NONET, never global loaders, recovery or entity substitution. Source-accepted trailing input and namespace forms outside this subset fail explicitly unsupported, not as ordinary invalid credentials.

Google OAuth access-token verification uses ordinary SANE HTTP, not the credential SDK byte adapter. Its optional expiry formatter stays private to the provider. Parse signed decimal int64 without trimming; syntax/range errors omit expiry before any timezone check. A valid parsed value reaches formatting only after successful typed 200 decoding and the four mandatory metadata strings. The bounded implementation supports explicit stable TZ=UTC or empty TZ, years 0001 through 9999, and checked C time representation. Other Local configurations or valid times outside that subset fail explicitly unsupported. Never mutate process timezone state, assume unset TZ means UTC, or treat a formatting boundary as an ordinary parse failure. Full Go Local initialization, timezone data and transition behavior remain separate migration work.

FTP uses the provider-private byte-I/O contract in `src/detectors/ftp_private.h`, configured by cloning its descriptor/state rather than mutating global state or borrowing HTTP transport userdata. Typed reply provenance is distinct from diagnostic text. Dial timeout and the fresh post-connect socket deadline are separate budgets; partial causes and handles are owned and each connection is closed once. Scripted control-flow evidence does not supply a native DNS/TCP adapter, which remains explicitly unsupported.

Profiles encode actual upstream client behavior, not curl defaults. `SANE` has a 5-second total timeout, 2-second dial and 3-second TLS handshake timeout, normal Go redirect behavior, environment proxy use, and no retry layer. Detector clients have a separate 10-second default, explicit redirect restrictions and local-address policies. Pinned/retryable profiles must preserve certificate, backoff, retry and opt-in coalescing rules when ported. Unsupported profiles must error, not silently behave like `SANE`.

`BR_HTTP_BROWSERSTACK` is an injected-only policy for the source's bare Go client with a fresh public-suffix cookie jar per credential pair. Zero timeout means no client-level total timeout; cancellation, explicit nonzero timeouts and representable deadlines still apply. An otherwise unbounded deadline exceeding ABI1's 32-bit millisecond field fails explicitly before transport invocation rather than wrapping or silently shortening it. The shared adapter supplies User-Agent once when the provider omits it. Native curl rejects this profile before I/O. Mock first-request/status results do not establish cookie, public-suffix, redirect, fresh-session or override-client mutation/concurrency parity.

## Engine semantics that must survive the port

The pipeline is source enumeration/read -> format handlers/chunking -> ordered decoders -> keyword/span prefilter -> detector/cache and overlap handling -> cleaning/entropy -> line/link/ignore processing and false-positive marking -> result selection/deduplication -> dispatcher/output. Preserve the actual branches in `pkg/engine/engine.go`; this outline does not replace them.

- Keywords are an OR, not an AND. Preserve the span calculation precedence: multipart span, then maximum secret size, then start offset; absence is not the same as zero. Keep original pre-decode bytes separately from decoded windows and their offsets.
- Default cleaning retains verified results keyed by `Redacted`, with the last duplicate winning. With no verified results it keeps only the first result. Verified map iteration order is unspecified. Do not substitute “keep all verified” without deduplication, or unconditionally invoke cleaning when `--filter-unverified` is off. Custom cleaners may override that setting.
- Default false-positive handling validates UTF-8, lowercases, checks the seven default terms (`example`, `xxxxxx`, `aaaaaa`, `abcde`, `00000`, `sample`, `*****`), then the four embedded word/badlist/programming-book/UUID lists. Check whole terms and substrings; preserve custom checkers and optional word checking. Run it at upstream call sites, not as an unconditional extraction filter. Entropy counts runes but divides by byte length; do not silently replace it with a textbook byte-only formula.
- The engine's result envelope must additionally retain source metadata, source/job/secret IDs, source type/name, detector description, decoder type, wordlist-FP flag and original chunk data. Match `proto/source_metadata.proto` and `ResultWithMetadata`, including primary-secret line placement, repeated occurrences and ignore tags. JSON output naming follows its printer, not a dump of the C struct.
- Keep cache identities distinct. Registry/selection includes version and custom name, but the verification cache hashes `Raw || RawV2 || big-endian int32 detector type` with BLAKE2b, without version. It copies verification status/error, and the engine sets the cache flag. Request coalescing is opt-in by type/credential. Output deduplication also includes source location and custom name; a global raw-secret set is wrong. Cache and formatting details need their own acceptance evidence.

## First complete offline batch

Port these directly from `pkg/detectors/{abstract,abuseipdb,abyssale}`. Each uses `PrefixRegex([keyword])` followed by the pattern below, trims capture 1, emits its protobuf type, `Raw`, and `SecretParts={"key": capture}`. Leave `RawV2`, `Redacted` and other fields at upstream defaults; copy descriptions exactly.

| Detector | ID/default membership | Capture pattern | Verification request and classification |
|---|---|---|---|
| Abstract | 384, disabled | `\b([0-9a-z]{32})\b` | GET `https://exchange-rates.abstractapi.com/v1/live/?api_key=KEY&base=USD`, `Content-Type: application/json`; 200 verified, 401 rejected |
| AbuseIPDB | 521, enabled | `\b([a-z0-9]{80})\b` | GET `https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8`, `Key: KEY`; 200 verified only if successfully read body contains literal `ipAddress`; 401 rejected |
| Abyssale | 239, enabled | `\b([a-z0-9A-Z]{40})\b` | GET `https://api.abyssale.com/ready`, `x-api-key: KEY`; 200 verified, 403 rejected |

For all three, other statuses produce `unexpected HTTP response status N`; transport failures become sanitized verification errors without dropping the candidate. AbuseIPDB uses a byte substring check, not JSON parsing. Abstract and Abyssale ignore response bodies. None applies detector-local false-positive filtering or custom cleaning.

After implementing, test extraction, prefix distance 40/41, CR/LF separation, boundaries, case, multiple findings and exact result fields. With verification disabled assert zero transport calls. With a fake, assert the complete requests and cover success, rejection, unexpected status, timeout/cancellation and secret redaction. Cover AbuseIPDB's missing substring, malformed-but-containing-substring body and body-read failure; cover ignored body-read errors for the other two. Exercise default selection separately from direct disabled-detector calls. Finish with one synthetic filesystem/stdin-to-JSON run with verification disabled and assertions for engine false positives, cleaning and duplicate line placement. This batch can be accepted entirely offline; it does not establish parity for any other detector or source.

### Construction policies and identity

Different constructors do not necessarily define different detector identities. Generic's zero-value scanner has an empty exclusion set; New() installs 14 source regexes. Separate C factories preserve both states, but registry membership follows the actual disabled zero-value constructor. Do not silently substitute New(), register a duplicate identity or let explicit selection override upstream disabled membership. Provider-local exclusion and Base64-suppression logic stays in its named module.

### Google credential boundary

`gcp_json` supplies only the string codecs shared by the two closed credential structs: retain callback JSON values while borrowing their text, repair invalid UTF8 on typed decoding, and marshal fixed field order with Go's HTML/separator escaping. GCP-only cleanup and Go literal unquoting stay provider-local. Do not replace those distinct codecs with one JSON unquote or generic map serializer.

`gcp_oauth` defines immutable cloned-state HTTP byte I/O for JWT grants, refresh grants and IAM requests. Its roles describe genuinely different source clients without widening the public HTTP enum or borrowing HTTP userdata. Callbacks return response bytes/read errors, never SDK tokens or verification decisions; C implements signing, parsing and provider policy. Complete request values survive send through release, including failed sends. Native SDK transport remains unsupported. Typed RetrieveError provenance and source error-stage decisions stay in the provider, before diagnostic formatting. Preserve the C result's byte-sliced Redacted value; only the outer JSON string applies Go-style invalid-byte replacement.

### Disjoint build ownership

- Engine/CLI builder: `include/briar.h`, top-level build rules, common result/regex/false-positive/HTTP helpers, engine/CLI/output files, and corresponding non-detector tests. Implement only needed helpers, not a Go compatibility layer.
- Detector builder: `src/detectors/**`, including its compiled registry and first three descriptors/ports, and `tests/detectors/**`. Consume the shared header; do not edit it independently. Request missing helper changes through the engine builder.
- Architecture changes are confined to this file. Inventory/evidence artifacts belong to the coordinator until separately assigned. No shared implementation file has two owners.

## Full-scope parity ledger

Use `upstream-inventory.json` for source discovery and `parity.json` for per-detector/per-component acceptance, against the pinned commit. The inventory records 921 `FromData` implementations, 892 registry candidates (890 composite literals and two factories), and 34 supporting components, including shared detector helpers. None of these counts is implementation credit.

Reconcile discovery with concrete method sets, factories, promoted/embedded methods, all versions, commented defaults, feature gates and configurable custom detectors. Cross-check `proto/detector_type.proto`; enum-only names are metadata, not implementations. Retain the two AWS factory registrations (`aws_access_keys.New()` and `aws_session_keys.New()`) as factories, not composite literals. Also retain 28 commented constructors and 34 feature gates. Inspect inherited behavior: Accuweather v2 overrides `FromData`/`Version` but delegates processing and inherits other methods from v1. Preserve disabled reasons and the distinction between CLI feature defaults (enabled) and package atomic zero defaults.

Each detector row records implementation path/receiver/factory, enum ID/name, version/custom identity, default/disabled/gated status, keywords, optional capabilities and native file/owner. Track these dimensions independently:

| Dimension | Acceptance evidence required |
|---|---|
| Extraction | All patterns and non-regex parsers, captures, multipart pairing/order, trimming/decoding and emitted raw identities |
| Filtering/cleaning | Detector-local checks, wordlists, entropy, custom cleaners/FP methods and their engine call-site interactions |
| Verification | Exact requests/protocol operations, auth/signatures, endpoints, status/body rules, negative/unknown outcomes, timeouts and opt-in deduplication |
| Result metadata | Description/type, redaction, extra/structured data, secret parts, primary-secret/offset behavior and output integration |
| Versioning/registry behavior | Each concrete version, inherited behavior, selector wildcards, disabled membership, factories, feature defaults and endpoint capabilities |
| Acceptance | Named synthetic fixtures, upstream source/test references, native checks and remaining discrepancies for every applicable dimension |

Follow `parity.json`'s aspect names and completion rules: missing entries are `not_started`; use `partial` until every applicable aspect has named offline evidence, then `verified`. A not-applicable aspect needs source justification. Inventory generation, pattern compilation, or an extraction example earns no verification/metadata/completion credit. Require engine-integration evidence too; disabled/versioned implementations remain in scope. Derive missing synthetic cases from source without copying unknown credential fixtures. Offline acceptance proves the pinned protocol contract, not present-day service acceptance.

Inventory every supporting package and root entry point too. Grouping below defines workstreams, not permission to omit individual components:

| Workstream | Required inventory and acceptance scope |
|---|---|
| Engine | Keyword matching/spans, overlap verification suppression, chunk/window handling, concurrency/cancellation, cleaning/FP/entropy order, line/link/ignore rules, dispatch and cache behavior |
| Decoders | Plain/UTF8 first, Base64, UTF16, escaped Unicode, HTML; enablement, malformed-input handling, original bytes and cross-decoder duplicates |
| Sources | Filesystem, stdin, Git, GitHub, GitHub experimental, GitLab, S3, GCS, Docker, Syslog, CircleCI, TravisCI, Postman, Elasticsearch, Jenkins, HuggingFace, JSON enumerator; enumeration, auth, pagination, filters, resume/progress and metadata, plus multi-scan orchestration |
| Files/input | `handlers`, archive formats, ar/RPM/APK, binary/size/depth/time limits; `gitparse`, `giturl`, `buffers`, `iobuf`, `writers`, temporary-file lifecycle and source chunking |
| Config/custom detectors | YAML/protobuf schemas and defaults, enum/version/range selectors, endpoint validation, custom regex combinations/exclusions/validations, 100-match limit, primary regex and webhook success/rotation behavior |
| Analysis | Every `analyzer/analyzers` implementation, provider permissions/resources, errors, configuration, CLI and permission-data generation; mocked provider/protocol operations |
| Interfaces | `main.go`, `manpage.go`, every command/flag/env/default/help/error/exit code, interactive `tui`, JSON/legacy JSON/plain/GitHub Actions/SARIF outputs, schemas and all `proto`/`pb` contracts |
| Shared runtime | `common`, `context`, `cache`, `verificationcache`, `hasher`, `roundtripper`, `sanitizer`, `cleantemp`, `process`, `feature`, `protoyaml`, `log`, `channelmetrics`, engine/runtime metrics, `version`, `updater`, and test-support behavior |
| Delivery/support | Build and platform contracts, scripts/hooks/action/container entry points, generated man/docs assets, notices and dependency licenses; upstream Linux/macOS/Windows on amd64/arm64 remain visible even where the current Nix shell cannot verify them |

For components, record exported behavior, upstream path, native replacement/dependency, owner, status, offline evidence and gaps. Reconcile every upstream package/file to a component row or a justified non-runtime/build/test/documentation classification. No silent exclusions for SDK-heavy code. Add typed C adapters where needed; do not substitute a scanner wrapper. Work through bounded families with targeted tests after implementation, then a representative end-to-end check. Packaging/updater behavior can be tested with local fixtures; this plan does not authorize publishing, deployment or live update traffic.

## Semantic differences requiring explicit verification

1. **RE2 versus PCRE2:** upstream uses both `go-re2` and Go `regexp`. Verify literal pattern translations and custom-pattern validation, leftmost-first captures, empty-match progression, scoped case folding, ASCII `\b`/`\w`/`\d`, whitespace classes, newline/anchor behavior (notably `$`), UTF-8/rune distances and invalid bytes. Do not globally enable case-insensitivity or UCP. `PrefixRegex` is exactly `(?i:KEYWORDS)(?:.|[\n\r]){0,40}?`, with joined regex fragments, not escaped literal keywords; the secret capture remains case-sensitive. PCRE2's acceptance of lookarounds/backreferences and potentially unbounded backtracking is not RE2 parity. Reject PCRE-only custom syntax, bound resources, and report execution-limit errors rather than “no match.” Resolve observed pattern gaps directly, not through a general Go emulation layer. `br_re2_any_unit_width` recognizes only the selected optimized full-any byte range, including specific non-scalar forms. D7Network uses it in its named fixed grammar; generic PrefixRegex composition remains incomplete. Do not apply it to narrower classes, Go trimming or empty-match progression.
2. **HTTP/URL behavior:** curl does not automatically match Go URL escaping, redirect method/auth/header rules, proxy handling, TLS trust/handshake timeouts, retry/backoff, local-IP checks or singleflight cancellation. Verify these per actual client profile. Do not merge the two upstream HTTP-client families or “improve” verification rules. The initial batch does not accept the unported profiles merely by declaring enum values.
3. **Strings/maps/serialization:** C strings must not truncate binary raw values. Go Unicode lowercasing/digit checks, rune-count/byte-denominator entropy, trim behavior, map iteration and NULL/empty serialization need targeted parity cases at their actual use sites. Match json-c output types/omissions/escaping to each upstream printer and protobuf representation. Compare unordered sets only where upstream ordering is genuinely unspecified.
4. **Identity/lifecycle:** configuration version wildcards differ from instance identity; cache and dedup keys differ from both. Verify source-location formatting, decoded-to-original offsets, targeted scans bypassing filtration, redacted errors and concurrent immutable state. Preserve these as explicit component evidence instead of inventing one universal key or cleanup policy.

Primary evidence: `pkg/detectors/detectors.go`, `falsepositives.go`, `http.go`; `pkg/common/http.go`; `pkg/engine/defaults/defaults.go`, `engine.go`, `ahocorasick/ahocorasickcore.go`; `pkg/config/detectors.go`; `pkg/verificationcache/verification_cache.go`; `pkg/output/json.go`; the three detector directories; and the `proto` schemas, all under `.reference/trufflehog`.
