# Acceptance and remaining scope

Reference: TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`. Passing the implemented slice does not establish full reproduction. `parity.json` records detector/component evidence and unresolved behavior; `upstream-inventory.json` is the complete migration queue.

## Verification workflow

Compile during implementation. When a detector is finished, run its named test, for example:

```sh
direnv exec . make build/tests/detectors/test_adafruitio
direnv exec . build/tests/detectors/test_adafruitio
```

Run broad checks at the integrated end step, not on every build:

```sh
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
direnv exec . python3 tests/cli_reference.py --reference "$BRIAR_REFERENCE_BINARY"
```

The reference binary must be the pinned 3.97.2 executable. The comparison script checks its version and runs both programs in network namespaces with empty HOME and verification disabled. Reference-only updater/concurrency controls do not imply native support for those flags.

Verify `.reference/trufflehog` with `nix hash path`; its hash must equal `UPSTREAM.json.source_nar_hash`. Executable bits are significant. The README restoration procedure exports the pinned Git tree without Git metadata and preserves those bits.

## What the checks establish

Named detector tests cover provider-specific extraction, filtering, pairing, metadata and verifier request/status/body/error behavior. Shared fixtures use synthetic candidates and injected HTTP, never real credentials against services. Registry tests cover identities, versions, defaults, order and dispatch to real scanners, without depending on implementation file grouping.

Core tests cover result ownership, matching and decoder behavior. CLI checks cover source boundaries, multipart windows, decoded locations and selection. The source-window counterexamples distinguish correct credential pairing from unsafe whole-file merging. Loopback-only HTTP fixtures cover implemented profile/body handling and the CONNECT-success-followed-by-TLS-failure regression.

Pinned-reference comparisons check complete JSON rows for selected cases, not the entire upstream engine. Named duplicate fixtures permit only observed decoder-label alternatives at otherwise identical identities and fields; native decoder ordering is deterministic. Full concurrency parity is not established.

## Current boundaries

The CLI requires explicit supported detector selection, JSON and disabled verification. Input is stdin or explicit regular files up to 64 KiB, split into 10 KiB content plus 3 KiB forward peek before decoding. Filesystem line advancement uses content only. RawV2-aware deduplication and decoded locations remain distinct from original-byte ownership.

PLAIN/UTF8, Base64, UTF16 and escaped Unicode receive original bytes independently; non-PLAIN iteration preserves intermediate findings through the default depth of five. UTF16 is upstream's printable-ASCII heuristic, not general Unicode conversion. In the implemented RE2 slice, malformed UTF-8 acts as a match barrier: later valid matches retain original byte offsets, but matches cannot cross the invalid sequence. General regexp/arbitrary-byte parity remains incomplete. HTML, traversal, archives, configurable depth and broad source/configuration/output behavior remain unported. Unported commands/options fail explicitly.

Native HTTP supports GET/POST in SANE/LOCAL slices. LOCAL does not follow redirects. POST preserves opaque/empty bodies without inventing Content-Type. SANE POST redirects remain unsupported. PUBLIC rejects before I/O until all-answer DNS checks, proxy semantics, cancellation and redirect policy are ported. Injected transports own the requested policy; mock success does not prove native PUBLIC support.

AWS access-key verification implements the fixed STS and SNS Query/XML operations and SigV4 signing through injected HTTP only. Its dedicated native SDK profile rejects before I/O. SDK configuration, retry policy, streaming XML and diagnostics remain partial. XML parsing accepts UTF-8 only, rejects DTDs and uses strict whole documents, which is narrower than the SDK's selected-result streaming behavior. Upstream panic shapes return explicit unsupported errors rather than undefined behavior.

Session-key verification instead uses the source's manually signed SANE GET/JSON path; native eager-body buffering cannot reproduce its unread-first-403 retry workaround.

Azure Batch, Cosmos DB, Storage and App Configuration share only Base64, HMAC and UTC-date mechanics, not signing protocols or response policy. Batch and Storage sign the decoded prefix after corrupt Base64 and remain subject to the native PUBLIC guard. App Configuration instead rejects corrupt Base64 before signing or HTTP. Its findings are unique by the full connection string, so inline decoding can preserve two connection forms with the same ID. Cosmos Table preserves the upstream full-host account-name bug. Cosmos and App Configuration deliberately ignore scan cancellation and deadlines because the source requests omit their context.

Azure Storage separately models Go XML struct decoding, including repeated containers and direct text/CDATA. Its strict whole-document parser rejects DTDs, trailing roots/junk and some namespace forms accepted upstream; these remain fail-closed gaps.

Azure Entra tenant discovery caches positive and negative results; only discovery GETs are coalesced, never credential POSTs. After typed response decoding, HTTP 200 rather than JWT signature or expiry validation establishes refresh verification. The source ignores JWT parsing errors, although parser stages affect available metadata. Nil-Claims panic shapes become explicit scan errors with invocation-only rollback. Numeric/aggregate claim formatting and runtime concurrency parity remain unsupported or unverified. Service principals reuse selected-claims parsing, not refresh-specific metadata or confidence policy.

API Management repository-key verification accepts a provider-private injected C Git runner. Native Git is unsupported: no process is spawned and no credential helper is consulted by default. Injected command/version/error behavior does not establish native process, environment or credential-isolation parity.

API Management subscription-key and direct-management verification suppress all transport errors, including DNS; neither may invent a reachable DNS-cache path from those errors. Direct management signs the encoded ASCII key itself with HMAC-SHA512 and a five-second UTC expiry containing seven fixed zero fractional digits. It does not decode the key or reuse Batch's signing protocol. Container Registry instead caches DNS failures only during verification and consumes verified passwords across usernames. These detector callbacks bypass default false-positive checks.

DevOps PAT verification uses bounded binary line scanning, not an unrestricted body substring search. LF/CR bytes count toward the 65,536-byte scanner buffer; an overlong line blocks later lines, while an earlier matching line wins. A marker-bearing unterminated final line of exactly 65,536 bytes has reader-shape ambiguity that ABI 1 cannot represent. Affected 2xx candidates receive an explicit unsupported verification error, without aborting later pairs. Keys remain lowercase-only even when their prefix is uppercase. Native buffering and release timing remain narrower than the source's streaming/deferred-close behavior.

SAS token validation preserves raw parameter order, last-duplicate values and shape-only checks without URL decoding. Body-read errors precede every status. A signature-mismatch 403 retries once with a literal container-query suffix while retaining the outer response; errors redact the original token, not the appended retry form. The literal IP-restriction check intentionally misses a first-position `sip=` parameter.

SAS and Function query guards inspect controls only before the first fragment delimiter. Source creation errors remain SAS candidate errors but skip Function candidates. Fragments and non-ASCII queries fail closed without I/O; SAS supports only its documented ASCII query subset, while Function also guards percent forms. Function remains disabled upstream and in CLI selection, and its native PUBLIC profile never falls back to SANE. Its full-match, last-literal-space extraction preserves padding and binary bytes, rather than substituting capture group one.

Azure Search query keys also use the full-match, last-literal-space endpoint transformation, retaining occurrence products and byte ownership. Verification supports canonical ASCII endpoints only. Known pre-fragment control-byte creation failures skip candidates; other unsupported URL forms remain candidate errors without stopping later pairs. Its native PUBLIC policy stays fail-closed.

Bannerbear versions share one provider module with explicit differences. V1 retains occurrences and version metadata on every outcome. V2 deduplicates keys and replaces metadata during verification: creation/transport failures remove the version map, while successful HTTP delivery restores it before status/body handling. For V2 HTTP 400, read errors precede binary marker search; a marker can verify a master key even after NUL, regardless of the key prefix. Non-marker 400 diagnostics remain explicitly unsupported, including ordinary ASCII bodies, because ABI 1 lacks arbitrary response status text and NUL-preserving error lengths. This is a candidate error, not a scan failure.

Baremetrics and Beamer both ignore body-read errors and verify only HTTP 200, but their transport policies differ. Baremetrics suppresses transport failures without dropping findings; Beamer retains key-redacted errors. Neither introduces entropy filtering, Base64 validation or a host cache.

Beebole uses a JSON POST and Basic authentication with the key as username and literal `x` password. Besnappy uses those credentials in a GET but remains disabled in CLI selection. Bitbar instead uses an empty password. Beebole's native POST redirects stay unsupported.

Besttime checks literal byte substrings, not parsed JSON. On HTTP 200, read errors win; the exact spaced success marker wins over the invalid-key marker, even after NUL or invalid UTF-8. Every non-200, including 401/403, is an error. Unknown-body diagnostics preserve complete original valid UTF-8 and non-NUL controls. Unknown bodies containing NUL or invalid UTF-8 instead receive an explicit unsupported candidate error after marker checks, allowing later keys; normalized decoder bytes never replace the original body.

Billomat removes an account ID only after a successful 404 body read contains its account-not-found marker. This suppresses the current finding and later uses of that ID in the same invocation, not earlier findings. Read failures and transport error text cannot cause deletion. Captured context words, including the provider name, remain source behavior rather than being heuristically filtered.

Bitbucket app passwords use three ordered regex passes and a case-sensitive username map. Later patterns overwrite earlier ones regardless of input position; the quoted pattern's ASCII whitespace excludes vertical tab. Raw is the assembled username/password pair, with no password-based location override, so quoted-only findings retain the source's filesystem fallback line. HTTP 403 verifies as well as 200. Arbitrary invalid-UTF-8 matching remains a gap because this detector uses Go stdlib regexp rather than the shared RE2 behavior.

BitcoinAverage validates both typed JSON fields, including unused `msg`, before trusting `success`. Duplicate nulls preserve primitive field values, unknown huge numbers are skipped, and only the first document is decoded. A later read error or trailing document need not invalidate a complete first object.

Bitfinex and Bitmex sign captured ASCII secrets without Base64 decoding, but use different protocols. Bitfinex signs a JSON POST with a microsecond nonce and HMAC-SHA384; its unequal directed pairs expose only the API key. Bitmex signs an empty-body GET with a five-second expiry and HMAC-SHA256. Its captures require surrounding SPACE/CR/LF, and Raw is the secret while RawV2 is key+secret. Native clock-range guards return scan errors with invocation-only rollback rather than emulating all Go time behavior.

Bitfinex HTTP 500 read errors precede binary invalid-key markers. Unknown supported bodies retain complete original UTF-8 diagnostics; NUL/invalid-UTF-8 variants remain unsupported candidate errors after marker checks. Native POST redirects stay fail-closed. Bitly retains unique tokens with literal-hyphen boundary quirks, while Blazemeter retains occurrences of lower-alphanumeric UUID shapes under both provider aliases. These four detectors preserve source-unredacted errors, so their verification errors are not credential-safe output.

BlitApp suppresses both request-creation and all transport errors, not just DNS failures. Blogger retains unredacted errors, including query keys; its exact-case 39-byte capture has no ending boundary, and HTTP 401 is an error rather than a normal rejection. BlockNative remains disabled because its API also returns 200 for invalid keys. Direct fixtures preserve that status-only rule and the source's uppercase-A-only first UUID block; explicit selectors cannot enable it.

BombBomb preserves the source's permissive JWT-shaped regex, including wildcard separators and empty segments. Only its possible final whitespace rune is trimmed; internal whitespace and NUL bytes remain unchanged in findings. Embedded-NUL verification is explicitly unsupported because ABI1 headers cannot carry those bytes. The guard preserves the candidate and continues, after nil-context handling. Other unsafe header controls are rejected before I/O by the shared adapter, with a documented Go error-wording gap; HTAB and non-ASCII bytes are preserved. No JWT validation or input normalization is substituted.

BoostNote and Borgbase retain source-unredacted errors. Borgbase verifies HTTP 200 only after a successful read containing the exact binary substring `"sshList":[]`, not an arbitrary parsed SSH list. Its request-local ten-second timeout does not reproduce mutation of the shared Go client or concurrency effects; native POST redirects stay fail-closed.

Box validates a typed first document before projecting three string metadata fields, preserving duplicate/null semantics and embedded NUL. Even null or an empty object verifies with three empty strings. The Box access-token pattern can also report an OAuth client ID; distinct detector identities are not silently merged. Box OAuth instead validates credentials through a malformed HTTP 400 response, then probes lexically sorted subject IDs, enterprise before user. Failed subject probes do not undo base verification, and success breaks only the current secret loop. Its error redaction covers the client ID but not the secret. Subject probes can issue access tokens and remain fake-only in verification evidence.

Braintree requires public IDs for verification but omits them from findings, and reads the body before every status check. C releases responses on read errors rather than reproducing the source's missing close; its private sandbox selector remains unexposed. Braintrust uses a direct token pattern despite keyword dispatch, always retains its shortened display value, and accepts HTTP 403. Its exact boolean feature override distinguishes OSS CLI-enabled defaults from Go package-zero state. Brandfetch versions share source-delegated verification and identical scan mechanics while retaining separate regexes and version maps, including v2's punctuation/no-boundary grammar.

BrowserStack is not a SANE client alias. Its injected-only profile preserves no client-level timeout and guards over-range deadlines; native curl rejects it before I/O. Mock status success does not prove fresh cookie jars, public-suffix handling, redirects, sessions or override-client mutation/concurrency. Usernames have an unbounded middle separator run, so RawV2 and Basic authentication preserve the complete capture. Hub-host dots remain source regex wildcards and can also make an access key a username candidate. Close-only versus eager-body timing remains a gap.

BscScan verifies HTTP 200 when the complete binary body lacks case-sensitive `NOTOK`, even for empty or non-JSON content. A body read error takes precedence; non-200 statuses ignore body errors. This is a byte-marker policy, not JSON validation. Browshot retains its literal-hyphen boundary quirks. Browshot, BscScan, BuddyNS and Budibase all preserve source-unredacted errors, including echoed query keys or authorization values.

Some verifiers mutate services: Azure Function verification can execute user code, Airbrake project-key verification posts a deploy record, AWS SNS Publish can trigger canary tracking, and Entra refresh-token exchanges can issue new tokens. These are not uniformly read-only credential checks. Some upstream verifiers omit secrets from error-redaction helpers; injected transports must not include credentials in those errors. Verification here is synthetic/offline, not evidence of live service acceptance.

Shared regexp/arbitrary-byte semantics, remaining detectors and helpers, complete engine/source/concurrency behavior and global parity remain unfinished. Nothing is deployed into Pi or used as a production security boundary.
