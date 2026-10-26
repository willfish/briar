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

Some verifiers mutate services: Airbrake project-key verification posts a deploy record, and AWS SNS Publish can trigger canary tracking. Neither is a read-only credential check. Some upstream verifiers omit secrets from error-redaction helpers; injected transports must not include credentials in those errors. Verification here is synthetic/offline, not evidence of live service acceptance.

Shared regexp/arbitrary-byte semantics, remaining detectors and helpers, complete engine/source/concurrency behavior and global parity remain unfinished. Nothing is deployed into Pi or used as a production security boundary.
