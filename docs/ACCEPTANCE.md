# Acceptance evidence and remaining scope

Reference: TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`. This is evidence for an implemented slice, not completion of the project.

## Native slice

The C library contains nineteen detector implementations: Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO, AdobeIO, Adzuna, Aeroworkflow, Agora, Aha, Airbrake project/user keys, Airship, Airtable OAuth/personal access tokens, AirVisual, Aiven and Alchemy. The registry preserves source order, versions and disabled Abstract/AdobeIO membership. Verification fixtures use synthetic candidates and injected/loopback transport, never real credentials against services.

Raw input is split into 10 KiB content plus 3 KiB forward peek before decoding. Filesystem base lines advance over content only; stdin retains its distinct metadata behavior. Keyword spans merge when overlapping or adjacent, with pinned multipart/max-size/start-offset overrides. RawV2-aware deduplication and decoded result locations are compared against the reference.

PLAIN/UTF8, Base64 and UTF16 initially receive original bytes independently. Non-PLAIN fan-out preserves intermediate findings and iterates to default depth five with bounded seen-data scheduling. UTF16 reproduces the source's printable-ASCII extraction, with LE results before BE results, not a general Unicode conversion. Escaped Unicode has a tested native helper but is not yet wired into the CLI. HTML remains unported.

## Reproduce checks

```sh
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
direnv exec . python3 tests/cli_reference.py --reference "$BRIAR_REFERENCE_BINARY"
nix hash path .reference/trufflehog
```

The reference tree must match `UPSTREAM.json.source_nar_hash`; executable bits are significant. The README's restore procedure exports the pinned Git tree without Git metadata and preserves those bits. Source bytes and the whole-tree hash were checked against the pinned Nix source.

`BRIAR_REFERENCE_BINARY` must identify the pinned 3.97.2 executable. Comparisons check its version and run both programs in Linux network namespaces with empty HOME and verification disabled. Reference-only updater/concurrency controls do not imply native support for those flags.

Observed fresh results:

| Check | Coverage | Result |
| --- | --- | --- |
| Strict C11 build/checks | `-Wall -Wextra -Wpedantic -Werror` | Passed |
| Shared core | 249 assertions | Zero failures |
| PLAIN/UTF8 | 29 cases, 188 assertions | Zero failures |
| Base64 | 25 cases, 154 assertions | Zero failures |
| UTF16 | 17 library cases, 106 assertions; CLI comparisons | Zero failures |
| Escaped Unicode library helper | 38 cases, 243 assertions | Zero failures |
| Detectors | 956 cases, 24,976 assertions | Zero failures |
| Native CLI | 333 assertions | Zero failures |
| Proxy CONNECT/TLS regression | 32 assertions | Zero failures |
| Native HTTP profiles/body handling | Nine loopback-only cases, 94 assertions | Zero failures |
| Source-inventory regressions | Four tests | Zero failures |
| Pinned-reference comparisons | 204 selected input/decoder/window cases | Zero failures |

Detector checks cover extraction, pairing/uniqueness, metadata and verifier request/status/body/error branches. Reference checks cover complete JSON rows, multipart/source boundaries, nested Base64/UTF16 paths, decoded locations, defaults and version selection. The 2,048/2,049-byte keyword separation and 11,000/15,000-byte bridged-window cases distinguish faithful source pairing from unsafe whole-file merging.

The upstream notifier can race when multiple decoders produce one finding. Native follows deterministic default decoder order. Seven named duplicate fixtures permit only observed PLAIN/BASE64/UTF16 label alternatives at otherwise identical identities and fields. Repeated isolated runs confirmed the UTF16 alternatives; negative guards reject candidate, metadata, detector and unobserved-case mismatches. Full concurrency parity is not established.

The CONNECT regression prevents a successful proxy tunnel response from becoming an origin response after TLS failure. Abstract and Abyssale retain an error with `verified=false`.

## Remaining boundaries and verification risks

All nineteen detector records and all supporting components remain incomplete in `parity.json`; another 902 detector implementations are not started. Passing this slice does not establish full TruffleHog reproduction.

The CLI requires explicit supported selection, JSON and disabled verification. Inputs remain stdin or explicit regular files up to 64 KiB. Traversal, archives, configurable depth, full source/configuration/output and unported options remain unsupported and fail explicitly.

Native HTTP supports GET/POST in SANE/LOCAL slices. LOCAL does not follow redirects; POST preserves opaque/empty bodies without inventing Content-Type. SANE POST redirects remain unsupported. PUBLIC rejects before network I/O until all-answer DNS checks, proxy semantics, cancellation and redirect policy are ported. Injected transports own the requested profile's policies; mock success is not native PUBLIC support.

Some verifiers mutate services: Airbrake project-key verification posts a deploy record and must not be treated as read-only. Several source verifiers omit secret arguments to error helpers, so injected transports must not include credentials in errors. All verification here is synthetic/offline; service acceptance is untested.

Shared regexp behavior, other decoders, remaining helpers and complete engine/source/concurrency behavior remain unfinished. Nothing is deployed into Pi or used as a production security boundary.
