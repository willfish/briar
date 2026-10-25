# Acceptance evidence and remaining scope

Reference: TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`. This is evidence for an implemented slice, not completion of the project.

## Native slice

The C library contains fifteen detector implementations: Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO, AdobeIO, Adzuna, Aeroworkflow, Agora, Aha, Airbrake project/user keys, Airship and Airtable OAuth. The registry preserves source order, versions and disabled Abstract/AdobeIO membership. Verification fixtures use synthetic candidates and injected/loopback transport, never real credentials against services.

Raw input is split into 10 KiB content plus 3 KiB forward peek before decoding. Filesystem base lines advance over content only; stdin retains its distinct metadata behavior. Keyword spans merge when overlapping or adjacent, with pinned multipart/max-size/start-offset overrides. Pairing, RawV2-aware deduplication and decoded result locations are exercised against the reference.

PLAIN/UTF8 and initial Base64 receive original bytes independently. Base64 retains intermediate findings through the default five passes. A native UTF16 helper reproduces the source's printable-ASCII extraction, with LE results before BE results; it is not yet wired into the CLI. Other decoders and configurable depth remain unported.

## Reproduce checks

```sh
direnv exec . make clean
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
direnv exec . python3 tests/cli_reference.py --reference "$BRIAR_REFERENCE_BINARY"
```

`BRIAR_REFERENCE_BINARY` must identify the pinned 3.97.2 executable. The comparison script checks its version and runs both executables in Linux network namespaces with empty HOME and verification disabled. Reference-only updater/concurrency controls do not imply native support for those flags.

Observed fresh results:

| Check | Coverage | Result |
| --- | --- | --- |
| Strict C11 build | `-Wall -Wextra -Wpedantic -Werror` | Passed |
| Shared core | 249 assertions | Zero failures |
| PLAIN/UTF8 | 29 cases, 188 assertions | Zero failures |
| Base64 | 25 cases, 154 assertions | Zero failures |
| UTF16 library helper | 17 cases, 106 assertions | Zero failures |
| Detectors | 744 cases, 19,885 assertions | Zero failures |
| Native CLI | 254 assertions | Zero failures |
| Proxy CONNECT/TLS regression | 32 assertions | Zero failures |
| Native HTTP profiles/body handling | Nine loopback-only cases, 94 assertions | Zero failures |
| Source-inventory regressions | Four tests | Zero failures |
| Pinned-reference comparisons | 158 selected input/decoder/window cases | Zero failures |

Detector checks cover extraction, pairing/uniqueness, exact metadata and verifier request/status/body/error branches. Reference checks cover complete JSON rows, multipart windows and source chunk boundaries, version selection, cleaning, duplicates, malformed UTF8, nested Base64 and filesystem metadata. The 2,048/2,049-byte keyword separation and 11,000/15,000-byte bridged-window cases distinguish source-faithful pairing from unsafe whole-file merging.

The upstream notifier can race when PLAIN and Base64 produce the same finding. Native ordering is PLAIN-first. Five identified duplicate fixtures permit only the observed `DecoderName` alternative at otherwise identical identities and fields; other comparisons remain strict. Full concurrency parity is not established.

The CONNECT regression prevents a proxy's successful tunnel response from being mistaken for an origin response after TLS failure. Abstract and Abyssale retain an error with `verified=false`.

## Remaining boundaries and verification risks

All fifteen detector records and all supporting components remain incomplete in `parity.json`; another 906 detector implementations are not started. Passing this slice does not establish full TruffleHog reproduction.

The CLI requires explicit supported selection, JSON and disabled verification. Inputs remain stdin or explicit regular files up to 64 KiB. Traversal, archives, full source/configuration/output behavior and all unported options remain unsupported and fail explicitly.

Native HTTP supports GET/POST in the SANE/LOCAL slices. LOCAL returns redirects without following them; POST preserves opaque binary/empty bodies and does not invent Content-Type. SANE POST redirects still fail explicitly. PUBLIC rejects before network I/O until all-answer DNS checks, proxy semantics, cancellation and redirect policy are ported. Injected transports own the requested profile's policies; Aha mock success is not native PUBLIC support.

Some upstream verifiers mutate services. Airbrake project-key verification posts a deploy record, so it must not be treated as a read-only credential check. Its fixture is synthetic/offline only. Several source verifiers omit secret arguments to their error helper; injected transports must not include credentials in their errors. Service acceptance is untested.

Shared regexp behavior, other decoders, remaining helpers and complete engine/source behavior remain unfinished. Nothing here is deployed into Pi or a production security boundary.
