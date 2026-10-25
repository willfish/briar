# Acceptance evidence and remaining scope

Reference: TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`. This is evidence for an implemented slice, not completion of the project.

## Native slice

The C library contains eleven detector implementations: Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO, AdobeIO, Adzuna, Aeroworkflow, Agora and Aha. The registry preserves source order, versions and disabled Abstract/AdobeIO membership. Detector verification fixtures use injected transport, not real credentials or service calls.

The CLI runs PLAIN/UTF8 and Base64 independently from original bytes. Valid UTF8 passes through; malformed input follows the pinned sanitization branch. Base64 preserves intermediate findings through the default five passes. Other decoders and configurable depth remain unported.

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
| Shared core | 252 assertions | Zero failures |
| PLAIN/UTF8 | 29 cases, 188 assertions | Zero failures |
| Base64 | 25 cases, 154 assertions | Zero failures |
| Detectors | 541 cases, 14,640 assertions | Zero failures |
| Native CLI | 158 assertions | Zero failures |
| Proxy CONNECT/TLS regression | 32 assertions | Zero failures |
| Source-inventory regressions | Four tests | Zero failures |
| Pinned-reference comparisons | 91 selected input/decoder cases | Zero failures |

Detector checks cover capture boundaries, pairing, entropy/uniqueness where applicable, exact metadata, mock requests and verifier status/body/error branches. Reference comparisons cover complete JSON rows, version selection, cleaning, duplicates, malformed UTF8, nested Base64 and filesystem metadata. Abstract/AdobeIO are disabled in the reference CLI, so their direct implementations use source-derived fixtures instead.

The upstream notifier races when PLAIN and Base64 produce the same finding. Native ordering is PLAIN-first. Five identified duplicate fixtures permit only the observed `DecoderName` alternative at otherwise identical result identities and fields; other comparisons remain strict. Full concurrency parity is not established.

The proxy regression prevents CONNECT `200 Connection established` from being mistaken for an origin response after TLS failure. Both status-only verifiers retain an error and `verified=false`. The native adapter suppresses CONNECT headers.

## Remaining boundaries

All eleven detector records and all supporting components remain incomplete in `parity.json`. Another 910 detector implementations are not started. Inventory discovery and passing this slice do not establish full TruffleHog reproduction.

The CLI requires explicit supported non-multipart selection, JSON and disabled verification. Adzuna, Aeroworkflow, Agora and Aha remain library-only until multipart chunk/window/prefilter behavior is implemented. Inputs are stdin or explicit regular files up to 64 KiB, without traversal, archives or the complete chunking/source pipeline. Unsupported selections, options and capabilities fail explicitly.

Injected HTTP dispatch accepts SANE and the two detector profiles, with pinned timeout defaults and context clamping. The injected transport owns redirect/address policy. Native curl still supports only the SANE bodyless-GET slice and rejects LOCAL/PUBLIC before network I/O. PUBLIC needs complete all-answer DNS checks, proxy semantics, cancellation and redirect policy; successful Aha mock checks do not prove those native policies.

Shared regexp behavior, additional helpers, other decoders and the remaining engine/configuration/output/source functionality are unfinished. Service acceptance is untested. AdobeIO preserves upstream's error-helper call without secret arguments, so injected transport errors must not contain credentials. This work is not an outbound-context redactor or a deployed Pi security boundary.
