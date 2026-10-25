# Acceptance evidence and remaining scope

Reference: TruffleHog 3.97.2, commit `cc1fe982afc515d2991365ce8d4d0dd07170fcad`. These checks cover the first native slice, not completion of the project.

## First native slice

The current C library implements seven descriptors: Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO and AdobeIO, with detector-local extraction, metadata and verification branches. Its registry preserves upstream order and distinct version identities. Abstract and AdobeIO are exposed directly for tests but remain disabled by default. Verification tests use injected responses or loopback-only fixtures and synthetic candidates, not service calls.

Fresh checks in this worktree:

```sh
direnv exec . make clean
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
direnv exec . python3 tests/cli_reference.py --reference "$BRIAR_REFERENCE_BINARY"
```

`BRIAR_REFERENCE_BINARY` must identify the pinned 3.97.2 executable. The comparison script checks its version, runs both executables inside a Linux network namespace with an empty HOME and passes verification-disabled flags. Reference-only update/concurrency controls are not treated as implemented native CLI features.

Observed results:

| Check | Coverage | Result |
| --- | --- | --- |
| Strict C11 build | `-Wall -Wextra -Wpedantic -Werror` | Passed |
| Core unit checks | 197 assertions | Zero failures |
| Detector checks | 333 cases, 8,499 assertions | Zero failures |
| Synthetic native CLI checks | 100 assertions | Zero failures |
| Proxy CONNECT/TLS regression | 32 assertions | Zero failures |
| Source-inventory regressions | Four tests | Zero failures |
| Pinned-reference comparisons | 38 implemented ASCII stdin/filesystem cases | Zero failures |

Detector tests cover prefix distances and case/boundaries, multiple findings, exact fields, no verification calls when disabled, complete mock requests, accepted/rejected/unexpected statuses, transport failures, cancellation/deadlines, upstream-directed error redaction and provider-specific body-read behavior. They also cover Accuweather entropy, uniqueness and inheritance, and AdobeIO component pairing. The reference comparisons check complete JSON rows for selected inputs, including version selection/wildcards, cleaning, duplicates, false positives and regular-file metadata. Abstract and AdobeIO are disabled in the reference CLI, so their direct implementations have source-derived native fixtures rather than CLI oracle comparisons.

The proxy regression reproduces a CONNECT `200 Connection established` followed by TLS failure without forwarding the tunnel. Proxy headers must not be mistaken for an origin response: both status-only verifiers retain an error and `verified=false`. The adapter sets `CURLOPT_SUPPRESS_CONNECT_HEADERS` to preserve that distinction.

The inventory additionally checks two AWS factory registrations and assignment of every non-test Go source file under `pkg/` to a detector or supporting component. Discovery does not earn implementation credit.

## Not established

All seven detector records remain partial in `parity.json`. The shared regexp layer is not complete RE2 parity, including arbitrary-byte behavior, and full native HTTP-client profiles are not established. The tests do not prove present-day acceptance by remote services. AdobeIO deliberately preserves upstream's call to the error helper without secret arguments; an injected transport must not put credentials in its error text. This native API is not yet an outbound-context redactor.

The CLI currently requires explicit supported detector selection, JSON output and disabled verification. It accepts ASCII stdin or explicit regular files up to 64 KiB, with no decoding, traversal or full chunking pipeline. Default/all scans and unsupported detector IDs/options fail explicitly, rather than silently claiming a complete scan.

The remaining 914 detector implementations and all unfinished supporting-component behavior remain in the full objective. No part of this slice is deployed into Pi or counted as complete TruffleHog reproduction.
