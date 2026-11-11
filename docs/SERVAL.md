# Serval offline detection

Native applicability: [TruffleHog PR #5528](https://github.com/trufflesecurity/trufflehog/pull/5528)
adds a new detector, not a Go dependency update. This port was based on the
complete detector and tests at merge `188766766fd81cde66e5500b0db0379235637134`
and Briar default branch `master` at `33cbe7f61c36fc230be39f4a6c0088404042f13e`.
No Serval source, identity or factory existed at that Briar revision.

## Behavior and limits

- Adds detector 1078 (`Serval.v0`) with `svl_secret_` keyword dispatch.
- Detects public API (`pk`), worker (`wk`) and managed worker (`mk`) secrets,
  including standalone secrets without a client ID.
- Requires exactly 43 base62 random characters and six base62 checksum digits,
  ASCII word boundaries and case-sensitive secret prefixes/tags.
- Validates IEEE CRC32 of `<tag>_<random>` with the issuer's base62 alphabet.
  Rejects bad checksums, including a valid checksum for the wrong tag.
- Pairs each unique secret with unique nearby-keyword UUID candidates in the
  detector input window. UUIDs are normalized to lowercase. As upstream offline
  scanning does, emits the candidate product, not an asserted identity association.
  Raw is the secret; paired RawV2 is `client_id:client_secret`.
- Enables the detector for offline pre-commit scans by default, with the exact
  `ServalDetectorEnabled` boolean override used by upstream OSS main.
- Retains existing engine false-positive filtering, decoding and window limits.
  Upstream's sequential synthetic fixtures pass direct detector tests but are
  filtered at the engine boundary; CLI tests generate non-sequential synthetic
  fixtures with independent Python `zlib.crc32` checksums instead.
- Hook output remains file/line/detector-only. CLI JSON intentionally contains
  secret values, as documented by the existing CLI contract.
- **No live verification.** Regional OAuth, access-token issuance and key-use
  timestamp side effects are not ported. A direct library request with
  `verify=true` fails explicitly with a secret-free unsupported error and never
  calls the transport. CLI verification remains unsupported. No new dependency,
  HTTP call, DNS lookup, endpoint or hook network behavior is introduced.

## Executed checks

Built and tested in a dedicated source-only scratch directory on the authorized
Linux host Andromeda using this repository's pinned Nix development environment.
Only repository source was transferred; no credentials or human worktree state.
Linux is required by the canonical runner's user/network namespaces and `/proc`
checks; the worker host is macOS.

1. Before implementation, added the synthetic C test and ran:
   `nix develop --command bash -c "make -j8 build/tests/detectors/test_serval > baseline-build.log 2>&1 && build/tests/detectors/test_serval"`
   — failed at `d != NULL`, proving current default branch lacks coverage.
2. After implementation:
   `nix develop --command python3 tests/integration.py --native-only --jobs 8`
   — exit 0, `PASS: implemented native integration checks; upstream comparisons explicitly omitted`.
   This builds `all` with C17 `-Wall -Wextra -Wpedantic -Werror` and runs
   the complete `make check` in isolated network namespaces with empty HOME.
   Includes all native core/detector tests, proxy/HTTP loopback fixtures,
   **1,214 e2e assertions**, **18 CLI failure/output tests** and
   **124 Serval C assertions**, all passing.

Serval assertions cover independent key types, standalone and paired findings,
case normalization, duplicate suppression, multiple UUID candidates, malformed
shape/tag/length/boundaries, per-tag checksum failures, unsupported verification,
zero transport use and invalid-input preservation of caller results. Registry
checks retain catalogue counts/dispatch and exact feature-flag policy. CLI
checks separately assert credential-bearing JSON, exclusion failure, secret-free
hook output, invalid-checksum clean runs, immutable input and rollback after a
missing-file failure.

Full pinned TruffleHog 3.97.2 reference comparisons were explicitly omitted:
that older baseline does not contain Serval. No live credentials or provider
verification were used, and this change does not claim full upstream parity.
