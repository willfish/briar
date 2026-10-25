# Briar

A native C reimplementation of TruffleHog, private and under development.

The target is **the entirety of TruffleHog 3.97.2**, not a smaller regex scanner: every detector's extraction, filtering, verification, results and version/default behavior, plus decoders, sources, engine, analyzers, configuration, CLI, outputs and distribution integrations. The exact tag and commit are pinned in [UPSTREAM.json](UPSTREAM.json).

## Current state

The source-derived inventory contains **921 detector implementations**, **892 registry constructor candidates**, including two AWS factory registrations, and **34 supporting components**, including shared detector helpers. It includes disabled and versioned detectors. Registry membership is not evidence that a detector is enabled by default; upstream feature gates require separate behavior checks.

The first native slice contains a C library, strict build, shared result/regex/HTTP primitives and ports of Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO and AdobeIO. The limited CLI supports selected stdin/regular-file JSON scans, with verification disabled. It explicitly rejects default/all scans and unported options rather than presenting a partial registry as a complete scanner.

All seven implementations remain **partial**, and no detector or component is counted as fully reproduced yet. [parity.json](parity.json) records the remaining behavior against [upstream-inventory.json](upstream-inventory.json); absent entries remain not started. [Acceptance evidence](docs/ACCEPTANCE.md) records the actual checks and limits. Inventory and ledger entries are not substitutes for behavioral evidence or the final full-scope audit.

Do not use this work-in-progress as a security boundary. Nothing is deployed into Pi. Verification tests use synthetic credentials and injected/offline responses, never real credentials against services. Native code must not wrap the Go scanner as its implementation.

## Development

The Nix/direnv environment declares the C toolchain, PCRE2, libcurl, json-c and Python for build/test tooling. No Go runtime is part of Briar's implementation.

```sh
direnv allow .
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
```

The executable is `build/briar`; run `--help` for the currently supported subset. Current CLI inputs are ASCII only, at most 64 KiB, and require an explicit supported detector selection. The entire upstream CLI and input pipeline remain the target, not these temporary limits.

The pinned upstream source is a read-only reference under ignored `.reference/trufflehog`. To restore that cache:

```sh
git clone --depth 1 --branch v3.97.2 git@github.com:trufflesecurity/trufflehog.git .reference/trufflehog
test "$(git -C .reference/trufflehog rev-parse HEAD)" = cc1fe982afc515d2991365ce8d4d0dd07170fcad
```

Do not regenerate the inventory against a different reference to make checks pass. An upstream-version change needs an explicit migration of the full parity ledger.

## License

This derivative work retains the GNU Affero General Public License version 3. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Briar is not affiliated with or endorsed by Truffle Security.
