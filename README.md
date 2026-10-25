# Briar

A native C reimplementation of TruffleHog, private and under development.

The target is **the entirety of TruffleHog 3.97.2**, not a smaller regex scanner: every detector's extraction, filtering, verification, results and version/default behavior, plus decoders, sources, engine, analyzers, configuration, CLI, outputs and distribution integrations. The exact tag and commit are pinned in [UPSTREAM.json](UPSTREAM.json).

## Current state

The source-derived inventory contains **921 detector implementations**, **892 registry constructor candidates**, including two AWS factory registrations, and **34 supporting components**, including shared detector helpers. It includes disabled and versioned detectors. Registry membership is not evidence that a detector is enabled by default; upstream feature gates require separate behavior checks.

The native library contains shared result/regex/HTTP primitives, PLAIN/UTF8 and Base64 decoding, and fifteen detector implementations: Abstract, AbuseIPDB, Abyssale, Accuweather v1/v2, AdafruitIO, AdobeIO, Adzuna, Aeroworkflow, Agora, Aha, Airbrake project/user keys, Airship and Airtable OAuth. The CLI supports selected stdin/regular-file JSON scans, including multipart credentials, with verification disabled. Raw source chunks use 10 KiB content plus 3 KiB forward peek before decoding. A source-derived UTF16 helper is library-only for now. Default/all scans and unported options fail explicitly rather than presenting partial coverage as a complete scanner.

All fifteen implementations remain **partial**, and no detector or component is counted as fully reproduced yet. [parity.json](parity.json) records the remaining behavior against [upstream-inventory.json](upstream-inventory.json); absent entries remain not started. [Acceptance evidence](docs/ACCEPTANCE.md) records the actual checks and limits. Inventory and ledger entries are not substitutes for behavioral evidence or the final full-scope audit.

Do not use this work-in-progress as a security boundary. Nothing is deployed into Pi. Verification tests use synthetic credentials and injected/offline responses, never real credentials against services. Some upstream verifiers mutate services, including the Airbrake project-key deploy POST; CLI verification remains disabled. Native code must not wrap the Go scanner as its implementation.

## Development

The Nix/direnv environment declares the C toolchain, PCRE2, libcurl, json-c and Python for build/test tooling. No Go runtime is part of Briar's implementation.

```sh
direnv allow .
direnv exec . make -j2 all check
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/test_inventory.py
direnv exec . python3 tools/progress.py
```

The executable is `build/briar`; run `--help` for the currently supported subset. Current CLI inputs are at most 64 KiB and require an explicit supported detector selection. Unicode and malformed input bytes use the pinned PLAIN/UTF8 sanitization rules; Base64 uses the pinned candidate and ASCII-output rules. The entire upstream CLI and input pipeline remain the target, not these temporary limits.

The pinned upstream source is a read-only reference under ignored `.reference/trufflehog`. To restore that cache:

```sh
git clone --depth 1 --branch v3.97.2 git@github.com:trufflesecurity/trufflehog.git .reference/trufflehog
test "$(git -C .reference/trufflehog rev-parse HEAD)" = cc1fe982afc515d2991365ce8d4d0dd07170fcad
```

Do not regenerate the inventory against a different reference to make checks pass. An upstream-version change needs an explicit migration of the full parity ledger.

## License

This derivative work retains the GNU Affero General Public License version 3. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Briar is not affiliated with or endorsed by Truffle Security.
