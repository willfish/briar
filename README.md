# Briar

A native C reimplementation of TruffleHog, private and under development.

The target is **the entirety of TruffleHog 3.97.2**, not a smaller regex scanner: every detector's extraction, filtering, verification, results and version/default behavior, plus decoders, sources, engine, analyzers, configuration, CLI, outputs and distribution integrations. The exact tag and commit are pinned in [UPSTREAM.json](UPSTREAM.json).

## Current state

The source-derived inventory contains **921 detector implementations**, **890 registry constructor candidates** and **33 supporting components**. It includes disabled and versioned detectors. Registry membership is not evidence that a detector is enabled by default; upstream feature gates require separate behavior checks.

No detector or component is counted as fully reproduced yet. [parity.json](parity.json) records verified work against [upstream-inventory.json](upstream-inventory.json); absent entries remain not started. The inventory and ledger are bookkeeping, not substitutes for behavioral evidence or the final full-scope audit.

Do not use this work-in-progress as a security boundary. Nothing is deployed into Pi. Verification tests use synthetic credentials and injected/offline responses, never real credentials against services. Native code must not wrap the Go scanner as its implementation.

## Development

The Nix/direnv environment declares the C toolchain, PCRE2, libcurl, json-c and Python for build/test tooling. No Go runtime is part of Briar's implementation.

```sh
direnv allow .
direnv exec . python3 tools/inventory.py --check
direnv exec . python3 tools/progress.py
```

The pinned upstream source is a read-only reference under ignored `.reference/trufflehog`. To restore that cache:

```sh
git clone --depth 1 --branch v3.97.2 git@github.com:trufflesecurity/trufflehog.git .reference/trufflehog
test "$(git -C .reference/trufflehog rev-parse HEAD)" = cc1fe982afc515d2991365ce8d4d0dd07170fcad
```

Do not regenerate the inventory against a different reference to make checks pass. An upstream-version change needs an explicit migration of the full parity ledger.

## License

This derivative work retains the GNU Affero General Public License version 3. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Briar is not affiliated with or endorsed by Truffle Security.
