# Briar

A native C reimplementation of [TruffleHog 3.97.2](https://github.com/trufflesecurity/trufflehog/tree/cc1fe982afc515d2991365ce8d4d0dd07170fcad), focused on fast
scanning and a small executable. No Go runtime or wrapped Go scanner.

The target is full upstream behaviour, including detectors, verification, decoders,
sources and outputs. The implementation is still incomplete, not a drop-in
replacement or a security boundary.

## Performance

Measured against pinned TruffleHog 3.97.2 on an AMD Ryzen Threadripper 7960X:

| Synthetic workload | Briar | TruffleHog | Speedup |
|---|---:|---:|---:|
| 8 MiB mixed source | 63.3 ms | 1008.0 ms | **15.9x** |
| 8 MiB mixed encoded | 71.5 ms | 1013.6 ms | **14.2x** |
| 8 MiB dense keywords, no valid secrets | 159.8 ms | 1014.0 ms | **6.3x** |
| 128 MiB mixed source | 661.9 ms | 1258.6 ms | **1.9x** |

All rows use the same 891 explicitly selected detectors and produce identical
complete JSON findings. Figures are medians of five warm-cache runs after a
warmup, with serial Briar against 16 TruffleHog workers and verification disabled.
Timing includes startup, network-namespace setup and JSON output. Small scans
benefit substantially from lower startup cost; these are not universal throughput
ratios. Each input file is 64 KiB.

The stripped Briar executable is **3.20 MiB**, compared with **122.30 MiB** for
TruffleHog: about **38x smaller**, or **97.4% less executable space**. This excludes
shared libraries, and the incomplete migration is not yet a feature-for-feature
size comparison.

The gains come from shared keyword matching, optional ASCII-prefix regex JIT,
faster decoder and false-positive searches, and hashed result deduplication.
See the [benchmark report](docs/benchmarks/2026-11-02-performance.md) for all six
workloads, artifact hashes and reproduction instructions.

## Build and use

Nix and direnv provide the C17 toolchain and native dependencies.

```sh
direnv allow .
mkdir -p state
direnv exec . flock state/build.lock make -j2 all
direnv exec . build/briar --help

# Scan a regular file with the Abyssale detector only.
direnv exec . build/briar filesystem ./file.txt \
  --json --no-verification --include-detectors=239
```

The `stdin` and `filesystem` commands currently support:

- Stdin or explicitly named regular files, streamed without a file-size limit.
- Explicit detector selection and JSON findings, including multipart credentials.
- PLAIN/UTF8, Base64, UTF16 and escaped-Unicode decoding.

Directory traversal, default/all scans, HTML decoding and CLI verification are
not supported. Unsupported options fail explicitly. **Findings on stdout contain
secrets**; treat the output as sensitive.

## Pre-commit with Docker

Reference this repository from `.pre-commit-config.yaml`, pinning a reviewed
release tag (or a full commit SHA). After the first green master release,
`pre-commit autoupdate --repo https://github.com/willfish/briar` advances the pin
to newer release tags. HTTPS access to the public repository requires no
GitHub credentials. See [CI and releases](docs/CI_RELEASES.md) for test gates and
automatic publication; consumers still need to run and commit `autoupdate`.

```yaml
repos:
  - repo: https://github.com/willfish/briar
    rev: <full-commit-sha>
    hooks:
      - id: briar
```

The hook scans implemented, default-enabled detectors without verification and
fails on findings or errors. Clean runs are quiet; findings show file, line and
detector, never credential contents. Input streams through a fixed-size buffer;
large files are not skipped or truncated. Docker builds a minimal `scratch` image
from the pinned revision; cache its build layers in CI.
The measured Linux amd64 image is **9.44 MB unpacked**, including static libraries
and notices, or **3.98 MB** as a gzipped Docker-save archive. The earlier executable
benchmarks do not include Docker or pre-commit overhead.
See [Docker and pre-commit](docs/PRE_COMMIT.md) for image builds, result handling,
prebuilt-image use and the remaining scanning limits.

## Development

The release target is the Linux amd64 Docker image, not a native macOS build.
With Docker, Make, Python 3 and pre-commit installed, run the same acceptance gate
as CI:

```sh
make check-container
```

This runs the complete native suite in a pinned Linux/glibc test image, then
checks the exact shipped static executable, the non-root runtime image and the
real pre-commit Docker hook. The runtime image must be at most **10,000,000
uncompressed bytes**, including licenses. Test tools never enter the runtime
image. Tests use synthetic credentials with no provider networking.

[Integration testing](docs/INTEGRATION_TESTING.md) provides a single Python runner,
coverage map and explicit parity gaps.
The reference fixture runner pins TruffleHog 3.97.2 directly in
`tests/cli_reference.py`.

## License

GNU Affero General Public License version 3. See [LICENSE](LICENSE) and
[NOTICE](NOTICE) for licensing and attribution. Briar is not affiliated with or
endorsed by Truffle Security.
