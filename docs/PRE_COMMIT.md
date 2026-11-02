# Docker and pre-commit

Briar's hook scans explicit files using the implemented, default-enabled detector
catalogue. It does not verify credentials or contact providers. This remains an
incomplete scanner, not a substitute for full TruffleHog coverage.

## Reference this repository

Install pre-commit and a working Docker engine configured for Linux containers.
Add this to the consuming repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/willfish/briar
    rev: <full-commit-sha>
    hooks:
      - id: briar
```

Replace `rev` with a reviewed commit containing `.pre-commit-hooks.yaml`. The
public repository can be fetched over HTTPS without credentials. Run
`pre-commit install`, or use
`pre-commit run briar --all-files` in CI. Docker hooks require a Docker-capable
runner; they do not run on pre-commit.ci.

The hook builds its image from that revision. It runs serially to avoid parallel
container startup, although pre-commit can still split long filename lists into
multiple invocations. It scans pre-commit's selected files, not Git history or
all files on disk. Symlinks are excluded by `types: [file]`.

To narrow the detector set, override `args` and retain the final `--` so filenames
cannot become options:

```yaml
      - id: briar
        args: ['--include-detectors=239,521', '--']
```

`--exclude-detectors` is also supported. Result-suppression options are rejected.

## Results and limits

- Clean scans exit zero. Findings exit 183 and fail the hook. Invalid arguments,
  unsupported inputs and scan/output errors exit 1 and also fail it.
- Clean scans are quiet. Findings show a count, filename, line, detector and
  decoder, followed by a reminder to remove credentials and stage the correction.
  Matches are labelled as potential secrets, not verified credentials.
- Credential values, provider metadata and even the potentially sensitive
  `Redacted` field are omitted. Filenames are quoted with control characters
  escaped, but their contents are not redacted.
- Files have no size cap. Input streams through a 13 KiB buffer, retaining 3 KiB
  of overlap between 10 KiB content chunks. Decoder windows remain bounded;
  findings and deduplication state still consume memory proportional to results.
- Directory traversal, archives, HTML decoding and provider verification remain
  unsupported. Upstream-disabled detectors remain disabled.
- Ordinary scanner filtering still applies. A successful hook is not proof that
  a file contains no secrets.
- Inputs are not modified. Pre-commit itself mounts the checkout read-write;
  the hook is not a filesystem or network sandbox. The application disables
  verification, but pre-commit's `docker` language does not disable networking.

A failed scan reports an error instead of partial findings. Results are buffered
until every selected file has been scanned successfully. Output failures cannot
retract bytes already written; always check the exit status.

Example finding output (no credential values):

```text
Found 1 potential secret (offline, not verified):
  "config/service.env":12: Abyssale (PLAIN)

Remove real credentials, stage the changes, and retry. Credential values are hidden.
```

For tooling, `args: ['--json', '--']` selects newline-delimited JSON containing
only `SourceMetadata`, `DetectorType`, `DetectorName` and `DecoderName`. The same
failure exit codes and credential-value protections apply. Unlike the ordinary
`stdin` and `filesystem` JSON output, hook JSON never includes credential fields.

## Build and run the image directly

```sh
docker build -t briar:local .
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --user "$(id -u):$(id -g)" \
  --volume "$PWD:/src:ro" briar:local -- ./file.txt

docker image inspect briar:local --format '{{.Size}}'
docker save briar:local | gzip -n > briar-image.tar.gz
```

The final `scratch` image contains a stripped, static PIE executable and license
notices only. No shell, package manager, compiler or shared-library closure is
shipped. Packed relative relocations reduce size without disabling address
randomization. The build rejects a runtime payload of 10,000,000 bytes or more.
Only Linux amd64 has been exercised; other architectures need their own checks.

The base image is digest-pinned and the curl/libxml2 source downloads are
checksum-pinned. Other build packages follow Alpine's stable release repository,
so rebuilding the same revision is not a promise of identical bytes. Review
package updates and the notices in `container/licenses` together. This container
packages the CLI, not a general-purpose HTTP verification library: optional curl
IDN, public-suffix, HTTP/2, Brotli and Zstandard dependencies are omitted.

## Measured size and overhead

The original JSON-output hook was measured on Linux amd64 with a Threadripper
7960X, Docker 29.9.2 and pre-commit 4.5.1. These are historical packaging results,
not timings for the current streaming reader and readable output:

- Unpacked image: **9,442,461 bytes** (9.44 decimal MB).
- Gzipped Docker-save archive: **3,978,964 bytes**. This is an archive measurement,
  not a registry's compressed-layer or network-transfer measurement.
- Uncached build steps: **57.1 seconds**, with the Alpine base already present
  and four build jobs. A fully cold machine also needs to pull that base.

For sixteen 64 KiB synthetic files, 891 detectors and sixteen findings:

| Invocation | Median elapsed |
|---|---:|
| Static executable, including network-namespace setup | 42 ms |
| Docker container | 219 ms |
| Cached repository hook (`docker`) | 611 ms |
| Cached prebuilt-image hook (`docker_image`) | 424 ms |

One warmup preceded five alternating runs. Complete location-only findings
matched after filename sorting, and inputs remained unchanged. Scans used empty
HOME directories and no external networking. These numbers measure packaging
and hook overhead, not a new TruffleHog speed comparison or a CI service-level
promise. The [measurement record](benchmarks/2026-11-02-container.json) identifies
the tested binary and image.

## CI caching and prebuilt images

The small runtime does **not** make a first-time source build cheap. A cold runner
still downloads the builder toolchain and compiles C dependencies. Cache Docker
build layers as well as `PRE_COMMIT_HOME`; caching only pre-commit's directory
does not preserve Docker images. Warm `language: docker` hooks also invoke
`docker build` to check the cache on each run.

To reuse an image already built on the runner without that build check:

```yaml
repos:
  - repo: local
    hooks:
      - id: briar
        name: Briar (offline secret scan)
        language: docker_image
        entry: --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges briar:local
        args: ['--']
        types: [file]
        require_serial: true
```

Build `briar:local` first. For a published image, replace it with your authorized
registry reference pinned by digest. This repository does not currently provide
a published-image hook. Image distribution is separate from the source-built
hook, and private images require registry access. Measure startup and cache
behaviour in your own CI before assuming a speedup.
