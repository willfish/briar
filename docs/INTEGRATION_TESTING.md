# Integration testing

These checks cover implemented integration boundaries. A passing run does not
mean every TruffleHog feature or failure condition is reproduced. Unsupported
operations must fail explicitly, but rejecting an operation is not parity with
an upstream implementation that supports it.

## Run

The required local and CI acceptance gate is:

```sh
make check-container
```

It needs Docker, Make, Python 3 and pre-commit on the host, not host Nix or a C
toolchain. The Dockerfile's separate `test` stage uses the pinned Nix/glibc
environment to compile and run the complete native suite. Each test container has
only loopback networking and an empty HOME. The entrypoint rejects external
interfaces or default routes; no privileged container or host sysctl change is
required. Native macOS is not a release target.

The same gate checks the final Linux amd64 image's uncompressed size against
10,000,000 bytes, runs the existing CLI/process-failure suites on its extracted
static executable inside the test container, exercises the actual non-root image
with read-only fixtures, and runs the real source-built pre-commit hook. Only then
does it write the tested image archive and checksum to `dist/`.

For a narrower development loop, `make check-native-container`, `make check-image`
and `make check-hook` run individual groups; none alone replaces the full gate.
Use `TEST_JOBS=N` to change native build/test parallelism.

### Native and pinned-reference checks

From the repository root, in the Nix/direnv environment:

```sh
direnv exec . python3 tests/integration.py --reference /path/to/pinned/trufflehog
```

The runner builds stale targets, holds `state/build.lock`, and runs native checks
and the complete retained reference corpus. It requires Linux user/network
namespaces, `/proc`, and the development environment's `ip` and `setpriv` tools.
Children run with an initially empty HOME and no external network interfaces.
HTTP fixtures use loopback only, synthetic credentials, and no forwarding.
Isolation failure is a test failure; there is no live-network fallback.

Use `--native-only` to explicitly omit upstream comparisons. `--jobs N` controls
build parallelism and independent reference comparisons, not scanner concurrency.
`--build-dir DIR` selects an alternative native build directory. Nonzero test or
build exits fail the runner; it also rejects a binary changing during the checks.

For the process-failure checks alone, after building:

```sh
direnv exec . unshare -Urn python3 tests/core/cli_failures.py build/briar
```

That script creates an empty HOME for each test. Add `--reference PATH` to run
only the shared upstream exit/outcome comparisons; the full runner executes both.

## Container artifact

The reference version is pinned in `tests/cli_reference.py`. To check the actual
static executable from a locally built image, without provider networking:

```sh
mkdir -p state
docker build -t briar:local .
container=$(docker create --network=none briar:local --help)
docker cp "$container:/briar" state/briar-container
docker rm "$container"
direnv exec . unshare -Urn python3 tests/core/e2e.py state/briar-container
direnv exec . unshare -Urn python3 tests/core/cli_failures.py state/briar-container
direnv exec . python3 tests/cli_reference.py --native state/briar-container \
  --reference /path/to/pinned/trufflehog --jobs 8
pre-commit validate-manifest .pre-commit-hooks.yaml
```

Exercise the repository hook in a disposable consumer with synthetic files using
`pre-commit try-repo /path/to/briar briar --all-files`. Check both clean and
finding-containing files, exit status, location-only output and unchanged inputs.
See [Docker and pre-commit](PRE_COMMIT.md) for the hook's contract.

Keep the C fault-injection suite in the supported Nix environment. Some tests
interpose shared-library/libc symbols: static linking can conflict with those
overrides, and a test's `malloc` forwarding to `calloc` recurses on musl. Those
harness assumptions are not valid substitutes for testing the shipped executable.
The Dockerfile's glibc `test` stage preserves this suite without adding glibc or
test tooling to the musl/scratch runtime.

## Coverage map

| Boundary | Executed evidence | What it checks |
|---|---|---|
| Arguments and selection | `tests/core/e2e.py`, `tests/core/cli_failures.py` | Supported options and terminator, invalid/missing values, detector versions/default restrictions, result filters and finding-sensitive exit 183 |
| Pre-commit command | `cli_failures.py`, `test_cli_io.c` | Implemented-catalogue selection, fail-on-finding, output allowlist, option-looking filenames, suppression guards and scan-failure rollback |
| Files and stdin | The same Python scripts | Missing/inaccessible paths, symlinks, nonregular files, read errors, size caps, chunk/peek boundaries, immutable inputs and rollback of earlier files on scan failure |
| Process and output | `cli_failures.py`, `tests/core/test_cli_io.c` | SIGINT/SIGTERM during pending input and blocked output, broken/full/nonblocking output, preserved descriptor flags, SIGPIPE disposition and diagnostic secrecy for tested failures |
| Decoder/engine/result pipeline | `e2e.py`, `tests/cli_reference.py`, core decoder/overlap/prefilter tests | Complete selected findings, nested decoding, filtering, multipart windows, locations, deduplication and overlap outcomes |
| Native HTTP | `tests/core/http_profiles.py` and its C helper | SANE/LOCAL GET/POST, binary and empty bodies, source-client routing, redirects and guards, status errors, malformed/incomplete headers, truncated/oversized bodies, gzip success/error, deadlines, cancellation, owned-client read-error promotion and release |
| Proxy/TLS failure | `tests/core/proxy_connect.py` and its C helper | CONNECT 200 followed by TLS failure cannot verify status-only detectors; no forwarding or external DNS |
| Provider and shared-library boundaries | All `tests/detectors/test_*.c` and `tests/core/test_*.c` through `make check` | Named provider extraction/verification policies, registry dispatch, injected transport/resource failures, ownership, JSON/error propagation, private protocol adapters and coalescing |
| Pinned upstream outcomes | `tests/cli_reference.py`, `cli_failures.py --reference` | Retained complete JSON comparisons plus shared invalid-command/option and `--fail` outcomes; exit codes must match, while diagnostic text is not claimed identical |

Scan failures before printing discard buffered findings. Output failures can
leave bytes already written; consumers must check the exit status and must not
treat partial stdout as a successful scan. Cancellation must not require draining
a stalled output pipe to let the process exit.

## Explicit gaps

No detector or component is promoted to complete by this suite.

- CLI verification, verification cache, upstream default/all scans, directory traversal,
  archives, other sources/printers, HTML decoding and remaining configuration are
  not implemented. Their rejection tests are safeguards, not upstream parity.
- Injected SQL, LDAP, FTP, DNS, SDK and authentication tests do not establish native
  protocol integration. Real provider acceptance is deliberately not exercised.
- HTTP coverage is the implemented native subset, not complete Go transport
  parity. PUBLIC policy, some redirects/client families, retries, trust-store
  behaviour, streaming and exact transport diagnostics remain incomplete.
- Gzip truncation detection remains a concrete gap: native curl can accept a
  one-byte gzip response as empty without reporting a body error. The malformed
  longer-stream test must not be interpreted as covering every truncated stream.
- Existing allocation-failure tests are not exhaustive fault injection at every
  allocation/syscall. Neither this boundary map nor assertion counts constitute
  a statement of 100 percent branch coverage or every possible race.
