# CI and releases

Every PR and push to `master` runs `make check-container`, the same acceptance
gate required locally by `AGENTS.md`.

- The separate Linux/glibc `test` Docker stage builds the full native C suite
  using pinned Nix inputs. Tests, workflow/shell lint and release-planner
  regressions run with no external networking and an empty HOME.
- The production Alpine/scratch image is built separately. Its **uncompressed
  image size must be at most 10,000,000 bytes**, including licenses. Python and
  compiler dependencies are never shipped in it.
- Existing end-to-end and process-failure suites exercise the exact shipped
  executable inside the offline test container. Direct runtime-image checks use
  the shipped non-root user and read-only fixtures. The real pre-commit Docker
  hook checks clean input, synthetic findings, credential-safe output and input
  immutability. A disposable tagged repository checks `pre-commit autoupdate`.

Native macOS builds are not a release requirement. No provider credentials, live
verification, privileged test containers or host namespace-policy changes are
needed. See [integration testing](INTEGRATION_TESTING.md) for retained gaps.

## Publication

Only a successful **push to master** can publish. PRs and manual validation runs
cannot publish or merge. Publication alone has `contents: write`; checkout
credentials are not persisted.

The publishing job refreshes `origin/master`. It skips a run unless its tested
SHA is still current master and contains the highest stable tag's commit. This
prevents an old failed run from creating a newer version of older source when
retried. The workflow concurrency group serializes master runs.

Without existing stable tags, the first version is `v0.1.0`. Later eligible
commits increment the highest stable version's patch component. Stable tags on
the same commit are reused on rerun; prerelease and non-semver tags are ignored.

The release targets the **exact tested commit** and attaches the already-tested
Linux amd64 Docker-save archive and `SHA256SUMS` from that workflow run, after
checksum verification. Publication never rebuilds the image. The archive loads
the image tag passed to Make, `briar:ci` in CI, and carries the source-revision
label. Registry distribution, other architectures and native macOS binaries are
outside this release contract.

## Consumers

Pin a reviewed stable tag in `.pre-commit-config.yaml`, then advance it explicitly:

```sh
pre-commit autoupdate --repo https://github.com/willfish/briar
pre-commit run briar --all-files
```

Commit the updated consumer config or use an updater PR. A new GitHub release
does not silently change consumer pins. The tagged `.pre-commit-hooks.yaml`
remains the source-built hook contract; an image archive alone is not enough.
