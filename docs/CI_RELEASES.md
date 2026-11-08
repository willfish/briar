# CI and releases

`.github/workflows/ci.yml` validates every PR and push to `master`:

- **Linux native:** pinned Nix environment, complete `make check` (core and all detector tests, HTTP/proxy fixtures, end-to-end and process-failure tests), in user/network namespaces without external networking. Workflow/shell lint and release-planner tests also run.
- **macOS native:** same pinned Nix inputs; production CLI/library build, all core tests, complete CLI end-to-end corpus, Box OAuth and RabbitMQ synthetic verifier tests. The complete detector fault-injection suite is Linux-specific (syscall delegation, malloc/stdio interposition); it is NOT claimed to run on macOS. No provider credentials or live verification are used.
- **Docker:** builds the existing production `Dockerfile` and checks its source-revision label. Exercises the exact shipped static executable through end-to-end/process-failure tests in isolated Linux namespaces. Runs the real source-built pre-commit Docker hook against clean and synthetic-finding fixtures, asserting failure/redaction/input immutability, and proves `pre-commit autoupdate` selects a newer tag using a disposable local tagged repository. C fault-injection tests stay on the Nix/glibc runner, not musl (see INTEGRATION_TESTING.md).

The native macOS CLI explicitly ignores SIGPIPE before creating HTTP helper threads, so a broken stdout reports a normal failure instead of a deferred signal termination during cleanup. This is executable policy only; the library retains its signal-disposition behavior.

## Publication

Only a **push to master** whose three jobs all succeed reaches the publication job. PRs, fork runs and manual validation runs cannot publish. CI cannot merge PRs. Publication alone gets `contents: write`; test jobs have read-only repository permissions and do not persist checkout credentials.

The first release is `v0.1.0`; later green master commits increment the highest stable version's patch component. Existing stable tags on the same commit are reused on rerun. Prerelease/non-semver tags are ignored. To intentionally change major/minor policy, change/review `tools/ci_release.py` rather than publishing an untested version manually.

A release tag targets the **exact master SHA tested in that run**. Releases attach the already-tested Linux amd64 Docker-save archive and `SHA256SUMS`; artifacts are downloaded from the same workflow run and checksummed, not rebuilt in the publishing job. The archive loads `briar:ci` and carries the source revision label. macOS is tested, but no misleading standalone macOS executable with Nix-store library dependencies is published. Image registry/multi-architecture distribution is not part of this workflow.

The master concurrency group serializes publication; PR updates can cancel obsolete PR runs, but cannot cancel master publication. If any test, build, hook check, artifact upload or checksum fails, **no release is published**. No `continue-on-error`, test bypass, tag-triggered shortcut or `pull_request_target` path exists.

## Consumers

After the first green master release, use its stable tag in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/willfish/briar
    rev: v0.1.0
    hooks:
      - id: briar
```

Advance the pin with:

```sh
pre-commit autoupdate --repo https://github.com/willfish/briar
pre-commit run briar --all-files
```

`autoupdate` discovers Git release tags and edits the consumer's pinned `rev`; it does not run automatically or silently change consumers when a GitHub release appears. Commit the consumer config update, or use your existing updater to propose it. The Docker-language hook then builds from the tagged source revision. An image archive alone would not make `autoupdate` work; the tagged `.pre-commit-hooks.yaml` is the integration contract.

## Local checks

```sh
nix develop -c actionlint .github/workflows/ci.yml
python3 -m unittest discover -s tests -p test_ci_release.py -v
nix develop -c make -j3 all check-core check-e2e
```

Use Linux for the complete suite and a running Docker engine for `tools/ci_hook_smoke.py`. A locally green subset is not evidence of green hosted CI; inspect all three checks before merging.
