# Briar development

- Treat the Linux amd64 Docker image as the shipped product. Do not add native
  macOS requirements or Darwin-only code unless explicitly requested.
- Run `make check-container` before claiming completion, committing or merging.
  CI uses this same Make target. It requires Docker, Make, Python 3 and pre-commit;
  it does not require host Nix or a host C toolchain.
- Keep the final runtime image at or below **10,000,000 uncompressed bytes**,
  including licenses. Do not replace this gate with a compressed archive size.
- Keep compiler, Python and test dependencies in the separate `test` Docker stage.
  Run the complete native suite there, then exercise the exact final image and
  its executable. `make check` alone is not the container acceptance gate.
- Preserve network isolation, synthetic credentials, the non-root runtime user,
  read-only fixture mounts, credential-safe hook output and unchanged inputs.
  Never use live provider credentials in tests or privileged containers to bypass
  isolation failures. Existing allocator-interposition tests require glibc.
- Keep release publication master-only and gated on container acceptance. Reject
  stale master runs and release the tested artifact, never an untested rebuild.

See `docs/INTEGRATION_TESTING.md` and `docs/CI_RELEASES.md` for scope and limits.
