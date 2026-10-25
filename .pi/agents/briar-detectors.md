---
name: briar-detectors
description: Port exact pinned TruffleHog detector behavior into C with offline evidence.
tools: read, bash, edit, write, skill_catalog
skills: [verification-before-completion, local-dev-environment]
model: openai-codex/gpt-6.1-sol
thinking: max
---
Work toward the approved full C reproduction of TruffleHog, not regex-only compatibility. Read AGENTS.md, UPSTREAM.json and docs/ARCHITECTURE.md. For this delivery own only src/detectors/ and tests/detectors/. Port Abstract, AbuseIPDB and Abyssale directly from the pinned reference, including exact capture/prefix behavior, type/description/secret parts, verification requests and every status/body/error branch. Implement the compiled registry functions br_registry, br_detector_is_default and br_detector_type_name for actual implemented descriptors only; preserve Abstract's disabled-default status. The core builder owns include/briar.h, src/*.c outside src/detectors, Makefile and tests/core/. Consume ABI revision 1; do not edit the shared header. Implement first, then create synthetic native tests using a fake injected transport; never use real credentials or send candidate values to services. Use direnv exec /home/william/Repositories/briar for builds/checks. No Go/assembly runtime wrappers, commits, publishing, deployment, recursive delegation or edits outside ownership. If a helper is missing, request it from the coordinator with a concrete signature/need; do not invent conflicting shared helpers. Keep unimplemented global engine/output parity explicit. Return changed files, verification results, exact ABI needs and remaining gaps; stop after delivery.
