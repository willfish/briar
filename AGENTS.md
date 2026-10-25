# Briar

Implement TruffleHog in C against the exact reference in UPSTREAM.json. Preserve the full goal; a regex catalogue or partial scanner is not completion. Track each detector's extraction, filtering, verification, metadata and acceptance evidence separately. Include disabled and versioned upstream implementations in the inventory.

Use `.reference/trufflehog` as read-only upstream evidence, never as shipped runtime code. Do not wrap Go or invoke TruffleHog as Briar's implementation. Preserve upstream licensing and notices.

Organise code by named detector/provider, never by implementation batches. Use the common `br_detector` interface, keep provider-specific behaviour explicit, and share only genuinely common mechanics. Put each detector's tests in its named test file and reuse the shared test helpers. Use `upstream-inventory.json` as the queue and `parity.json` as the evidence ledger, not competing lists. Every file must do one thing clearly for its reader and reduce codebase churn.

Compile as needed while implementing. Run focused checks when a detector is finished, commit each detector independently, and reserve broad integration checks for the integrated end step. Use four detector-scoped agents when migrating in parallel, with disjoint ownership and no shared-file edits.

Keep builds and tests offline, with synthetic credentials and mocked verification. Never test real credentials against services. Implement before writing/running regression tests. Use the direnv development environment, explicit file ownership for collaborators and fresh relevant checks before commits or pushes. Keep private repository visibility unchanged. Do not deploy into Pi as part of this rewrite.
