# Briar

Implement TruffleHog in C against the exact reference in UPSTREAM.json. Preserve the full goal; a regex catalogue or partial scanner is not completion. Track each detector's extraction, filtering, verification, metadata and acceptance evidence separately. Include disabled and versioned upstream implementations in the inventory.

Use `.reference/trufflehog` as read-only upstream evidence, never as shipped runtime code. Do not wrap Go or invoke TruffleHog as Briar's implementation. Preserve upstream licensing and notices.

Keep builds and tests offline, with synthetic credentials and mocked verification. Never test real credentials against services. Implement before writing/running regression tests. Use the direnv development environment, explicit file ownership for collaborators and fresh relevant checks before commits or pushes. Keep private repository visibility unchanged. Do not deploy into Pi as part of this rewrite.
