# Contributing

Rust follows the librustzcash house style.

- `cargo fmt` before a review.
- `cargo clippy --workspace --all-targets -- -D warnings` stays clean.
- `cargo test --workspace` is the check that matters.
- Library paths return `Result`. `unwrap` belongs in tests.
- Do not log a share, a nonce, a viewing key, or alpha.
- Comments say why. They do not restate the line.
- New mandate behavior needs a vector in `spec/vectors/mandate.json` and a test that loads it.

The TypeScript in `src/` is the ZIP-321 receive helper. `pnpm test` covers it.

Write in plain sentences. Do not use an em dash.
