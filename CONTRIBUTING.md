# Contributing

- Pseudonyms are welcome. Configure git with a noreply address before your first commit.
- No custom cryptography, telemetry or third-party analytics SDKs.
- Protocol changes start with `docs/PROTOCOL.md` and `docs/test-vectors.json`; both clients must
  pass the vectors.
- Before a pull request: `cargo fmt --all`, `cargo clippy --workspace --all-targets`,
  `cargo test --workspace`, and `./gradlew testDebugUnitTest` for Android changes.
- Tests must never touch real user data: use temporary directories.
- Report vulnerabilities privately, see `SECURITY.md`.
