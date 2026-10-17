# YARA-X 1.20.0 dependency patch

This directory contains the published `yara-x` 1.20.0 registry source. The
upstream BSD-3-Clause license and source files are retained.

The public source export includes `LICENSE` from the exact upstream `v1.20.0`
tag, SHA-256 `fdf05444c9178e662fa28810d94a1fa6ec32d7be798241c98094213317265880`.
The embedded Teddy MIT notice remains in `src/teddy/LICENSE-MIT.md`.

- Registry archive: `yara-x-1.20.0.crate` (954,448 bytes).
- Archive SHA-256: `015b06cc60800856d04c3115ef6b7c6cbb95f59f20a9df4358dd2f85f3d5b391`.
- Upstream repository: <https://github.com/VirusTotal/yara-x>.
- Official Wasmtime upgrade: [ee3aa167be3c2c9dd0a289625a2b917ee5786054](https://github.com/VirusTotal/yara-x/commit/ee3aa167be3c2c9dd0a289625a2b917ee5786054).
- Official MSRV update: [8b9b759328f5f44f6469e0df7b4c649c082f7c4f](https://github.com/VirusTotal/yara-x/commit/8b9b759328f5f44f6469e0df7b4c649c082f7c4f).

The only changes to upstream package content are in the normalized `Cargo.toml`:
Wasmtime is pinned to `=48.0.5`, and `rust-version` is raised to `1.95.0`.
`default-features = false` and the `cranelift`/`runtime` feature selection remain
unchanged. No upstream Rust source is edited. `Cargo.toml.orig` remains the
published upstream manifest for comparison; the normalized manifest controls
the build.

`AGF-UPSTREAM-SHA256.json` records the original registry source bytes before this
patch. Its original `Cargo.toml` hash intentionally differs from the patched
manifest. Cargo's `.cargo-checksum.json` and `.cargo-ok` internal bookkeeping
files are omitted from this path dependency; the original registry archive and
registry source cache are not modified. This document and the hash inventory
are project additions, so they do not appear in that upstream inventory.

The workspace keeps its registry dependency declaration and uses a
`[patch.crates-io]` path override with a workspace exclusion. This avoids a git
dependency and keeps the existing registry-only source policy. Native acceptance
hashes every file in this directory as the twelfth input scope.

Wasmtime 48.0.5 meets the fixed-version ranges for
[RUSTSEC-2026-0316](https://rustsec.org/advisories/RUSTSEC-2026-0316.html) and
[RUSTSEC-2026-0327](https://rustsec.org/advisories/RUSTSEC-2026-0327.html).
Version resolution, cache preparation, format checks, compilation, security
checks, and deployment are separate evidence. Fetching dependencies is an
online development preparation step and does not establish offline acceptance
or a passing project build.
