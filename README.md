# Facts SDK

## Protocol v0 Reference Implementation

This repository is a portable Rust/SQLite reference implementation of Facts Protocol v0. It preserves exact signed protocol bytes, validates the protocol’s canonical JSON/Markdown/CBOR and COSE profiles, derives rebuildable SQLite projecteds, and exposes CLI and Axum HTTP components.

## Status

The committed implementation includes:

- all registered object types with positive and negative fixtures;
- canonical encoding, signing, Merkle commitments, snapshots, and bundles;
- causal authorization, consensus, settlement, lifecycle, and reconciliation state;
- SQLite migrations, WAL recovery, backup/restore, and projected rebuilds;
- local CLI query and synchronization workflows;
- HTTP discovery, fetch, push, pull, query, proof, and error handling;
- an executable conformance corpus currently reporting passing checks, including the machine-readable authority matrix.

Encryption, semantic/vector search, hosted multi-writer deployment, independent security review, and comparison with an independent implementation remain outside the verified scope.

## Requirements

Install Rust and Cargo. The repository pins the toolchain in `rust-toolchain.toml` and uses a bundled SQLite build, so no system SQLite installation is required for the normal workspace build.

## Build and Verify

```sh
cargo build --workspace --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p fact -- conformance run fixtures
```

The CLI binary is named `fact`, made available in the [facts-kms/sdk](https://github.com/facts-kms/cli) repository. The HTTP crate provides an Axum router for embedding in a service; this repository does not ship a standalone HTTP daemon binary.

For a runnable walkthrough, see [QUICKSTART.md](QUICKSTART.md). The implementation-facing architecture is documented in the [facts-kms/arch](https://github.com/facts-kms/arch) repository.

## Common CLI Usage

The ergonomic CLI keeps the active ledger in a user-level catalog rather than deriving it from the current directory. Set `FACT_HOME` to override the default platform data location.

```sh
fact init
fact propose notes.md --decision accept
fact pending
fact list
fact search "coffee"
fact history
fact comments <proposition-reference>
fact revisions <proposition-reference>
fact use work
```

`fact init` creates and activates the `default` ledger. `fact init work` creates and activates a named ledger. `fact propose` accepts a Markdown file, `-` for standard input, or opens the configured editor when no file is supplied. `--decision accept` or `--decision reject` performs the corresponding signed decision and settlement as one convenience operation. Full IDs and unique ID/hash prefixes are accepted by `fact accept` and `fact reject`; omitted references work only when exactly one pending proposition is available.

`fact pending` is the actionable inbox, `fact list` defaults to effective accepted facts, `fact list --all` includes other proposition states, `fact search` performs deterministic lexical search, and `fact history` shows the append-only protocol objects. An accepted proposition with a newer unsettled revision is shown as `accepted, update pending`; the older effective content remains searchable until the update settles. Use `fact comments REF` and `fact revisions REF` for focused inspection; `fact history REF` scopes the event stream to one proposition.

Content movement is explicit: `fact open` views through an editor without changing state, `fact echo` emits canonical Markdown for pipes, `fact export` writes to a file without overwriting unless `--force` is supplied, `fact import` creates a proposition from a file, standard input, editor, or short `--message`, and `fact revise`/`fact edit` creates an immutable revision. When no file or `--message` is supplied, revision editing starts with the proposition's latest revision.

Named remotes are local-environment connection settings managed with `fact remote list|add|remove|rename` or the explicit `fact ledger remote ...` forms. No-argument `fact push` and `fact pull` use the active ledger and one configured remote; explicit bundle operations remain available through `fact sync push` and `fact sync pull`.

Use `fact help` for the human workflow, `fact help --category implicit` for personal commands, and `fact help --category explicit` for protocol and administration commands. Permission grants and revocations are available under `fact permission grant|revoke`, while `fact identity recognize|revoke` remains supported for compatibility.

Lower-level protocol-oriented commands remain available under `fact ledger`, `fact proposition`, `fact deliberation`, `fact decision`, `fact object`, and `fact query`.

## Workspace Layout

| Path | Purpose |
| --- | --- |
| `crates/fact-core` | IDs, hashes, timestamps, and shared errors |
| `crates/fact-canonical` | Canonical JSON, Markdown, and deterministic CBOR |
| `crates/fact-crypto` | Ed25519 and COSE signing/verification |
| `crates/fact-schema` | Object envelopes and the 27 object schemas |
| `crates/fact-store` | SQLite storage and migrations |
| `crates/fact-state` | Causal authorization and derived state |
| `crates/fact-commitment` | Merkle, snapshot, bundle, and proof formats |
| `crates/fact-search` | Deterministic lexical search |
| `crates/fact-http` | Axum HTTP binding |
| `crates/fact-cli` | `fact` command-line interface |
| `crates/fact-conformance` | Fixture materialization and conformance runner |
| `fixtures` | Positive, negative, and scenario test corpus |
| `migrations` | SQLite schema migrations |

## License

MIT
