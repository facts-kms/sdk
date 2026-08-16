# Quickstart

This walkthrough builds the reference implementation, runs the conformance corpus, initializes a user-level ledger, creates propositions, and accepts one as an effective fact.

Run these commands from the repository root.

## 1. Build and run the conformance suite

```sh
cargo build --workspace --locked
cargo run --locked -p fact -- conformance run fixtures
```

Expected result:

```text
conformance vectors: 74 passed, 0 failed (Some("fixtures"))
```

For machine-readable output:

```sh
cargo run --locked -p fact -- --json conformance run fixtures
```

## 2. Validate a fixture

The positive fixture corpus contains canonical unsigned object envelopes. Validate one directly:

```sh
cargo run --locked -p fact -- object validate fixtures/positive/objects/actor.json
```

Expected result:

```text
valid canonical actor object bytes (402)
```

A negative fixture should fail validation, for example:

```sh
cargo run --locked -p fact -- object validate fixtures/negative/encoding/noncanonical-json.json
```

## 3. Initialize a local ledger

Use a fixed 32-byte seed for a repeatable signing identity in this demo. The ledger ID and object IDs are UUIDv7 values and therefore change on each initialization.

```sh
cargo run --locked -p fact -- --json init
```

The JSON response reports the active `ledger_id` and `actor_id`. User-level state is stored under the platform data directory, or under `FACT_HOME` when that variable is set. The bootstrap objects are staged and inserted atomically.

Create a proposition from a Markdown file and accept it immediately:

```sh
cargo run --locked -p fact -- propose notes.md --decision accept
```

The command creates the proposition, revision, deliberation, decision, and settlement objects. To separate proposal and decision, omit `--decision`, then use the short reference shown by `fact pending`:

```sh
cargo run --locked -p fact -- propose notes.md
cargo run --locked -p fact -- pending
cargo run --locked -p fact -- accept <short-reference>
```

List current effective facts or all proposition states:

```sh
cargo run --locked -p fact -- list
cargo run --locked -p fact -- list --all
cargo run --locked -p fact -- list --status pending
cargo run --locked -p fact -- search "fixtures"
cargo run --locked -p fact -- history
cargo run --locked -p fact -- comments <short-reference>
cargo run --locked -p fact -- revisions <short-reference>
```

Use `fact help --category implicit` for the personal command set and
`fact help --category explicit` for protocol and administration commands. Short
Markdown can be supplied without a temporary file:

```sh
cargo run --locked -p fact -- propose --message '# Inline fact

Created from a message.'
```

The lower-level SQLite commands remain available when an explicit database path and protocol identifiers are needed.

## 4. Inspect available commands

```sh
cargo run --locked -p fact -- --help
cargo run --locked -p fact -- object --help
cargo run --locked -p fact -- query --help
cargo run --locked -p fact -- sync --help
cargo run --locked -p fact -- proposition inspect <DATABASE> <LEDGER_ID> <PROPOSITION_ID>
cargo run --locked -p fact -- deliberation inspect <DATABASE> <LEDGER_ID> <DELIBERATION_ID>
```

Useful local commands include `object validate`, `object export`, `state rebuild`, `query search`, `commitment create`, `proof include`, `proof exclude`, and `conformance materialize`.

## 5. Clean up an isolated demo environment

When testing without affecting your normal user state, set `FACT_HOME` to a temporary directory:

```sh
FACT_HOME=/tmp/fact-demo cargo run --locked -p fact -- init
```

For HTTP integration, construct `fact_http::AppState` with a `fact_store::Store` and pass it to `fact_http::router`; the crate’s tests and conformance API vectors provide in-process examples of the supported routes.
