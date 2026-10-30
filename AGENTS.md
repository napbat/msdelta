# Agent rules

These rules apply to all agents that change this repository. Obey all rules in all changes.

## Language: ASD-STE100 style

Write all new and changed text in a style like ASD-STE100 Simplified Technical English. This
includes doc comments, code comments, Markdown files and commit messages. Follow the writing
rules below. The STE dictionary does not apply: use any clear English word.

- Keep sentences short: about 20 words for an instruction, about 25 words for a description.
- Write one instruction in each sentence.
- Use the imperative form for instructions.
- Use the active voice.
- Prefer simple tenses.
- Give each word one meaning, and use the same term for the same item each time.
- Use the names from the code for code items (for example `DeltaHeader`, `apply`).
- Use articles ("the", "a") where they make the text clearer.
- Avoid long noun clusters. Break up clusters of more than three words.
- Write short paragraphs with one topic each.
- Use a vertical list for a sequence of steps or for many items.
- Put a warning or a caution before the instruction it applies to.

Start the summary line of each doc comment with a verb in the imperative form (for example
"Read one symbol."). Do not use the third person ("Reads").

Write a commit message as `area: summary`, with a lowercase summary. Use the module name as the
area (for example `bits`, `lz`, `header`). For a change outside `src/`, use the top-level item
(for example `ci`, `scripts`, `readme`).

## Lints: Clippy pedantic

The crate denies all warnings, all Clippy `pedantic` lints, `missing_docs` and `unsafe_code`.
The `[lints]` table in `Cargo.toml` sets this.

- Do not lower a lint level in the manifest or in the code.
- Do not use `#[allow(...)]`. The manifest denies `clippy::allow_attributes`.
- Use `#[expect(lint, reason = "...")]` only if no change to the code can remove the lint.
- Make sure that each expectation is fulfilled on 32-bit and 64-bit targets, with and without
  the `std` feature. An unfulfilled expectation is an error.
- Do not add an item to `clippy.toml` to hide a lint.
- Do not add `unsafe` code.

## File size: 1000 lines

- Keep each source file at a maximum of 1000 lines. This includes integration tests.
- If a change makes a file longer than 1000 lines, split the file into submodules by topic.
- Put each submodule in a new file below the directory of its parent module.

Clippy also limits each function to 100 lines (the `too_many_lines` default).

## Layout: Cargo package layout

- Put the library root in `src/lib.rs` and integration tests in `tests/`.
- Put a module in `foo.rs` and its child modules in `foo/`. Do not use `mod.rs` files.
- Put development scripts in `scripts/`. The package does not include them.
- Re-export a new public type from the crate root (`src/lib.rs`).

## Library rules

- Keep the library usable as `no_std + alloc`. Import `alloc` items through
  `use crate::prelude::*;`.
- Treat each delta and each source as untrusted input. Do not panic on input data.
- Use checked arithmetic and `TryFrom` for values from input data. On failure, return an
  `Error` with the `ErrorKind` that matches the problem. Do not use an `as` cast that can
  truncate or wrap.
- Bound each allocation that a value from the delta controls.
- Give the same output as `msdelta.dll` (`ApplyDeltaB`). For a feature that the crate does not
  support, return an `Unsupported` error. Do not guess.
- Remember that `usize` has 32 bits on `i686-pc-windows-msvc`.
- Do not use language features or library APIs newer than Rust 1.88 (`rust-version`).

## Tests

- Add a regression test for each defect. Make sure that the test fails before the fix.
- Make each fixture delta with `scripts/make-fixtures.py`, `msdelta.dll` (PA30) and
  `UpdateCompression.dll` (PA31). Make the source and the target in the test with the
  fixed-seed generator, or use the self-built PE images of `scripts/build-pe-fixtures.py`.
  Do not commit Microsoft files.
- Make sure that the tests pass with and without the default features (`std`, `lzms`).
- For a PE transform, compare the transformed source with `UpdateCompression.dll`
  (`PreProcessor::PreProcessForApply`), and isolate the transform with `-ResetFlags`.
- Do not use wall-clock time or random data without a fixed seed.

## Checks

Make sure that all these checks pass before you report a change as complete:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo clippy --all-targets --target i686-pc-windows-msvc -- -D warnings
cargo test
cargo test --no-default-features
cargo test --target i686-pc-windows-msvc
cargo doc --no-deps
cargo +1.88.0 test
```

`mise run precommit` runs the format and Clippy checks.
