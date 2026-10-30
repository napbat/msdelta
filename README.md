# msdelta

msdelta applies Windows MSDELTA patches in the PA30 format. It is portable Rust: it does not
use `msdelta.dll` or other Windows APIs, and it works with `no_std`.

Windows updates store most changed files as delta patches. On Windows, `ApplyDeltaB` in
`msdelta.dll` applies them. msdelta gives the same output on each platform.

## Status

| Feature | Status |
| --- | --- |
| PA30 header (`GetDeltaInfoB`) | Supported |
| Raw deltas (`DELTA_FILE_TYPE_RAW`), with and without a source | Supported |
| MD5 and SHA-1 target hashes | Supported |
| PE preprocessing (I386, AMD64, ARM, ARM64, CLI4) | Not yet |
| Non-empty base rift tables | Not yet |
| PA31 (Windows 11 update payloads) | Not yet |

msdelta returns an `Unsupported` error for a delta that needs a missing feature. It does not
guess.

## Usage

```rust,no_run
# let (source, delta): (&[u8], &[u8]) = (&[], &[]);
let header = msdelta::DeltaHeader::parse(delta)?;
println!("target: {} bytes", header.target_size);

let target = msdelta::apply(source, delta)?;
# Ok::<(), msdelta::Error>(())
```

`apply` checks the target hash of the delta. `apply_with` sets a limit for the target size and
can skip the hash check.

## Format notes

A PA30 delta starts with `PA30` and the 64-bit target file time. An LSB-first bitstream
follows. Its first three bits give the padding of the last byte. The stream codes each number
as a count of nibbles and the nibbles, and each buffer as a size, padding to a byte boundary,
and the bytes.

The outer stream has the `DELTA_HEADER_INFO` fields, the preprocessing buffer and the patch
buffer. The patch buffer has the base rift table, the compression parameters and the
compressed target. The compressor is an LZX variant with a window that starts with the source.

These notes and the [msdelta-pa30-format](https://github.com/smilingthax/msdelta-pa30-format)
notes describe the format.

## Tests

`scripts/make-fixtures.py` makes the fixtures with `msdelta.dll` on Windows. A fixed-seed
generator makes the sources and the targets, so the repository keeps only the deltas. The
tests compare the output of msdelta with the target of `msdelta.dll`, and the header with
`GetDeltaInfoB`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
