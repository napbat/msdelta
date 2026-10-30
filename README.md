# msdelta

msdelta applies Windows MSDELTA patches in the PA30 and PA31 formats. It is portable Rust: it
does not use `msdelta.dll`, `UpdateCompression.dll` or other Windows APIs, and it works with
`no_std`.

Windows updates store most changed files as delta patches. On Windows, `ApplyDeltaB` in
`msdelta.dll` (PA30) or `UpdateCompression.dll` (PA30 and PA31) applies them. msdelta gives
the same output on each platform.

## Status

| Feature | Status |
| --- | --- |
| PA30 header (`GetDeltaInfoB`) | Supported |
| PA31 header, with the source hash (Windows 11 update payloads) | Supported |
| Raw deltas (`DELTA_FILE_TYPE_RAW`), with and without a source | Supported |
| Base rift tables and source matches through rift tables | Supported |
| MD5, SHA-1 and SHA-256 target hashes, PA31 source hash check | Supported |
| PE preprocessing: AMD64, CLI4_AMD64, I386, CLI4_I386 (images without .NET metadata) | Supported |
| PE transforms: mark, imports, exports, resources, relocations, unbind, x64 disassembly, x64 `.pdata`, x86 lock prefixes, jumps and calls | Supported |
| `DELTA_FLAG_E8` post-processing | Supported |
| bsdiff patches of PA31 deltas (flag `0x2000000`, LZMS framing) | Supported with the `lzms` feature |
| .NET (CLI) metadata and CLI map | Not supported |
| IA64, ARM, ARM64 and CLI4_ARM/CLI4_ARM64 preprocessing | Not supported |
| PA31 reverse deltas (file type set bit `0x100`, WinSxS `r\` files) | Not supported |
| PA19 deltas | Not supported |

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

`apply` checks the target hash of the delta, and the source hash of a PA31 delta. `apply_with`
sets a limit for the target size and can skip the hash checks.

For a PSF payload of a Windows update (`f\` files in `express.psf.cix.xml`), remove the 4-byte
CRC32 prefix before you give the delta to msdelta.

## Features

- `std` (default): link the standard library. The crate works without it (`no_std + alloc`).
- `lzms` (default): decompress the LZMS patch buffer of a bsdiff delta with the
  [lzms](https://github.com/napbat/lzms) crate. Without it, such a delta gives `Unsupported`.

## Format notes

A PA30 delta starts with `PA30` and the 64-bit target file time. An LSB-first bitstream
follows. Its first three bits give the padding of the last byte. The stream codes each number
as a count of nibbles and the nibbles, and each buffer as a size, padding to a byte boundary,
and the bytes.

The outer stream has the `DELTA_HEADER_INFO` fields, the preprocessing buffer and the patch
buffer. The patch buffer has the base rift table, the compression parameters and the
compressed target. The compressor is an LZX variant with a window that starts with the source.

A PA31 delta starts with `PA31` and the file time. Its outer stream starts with a buffer with
its own bitstream: the `DELTA_HEADER_INFO` fields, the size of the header structure of
`UpdateCompression.dll` (0x88), the format version (1), the lowest applier version (0 or 1) and
the source hash. The preprocessing buffer and the patch buffer follow, as in PA30. The flag
`0x10000000` makes `UpdateCompression.dll` write PA31.

A rift table is a list of `(left, right)` entries: a piecewise mapping between two address
spaces. Each value is coded with a Huffman code of 252 symbols for signed integers. For a PE
image, the preprocessing buffer has the target image base, global pointer, time stamp, a rift
table from target RVAs to file offsets, and a rift table from source RVAs to target RVAs. The
applier changes a copy of the source with the transforms of the flags, so that it looks like
the target. The decompressor then uses the inverse of the composed rift tables to find the
source data of each source match.

With flag `0x2000000`, `UpdateCompression.dll` stores a bsdiff patch instead of the LZX
stream. The patch buffer is LZMS data in the buffer framing of the Windows Compression API
(flag `0x8000000`). The commands follow the format of `bspatch`, with 8-byte numbers in sign
and magnitude form.

These notes and the [msdelta-pa30-format](https://github.com/smilingthax/msdelta-pa30-format)
notes describe the format. The PE transforms follow the behavior of `UpdateCompression.dll`.

## Tests

`scripts/make-fixtures.py` makes the fixtures with `msdelta.dll` and `UpdateCompression.dll`
on Windows. A fixed-seed generator makes most sources and targets, so the repository keeps
only the deltas. The PE fixtures use small DLLs that `scripts/build-pe-fixtures.py` builds from
the C sources in `tests/fixtures/pe/src` with the MSVC tools: x64 and x86 DLLs with code,
imports, exports, relocations, resources and unwind data, and a data-only DLL in the shape of
`apisetschema.dll`. The tests compare the output of msdelta with the target of the Windows
DLL, and the header with `GetDeltaInfoB`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
