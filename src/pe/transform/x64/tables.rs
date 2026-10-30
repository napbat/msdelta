//! Give the opcode tables of `DisassemblerAmd64`.
//!
//! The `DisassemblerAmd64` constructor (`0x18004dfa4` in `UpdateCompression.dll`) builds four
//! tables of 256 `u32` values from immediate operands in its code. The DLL has no copy of the
//! tables in its data sections. To get the tables, call the constructor in-process (for example
//! with Python `ctypes` at RVA `0x4dfa4` of the loaded `UpdateCompression.dll`) on a buffer of
//! 4096 bytes. Then read the buffer as four arrays of 256 little-endian `u32` values at the byte
//! offsets 0, 1024, 2048 and 3072. All values are smaller than 8, so this module keeps them as
//! `u8` values.
//!
//! Operand kinds (the tables at the offsets 0 and 1024):
//!
//! - 0: no operand after the opcode.
//! - 1: an opcode that the disassembler does not accept.
//! - 2: a `ModRM` byte, with an optional SIB byte and displacement.
//! - 3: a memory offset (`moffs`) of 8 bytes, or 4 bytes with the `67` prefix.
//! - 4: an 8-bit relative operand.
//! - 5: a 32-bit relative operand.
//!
//! Immediate kinds (the tables at the offsets 2048 and 3072):
//!
//! - 0: no immediate.
//! - 1: 1 byte.
//! - 2: 2 bytes.
//! - 3: 3 bytes (`ENTER`).
//! - 4: 8 bytes with `REX.W`, 2 bytes with the `66` prefix, else 4 bytes (`MOV r, imm`).
//! - 5: 2 bytes with the `66` prefix and without `REX.W`, else 4 bytes.
//! - 6: 1 byte if the `ModRM` `reg` field is 0 or 1 (`TEST` in group 3), else none.
//! - 7: the same as kind 5 if the `ModRM` `reg` field is 0 or 1, else none.

/// The operand kind of each one-byte opcode.
#[rustfmt::skip]
pub(super) const ONE_BYTE_OPERANDS: [u8; 256] = [
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, // 0x
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, // 1x
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, // 2x
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, // 3x
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 5x
    1, 1, 1, 2, 1, 1, 1, 1, 0, 2, 0, 2, 0, 0, 0, 0, // 6x
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, // 7x
    2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 8x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, // 9x
    3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Ax
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Bx
    2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, // Cx
    2, 2, 2, 2, 1, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, // Dx
    4, 4, 4, 4, 0, 0, 0, 0, 5, 5, 1, 4, 0, 0, 0, 0, // Ex
    0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 2, // Fx
];

/// The operand kind of each `0F` opcode.
#[rustfmt::skip]
pub(super) const TWO_BYTE_OPERANDS: [u8; 256] = [
    2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 2, // 0x
    2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, // 1x
    2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, // 2x
    0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 3x
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 4x
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 5x
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 6x
    2, 2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 2, 2, // 7x
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 8x
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 9x
    0, 0, 0, 2, 2, 2, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, // Ax
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, // Bx
    2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, // Cx
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // Dx
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // Ex
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, // Fx
];

/// The immediate kind of each one-byte opcode.
#[rustfmt::skip]
pub(super) const ONE_BYTE_IMMEDIATES: [u8; 256] = [
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, // 0x
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, // 1x
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, // 2x
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, // 3x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 4x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 5x
    0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 1, 1, 0, 0, 0, 0, // 6x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 7x
    1, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 8x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 9x
    0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, // Ax
    1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, // Bx
    1, 1, 2, 0, 0, 0, 1, 5, 3, 0, 2, 0, 0, 1, 0, 0, // Cx
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Dx
    0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, // Ex
    0, 0, 0, 0, 0, 0, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, // Fx
];

/// The immediate kind of each `0F` opcode.
#[rustfmt::skip]
pub(super) const TWO_BYTE_IMMEDIATES: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 0x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 2x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 3x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 4x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 5x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 6x
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 7x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 8x
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 9x
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, // Ax
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, // Bx
    0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Cx
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Dx
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Ex
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Fx
];
