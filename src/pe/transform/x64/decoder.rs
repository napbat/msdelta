//! Find the length of an AMD64 instruction, as `DisassemblerAmd64::Disassemble` does.
//!
//! The decoder is not a full disassembler. It reads the prefixes, the opcode, the `ModRM` byte, the
//! SIB byte, the displacement and the immediate. It finds the length of the instruction and the
//! position of a 32-bit relative operand: the operand of `CALL rel32`, `JMP rel32` and `Jcc
//! rel32`, or the displacement of a RIP-relative memory operand.

use super::tables::{
    ONE_BYTE_IMMEDIATES, ONE_BYTE_OPERANDS, TWO_BYTE_IMMEDIATES, TWO_BYTE_OPERANDS,
};

/// The maximum length of an instruction.
const MAX_LENGTH: usize = 15;

/// One instruction that the decoder found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Instruction {
    /// The length of the instruction. For bytes that the decoder does not accept, this is the
    /// count of bytes that the decoder read. It is at least 1.
    pub(super) length: u8,
    /// The position of the 32-bit relative operand in the instruction, if there is one.
    pub(super) relative: Option<u8>,
}

/// The kind of the last operand that the decoder found (byte 2 of `Instruction` in the DLL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// No relative operand.
    Other,
    /// A 32-bit relative operand or a RIP-relative displacement.
    Relative,
}

/// The state of the decoder.
struct Decoder<'a> {
    /// The bytes from the start of the instruction. The decoder reads at most `limit` bytes.
    code: &'a [u8],
    /// The count of bytes that the decoder can read.
    limit: usize,
    /// The count of bytes that the decoder read (byte 0 of `Instruction` in the DLL).
    length: usize,
    /// The position of the last operand (byte 1 of `Instruction` in the DLL).
    operand: usize,
    /// The kind of the last operand.
    kind: Kind,
}

impl Decoder<'_> {
    /// Return `Some` if `count` bytes from `position` are available.
    fn need(&self, position: usize, count: usize) -> Option<()> {
        (self.limit.saturating_sub(position) >= count).then_some(())
    }

    /// Read the byte at `position`, or return `None` if the byte is not available.
    fn byte(&self, position: usize) -> Option<u8> {
        self.need(position, 1)?;
        self.code.get(position).copied()
    }

    /// Add an operand of `size` bytes at `position`, and move the length after it.
    fn operand(&mut self, position: usize, size: usize, kind: Kind) -> Option<()> {
        self.need(position, size)?;
        self.operand = position;
        self.kind = kind;
        self.length = position + size;
        Some(())
    }

    /// Add an immediate of `size` bytes after the bytes that the decoder read.
    fn immediate(&mut self, size: usize) -> Option<()> {
        self.need(self.length, size)?;
        self.length += size;
        Some(())
    }

    /// Read the `ModRM` byte at `position`, with the SIB byte and the displacement. Return
    /// `true` if the `reg` field is 0 or 1.
    fn modrm(&mut self, position: usize) -> Option<bool> {
        let modrm = self.byte(position)?;
        let position = position + 1;
        self.length = position;
        let mode = modrm >> 6;
        let rm = modrm & 7;
        let low_reg = modrm & 0x38 == 0 || modrm & 0x38 == 8;
        match (mode, rm) {
            (3, _) => {}
            (0, 5) => self.operand(position, 4, Kind::Relative)?,
            (_, 4) => {
                let sib = self.byte(position)?;
                let after = position + 1;
                self.length = after;
                if mode == 1 {
                    self.operand(after, 1, Kind::Other)?;
                } else if mode == 2 || sib & 7 == 5 {
                    self.operand(after, 4, Kind::Other)?;
                }
            }
            (1, _) => self.operand(position, 1, Kind::Other)?,
            (2, _) => self.operand(position, 4, Kind::Other)?,
            _ => {}
        }
        Some(low_reg)
    }

    /// Decode the instruction. Return `None` for bytes that the decoder does not accept.
    fn decode(&mut self) -> Option<()> {
        let mut operand_size = false;
        let mut address_size = false;
        let mut opcode;
        loop {
            opcode = self.byte(self.length)?;
            self.length += 1;
            match opcode {
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf0 | 0xf2 | 0xf3 => {}
                0x66 => operand_size = true,
                0x67 => address_size = true,
                _ => break,
            }
        }
        let mut position = self.length;
        let mut wide = false;
        if opcode & 0xf0 == 0x40 {
            let next = self.byte(position)?;
            wide = opcode & 8 != 0;
            if next & 0xf0 == 0x40 {
                // The DLL does not count the second REX prefix.
                return None;
            }
            position += 1;
            self.length = position;
            opcode = next;
        }
        let (operands, immediates) = if opcode == 0x0f {
            let second = self.byte(position)?;
            position += 1;
            self.length = position;
            (
                TWO_BYTE_OPERANDS[usize::from(second)],
                TWO_BYTE_IMMEDIATES[usize::from(second)],
            )
        } else {
            (
                ONE_BYTE_OPERANDS[usize::from(opcode)],
                ONE_BYTE_IMMEDIATES[usize::from(opcode)],
            )
        };
        let mut low_reg = false;
        match operands {
            1 => return None,
            2 => low_reg = self.modrm(position)?,
            3 => {
                let size = if address_size { 4 } else { 8 };
                self.operand(position, size, Kind::Other)?;
            }
            4 => self.operand(position, 1, Kind::Other)?,
            5 => self.operand(position, 4, Kind::Relative)?,
            _ => {}
        }
        let full = if wide || !operand_size { 4 } else { 2 };
        match immediates {
            1 => self.immediate(1),
            2 => self.immediate(2),
            3 => self.immediate(3),
            4 if wide => self.immediate(8),
            4 if operand_size => self.immediate(2),
            4 => self.immediate(4),
            5 => self.immediate(full),
            6 if low_reg => self.immediate(1),
            7 if low_reg => self.immediate(full),
            _ => Some(()),
        }
    }
}

/// Decode the instruction at the start of `code`, as `DisassemblerAmd64::Disassemble` does.
///
/// The decoder reads at most 15 bytes. If `code` is empty, the length is 0.
pub(super) fn decode(code: &[u8]) -> Instruction {
    let mut decoder = Decoder {
        code,
        limit: code.len().min(MAX_LENGTH),
        length: 0,
        operand: 0xff,
        kind: Kind::Other,
    };
    let accepted = decoder.decode().is_some();
    // The length and the operand position are at most 15.
    let length = u8::try_from(decoder.length).unwrap_or(u8::MAX);
    let relative = if accepted && decoder.kind == Kind::Relative {
        u8::try_from(decoder.operand).ok()
    } else {
        None
    };
    Instruction { length, relative }
}

#[cfg(test)]
mod tests {
    use super::{Instruction, decode};

    fn check(code: &[u8], length: u8, relative: Option<u8>) {
        assert_eq!(
            decode(code),
            Instruction { length, relative },
            "{code:02x?}"
        );
    }

    #[test]
    fn relative_operands() {
        // call rel32
        check(&[0xe8, 1, 2, 3, 4], 5, Some(1));
        // jne rel32
        check(&[0x0f, 0x85, 1, 2, 3, 4], 6, Some(2));
        // mov rax, [rip + disp32]
        check(&[0x48, 0x8b, 0x05, 1, 2, 3, 4], 7, Some(3));
        // cmp byte [rip + disp32], imm8
        check(&[0x80, 0x3d, 1, 2, 3, 4, 5], 7, Some(2));
        // test dword [rip + disp32], imm32
        check(&[0xf7, 0x05, 1, 2, 3, 4, 5, 6, 7, 8], 10, Some(2));
    }

    #[test]
    fn other_operands() {
        // jmp rel8
        check(&[0xeb, 0x10], 2, None);
        // mov rax, imm64
        check(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8], 10, None);
        // mov ax, imm16
        check(&[0x66, 0xb8, 1, 2], 4, None);
        // mov eax, [rsp + disp8]
        check(&[0x8b, 0x44, 0x24, 0x10], 4, None);
        // mov eax, [disp32] with a SIB byte
        check(&[0x8b, 0x04, 0x25, 1, 2, 3, 4], 7, None);
        // not dword [rax]: group 3 without an immediate
        check(&[0xf7, 0x10], 2, None);
        // mov al, [moffs64]
        check(&[0xa0, 1, 2, 3, 4, 5, 6, 7, 8], 9, None);
    }

    #[test]
    fn rejected_bytes() {
        // Two REX prefixes: the DLL counts only the first one.
        check(&[0x48, 0x48, 0x90], 1, None);
        // A truncated call rel32.
        check(&[0xe8, 1, 2], 1, None);
        // A truncated RIP-relative operand with an immediate.
        check(&[0x80, 0x3d, 1, 2, 3, 4], 6, None);
        // Only prefixes.
        check(&[0x66, 0x66], 2, None);
        check(&[], 0, None);
    }
}
