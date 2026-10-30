//! Undo the x86 `E8` call translation (`DELTA_FLAG_E8`).
//!
//! Before compression, the creator changes the relative target of each `E8` (`call`)
//! instruction to an absolute target. The applier changes the targets back after
//! decompression, as `E8x86::PostProcess` does.

/// The largest part of the buffer that the translation changes, in bytes.
const LIMIT: usize = 0x4000_0000;

/// Change each absolute `E8` target in `data` back to a relative target.
pub(crate) fn post_process(data: &mut [u8]) {
    let size = data.len().min(LIMIT);
    // `size <= 2^30`, so it fits in `i32`.
    let limit = i32::try_from(size).unwrap_or(i32::MAX);
    let mut index = 0;
    while index < size {
        if data[index] != 0xe8 {
            index += 1;
            continue;
        }
        if size - index < 5 {
            break;
        }
        let field = &mut data[index + 1..index + 5];
        let value = i32::from_le_bytes([field[0], field[1], field[2], field[3]]);
        // `index < 2^30`, so it fits in `i32`.
        let position = i32::try_from(index).unwrap_or(i32::MAX);
        if value.wrapping_add(position) >= 0 && value < limit {
            let relative = if value < 0 {
                value.wrapping_add(limit)
            } else {
                value.wrapping_sub(position)
            };
            field.copy_from_slice(&relative.to_le_bytes());
        }
        index += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_target_becomes_relative() {
        // The target 5 is inside the 8-byte buffer: it becomes 5 - 1 = 4.
        let mut data = [0x90, 0xe8, 5, 0, 0, 0, 0x90, 0x90];
        post_process(&mut data);
        assert_eq!(data, [0x90, 0xe8, 4, 0, 0, 0, 0x90, 0x90]);
    }
}
