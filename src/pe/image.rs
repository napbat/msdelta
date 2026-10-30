//! Read the structure of a PE image for the transforms.
//!
//! `portex` parses the headers, the section table and the data directory table. This module
//! adds the rules of `msdelta.dll` on top of the parsed headers:
//!
//! - The checks of the `SectionHelper` constructor, which decide if `msdelta.dll` accepts the
//!   source as a PE image.
//! - The RVA to file offset conversion of `SectionHelper::GetImageOffset`. It uses
//!   `SizeOfRawData` and `SizeOfHeaders`, not the loader rules of `portex`, because the
//!   transforms must change the same bytes as `msdelta.dll`.
//! - The file offsets of the data directories, as the `DataDirectories` constructor finds them.
//!
//! `Pe` keeps the values from the source before the transforms. The transforms change only
//! image data, not the headers that `Pe` uses.

use crate::prelude::*;
use crate::rift::RiftTable;
use crate::{Error, Result};
use portex::PeHeaders;
use portex::section::SectionHeader;

use super::TargetInfo;

/// The smallest PE image that `msdelta.dll` accepts, in bytes.
const MIN_SIZE: usize = 0x200;
/// The size of a section header.
const SECTION_SIZE: usize = SectionHeader::SIZE;
/// `IMAGE_FILE_MACHINE_I386`.
pub(crate) const MACHINE_I386: u16 = 0x14c;
/// `IMAGE_FILE_MACHINE_IA64`.
const MACHINE_IA64: u16 = 0x200;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub(crate) const MACHINE_AMD64: u16 = 0x8664;

/// The data directory indexes.
pub(crate) mod directory {
    /// `IMAGE_DIRECTORY_ENTRY_EXPORT`.
    pub(crate) const EXPORT: usize = 0;
    /// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
    pub(crate) const IMPORT: usize = 1;
    /// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
    pub(crate) const RESOURCE: usize = 2;
    /// `IMAGE_DIRECTORY_ENTRY_BASERELOC`.
    pub(crate) const BASERELOC: usize = 5;
    /// `IMAGE_DIRECTORY_ENTRY_DEBUG`.
    pub(crate) const DEBUG: usize = 6;
    /// `IMAGE_DIRECTORY_ENTRY_GLOBALPTR`.
    pub(crate) const GLOBALPTR: usize = 8;
    /// `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`.
    pub(crate) const LOAD_CONFIG: usize = 10;
    /// `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`.
    pub(crate) const COM_DESCRIPTOR: usize = 14;
}

/// Return the error for a field outside the image.
fn outside() -> Error {
    Error::invalid_data("a PE field is outside the image")
}

/// Read a little-endian `u16` at `offset`.
pub(crate) fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = offset
        .checked_add(2)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(outside)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian `u32` at `offset`.
pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = offset
        .checked_add(4)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(outside)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u64` at `offset`.
pub(crate) fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let low = u32_at(data, offset)?;
    let high = u32_at(data, offset.checked_add(4).ok_or_else(outside)?)?;
    Ok(u64::from(low) | (u64::from(high) << 32))
}

/// Write a little-endian `u32` at `offset`.
pub(crate) fn set_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    offset
        .checked_add(4)
        .and_then(|end| data.get_mut(offset..end))
        .ok_or_else(outside)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write a little-endian `u64` at `offset`.
pub(crate) fn set_u64(data: &mut [u8], offset: usize, value: u64) -> Result<()> {
    offset
        .checked_add(8)
        .and_then(|end| data.get_mut(offset..end))
        .ok_or_else(outside)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Convert a `u32` file offset to `usize`.
pub(crate) fn at(offset: u32) -> usize {
    // `usize` has at least 32 bits on each supported target.
    offset as usize
}

/// Return the low 32 bits of `value`, as a store to a 32-bit field does.
pub(crate) fn low32(value: i64) -> u32 {
    u32::try_from(value.cast_unsigned() & 0xffff_ffff).unwrap_or_default()
}

/// The export directory, as `DataDirectories` finds it.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Exports {
    /// The file offset of `IMAGE_EXPORT_DIRECTORY`, or `None`.
    pub(crate) directory: Option<usize>,
    /// The file offset and the count of `AddressOfFunctions`.
    pub(crate) functions: Option<(usize, u32)>,
    /// The file offsets of `AddressOfNames` and `AddressOfNameOrdinals`, and the count.
    pub(crate) names: Option<(usize, usize, u32)>,
}

/// The resource directory, as `ResourceRecord` holds it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Resources {
    /// The file offset of the root directory and of the start of the resource data.
    pub(crate) base: usize,
    /// The file offset of the end of the resource data.
    pub(crate) end: usize,
    /// The RVA of the resource data.
    pub(crate) rva: u32,
}

/// The base relocations, as `DataDirectories` finds them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Relocations {
    /// The file offset of the relocation data.
    pub(crate) offset: usize,
    /// The size of the data directory.
    pub(crate) size: u32,
    /// The larger of the directory size and the rest of the `.reloc` section.
    pub(crate) extent: u32,
}

/// The data directories of an image, as `DataDirectories` finds them.
#[derive(Debug, Clone, Default)]
pub(crate) struct Directories {
    /// `NumberOfRvaAndSizes`.
    pub(crate) count: u32,
    /// The file offset of the data directory table.
    pub(crate) table: usize,
    /// The RVA of each directory.
    pub(crate) rva: [u32; 16],
    /// The file offset of each directory. Zero means that the directory is not present.
    pub(crate) offset: [u32; 16],
    /// The size of each directory, limited to the end of the file.
    pub(crate) size: [u32; 16],
    /// The export directory.
    pub(crate) exports: Exports,
    /// The file offset and the count of the import descriptors before the first empty one.
    pub(crate) imports: Option<(usize, u32)>,
    /// The resource directory.
    pub(crate) resources: Option<Resources>,
    /// The file offset of the load configuration directory.
    pub(crate) load_config: Option<usize>,
    /// The base relocations.
    pub(crate) relocations: Option<Relocations>,
    /// The file offset of the CLI header.
    pub(crate) clr: Option<usize>,
    /// The file offset and the count of the debug directory entries.
    pub(crate) debug: Option<(usize, u32)>,
}

/// The structure of a PE image.
#[derive(Debug, Clone)]
pub(crate) struct Pe {
    /// The headers that `portex` parsed.
    pub(crate) headers: PeHeaders,
    /// The size of the image file.
    pub(crate) file_size: u32,
    /// `true` for a PE32 image, `false` for a PE32+ image.
    pub(crate) is32: bool,
    /// The file offset of the NT headers (the `PE\0\0` signature).
    pub(crate) nt: usize,
    /// The file offset of the optional header.
    pub(crate) optional: usize,
    /// The file offset of the section table.
    pub(crate) section_table: usize,
    /// The smaller of `SizeOfHeaders` and the file size.
    pub(crate) header_limit: u32,
    /// The data directories.
    pub(crate) directories: Directories,
}

impl Pe {
    /// Read the headers of `data`, and apply the checks of the `SectionHelper` constructor.
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        let bad = |what: &str| Error::invalid_data(format!("the source is not a PE image: {what}"));
        let file_size = u32::try_from(data.len()).map_err(|_| bad("larger than 4 GiB"))?;
        if data.len() < MIN_SIZE {
            return Err(bad("smaller than 512 bytes"));
        }
        let headers = PeHeaders::from_slice(data)
            .map_err(|e| bad("the headers do not parse").with_details(format!("{e}")))?;
        if headers.dos_header.e_magic != 0x5a4d {
            return Err(bad("no MZ signature"));
        }
        let lfanew = u32::try_from(headers.dos_header.e_lfanew).map_err(|_| bad("bad e_lfanew"))?;
        if lfanew > file_size {
            return Err(bad("bad e_lfanew"));
        }
        let fits = |extra: u32| {
            lfanew
                .checked_add(extra)
                .is_some_and(|end| end <= file_size)
        };
        let coff = &headers.coff_header;
        let magic = match &headers.optional_header {
            portex::optional::OptionalHeader::Pe32(header) => header.magic,
            portex::optional::OptionalHeader::Pe32Plus(header) => header.magic,
        };
        let is32 = if fits(248) && magic == 0x10b && coff.size_of_optional_header == 224 {
            true
        } else if fits(264) && magic == 0x20b && coff.size_of_optional_header == 240 {
            false
        } else {
            return Err(bad("bad optional header"));
        };
        let wrong_width = match coff.machine {
            MACHINE_I386 => !is32,
            MACHINE_IA64 | MACHINE_AMD64 => is32,
            _ => false,
        };
        if wrong_width {
            return Err(bad("the machine does not match the optional header"));
        }
        let nt = at(lfanew);
        let optional = nt + 24;
        let section_table = optional + usize::from(coff.size_of_optional_header);
        for section in &headers.section_headers {
            let end = section
                .pointer_to_raw_data
                .checked_add(section.size_of_raw_data);
            if section.pointer_to_raw_data > file_size || end.is_none_or(|end| end > file_size) {
                return Err(bad("a section is outside the file"));
            }
        }
        let header_limit = headers.optional_header.size_of_headers().min(file_size);
        let mut pe = Self {
            headers,
            file_size,
            is32,
            nt,
            optional,
            section_table,
            header_limit,
            directories: Directories::default(),
        };
        pe.directories = pe.read_directories(data)?;
        Ok(pe)
    }

    /// Return the section headers.
    pub(crate) fn sections(&self) -> &[SectionHeader] {
        &self.headers.section_headers
    }

    /// Return the file offset of section header `index`.
    pub(crate) fn section_header_offset(&self, index: usize) -> usize {
        self.section_table + SECTION_SIZE * index
    }

    /// Find the section whose raw data covers `rva`, as `msdelta.dll` does.
    fn section_of(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections().iter().find(|section| {
            section.virtual_address <= rva
                && section
                    .size_of_raw_data
                    .wrapping_add(section.virtual_address)
                    > rva
        })
    }

    /// Return the file offset of `size` bytes at `rva`, or zero if the bytes are not in the
    /// file, as `SectionHelper::GetImageOffset` does.
    pub(crate) fn image_offset(&self, rva: u32, size: u32) -> u32 {
        if rva < self.header_limit {
            return if size > self.header_limit - rva {
                0
            } else {
                rva
            };
        }
        let Some(section) = self.section_of(rva) else {
            return 0;
        };
        let delta = rva - section.virtual_address;
        let raw = section.size_of_raw_data;
        if delta > raw || size > raw - delta {
            return 0;
        }
        delta.wrapping_add(section.pointer_to_raw_data)
    }

    /// Return the count of file bytes from `rva` to the end of its section, as
    /// `SectionHelper::GetMaxSize` does.
    pub(crate) fn max_size(&self, rva: u32) -> u32 {
        if self.header_limit > rva {
            return self.header_limit - rva;
        }
        self.section_of(rva).map_or(0, |section| {
            section
                .virtual_address
                .wrapping_add(section.size_of_raw_data)
                .wrapping_sub(rva)
        })
    }

    /// Return the rift table from file offsets to RVAs, as
    /// `SectionHelper::ExtractImageOffsetToRva` does.
    pub(crate) fn image_offset_to_rva(&self) -> RiftTable {
        let mut table = RiftTable::new();
        table.add(0, 0);
        for section in self.sections() {
            if section.pointer_to_raw_data != 0 && section.virtual_address != 0 {
                table.add(
                    i64::from(section.pointer_to_raw_data),
                    i64::from(section.virtual_address),
                );
            }
        }
        table
    }

    /// Find the data directories, as the `DataDirectories` constructor does.
    fn read_directories(&self, data: &[u8]) -> Result<Directories> {
        let optional = &self.headers.optional_header;
        let (count, table) = match optional {
            portex::optional::OptionalHeader::Pe32(header) => {
                (header.number_of_rva_and_sizes, self.nt + 120)
            }
            portex::optional::OptionalHeader::Pe32Plus(header) => {
                (header.number_of_rva_and_sizes, self.nt + 136)
            }
        };
        let mut dirs = Directories {
            count,
            table,
            ..Directories::default()
        };
        for (index, entry) in optional.data_directories().iter().enumerate().take(16) {
            if dirs.count <= u32::try_from(index).unwrap_or(u32::MAX) {
                continue;
            }
            let rva = entry.virtual_address;
            dirs.rva[index] = rva;
            let mut offset = self.image_offset(rva, 0);
            if offset == 0 && rva < self.file_size {
                offset = rva;
            }
            if offset != 0 {
                dirs.offset[index] = offset;
                dirs.size[index] = (self.file_size - offset).min(entry.size);
            }
        }
        dirs.exports = self.read_exports(data, &dirs)?;
        let present = |index: usize| (dirs.offset[index] != 0).then(|| at(dirs.offset[index]));
        if let Some(offset) = present(directory::IMPORT) {
            let limit = dirs.size[directory::IMPORT] / 20;
            let mut count = 0;
            while count < limit && u32_at(data, offset + 20 * at(count))? != 0 {
                count += 1;
            }
            dirs.imports = Some((offset, count));
        }
        if let Some(base) = present(directory::RESOURCE) {
            if dirs.count <= 2 {
                return Err(Error::invalid_data("the resource directory is not valid"));
            }
            dirs.resources = Some(Resources {
                base,
                end: base + at(dirs.size[directory::RESOURCE]),
                rva: dirs.rva[directory::RESOURCE],
            });
        }
        let load_config_size = if self.is32 { 64 } else { 96 };
        if dirs.size[directory::LOAD_CONFIG] >= load_config_size {
            dirs.load_config = present(directory::LOAD_CONFIG);
        }
        if let Some(offset) = present(directory::BASERELOC) {
            dirs.relocations = Some(self.relocations(&dirs, offset));
        }
        if dirs.size[directory::COM_DESCRIPTOR] >= 0x48 {
            dirs.clr = present(directory::COM_DESCRIPTOR);
        }
        if let Some(offset) = present(directory::DEBUG) {
            dirs.debug = Some((offset, dirs.size[directory::DEBUG] / 28));
        }
        Ok(dirs)
    }

    /// Find the extent of the base relocations: the directory size, or the rest of the first
    /// `.reloc` section if that is larger.
    fn relocations(&self, dirs: &Directories, offset: usize) -> Relocations {
        let size = dirs.size[directory::BASERELOC];
        let file_offset = dirs.offset[directory::BASERELOC];
        let mut extent = 0;
        // `msdelta.dll` compares the name with `.reloc` and ignores the case of the letters.
        let reloc = self.sections().iter().find(|section| {
            u64::from_le_bytes(section.name) | 0x2020_2020_2020_2020 == 0x2020_636f_6c65_722e
        });
        if let Some(section) = reloc {
            let end = section
                .size_of_raw_data
                .wrapping_add(section.pointer_to_raw_data);
            if section.pointer_to_raw_data <= file_offset && end > file_offset {
                extent = end - file_offset;
            }
        }
        Relocations {
            offset,
            size,
            extent: extent.max(size),
        }
    }

    /// Find the export tables, as the `DataDirectories` constructor does.
    fn read_exports(&self, data: &[u8], dirs: &Directories) -> Result<Exports> {
        let mut exports = Exports::default();
        if dirs.offset[directory::EXPORT] == 0 || dirs.size[directory::EXPORT] < 0x28 {
            return Ok(exports);
        }
        let dir = at(dirs.offset[directory::EXPORT]);
        exports.directory = Some(dir);
        let functions = u32_at(data, dir + 20)?;
        if functions <= 0x3fff_ffff {
            let offset = self.image_offset(u32_at(data, dir + 28)?, 4 * functions);
            if offset != 0 {
                exports.functions = Some((at(offset), functions));
            }
        }
        let names = u32_at(data, dir + 24)?;
        if names <= 0x3fff_ffff {
            let name_offset = self.image_offset(u32_at(data, dir + 32)?, 4 * names);
            let ordinal_offset = self.image_offset(u32_at(data, dir + 36)?, 2 * names);
            if name_offset != 0 && ordinal_offset != 0 {
                exports.names = Some((at(name_offset), at(ordinal_offset), names));
            }
        }
        Ok(exports)
    }

    /// Write the image base, the global pointer, the time stamp and a zero checksum of the
    /// target, as `PreProcessPEForApply` does after the transforms.
    pub(crate) fn set_target_fields(&self, data: &mut [u8], info: &TargetInfo) -> Result<()> {
        if self.is32 {
            // A PE32 image has a 32-bit image base: keep the low half.
            set_u32(
                data,
                self.optional + 28,
                low32(info.image_base.cast_signed()),
            )?;
        } else {
            set_u64(data, self.optional + 24, info.image_base)?;
        }
        if self.directories.count <= 8 {
            return Err(Error::invalid_data(
                "the image has no global pointer directory",
            ));
        }
        set_u32(
            data,
            self.directories.table + 8 * directory::GLOBALPTR,
            info.global_pointer,
        )?;
        set_u32(data, self.nt + 8, info.time_stamp)?;
        set_u32(data, self.optional + 64, 0)
    }
}
